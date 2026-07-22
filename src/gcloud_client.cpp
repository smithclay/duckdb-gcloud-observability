#include "gcloud_client.hpp"

#include "gcloud_json.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"
#ifdef __EMSCRIPTEN__
#include "duckdb/common/http_util.hpp"
#endif

#include "yyjson.hpp"

#include <cstring>
#include <memory>

#ifndef __EMSCRIPTEN__
// Use DuckDB's bundled cpp-httplib. Defining CPPHTTPLIB_OPENSSL_SUPPORT (see CMakeLists) both
// enables TLS and selects the `duckdb_httplib_openssl` namespace, so these symbols never collide
// with core DuckDB's non-SSL `duckdb_httplib` build. DuckDB-WASM supplies a browser-backed HTTPUtil
// instead, so a browser build pulls in neither httplib nor native sockets.
#include "httplib.hpp"

#include <chrono>
#include <thread>
#endif

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

static constexpr const char *kEntriesListPath = "/v2/entries:list";

// Defined here, where `Client` is complete, so the header's unique_ptr<Client> member can point at
// a forward-declared type. The destructor uses an empty body rather than `= default` to keep
// clang-tidy's performance-trivially-destructible check quiet.
GcloudClient::GcloudClient() = default;
GcloudClient::~GcloudClient() {
}

#ifndef __EMSCRIPTEN__
duckdb_httplib_openssl::Client &GcloudClient::GetConnection() const {
	if (!connection) {
		string origin, path_prefix;
		SplitGcloudEndpoint(endpoint, origin, path_prefix);
		connection = make_uniq<duckdb_httplib_openssl::Client>(origin);
		connection->set_connection_timeout(static_cast<time_t>(timeout_seconds), 0);
		connection->set_read_timeout(static_cast<time_t>(timeout_seconds), 0);
		// Keep the socket open between requests so cursor pagination reuses one TCP+TLS connection
		// instead of handshaking per page. cpp-httplib defaults keep-alive off.
		connection->set_keep_alive(true);
		// No set_follow_location: the endpoint is a fixed POST; following a 3xx would forward the
		// Authorization bearer token to the redirect target and mask real non-2xx errors.

		if (insecure_tls) {
			connection->enable_server_certificate_verification(false);
			connection->enable_server_hostname_verification(false);
		}
	}
	return *connection;
}
#endif

#ifndef __EMSCRIPTEN__
//! Sleep for `seconds`, polling the query's interrupt flag so a cancelled query (Ctrl+C) aborts
//! the wait within ~100ms instead of blocking a scan thread for the full retry delay.
static void SleepCheckingInterrupt(ClientContext &context, uint64_t seconds) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (std::chrono::steady_clock::now() < deadline) {
		if (context.interrupted) {
			throw InterruptException();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

//! TLS certificate/hostname failures are configuration or security problems — retrying cannot
//! succeed and would only delay (or worse, mask) the real error.
static bool IsRetryableTransportError(duckdb_httplib_openssl::Error error) {
	switch (error) {
	case duckdb_httplib_openssl::Error::SSLLoadingCerts:
	case duckdb_httplib_openssl::Error::SSLServerVerification:
	case duckdb_httplib_openssl::Error::SSLServerHostnameVerification:
		return false;
	default:
		return true;
	}
}

//! Seconds to wait before retrying a 429, based on the server's advice (Retry-After), else
//! exponential backoff. Clamped to [1, 60] so a stray/huge header value can't stall the query.
static uint64_t RateLimitRetryDelaySeconds(const duckdb_httplib_openssl::Response &response, uint64_t attempt) {
	if (response.has_header("Retry-After")) {
		try {
			long long secs = std::stoll(response.get_header_value("Retry-After"));
			if (secs < 0) {
				secs = 0;
			}
			if (secs > 59) {
				return 60;
			}
			return static_cast<uint64_t>(secs) + 1; // +1s margin to clear the reset boundary
		} catch (const std::exception &) {
			// Unparseable header (e.g. an HTTP-date Retry-After); fall back to backoff below.
		}
	}
	return MinValue<uint64_t>(uint64_t(1) << attempt, 60); // 1, 2, 4, 8, ... seconds
}
#endif

//! Google's JSON error envelope is {"error":{"code":403,"message":"...","status":"PERMISSION_DENIED"}}.
//! Surface `message` (and `status`), which say exactly which API or permission is missing, rather
//! than dumping the whole body.
static string DescribeApiError(const string &body) {
	std::unique_ptr<yyjson_doc, void (*)(yyjson_doc *)> doc(yyjson_read(body.c_str(), body.size(), 0), yyjson_doc_free);
	if (!doc) {
		return body;
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	yyjson_val *error = root ? yyjson_obj_get(root, "error") : nullptr;
	if (!error || !yyjson_is_obj(error)) {
		return body;
	}
	yyjson_val *message = yyjson_obj_get(error, "message");
	yyjson_val *status = yyjson_obj_get(error, "status");
	if (!message || !yyjson_is_str(message)) {
		return body;
	}
	string described = yyjson_get_str(message);
	if (status && yyjson_is_str(status)) {
		described = string(yyjson_get_str(status)) + ": " + described;
	}
	return described;
}

//! Assemble the bearer token and the headers every Google API request carries.
static void BuildAuthHeaders(ClientContext &context, const GcloudAuthConfig &auth, string &out_authorization,
                             string &out_quota_project) {
	auto access_token = GetGcloudAccessToken(context, auth);
	out_authorization = "Bearer " + access_token.token;
	// End-user (authorized_user) credentials have no project of their own, so Google bills the call
	// against this header; without it such requests fail with USER_PROJECT_DENIED.
	out_quota_project = access_token.quota_project;
}

string GcloudClient::Request(ClientContext &context, const char *method, const string &path, const string &json_body,
                             const char *api_name) const {
	string origin, path_prefix;
	SplitGcloudEndpoint(endpoint, origin, path_prefix);
	auto full_path = path_prefix + path;
	bool is_post = strcmp(method, "POST") == 0;

#ifdef __EMSCRIPTEN__
	// Browser build: DuckDB-WASM's HTTPUtil issues the request through fetch(), so the browser owns
	// transport, TLS, and retry. `endpoint` will normally point at a CORS proxy, because Google's
	// APIs send no Access-Control-Allow-Origin and a page therefore cannot call them directly.
	if (context.interrupted) {
		throw InterruptException();
	}
	string authorization, quota_project;
	BuildAuthHeaders(context, auth, authorization, quota_project);

	auto &http_util = HTTPUtil::Get(*context.db);
	auto url = origin + full_path;
	auto params = http_util.InitializeParameters(context, url);
	params->timeout = timeout_seconds;
	params->retries = retries;
	params->keep_alive = true;
	// Following a redirect would forward the Authorization bearer token to the redirect target.
	params->follow_location = false;

	HTTPHeaders headers;
	headers.Insert("Authorization", authorization);
	headers.Insert("Accept", "application/json");
	if (!quota_project.empty()) {
		headers.Insert("x-goog-user-project", quota_project);
	}

	unique_ptr<HTTPResponse> response;
	if (is_post) {
		headers.Insert("Content-Type", "application/json");
		PostRequestInfo request(url, headers, *params, reinterpret_cast<const_data_ptr_t>(json_body.data()),
		                        json_body.size());
		request.try_request = true;
		response = http_util.Request(request);
	} else {
		GetRequestInfo request(url, headers, *params, nullptr, nullptr);
		request.try_request = true;
		response = http_util.Request(request);
	}

	if (!response) {
		throw IOException("%s API request to %s failed: no response (check the proxy URL and its CORS allowlist)",
		                  api_name, url);
	}
	if (!response->Success()) {
		auto status = static_cast<uint16_t>(response->status);
		if (response->status != HTTPStatusCode::INVALID) {
			// The body carries Google's error message but never the bearer token, which travels only
			// in the request's Authorization header.
			throw IOException("%s API returned HTTP %d: %s", api_name, status, DescribeApiError(response->body));
		}
		throw IOException("%s API request to %s failed: %s (check the proxy URL, its CORS allowlist -- which must "
		                  "permit the Authorization and x-goog-user-project headers -- and the network connection)",
		                  api_name, url, response->GetError());
	}
	return response->body;
#else
	// A 401 means the token was rejected (expired, or revoked mid-query). Drop the cached token and
	// re-mint exactly once: a second 401 is a real authorization problem, not a stale token, and
	// retrying it would loop.
	bool token_refreshed = false;

	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}

		string authorization, quota_project;
		BuildAuthHeaders(context, auth, authorization, quota_project);
		duckdb_httplib_openssl::Headers headers = {
		    {"Authorization", authorization},
		    {"Accept", "application/json"},
		};
		if (!quota_project.empty()) {
			headers.emplace("x-goog-user-project", quota_project);
		}

		auto response = is_post ? GetConnection().Post(full_path.c_str(), headers, json_body, "application/json")
		                        : GetConnection().Get(full_path.c_str(), headers);

		if (!response) {
			auto error = response.error();
			// Drop the pooled connection: after a transport error the socket may be half-dead, and
			// reconnecting from scratch is the reliable way to retry.
			connection.reset();
			if (attempt >= retries || !IsRetryableTransportError(error)) {
				throw IOException("%s API request to %s failed: %s", api_name, endpoint,
				                  duckdb_httplib_openssl::to_string(error));
			}
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}

		// Stale/revoked token: re-mint once, then fall through to the normal error path.
		if (response->status == 401 && !token_refreshed) {
			token_refreshed = true;
			InvalidateGcloudTokenCache(auth);
			continue;
		}
		// Rate limited: wait out the server-advised delay instead of failing the whole query.
		if (response->status == 429 && attempt < retries) {
			SleepCheckingInterrupt(context, RateLimitRetryDelaySeconds(*response, attempt));
			continue;
		}
		// Server-side errors are usually transient; ride them out rather than lose the query.
		if (response->status >= 500 && attempt < retries) {
			SleepCheckingInterrupt(context, MinValue<uint64_t>(uint64_t(1) << attempt, 60));
			continue;
		}
		if (response->status < 200 || response->status >= 300) {
			// The body carries Google's error message but never the bearer token.
			throw IOException("%s API returned HTTP %d: %s", api_name, response->status,
			                  DescribeApiError(response->body));
		}
		return response->body;
	}
#endif
}

string GcloudClient::ListEntries(ClientContext &context, const string &json_body) const {
	return Request(context, "POST", kEntriesListPath, json_body, "Cloud Logging");
}

string GcloudClient::Get(ClientContext &context, const string &path, const char *api_name) const {
	return Request(context, "GET", path, string(), api_name);
}

} // namespace duckdb
