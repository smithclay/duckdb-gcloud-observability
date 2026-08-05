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

#include <curl/curl.h>

#include <chrono>
#include <mutex>
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

//! Exponential retry delay capped before shifting, so even the maximum accepted retry budget
//! cannot shift past the width of uint64_t.
static uint64_t RetryDelaySeconds(uint64_t attempt) {
	return attempt >= 6 ? 60 : uint64_t(1) << attempt;
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
	return RetryDelaySeconds(attempt); // 1, 2, 4, 8, ... 60 seconds
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
			SleepCheckingInterrupt(context, RetryDelaySeconds(attempt));
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
			SleepCheckingInterrupt(context, RetryDelaySeconds(attempt));
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

#ifndef __EMSCRIPTEN__
namespace {

struct CurlGlobalState {
	CurlGlobalState() {
		if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
			throw InternalException("Could not initialize libcurl for the App Topology client");
		}
	}
	~CurlGlobalState() {
		curl_global_cleanup();
	}
};

static CurlGlobalState &GetCurlGlobalState() {
	static CurlGlobalState state;
	return state;
}

struct GrpcResponse {
	string body;
	string grpc_status;
	string grpc_message;
};

static size_t AppendCurlBody(char *data, size_t size, size_t count, void *userdata) {
	auto &response = *static_cast<GrpcResponse *>(userdata);
	auto bytes = size * count;
	response.body.append(data, bytes);
	return bytes;
}

static string TrimHeaderValue(string value) {
	StringUtil::Trim(value);
	return value;
}

static size_t CaptureCurlHeader(char *data, size_t size, size_t count, void *userdata) {
	auto &response = *static_cast<GrpcResponse *>(userdata);
	auto bytes = size * count;
	string header(data, bytes);
	auto colon = header.find(':');
	if (colon == string::npos) {
		return bytes;
	}
	auto name = StringUtil::Lower(header.substr(0, colon));
	auto value = TrimHeaderValue(header.substr(colon + 1));
	if (name == "grpc-status") {
		response.grpc_status = value;
	} else if (name == "grpc-message") {
		response.grpc_message = value;
	}
	return bytes;
}

static int CurlProgress(void *userdata, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
	auto &context = *static_cast<ClientContext *>(userdata);
	return context.interrupted ? 1 : 0;
}

static string PercentDecodeGrpcMessage(const string &value) {
	string result;
	result.reserve(value.size());
	for (idx_t i = 0; i < value.size(); i++) {
		if (value[i] == '%' && i + 2 < value.size()) {
			auto hex = [](char ch) -> int {
				if (ch >= '0' && ch <= '9')
					return ch - '0';
				if (ch >= 'a' && ch <= 'f')
					return ch - 'a' + 10;
				if (ch >= 'A' && ch <= 'F')
					return ch - 'A' + 10;
				return -1;
			};
			auto high = hex(value[i + 1]);
			auto low = hex(value[i + 2]);
			if (high >= 0 && low >= 0) {
				result.push_back(static_cast<char>((high << 4) | low));
				i += 2;
				continue;
			}
		}
		result.push_back(value[i]);
	}
	return result;
}

static string FrameGrpcMessage(const string &protobuf) {
	if (protobuf.size() > std::numeric_limits<uint32_t>::max()) {
		throw InvalidInputException("App Topology request is too large for one gRPC message");
	}
	auto length = static_cast<uint32_t>(protobuf.size());
	string result(5, '\0');
	result[1] = static_cast<char>((length >> 24) & 0xff);
	result[2] = static_cast<char>((length >> 16) & 0xff);
	result[3] = static_cast<char>((length >> 8) & 0xff);
	result[4] = static_cast<char>(length & 0xff);
	result.append(protobuf);
	return result;
}

static string UnframeGrpcMessage(const string &body) {
	idx_t offset = 0;
	string result;
	idx_t messages = 0;
	while (offset < body.size()) {
		if (body.size() - offset < 5) {
			throw IOException("App Topology API returned a truncated gRPC frame");
		}
		auto flags = static_cast<uint8_t>(body[offset]);
		auto length = (static_cast<uint32_t>(static_cast<uint8_t>(body[offset + 1])) << 24) |
		              (static_cast<uint32_t>(static_cast<uint8_t>(body[offset + 2])) << 16) |
		              (static_cast<uint32_t>(static_cast<uint8_t>(body[offset + 3])) << 8) |
		              static_cast<uint32_t>(static_cast<uint8_t>(body[offset + 4]));
		offset += 5;
		if (length > body.size() - offset) {
			throw IOException("App Topology API returned a truncated gRPC message");
		}
		if (flags & 1) {
			throw IOException("App Topology API returned a compressed gRPC message, which is not supported");
		}
		if (flags & 0x80) {
			// gRPC-Web trailer frames are not expected from the native API, but safely skip one if a
			// test proxy translates the call.
			offset += length;
			continue;
		}
		if (++messages > 1) {
			throw IOException("App Topology API returned more than one message for a unary gRPC call");
		}
		result.assign(body.data() + offset, length);
		offset += length;
	}
	if (messages != 1) {
		throw IOException("App Topology API returned no message for a unary gRPC call");
	}
	return result;
}

static bool RetryableGrpcStatus(const string &status) {
	return status == "8" || status == "13" || status == "14"; // RESOURCE_EXHAUSTED, INTERNAL, UNAVAILABLE
}

static bool IsRetryableCurlError(CURLcode code) {
	switch (code) {
	case CURLE_COULDNT_RESOLVE_PROXY:
	case CURLE_COULDNT_RESOLVE_HOST:
	case CURLE_COULDNT_CONNECT:
	case CURLE_PARTIAL_FILE:
	case CURLE_HTTP2:
	case CURLE_SEND_ERROR:
	case CURLE_RECV_ERROR:
	case CURLE_OPERATION_TIMEDOUT:
	case CURLE_GOT_NOTHING:
	case CURLE_AGAIN:
	case CURLE_HTTP2_STREAM:
		return true;
	default:
		return false;
	}
}

} // namespace
#endif

string GcloudClient::GrpcUnary(ClientContext &context, const string &method, const string &protobuf,
                               const char *api_name) const {
#ifdef __EMSCRIPTEN__
	throw NotImplementedException("%s service maps require native gRPC/HTTP2 and are not available in DuckDB-WASM",
	                              api_name);
#else
	(void)GetCurlGlobalState();
	auto framed = FrameGrpcMessage(protobuf);
	auto url = endpoint + method;
	bool token_refreshed = false;
	for (uint64_t attempt = 0;; attempt++) {
		if (context.interrupted) {
			throw InterruptException();
		}
		auto access_token = GetGcloudAccessToken(context, auth);
		GrpcResponse response;
		char curl_error[CURL_ERROR_SIZE] = {0};
		auto curl = curl_easy_init();
		if (!curl) {
			throw InternalException("Could not initialize an App Topology HTTP/2 request");
		}
		curl_slist *headers = nullptr;
		headers = curl_slist_append(headers, ("authorization: Bearer " + access_token.token).c_str());
		headers = curl_slist_append(headers, "content-type: application/grpc");
		headers = curl_slist_append(headers, "te: trailers");
		if (send_quota_project && !access_token.quota_project.empty()) {
			headers = curl_slist_append(headers, ("x-goog-user-project: " + access_token.quota_project).c_str());
		}
		curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, framed.data());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(framed.size()));
		curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(timeout_seconds));
		curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, static_cast<long>(timeout_seconds));
		curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, AppendCurlBody);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, CaptureCurlHeader);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
		curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, CurlProgress);
		curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &context);
		curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);
		if (insecure_tls) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}

		auto code = curl_easy_perform(curl);
		long http_status = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);

		if (code == CURLE_ABORTED_BY_CALLBACK && context.interrupted) {
			throw InterruptException();
		}
		if (code != CURLE_OK) {
			if (attempt < retries && IsRetryableCurlError(code)) {
				SleepCheckingInterrupt(context, RetryDelaySeconds(attempt));
				continue;
			}
			throw IOException("%s gRPC request to %s failed: %s", api_name, endpoint,
			                  curl_error[0] ? curl_error : curl_easy_strerror(code));
		}
		if (http_status == 401 && !token_refreshed) {
			token_refreshed = true;
			InvalidateGcloudTokenCache(auth);
			continue;
		}
		if ((http_status == 429 || http_status >= 500 || RetryableGrpcStatus(response.grpc_status)) &&
		    attempt < retries) {
			SleepCheckingInterrupt(context, RetryDelaySeconds(attempt));
			continue;
		}
		if (http_status < 200 || http_status >= 300) {
			throw IOException("%s gRPC endpoint returned HTTP %d", api_name, http_status);
		}
		if (response.grpc_status.empty()) {
			throw IOException("%s gRPC response did not include a grpc-status trailer", api_name);
		}
		if (response.grpc_status != "0") {
			auto message = PercentDecodeGrpcMessage(response.grpc_message);
			throw IOException("%s gRPC returned status %s: %s", api_name, response.grpc_status,
			                  message.empty() ? "unknown error" : message);
		}
		return UnframeGrpcMessage(response.body);
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
