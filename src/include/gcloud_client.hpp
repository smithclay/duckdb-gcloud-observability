#pragma once

#include "duckdb.hpp"
#include "gcloud_auth.hpp"

#ifndef __EMSCRIPTEN__
//! Forward-declared so the (large) httplib header stays out of this public header. The namespace
//! name matches cpp-httplib's OpenSSL build, which CMake selects globally via CPPHTTPLIB_OPENSSL_SUPPORT.
//! Browser builds use DuckDB's own HTTPUtil instead and have no native socket layer at all.
namespace duckdb_httplib_openssl {
class Client;
}
#endif

namespace duckdb {
class ClientContext;

//! Minimal client for the Cloud Logging API (POST /v2/entries:list). It knows how to authenticate
//! (OAuth2 bearer token, obtained per gcloud_auth.hpp) and POST a JSON body; parsing the response
//! and mapping LogEntry to OTLP lives in the table function. A single keep-alive connection is
//! reused across pages.
struct GcloudClient {
	//! API base, e.g. "https://logging.googleapis.com". Requests go to <endpoint><path>. It may carry
	//! a path prefix ("https://lab.example.com/api/gcloud/logging"), which is how a browser build is
	//! pointed at a CORS proxy; the prefix is preserved ahead of the request path.
	string endpoint = "https://logging.googleapis.com";
	//! How to obtain the bearer token for each request.
	GcloudAuthConfig auth;
	//! Whether authenticated requests should carry x-goog-user-project when ADC supplies a quota
	//! project. App Topology authorizes against the topology resource project and does not require
	//! callers with topology-viewer access to also hold serviceusage.services.use on the ADC project.
	bool send_quota_project = true;
	//! Skip TLS certificate/hostname verification (test doubles only).
	bool insecure_tls = false;
	//! Per-request connection/read timeout.
	uint64_t timeout_seconds = 60;
	//! Retry budget for transient failures: HTTP 429, HTTP 5xx, and transport errors (connection
	//! reset, timeout) share this budget with exponential backoff. 0 disables retrying.
	//! Non-transient failures (4xx other than 429, TLS certificate verification) are never retried.
	//! A 401 is retried exactly once, after dropping the cached token — see ListEntries.
	uint64_t retries = 4;

	// Owns a live keep-alive connection (the unique_ptr below), so the type is non-copyable. It is
	// only ever default-constructed in place inside the table function's bind data. The constructor
	// and destructor are declared here and defined out-of-line so the unique_ptr may hold a
	// forward-declared (incomplete) Client; both must live where Client is complete.
	GcloudClient();
	~GcloudClient();

	//! Issue one authenticated request against `endpoint` and return the raw response body.
	//! `method` is "GET" or "POST"; `json_body` is ignored for GET. `api_name` names the API in error
	//! messages ("Cloud Logging", "Cloud Monitoring"). Transparently retries transient failures
	//! (429 / 5xx / transport errors) up to `retries` times, sleeping in small slices so query
	//! interrupts (Ctrl+C) cancel the wait promptly, and re-mints the token once on a 401. Throws
	//! IOException when retries are exhausted or the failure is not transient, and InterruptException
	//! if the query was cancelled.
	string Request(ClientContext &context, const char *method, const string &path, const string &json_body,
	               const char *api_name) const;

	//! POST `json_body` to /v2/entries:list. Convenience wrapper over Request.
	string ListEntries(ClientContext &context, const string &json_body) const;

	//! POST one pre-batched request to /v2/entries:write. Unlike the read request path, ambiguous
	//! transport failures are not retried because the server may already have accepted the batch.
	//! A server-generated 429 is retried; 5xx responses are treated as ambiguous and are not replayed.
	string WriteEntries(ClientContext &context, const string &json_body) const;

	//! GET `path` (which must already carry any query string). Convenience wrapper over Request.
	string Get(ClientContext &context, const string &path, const char *api_name) const;

	//! Issue one protobuf gRPC unary call over HTTP/2. App Topology currently exposes its Preview
	//! graph generator through gRPC only, so this keeps that transport behind the same authenticated,
	//! retrying client used by the JSON APIs. `method` is the full `/package.Service/Method` path.
	string GrpcUnary(ClientContext &context, const string &method, const string &protobuf, const char *api_name) const;

private:
#ifndef __EMSCRIPTEN__
	//! Lazily created on first use and reused (HTTP keep-alive). Mutable because ListEntries is
	//! const — it runs against the const bind data shared by all scans — yet must cache the socket.
	//! Reset (and re-established) after a transport error, since the failure may have left the
	//! pooled socket broken.
	mutable unique_ptr<duckdb_httplib_openssl::Client> connection;

	//! Return the shared connection, creating and configuring it (TLS, timeouts) on the first call.
	//! Authorization is *not* set here: the token can be refreshed between requests, so it is
	//! attached per-request instead.
	duckdb_httplib_openssl::Client &GetConnection() const;
#endif
};

} // namespace duckdb
