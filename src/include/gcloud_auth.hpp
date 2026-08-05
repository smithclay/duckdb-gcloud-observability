#pragma once

#include "duckdb.hpp"

namespace duckdb {
class ClientContext;

//! OAuth2 scope requested for the logging read path. Mirrors the OpenTelemetry Collector's
//! googlecloudmonitoringreceiver, which calls google.FindDefaultCredentials(ctx, <read scope>).
extern const char *const kLoggingReadScope;

//! OAuth2 scope requested by entries.write. Kept separate from the read scope so a service-account
//! token used only for queries is never granted write authority.
extern const char *const kLoggingWriteScope;

//! OAuth2 scope for the Cloud Monitoring read path, used by the alerts tables. Requested separately
//! from the logging scope so a logs-only query never asks for monitoring authority (and vice
//! versa); the token cache is keyed by scope, so the two coexist.
extern const char *const kMonitoringReadScope;

//! App Topology's generated topology method accepts the general Cloud Platform scope.
extern const char *const kCloudPlatformScope;

//! How to obtain an OAuth2 bearer token for the Cloud Logging API. Exactly one of `token` (an
//! already-minted access token) or a credentials JSON file is used; when both are empty the file is
//! discovered the way every Google client library does it (Application Default Credentials).
struct GcloudAuthConfig {
	//! Pre-minted OAuth2 access token, e.g. `gcloud auth print-access-token`. Used verbatim, never
	//! refreshed — when it expires the query fails with a 401. Takes precedence over `credentials_file`.
	string token;
	//! Explicit path to a credentials JSON file (service account key, or the authorized_user file
	//! written by `gcloud auth application-default login`). Empty => discover via ADC.
	string credentials_file;
	//! Billing/quota project sent as `x-goog-user-project`. Required by Google when calling with
	//! end-user (authorized_user) credentials. Empty => taken from the credentials file's
	//! `quota_project_id`, if present.
	string quota_project;
	//! OAuth2 scope requested when minting a token. Only the `service_account` path sends it: the
	//! refresh-token grant deliberately sends no scope, because it returns whatever was originally
	//! consented to (typically cloud-platform, which covers both APIs).
	string scope = kLoggingReadScope;
	//! Skip TLS verification when talking to the OAuth2 token endpoint. Test doubles only.
	bool insecure_tls = false;
	//! Per-request connection/read timeout for the token exchange.
	uint64_t timeout_seconds = 60;

	bool HasStaticToken() const {
		return !token.empty();
	}
};

//! A bearer token plus the quota project that must accompany it.
struct GcloudAccessToken {
	string token;
	string quota_project;
};

//! Return the path Application Default Credentials would resolve to, checking, in order:
//!   1. $GOOGLE_APPLICATION_CREDENTIALS
//!   2. $CLOUDSDK_CONFIG/application_default_credentials.json
//!   3. $HOME/.config/gcloud/application_default_credentials.json  (what `gcloud auth
//!      application-default login` writes)
//! Returns an empty string when no file exists at any of them.
string DiscoverAdcPath();

//! Best-effort project inferred from the Application Default Credentials file: its
//! `quota_project_id` (which `gcloud auth application-default login` sets to the active project) or,
//! for a service-account key, its `project_id`. Returns an empty string if nothing can be read —
//! never throws, since this only supplies a default the user may override.
string TryDiscoverAdcProject();

//! Mint (or return a cached) OAuth2 access token for `config`.
//!
//! For `authorized_user` credentials this performs the refresh-token grant; for `service_account`
//! keys it builds an RS256 self-signed JWT assertion and exchanges it. Tokens are cached
//! process-wide, keyed by credential identity, and reused until 60s before expiry.
//!
//! Throws InvalidInputException when no credentials can be found or the file is an unsupported
//! type, and IOException when the token endpoint rejects the exchange.
GcloudAccessToken GetGcloudAccessToken(ClientContext &context, const GcloudAuthConfig &config);

//! Drop any cached token for `config`. Called after a 401 so the next attempt re-mints rather than
//! replaying a token the server has already rejected.
void InvalidateGcloudTokenCache(const GcloudAuthConfig &config);

} // namespace duckdb
