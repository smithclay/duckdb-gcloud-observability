#include "gcloud_auth.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

// DuckDB's bundled cpp-httplib. CPPHTTPLIB_OPENSSL_SUPPORT (see CMakeLists) both enables TLS and
// selects the `duckdb_httplib_openssl` namespace, so these symbols never collide with core DuckDB's
// non-SSL `duckdb_httplib` build.
#include "httplib.hpp"
#include "yyjson.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <sys/stat.h>
#include <unordered_map>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

const char *const kLoggingReadScope = "https://www.googleapis.com/auth/logging.read";
const char *const kMonitoringReadScope = "https://www.googleapis.com/auth/monitoring.read";

//! Google's public OAuth2 token endpoint. Credentials files normally carry their own `token_uri`;
//! this is the fallback when they do not.
static constexpr const char *kDefaultTokenUri = "https://oauth2.googleapis.com/token";

//===--------------------------------------------------------------------===//
// Small RAII helpers — free on every path, including exceptions
//===--------------------------------------------------------------------===//
namespace {
struct YyjsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
using YyjsonDocPtr = std::unique_ptr<yyjson_doc, YyjsonDocDeleter>;

struct BioDeleter {
	void operator()(BIO *bio) const {
		BIO_free(bio);
	}
};
struct EvpPkeyDeleter {
	void operator()(EVP_PKEY *key) const {
		EVP_PKEY_free(key);
	}
};
struct EvpMdCtxDeleter {
	void operator()(EVP_MD_CTX *ctx) const {
		EVP_MD_CTX_free(ctx);
	}
};
using BioPtr = std::unique_ptr<BIO, BioDeleter>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;
} // namespace

static const char *GetStr(yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	return (v && yyjson_is_str(v)) ? yyjson_get_str(v) : nullptr;
}

//===--------------------------------------------------------------------===//
// Credential discovery (Application Default Credentials)
//===--------------------------------------------------------------------===//

static bool FileExists(const string &path) {
	struct stat sb;
	return !path.empty() && stat(path.c_str(), &sb) == 0 && S_ISREG(sb.st_mode);
}

//! Last-modified time, used in the token cache key so that re-running
//! `gcloud auth application-default login` invalidates tokens minted from the previous file.
static int64_t FileMTime(const string &path) {
	struct stat sb;
	if (stat(path.c_str(), &sb) != 0) {
		return 0;
	}
	return static_cast<int64_t>(sb.st_mtime);
}

static string GetEnv(const char *name) {
	const char *value = std::getenv(name);
	return value ? string(value) : string();
}

string DiscoverAdcPath() {
	// 1. The explicit override honored by every Google client library.
	auto explicit_path = GetEnv("GOOGLE_APPLICATION_CREDENTIALS");
	if (!explicit_path.empty()) {
		// Surface a bad override loudly rather than silently falling through to the gcloud file:
		// a user who set this variable meant it.
		if (!FileExists(explicit_path)) {
			throw InvalidInputException(
			    "GOOGLE_APPLICATION_CREDENTIALS points at '%s', which does not exist or is not a file", explicit_path);
		}
		return explicit_path;
	}
	// 2/3. The well-known gcloud location, honoring CLOUDSDK_CONFIG.
	auto sdk_config = GetEnv("CLOUDSDK_CONFIG");
	if (!sdk_config.empty()) {
		auto path = sdk_config + "/application_default_credentials.json";
		return FileExists(path) ? path : string();
	}
	auto home = GetEnv("HOME");
	if (!home.empty()) {
		auto path = home + "/.config/gcloud/application_default_credentials.json";
		return FileExists(path) ? path : string();
	}
	return string();
}

string TryDiscoverAdcProject() {
	string path;
	try {
		path = DiscoverAdcPath();
	} catch (const std::exception &) {
		return string(); // A broken GOOGLE_APPLICATION_CREDENTIALS is reported later, at token time.
	}
	if (path.empty()) {
		return string();
	}
	std::ifstream stream(path, std::ios::in | std::ios::binary);
	if (!stream) {
		return string();
	}
	std::ostringstream buffer;
	buffer << stream.rdbuf();
	auto contents = buffer.str();

	YyjsonDocPtr doc(yyjson_read(contents.c_str(), contents.size(), 0));
	if (!doc) {
		return string();
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	// `quota_project_id` is what gcloud records for user credentials; `project_id` is what a
	// service-account key carries.
	if (const char *quota_project = GetStr(root, "quota_project_id")) {
		return string(quota_project);
	}
	if (const char *project = GetStr(root, "project_id")) {
		return string(project);
	}
	return string();
}

static string ReadWholeFile(const string &path) {
	std::ifstream stream(path, std::ios::in | std::ios::binary);
	if (!stream) {
		throw IOException("Could not open Google credentials file '%s'", path);
	}
	std::ostringstream buffer;
	buffer << stream.rdbuf();
	return buffer.str();
}

//===--------------------------------------------------------------------===//
// base64url + RS256 (service-account self-signed JWT assertion)
//===--------------------------------------------------------------------===//

//! RFC 4648 §5 base64url, unpadded — the encoding JWT uses for all three segments.
static string Base64UrlEncode(const unsigned char *data, size_t length) {
	static constexpr const char *kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	string out;
	out.reserve((length + 2) / 3 * 4);
	size_t i = 0;
	for (; i + 2 < length; i += 3) {
		uint32_t triple = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | uint32_t(data[i + 2]);
		out += kAlphabet[(triple >> 18) & 0x3F];
		out += kAlphabet[(triple >> 12) & 0x3F];
		out += kAlphabet[(triple >> 6) & 0x3F];
		out += kAlphabet[triple & 0x3F];
	}
	if (i < length) {
		uint32_t triple = uint32_t(data[i]) << 16;
		bool has_second = (i + 1 < length);
		if (has_second) {
			triple |= uint32_t(data[i + 1]) << 8;
		}
		out += kAlphabet[(triple >> 18) & 0x3F];
		out += kAlphabet[(triple >> 12) & 0x3F];
		if (has_second) {
			out += kAlphabet[(triple >> 6) & 0x3F];
		}
		// No '=' padding: JWT segments are unpadded.
	}
	return out;
}

static string Base64UrlEncode(const string &data) {
	return Base64UrlEncode(reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

//! Sign `payload` with the PEM-encoded RSA private key from a service-account key file, using
//! RSASSA-PKCS1-v1_5 over SHA-256 (JWT "alg":"RS256").
static string SignRs256(const string &private_key_pem, const string &payload) {
	BioPtr bio(BIO_new_mem_buf(private_key_pem.data(), static_cast<int>(private_key_pem.size())));
	if (!bio) {
		throw IOException("OpenSSL: could not allocate a BIO for the service-account private key");
	}
	EvpPkeyPtr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
	if (!key) {
		throw InvalidInputException(
		    "Could not parse `private_key` from the service-account key file as a PEM private key");
	}

	EvpMdCtxPtr ctx(EVP_MD_CTX_new());
	if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key.get()) != 1) {
		throw IOException("OpenSSL: could not initialize an RS256 signing context");
	}
	if (EVP_DigestSignUpdate(ctx.get(), payload.data(), payload.size()) != 1) {
		throw IOException("OpenSSL: RS256 signing update failed");
	}
	size_t signature_length = 0;
	if (EVP_DigestSignFinal(ctx.get(), nullptr, &signature_length) != 1) {
		throw IOException("OpenSSL: could not determine the RS256 signature length");
	}
	string signature(signature_length, '\0');
	auto *signature_bytes = reinterpret_cast<unsigned char *>(&signature[0]);
	if (EVP_DigestSignFinal(ctx.get(), signature_bytes, &signature_length) != 1) {
		throw IOException("OpenSSL: RS256 signing failed");
	}
	signature.resize(signature_length);
	return Base64UrlEncode(reinterpret_cast<const unsigned char *>(signature.data()), signature.size());
}

static int64_t NowEpochSeconds() {
	return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
	    .count();
}

//! Build the signed JWT a service account presents to the token endpoint in exchange for an access
//! token (RFC 7523 §2.1, "urn:ietf:params:oauth:grant-type:jwt-bearer").
static string BuildServiceAccountAssertion(const string &client_email, const string &private_key_pem,
                                           const string &token_uri, const string &scope) {
	int64_t issued_at = NowEpochSeconds();
	int64_t expires_at = issued_at + 3600; // Google caps assertion lifetime at 1 hour.

	string header = R"({"alg":"RS256","typ":"JWT"})";
	string claims = StringUtil::Format(R"({"iss":"%s","scope":"%s","aud":"%s","exp":%lld,"iat":%lld})", client_email,
	                                   scope, token_uri, static_cast<long long>(expires_at),
	                                   static_cast<long long>(issued_at));

	string signing_input = Base64UrlEncode(header) + "." + Base64UrlEncode(claims);
	return signing_input + "." + SignRs256(private_key_pem, signing_input);
}

//===--------------------------------------------------------------------===//
// Token endpoint exchange
//===--------------------------------------------------------------------===//

//! Split "https://oauth2.googleapis.com/token" into origin ("https://oauth2.googleapis.com") and
//! path ("/token"); httplib's Client wants scheme+host+port with no path.
static void SplitUrl(const string &url, string &origin, string &path) {
	auto scheme_end = url.find("://");
	auto host_start = (scheme_end == string::npos) ? 0 : scheme_end + 3;
	auto path_start = url.find('/', host_start);
	if (path_start == string::npos) {
		origin = url;
		path = "/";
	} else {
		origin = url.substr(0, path_start);
		path = url.substr(path_start);
	}
}

//! POST a form-encoded grant to `token_uri` and pull `access_token` / `expires_in` out of the
//! response. Errors carry Google's `error_description`, which is what actually tells a user their
//! refresh token expired or the scope was denied.
static void PostTokenRequest(const GcloudAuthConfig &config, const string &token_uri, const string &form_body,
                             string &out_token, int64_t &out_expiry_epoch) {
	string origin, path;
	SplitUrl(token_uri, origin, path);

	duckdb_httplib_openssl::Client client(origin);
	client.set_connection_timeout(static_cast<time_t>(config.timeout_seconds), 0);
	client.set_read_timeout(static_cast<time_t>(config.timeout_seconds), 0);
	if (config.insecure_tls) {
		client.enable_server_certificate_verification(false);
		client.enable_server_hostname_verification(false);
	}

	auto response = client.Post(path.c_str(), form_body, "application/x-www-form-urlencoded");
	if (!response) {
		throw IOException("Google OAuth2 token request to %s failed: %s", token_uri,
		                  duckdb_httplib_openssl::to_string(response.error()));
	}
	if (response->status < 200 || response->status >= 300) {
		// The body echoes {"error":"invalid_grant","error_description":"..."} but never the
		// client_secret/assertion, which travel only in the request.
		string detail = response->body;
		YyjsonDocPtr doc(yyjson_read(response->body.c_str(), response->body.size(), 0));
		if (doc) {
			yyjson_val *root = yyjson_doc_get_root(doc.get());
			const char *description = GetStr(root, "error_description");
			const char *error = GetStr(root, "error");
			if (description) {
				detail = error ? string(error) + ": " + description : string(description);
			}
		}
		throw IOException("Google OAuth2 token request returned HTTP %d: %s\n"
		                  "If your Application Default Credentials expired, re-run:\n"
		                  "  gcloud auth application-default login",
		                  response->status, detail);
	}

	YyjsonDocPtr doc(yyjson_read(response->body.c_str(), response->body.size(), 0));
	if (!doc) {
		throw IOException("Google OAuth2 token endpoint returned a non-JSON response");
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	const char *access_token = GetStr(root, "access_token");
	if (!access_token) {
		throw IOException("Google OAuth2 token endpoint response carried no `access_token`");
	}
	out_token = access_token;

	// Refresh a minute early so a token never expires mid-query (pagination can span many requests).
	int64_t expires_in = 3600;
	yyjson_val *expires = yyjson_obj_get(root, "expires_in");
	if (expires && yyjson_is_num(expires)) {
		expires_in = static_cast<int64_t>(yyjson_get_num(expires));
	}
	out_expiry_epoch = NowEpochSeconds() + MaxValue<int64_t>(expires_in - 60, 0);
}

//===--------------------------------------------------------------------===//
// Process-wide token cache
//===--------------------------------------------------------------------===//

namespace {
struct CachedToken {
	string token;
	string quota_project;
	int64_t expiry_epoch = 0;
};
} // namespace

static std::mutex g_token_cache_mutex;
static std::unordered_map<string, CachedToken> g_token_cache; // NOLINT: process-lifetime cache

//! Identity of the credential a token was minted from. The file's mtime is part of the key so a
//! fresh `gcloud auth application-default login` never replays a token from the old file.
static string TokenCacheKey(const string &credentials_path, const GcloudAuthConfig &config) {
	return credentials_path + "|" + std::to_string(FileMTime(credentials_path)) + "|" + config.quota_project + "|" +
	       config.scope;
}

void InvalidateGcloudTokenCache(const GcloudAuthConfig &config) {
	if (config.HasStaticToken()) {
		return; // Never cached: a static token is used verbatim.
	}
	auto path = config.credentials_file.empty() ? DiscoverAdcPath() : config.credentials_file;
	if (path.empty()) {
		return;
	}
	std::lock_guard<std::mutex> guard(g_token_cache_mutex);
	g_token_cache.erase(TokenCacheKey(path, config));
}

//===--------------------------------------------------------------------===//
// Credential-type dispatch
//===--------------------------------------------------------------------===//

//! Exchange an `authorized_user` credential (what `gcloud auth application-default login` writes)
//! for an access token via the refresh-token grant.
static void MintFromAuthorizedUser(const GcloudAuthConfig &config, yyjson_val *root, const string &token_uri,
                                   string &out_token, int64_t &out_expiry) {
	const char *client_id = GetStr(root, "client_id");
	const char *client_secret = GetStr(root, "client_secret");
	const char *refresh_token = GetStr(root, "refresh_token");
	if (!client_id || !client_secret || !refresh_token) {
		throw InvalidInputException(
		    "authorized_user credentials must carry `client_id`, `client_secret` and `refresh_token`");
	}
	string body = "grant_type=refresh_token";
	body += "&client_id=" + StringUtil::URLEncode(client_id);
	body += "&client_secret=" + StringUtil::URLEncode(client_secret);
	body += "&refresh_token=" + StringUtil::URLEncode(refresh_token);
	PostTokenRequest(config, token_uri, body, out_token, out_expiry);
}

//! Exchange a `service_account` key for an access token via a self-signed RS256 JWT assertion.
static void MintFromServiceAccount(const GcloudAuthConfig &config, yyjson_val *root, const string &token_uri,
                                   string &out_token, int64_t &out_expiry) {
	const char *client_email = GetStr(root, "client_email");
	const char *private_key = GetStr(root, "private_key");
	if (!client_email || !private_key) {
		throw InvalidInputException("service_account credentials must carry `client_email` and `private_key`");
	}
	string assertion = BuildServiceAccountAssertion(client_email, private_key, token_uri, config.scope);
	string body = "grant_type=" + StringUtil::URLEncode("urn:ietf:params:oauth:grant-type:jwt-bearer");
	body += "&assertion=" + StringUtil::URLEncode(assertion);
	PostTokenRequest(config, token_uri, body, out_token, out_expiry);
}

GcloudAccessToken GetGcloudAccessToken(ClientContext &context, const GcloudAuthConfig &config) {
	if (context.interrupted) {
		throw InterruptException();
	}
	// A caller-supplied token wins and is never cached, refreshed, or logged.
	if (config.HasStaticToken()) {
		return GcloudAccessToken {config.token, config.quota_project};
	}

	string path = config.credentials_file;
	if (path.empty()) {
		path = DiscoverAdcPath();
		if (path.empty()) {
			throw InvalidInputException(
			    "No Google credentials found. Authenticate with the gcloud CLI:\n"
			    "  gcloud auth application-default login\n"
			    "or point at a service-account key:\n"
			    "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project', CREDENTIALS '/path/to/key.json');\n"
			    "or supply a token directly:\n"
			    "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<gcloud auth print-access-token>');");
		}
	} else if (!FileExists(path)) {
		throw InvalidInputException("gcloud secret CREDENTIALS points at '%s', which does not exist or is not a file",
		                            path);
	}

	auto cache_key = TokenCacheKey(path, config);
	{
		std::lock_guard<std::mutex> guard(g_token_cache_mutex);
		auto entry = g_token_cache.find(cache_key);
		if (entry != g_token_cache.end() && entry->second.expiry_epoch > NowEpochSeconds()) {
			return GcloudAccessToken {entry->second.token, entry->second.quota_project};
		}
	}

	auto contents = ReadWholeFile(path);
	YyjsonDocPtr doc(yyjson_read(contents.c_str(), contents.size(), 0));
	if (!doc) {
		throw InvalidInputException("Google credentials file '%s' is not valid JSON", path);
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw InvalidInputException("Google credentials file '%s' is not a JSON object", path);
	}

	const char *type = GetStr(root, "type");
	if (!type) {
		throw InvalidInputException("Google credentials file '%s' carries no `type` field", path);
	}
	const char *token_uri_field = GetStr(root, "token_uri");
	string token_uri = token_uri_field ? string(token_uri_field) : string(kDefaultTokenUri);

	// The quota project the credentials file was configured with; an explicit secret value wins.
	string quota_project = config.quota_project;
	if (quota_project.empty()) {
		const char *file_quota_project = GetStr(root, "quota_project_id");
		if (file_quota_project) {
			quota_project = file_quota_project;
		}
	}

	string token;
	int64_t expiry = 0;
	if (std::strcmp(type, "authorized_user") == 0) {
		MintFromAuthorizedUser(config, root, token_uri, token, expiry);
	} else if (std::strcmp(type, "service_account") == 0) {
		MintFromServiceAccount(config, root, token_uri, token, expiry);
	} else {
		// external_account (workload identity federation) and impersonated_service_account need
		// extra round trips this extension does not implement; the TOKEN escape hatch covers them.
		throw InvalidInputException("Unsupported Google credential type '%s' in '%s'. Supported types are "
		                            "`authorized_user` and `service_account`. For other credential types, mint a "
		                            "token yourself and pass it as TOKEN:\n"
		                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<access token>');",
		                            type, path);
	}

	{
		// Field-wise, not brace-init: DuckDB builds extensions as C++11, where the default member
		// initializer on CachedToken::expiry_epoch makes the type a non-aggregate.
		CachedToken cached;
		cached.token = token;
		cached.quota_project = quota_project;
		cached.expiry_epoch = expiry;

		std::lock_guard<std::mutex> guard(g_token_cache_mutex);
		g_token_cache[cache_key] = cached;
	}
	return GcloudAccessToken {token, quota_project};
}

} // namespace duckdb
