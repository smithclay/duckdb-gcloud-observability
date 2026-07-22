#include "gcloud_secret.hpp"

#include "duckdb/catalog/catalog_transaction.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

namespace duckdb {

//! Build a KeyValueSecret from `CREATE SECRET (TYPE gcloud, ...)` options.
static unique_ptr<BaseSecret> CreateGcloudSecretFromConfig(ClientContext &context, CreateSecretInput &input) {
	auto secret = make_uniq<KeyValueSecret>(input.scope, "gcloud", "config", input.name);

	// Only copy the keys we understand; ignore anything else.
	for (const auto &option : input.options) {
		auto lower_name = StringUtil::Lower(option.first);
		if (lower_name == "project" || lower_name == "token" || lower_name == "credentials" ||
		    lower_name == "quota_project" || lower_name == "universe_domain" || lower_name == "endpoint" ||
		    lower_name == "insecure_tls") {
			secret->secret_map[lower_name] = option.second;
		}
	}

	// Never print the access token in duckdb_secrets() / SHOW SECRETS. CREDENTIALS is only a path,
	// so it stays visible — seeing which key file is in use is useful and leaks nothing.
	secret->redact_keys = {"token"};
	return std::move(secret);
}

void RegisterGcloudSecretType(ExtensionLoader &loader) {
	SecretType secret_type;
	secret_type.name = "gcloud";
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	loader.RegisterSecretType(secret_type);

	CreateSecretFunction gcloud_secret_function = {"gcloud", "config", CreateGcloudSecretFromConfig};
	gcloud_secret_function.named_parameters["project"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["token"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["credentials"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["quota_project"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["universe_domain"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["endpoint"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["monitoring_endpoint"] = LogicalType::VARCHAR;
	gcloud_secret_function.named_parameters["insecure_tls"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(gcloud_secret_function);
}

//! Coerce a secret value (stored as VARCHAR or BOOLEAN) to a bool. Accepts true/1/yes/on.
static bool ValueToBool(const Value &value) {
	if (value.type().id() == LogicalTypeId::BOOLEAN) {
		return BooleanValue::Get(value);
	}
	auto s = StringUtil::Lower(value.ToString());
	return s == "true" || s == "1" || s == "yes" || s == "on";
}

//! Copy a string-valued secret key into `target` when present and non-empty.
static void ReadStringKey(const KeyValueSecret &secret, const char *key, string &target) {
	Value value;
	if (secret.TryGetValue(key, value) && !value.IsNull() && !value.ToString().empty()) {
		target = value.ToString();
	}
}

GcloudCredentials GetGcloudCredentials(ClientContext &context, const string &secret_name) {
	auto &secret_manager = SecretManager::Get(context);
	auto transaction = CatalogTransaction::GetSystemCatalogTransaction(context);

	unique_ptr<SecretEntry> entry;
	if (!secret_name.empty()) {
		entry = secret_manager.GetSecretByName(transaction, secret_name);
		if (!entry) {
			throw InvalidInputException("No secret with name '%s' found", secret_name);
		}
	} else {
		// No explicit name: use the first secret of type `gcloud`, if any.
		for (auto &candidate : secret_manager.AllSecrets(transaction)) {
			if (candidate.secret && candidate.secret->GetType() == "gcloud") {
				entry = make_uniq<SecretEntry>(candidate);
				break;
			}
		}
		// Unlike the datadog/splunk siblings, a missing secret is not an error: Application Default
		// Credentials are the norm on Google Cloud, so `read_gcloud_logs(project => '...')` must work
		// straight after `gcloud auth application-default login` with no CREATE SECRET at all.
		if (!entry) {
			return GcloudCredentials();
		}
	}

	const auto &base_secret = *entry->secret;
	if (base_secret.GetType() != "gcloud") {
		throw InvalidInputException("Secret '%s' is not a 'gcloud' secret (found type '%s')", secret_name,
		                            base_secret.GetType());
	}
	const auto *kv_secret = dynamic_cast<const KeyValueSecret *>(&base_secret);
	if (!kv_secret) {
		throw InvalidInputException("Secret '%s' is not a key-value 'gcloud' secret", base_secret.GetName());
	}

	GcloudCredentials credentials;
	ReadStringKey(*kv_secret, "project", credentials.project);
	ReadStringKey(*kv_secret, "token", credentials.token);
	ReadStringKey(*kv_secret, "credentials", credentials.credentials_file);
	ReadStringKey(*kv_secret, "quota_project", credentials.quota_project);
	ReadStringKey(*kv_secret, "universe_domain", credentials.universe_domain);
	ReadStringKey(*kv_secret, "endpoint", credentials.endpoint);
	ReadStringKey(*kv_secret, "monitoring_endpoint", credentials.monitoring_endpoint);

	Value value;
	if (kv_secret->TryGetValue("insecure_tls", value) && !value.IsNull()) {
		credentials.insecure_tls = ValueToBool(value);
	}
	return credentials;
}

//! Normalize an API base: trim, drop trailing '/', and assume HTTPS for a bare host.
static string NormalizeEndpoint(string base, const char *fallback) {
	StringUtil::Trim(base);
	while (!base.empty() && base.back() == '/') {
		base.pop_back();
	}
	if (base.empty()) {
		return string(fallback);
	}
	// A bare host ("logging.googleapis.com", "localhost:8080") is accepted and assumed HTTPS, so a
	// user need not repeat the scheme; httplib requires scheme+host+port with no path.
	if (!StringUtil::StartsWith(base, "http://") && !StringUtil::StartsWith(base, "https://")) {
		base = "https://" + base;
	}
	return base;
}

string GcloudLoggingEndpoint(const GcloudCredentials &credentials) {
	return NormalizeEndpoint(credentials.endpoint.empty() ? "https://logging." + credentials.universe_domain
	                                                      : credentials.endpoint,
	                         "https://logging.googleapis.com");
}

string GcloudMonitoringEndpoint(const GcloudCredentials &credentials) {
	// An explicit `endpoint` overrides the Logging host wholesale, so it cannot also name the
	// Monitoring host; derive from the universe domain and let MONITORING_ENDPOINT override.
	if (!credentials.monitoring_endpoint.empty()) {
		return NormalizeEndpoint(credentials.monitoring_endpoint, "https://monitoring.googleapis.com");
	}
	return NormalizeEndpoint("https://monitoring." + credentials.universe_domain,
	                         "https://monitoring.googleapis.com");
}

} // namespace duckdb
