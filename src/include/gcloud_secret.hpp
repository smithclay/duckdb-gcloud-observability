#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! Everything needed to read from the Cloud Logging API. Unlike the sibling datadog/splunk
//! extensions, *no* field is strictly required: with no secret at all the reader falls back to
//! Application Default Credentials and infers the project from them, exactly as the gcloud CLI and
//! the OpenTelemetry Collector's googlecloudmonitoringreceiver do.
struct GcloudCredentials {
	//! Google Cloud project whose logs are read. May be overridden per-query by `project =>`.
	string project;
	//! Pre-minted OAuth2 access token (`gcloud auth print-access-token`). Takes precedence over
	//! `credentials_file`; never refreshed.
	string token;
	//! Path to a service-account key or authorized_user JSON. Empty => Application Default Credentials.
	string credentials_file;
	//! Billing/quota project for `x-goog-user-project`. Empty => the credentials file's
	//! `quota_project_id`, when it has one.
	string quota_project;
	//! Universe domain, for Sovereign Cloud / non-standard universes. The Cloud Logging endpoint is
	//! derived as `https://logging.<universe_domain>` unless `endpoint` overrides it wholesale.
	string universe_domain = "googleapis.com";
	//! Full override of the API base, e.g. "https://logging.googleapis.com". Empty => derive from
	//! `universe_domain`. Mirrors googlecloudmonitoringreceiver's `endpoint` option.
	string endpoint;
	//! Skip TLS certificate/hostname verification. Must stay false against real Google endpoints.
	bool insecure_tls = false;
};

//! Register the `gcloud` secret type and its `config` provider so users can run:
//!   CREATE SECRET (TYPE gcloud, PROJECT 'my-project');
//!   CREATE SECRET (TYPE gcloud, PROJECT 'my-project', CREDENTIALS '/path/to/sa-key.json');
//!   CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<access token>');
void RegisterGcloudSecretType(ExtensionLoader &loader);

//! Resolve Cloud Logging credentials from the secret manager. If `secret_name` is empty the first
//! secret of type `gcloud` in scope is used; if there is no `gcloud` secret at all, defaults are
//! returned so Application Default Credentials still apply. Throws only when a *named* secret is
//! missing, is of the wrong type, or carries a contradictory configuration.
GcloudCredentials GetGcloudCredentials(ClientContext &context, const string &secret_name);

//! Base URL for the Cloud Logging API implied by `credentials` (`endpoint` wins over
//! `universe_domain`), with any trailing '/' removed.
string GcloudLoggingEndpoint(const GcloudCredentials &credentials);

} // namespace duckdb
