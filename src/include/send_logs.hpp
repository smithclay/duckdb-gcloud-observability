#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! One Cloud Logging LogEntry assembled from an OTLP-shaped DuckDB row. Empty strings mean the
//! corresponding field is absent. Attribute JSON is interpreted by BuildGcloudWriteBody.
struct GcloudWriteLog {
	string project;
	string log_name;
	string log_id;
	string body;
	string service_name;
	string service_namespace;
	string service_instance_id;
	string severity;
	string trace_id;
	string span_id;
	string insert_id;
	string resource_type;
	string resource_attributes_json;
	string log_attributes_json;
	bool has_timestamp_nanos = false;
	int64_t timestamp_nanos = 0;
	bool trace_sampled = false;
};

//! Build one entries.write request. The request uses all-or-error semantics (`partialSuccess` is
//! false); each entry carries a stable timestamp and insertId before this helper is called.
string BuildGcloudWriteBody(const GcloudWriteLog *logs, idx_t count);
inline string BuildGcloudWriteBody(const vector<GcloudWriteLog> &logs) {
	return BuildGcloudWriteBody(logs.data(), logs.size());
}

//! Conservative worst-case JSON-escaped size used to keep requests below Cloud Logging's 10 MiB
//! entries.write limit. It is a batching estimate, not a per-entry rejection threshold.
idx_t EstimateGcloudWriteLogBytes(const GcloudWriteLog &log);

//! Register `send_gcloud_logs(struct [, secret])`. The first argument is normally a whole row from
//! an OTLP-shaped relation. Recognized fields are mapped by name; unknown fields are ignored.
void RegisterGcloudSendLogsFunction(ExtensionLoader &loader);

} // namespace duckdb
