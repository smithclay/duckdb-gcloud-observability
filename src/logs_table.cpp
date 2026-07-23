#include "logs_table.hpp"

#include "gcloud_client.hpp"
#include "gcloud_json.hpp"
#include "gcloud_secret.hpp"
#include "gcloud_yyjson.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_between_expression.hpp"
#include "duckdb/planner/expression/bound_columnref_expression.hpp"
#include "duckdb/planner/expression/bound_comparison_expression.hpp"
#include "duckdb/planner/expression/bound_conjunction_expression.hpp"
#include "duckdb/planner/expression/bound_constant_expression.hpp"
#include "duckdb/planner/expression/bound_operator_expression.hpp"
#include "duckdb/planner/operator/logical_get.hpp"

#include <cstdlib>
#include <cstring>
#include <deque>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

//===--------------------------------------------------------------------===//
// Output schema — matches duckdb-otlp `read_otlp_logs`
//===--------------------------------------------------------------------===//
static constexpr idx_t COL_TIME = 0;
static constexpr idx_t COL_OBSERVED_TIME = 1;
static constexpr idx_t COL_TRACE_ID = 2;
static constexpr idx_t COL_SPAN_ID = 3;
static constexpr idx_t COL_SERVICE_NAME = 4;
static constexpr idx_t COL_SERVICE_NAMESPACE = 5;
static constexpr idx_t COL_SERVICE_INSTANCE_ID = 6;
static constexpr idx_t COL_SEVERITY_NUMBER = 7;
static constexpr idx_t COL_SEVERITY_TEXT = 8;
static constexpr idx_t COL_BODY = 10;
static constexpr idx_t COL_RESOURCE_ATTRS = 11;
static constexpr idx_t COL_LOG_ATTRS = 15;
static constexpr idx_t COL_FLAGS = 17;
static constexpr idx_t COLUMN_COUNT = 18;

void GetGcloudLogsSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"time_unix_nano",
	         "observed_time_unix_nano",
	         "trace_id",
	         "span_id",
	         "service_name",
	         "service_namespace",
	         "service_instance_id",
	         "severity_number",
	         "severity_text",
	         "event_name",
	         "body",
	         "resource_attributes",
	         "scope_name",
	         "scope_version",
	         "scope_attributes",
	         "log_attributes",
	         "dropped_attributes_count",
	         "flags"};
	types = {LogicalType::TIMESTAMP_NS, LogicalType::TIMESTAMP_NS, LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::INTEGER,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::INTEGER,      LogicalType::INTEGER};
	D_ASSERT(names.size() == COLUMN_COUNT && types.size() == COLUMN_COUNT);
}

//! Lowercase, converting camelCase boundaries to '_' while leaving '.' and existing '_' alone.
//! Mirrors the collector's shared.ToSnakeCase, which it applies to every `gcp.label.*` key.
static string ToSnakeCase(const string &input) {
	string out;
	out.reserve(input.size() + 4);
	for (idx_t i = 0; i < input.size(); i++) {
		char c = input[i];
		if (c >= 'A' && c <= 'Z') {
			if (i > 0 && input[i - 1] != '.' && input[i - 1] != '_') {
				out += '_';
			}
			out += static_cast<char>(c - 'A' + 'a');
		} else {
			out += c;
		}
	}
	return out;
}

//! Copy every string entry of a GCP label map into `root` as `gcp.label.<snake_case key>`, matching
//! the OpenTelemetry Collector's googlecloudlogentryencodingextension.
static void PutLabels(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *labels) {
	if (!labels || !yyjson_is_obj(labels)) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *val;
	yyjson_obj_foreach(labels, idx, max, key, val) {
		const char *key_str = yyjson_get_str(key);
		if (!key_str || !yyjson_is_str(val)) {
			continue;
		}
		auto attribute_key = ToSnakeCase("gcp.label." + string(key_str));
		GcloudPutStr(doc, root, attribute_key.c_str(), yyjson_get_str(val));
	}
}

//===--------------------------------------------------------------------===//
// LogEntry -> OTLP mapping
//===--------------------------------------------------------------------===//

//! Map a Cloud Logging LogSeverity name to an OTLP SeverityNumber. Follows the
//! googlecloudlogentryencodingextension exactly — note NOTICE lands on INFO2 (10) and EMERGENCY on
//! FATAL4 (24), neither of which is the "obvious" adjacent value.
//!
//! This is the one place the sibling readers deliberately disagree. `duckdb-splunk` and
//! `duckdb-datadog` map freeform level strings via the OTel log data model's Appendix B, where
//! CRITICAL is 18, ALERT 19 and EMERGENCY 21. Cloud Logging's LogSeverity is not that vocabulary: it
//! is a fixed nine-value enum, and the Collector spreads its top three across FATAL/FATAL2/FATAL4.
//! Matching the Collector wins here, because GCP logs also reach OTLP through it — a row read by
//! this extension and the same row exported by the Collector must land on the same number. The
//! bands still agree across all three readers (>= 17 is error-class, >= 21 is fatal-class); only the
//! exact value within the band differs.
static int32_t SeverityToNumber(const char *severity) {
	if (!severity) {
		return 0;
	}
	auto s = StringUtil::Upper(severity);
	if (s == "DEBUG") {
		return 5;
	}
	if (s == "INFO") {
		return 9;
	}
	if (s == "NOTICE") {
		return 10;
	}
	if (s == "WARNING") {
		return 13;
	}
	if (s == "ERROR") {
		return 17;
	}
	if (s == "CRITICAL") {
		return 21;
	}
	if (s == "ALERT") {
		return 22;
	}
	if (s == "EMERGENCY") {
		return 24;
	}
	return 0; // DEFAULT, and anything unrecognized.
}

//! Read a LogEntry timestamp field into a TIMESTAMP_NS Value; NULL when absent or unparseable.
static Value TimestampValue(yyjson_val *entry, const char *key) {
	int64_t nanos;
	if (ParseRfc3339ToNanos(GcloudGetStr(entry, key), nanos)) {
		return Value::TIMESTAMPNS(timestamp_ns_t(nanos));
	}
	return Value();
}

//! Extract the 32-hex trace id from a LogEntry `trace`, formatted
//! "projects/[PROJECT_ID]/traces/[TRACE_ID]". Values that are already a bare id are passed through,
//! since Cloud Run and some agents write one.
static string ExtractTraceId(const char *trace) {
	if (!trace) {
		return string();
	}
	string value(trace);
	auto marker = value.find("/traces/");
	if (marker != string::npos) {
		return value.substr(marker + 8);
	}
	return value.find('/') == string::npos ? value : string();
}

//! Split a LogEntry `logName` ("projects/[PROJECT_ID]/logs/[LOG_ID]", or the organizations/
//! billingAccounts/folders variants) into the parent-scoped resource attribute and `cloud.resource_id`.
static void PutLogNameAttributes(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *log_name) {
	if (!log_name) {
		return;
	}
	struct ParentPrefix {
		const char *prefix;
		const char *attribute;
	};
	static const ParentPrefix kParents[] = {
	    {"projects/", "gcp.project"},
	    {"organizations/", "gcp.organization"},
	    {"billingAccounts/", "gcp.billing_account"},
	    {"folders/", "gcp.folder"},
	};

	string value(log_name);
	for (const auto &parent : kParents) {
		if (!StringUtil::StartsWith(value, parent.prefix)) {
			continue;
		}
		auto rest = value.substr(strlen(parent.prefix));
		auto marker = rest.find("/logs/");
		if (marker == string::npos) {
			return;
		}
		auto parent_id = rest.substr(0, marker);
		auto log_id = rest.substr(marker + 6);
		if (parent_id.empty() || log_id.empty()) {
			return;
		}
		GcloudPutStr(doc, root, parent.attribute, parent_id.c_str());
		GcloudPutStr(doc, root, "cloud.resource_id", log_id.c_str());
		return;
	}
}

//! resource_attributes: identity of the monitored resource the entry came from.
static string BuildResourceAttributes(yyjson_val *entry, yyjson_val *resource, yyjson_val *resource_labels) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	PutLogNameAttributes(doc.get(), root, GcloudGetStr(entry, "logName"));
	GcloudPutStr(doc.get(), root, "gcp.resource_type", GcloudGetStr(resource, "type"));
	PutLabels(doc.get(), root, resource_labels);

	return GcloudWriteIfAny(doc.get(), root);
}

//! LogEntry.httpRequest -> OpenTelemetry HTTP semantic-convention attributes.
static void PutHttpRequest(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *request) {
	if (!request) {
		return;
	}
	GcloudPutStr(doc, root, "http.request.method", GcloudGetStr(request, "requestMethod"));
	GcloudPutStr(doc, root, "url.full", GcloudGetStr(request, "requestUrl"));
	GcloudPutStr(doc, root, "user_agent.original", GcloudGetStr(request, "userAgent"));
	GcloudPutStr(doc, root, "network.peer.address", GcloudGetStr(request, "remoteIp"));
	GcloudPutStr(doc, root, "server.address", GcloudGetStr(request, "serverIp"));
	GcloudPutStr(doc, root, "http.request.header.referer", GcloudGetStr(request, "referer"));

	int64_t status = 0;
	if (GcloudGetInt64Flexible(request, "status", status)) {
		GcloudPutInt(doc, root, "http.response.status_code", status);
	}
	int64_t request_size = 0;
	if (GcloudGetInt64Flexible(request, "requestSize", request_size)) {
		GcloudPutInt(doc, root, "http.request.body.size", request_size);
	}
	int64_t response_size = 0;
	if (GcloudGetInt64Flexible(request, "responseSize", response_size)) {
		GcloudPutInt(doc, root, "http.response.body.size", response_size);
	}
	int64_t cache_fill_bytes = 0;
	if (GcloudGetInt64Flexible(request, "cacheFillBytes", cache_fill_bytes)) {
		GcloudPutInt(doc, root, "gcp.cache.fill_bytes", cache_fill_bytes);
	}

	// `latency` is a proto Duration in JSON form: a decimal number of seconds with an "s" suffix.
	if (const char *latency = GcloudGetStr(request, "latency")) {
		string value(latency);
		if (!value.empty() && value.back() == 's') {
			value.pop_back();
			char *end = nullptr;
			double seconds = std::strtod(value.c_str(), &end);
			if (end && end != value.c_str() && *end == '\0') {
				GcloudPutDouble(doc, root, "http.request.server.duration", seconds);
			}
		}
	}

	// "HTTP/1.1" -> name "http", version "1.1"; anything unrecognized is kept whole, lowercased.
	if (const char *protocol = GcloudGetStr(request, "protocol")) {
		string value(protocol);
		auto slash = value.find('/');
		if (slash != string::npos && slash + 1 < value.size()) {
			auto name = StringUtil::Lower(value.substr(0, slash));
			GcloudPutStr(doc, root, "network.protocol.name", name.c_str());
			GcloudPutStr(doc, root, "network.protocol.version", value.substr(slash + 1).c_str());
		} else {
			auto name = StringUtil::Lower(value);
			GcloudPutStr(doc, root, "network.protocol.name", name.c_str());
		}
	}

	bool flag = false;
	if (GcloudGetBool(request, "cacheLookup", flag)) {
		GcloudPutBool(doc, root, "gcp.cache.lookup", flag);
	}
	if (GcloudGetBool(request, "cacheHit", flag)) {
		GcloudPutBool(doc, root, "gcp.cache.hit", flag);
	}
	if (GcloudGetBool(request, "cacheValidatedWithOriginServer", flag)) {
		GcloudPutBool(doc, root, "gcp.cache.validated_with_origin_server", flag);
	}
}

//! LogEntry.sourceLocation -> OpenTelemetry code.* attributes.
static void PutSourceLocation(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *location) {
	if (!location) {
		return;
	}
	GcloudPutStr(doc, root, "code.file.path", GcloudGetStr(location, "file"));
	GcloudPutStr(doc, root, "code.function.name", GcloudGetStr(location, "function"));
	int64_t line = 0;
	if (GcloudGetInt64Flexible(location, "line", line)) {
		GcloudPutInt(doc, root, "code.line.number", line);
	}
}

//! LogEntry.operation -> gcp.operation.* attributes.
static void PutOperation(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *operation) {
	if (!operation) {
		return;
	}
	GcloudPutStr(doc, root, "gcp.operation.id", GcloudGetStr(operation, "id"));
	GcloudPutStr(doc, root, "gcp.operation.producer", GcloudGetStr(operation, "producer"));
	bool flag = false;
	if (GcloudGetBool(operation, "first", flag)) {
		GcloudPutBool(doc, root, "gcp.operation.first", flag);
	}
	if (GcloudGetBool(operation, "last", flag)) {
		GcloudPutBool(doc, root, "gcp.operation.last", flag);
	}
}

//! Merge the structured fields of a `jsonPayload` into the attribute bag, skipping keys a
//! higher-priority source already claimed. This is the flat-table counterpart of the collector
//! putting jsonPayload into the log record's Body: because `body` here is a single VARCHAR, the
//! payload's fields would otherwise only be reachable by re-parsing `body` in SQL.
static void MergeJsonPayload(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *payload) {
	if (!payload || !yyjson_is_obj(payload)) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *val;
	yyjson_obj_foreach(payload, idx, max, key, val) {
		const char *key_str = yyjson_get_str(key);
		if (!key_str || yyjson_mut_obj_get(root, key_str)) {
			continue;
		}
		yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, key_str), yyjson_val_mut_copy(doc, val));
	}
}

//! log_attributes: everything about *this entry* that is not a dedicated column.
static string BuildLogAttributes(yyjson_val *entry, yyjson_val *json_payload) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	GcloudPutStr(doc.get(), root, "log.record.uid", GcloudGetStr(entry, "insertId"));
	PutLabels(doc.get(), root, yyjson_obj_get(entry, "labels"));
	PutHttpRequest(doc.get(), root, GcloudGetObj(entry, "httpRequest"));
	PutSourceLocation(doc.get(), root, GcloudGetObj(entry, "sourceLocation"));
	PutOperation(doc.get(), root, GcloudGetObj(entry, "operation"));
	MergeJsonPayload(doc.get(), root, json_payload);

	return GcloudWriteIfAny(doc.get(), root);
}

//! The log message. Cloud Logging entries carry exactly one payload; a textPayload *is* the message,
//! while a structured payload conventionally holds the human-readable text under `message`. Falling
//! back to the serialized payload keeps `body` non-NULL for entries that follow neither convention
//! (audit logs, VPC flow logs), whose fields remain individually queryable via `log_attributes`.
static string BuildBody(yyjson_val *entry, yyjson_val *json_payload) {
	if (const char *text = GcloudGetStr(entry, "textPayload")) {
		return string(text);
	}
	if (json_payload) {
		if (const char *message = GcloudLookupStr({json_payload}, {"message", "msg"})) {
			return string(message);
		}
		return GcloudWriteValue(json_payload);
	}
	if (yyjson_val *proto_payload = GcloudGetObj(entry, "protoPayload")) {
		return GcloudWriteValue(proto_payload);
	}
	return string();
}

//! Map one LogEntry to the projected columns of a row. `column_ids[c]` is the source column for
//! output slot c (projection pushdown); only projected columns are computed. `jsonPayload`,
//! `resource.labels` and the severity string are each shared by several columns, so each is resolved
//! once, up front, at negligible cost (they are plain object lookups, not parses).
static void MapEntry(yyjson_val *entry, const vector<column_t> &column_ids, vector<Value> &row) {
	row.assign(column_ids.size(), Value()); // all projected columns NULL by default

	yyjson_val *resource = GcloudGetObj(entry, "resource");
	yyjson_val *resource_labels = GcloudGetObj(resource, "labels");
	yyjson_val *labels = GcloudGetObj(entry, "labels");
	yyjson_val *json_payload = GcloudGetObj(entry, "jsonPayload");

	for (idx_t c = 0; c < column_ids.size(); c++) {
		switch (column_ids[c]) {
		case COL_TIME:
			row[c] = TimestampValue(entry, "timestamp");
			break;
		case COL_OBSERVED_TIME: {
			// receiveTimestamp is when Cloud Logging ingested the entry — the OTLP observed time.
			// Entries written by the API always have it, but fall back so the column is never NULL
			// when `timestamp` is present.
			auto observed = TimestampValue(entry, "receiveTimestamp");
			row[c] = observed.IsNull() ? TimestampValue(entry, "timestamp") : observed;
			break;
		}
		case COL_TRACE_ID: {
			auto trace_id = ExtractTraceId(GcloudGetStr(entry, "trace"));
			if (!trace_id.empty()) {
				row[c] = Value(trace_id);
			}
			break;
		}
		case COL_SPAN_ID:
			if (const char *span_id = GcloudGetStr(entry, "spanId")) {
				row[c] = Value(string(span_id));
			}
			break;
		case COL_SERVICE_NAME: {
			// Cloud Run / Cloud Functions / GKE name the workload in different resource labels;
			// structured loggers usually carry it in the payload. Check the explicit ones first.
			const char *service = GcloudLookupStr({resource_labels}, {"service_name"});
			if (!service) {
				service = GcloudLookupStr({json_payload}, {"service", "service_name", "serviceName", "service.name"});
			}
			if (!service) {
				service = GcloudLookupStr({labels}, {"service_name", "service"});
			}
			if (!service) {
				service = GcloudLookupStr({resource_labels}, {"function_name", "container_name", "job"});
			}
			if (service) {
				row[c] = Value(string(service));
			}
			break;
		}
		case COL_SERVICE_NAMESPACE:
			if (const char *namespace_name = GcloudLookupStr({resource_labels}, {"namespace_name", "namespace_id"})) {
				row[c] = Value(string(namespace_name));
			}
			break;
		case COL_SERVICE_INSTANCE_ID:
			if (const char *instance =
			        GcloudLookupStr({resource_labels}, {"instance_id", "pod_name", "revision_name", "task_id"})) {
				row[c] = Value(string(instance));
			}
			break;
		case COL_SEVERITY_NUMBER:
			if (const char *severity = GcloudGetStr(entry, "severity")) {
				row[c] = Value::INTEGER(SeverityToNumber(severity));
			}
			break;
		case COL_SEVERITY_TEXT:
			if (const char *severity = GcloudGetStr(entry, "severity")) {
				row[c] = Value(string(severity));
			}
			break;
		case COL_BODY: {
			auto body = BuildBody(entry, json_payload);
			if (!body.empty()) {
				row[c] = Value(body);
			}
			break;
		}
		case COL_RESOURCE_ATTRS: {
			auto resource_attributes = BuildResourceAttributes(entry, resource, resource_labels);
			if (!resource_attributes.empty()) {
				row[c] = Value(resource_attributes);
			}
			break;
		}
		case COL_LOG_ATTRS: {
			auto log_attributes = BuildLogAttributes(entry, json_payload);
			if (!log_attributes.empty()) {
				row[c] = Value(log_attributes);
			}
			break;
		}
		case COL_FLAGS: {
			// OTLP log record flags: bit 0 mirrors the W3C trace flag "sampled".
			bool sampled = false;
			if (GcloudGetBool(entry, "traceSampled", sampled)) {
				row[c] = Value::INTEGER(sampled ? 1 : 0);
			}
			break;
		}
		default:
			// Columns Cloud Logging has no data for (scope_*, event_name,
			// dropped_attributes_count) and virtual columns (e.g. the rowid sentinel a bare
			// count(*) projects) stay NULL.
			break;
		}
	}
}

//===--------------------------------------------------------------------===//
// Table function state
//===--------------------------------------------------------------------===//

struct GcloudLogsBindData : public TableFunctionData {
	vector<string> resource_names;
	//! Filter resolved at bind time from the user's `filter` plus `start_time`/`end_time`. Terms
	//! translated from the SQL WHERE clause are ANDed on later, in InitGlobal.
	string filter;
	string order_by = "timestamp desc";
	int64_t max_rows = 0;     // 0 = unlimited
	int64_t page_size = 1000; // entries per API request
	//! Populated by GcloudLogsPushdownComplexFilter during planning.
	GcloudFilterPushdown pushdown;
	//! Set for catalog-backed tables so EXPLAIN can name the table; null for read_gcloud_logs.
	TableCatalogEntry *table = nullptr;
	GcloudClient client;
};

struct GcloudLogsGlobalState : public GlobalTableFunctionState {
	//! Source column for each output slot (projection pushdown); may contain virtual-column
	//! sentinels (e.g. rowid for a bare count(*)), which MapEntry leaves NULL.
	vector<column_t> column_ids;
	//! Rows (projected columns only) from the pages fetched so far, waiting to be emitted. Holds at
	//! most one page, so an unbounded scan streams rather than materializing the whole result set.
	std::deque<vector<Value>> buffer;
	//! The bind-time filter with the pushed-down WHERE terms ANDed on — what actually goes to the API.
	string request_filter;
	//! Next-page cursor from `nextPageToken` ("" = request the first page).
	string page_token;
	idx_t total_emitted = 0;
	bool finished = false;

	idx_t MaxThreads() const override {
		return 1; // Cursor pagination is inherently sequential.
	}
};

void ValidateGcloudLogsSettings(const GcloudLogsSettings &settings, const string &error_prefix) {
	if (settings.max_rows < 0) {
		throw InvalidInputException("%s: max_rows must be >= 0 (0 means unlimited)", error_prefix);
	}
	if (settings.page_size < 1 || settings.page_size > 1000) {
		throw InvalidInputException("%s: page_size must be between 1 and 1000", error_prefix);
	}
	// entries.list rejects anything else, and silently sorting the wrong way is worse than failing.
	if (!StringUtil::CIEquals(settings.order_by, "timestamp desc") &&
	    !StringUtil::CIEquals(settings.order_by, "timestamp asc")) {
		throw InvalidInputException("%s: order_by must be 'timestamp desc' or 'timestamp asc' (got '%s')", error_prefix,
		                            settings.order_by);
	}
	if (settings.retries < 0) {
		throw InvalidInputException("%s: retries must be >= 0 (0 disables retrying)", error_prefix);
	}
	if (settings.timeout_seconds < 1) {
		throw InvalidInputException("%s: timeout must be >= 1 (seconds)", error_prefix);
	}
}

//! Fetch the next page of entries.list and update pagination state.
//!
//! Cloud Logging may return a page with *zero* entries and still hand back a nextPageToken — it
//! scans a time slice per page, not a fixed number of matches. So, unlike the sibling
//! duckdb-datadog reader, this must NOT treat an empty page as the end of the stream: it keys
//! termination off the token alone. A server echoing a non-advancing cursor would otherwise spin
//! forever, so that case ends the scan too.
static void FetchNextPage(ClientContext &context, const GcloudLogsBindData &bind, GcloudLogsGlobalState &state) {
	// Never ask for more rows than the query can still use, so the last page is not over-fetched.
	// Rows already buffered but not yet emitted count against the cap too.
	auto accounted = state.total_emitted + state.buffer.size();
	auto page_size = GetGcloudLogsPageSize(bind.page_size, bind.max_rows, accounted);
	if (page_size <= 0) {
		state.finished = true;
		return;
	}

	auto body =
	    BuildGcloudListBody(bind.resource_names, state.request_filter, bind.order_by, page_size, state.page_token);
	auto response = bind.client.ListEntries(context, body);

	YyjsonDocPtr doc(yyjson_read(response.c_str(), response.size(), 0));
	if (!doc) {
		throw IOException("Cloud Logging API returned a non-JSON response");
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("Cloud Logging API returned an unexpected response shape");
	}

	yyjson_val *entries = yyjson_obj_get(root, "entries");
	if (entries && yyjson_is_arr(entries)) {
		size_t idx, max;
		yyjson_val *entry;
		yyjson_arr_foreach(entries, idx, max, entry) {
			if (!yyjson_is_obj(entry)) {
				continue;
			}
			vector<Value> row;
			MapEntry(entry, state.column_ids, row);
			state.buffer.push_back(std::move(row));
		}
	}

	const char *next = GcloudGetStr(root, "nextPageToken");
	if (!next || next[0] == '\0' || state.page_token == next) {
		state.finished = true;
	} else {
		state.page_token = next; // copies the C-string before `doc` is freed at scope end
	}
}

//===--------------------------------------------------------------------===//
// Conservative WHERE pushdown
//===--------------------------------------------------------------------===//
//
// Only predicates whose Logging-query-language translation matches a *superset* of the SQL match
// are pushed, because DuckDB keeps evaluating the original WHERE above the scan: a term that is
// too broad merely costs bandwidth, while one that is too narrow silently drops rows.
//
// Two columns qualify. `time_unix_nano` maps to the `timestamp` field verbatim (bounds are rounded
// outward to whole seconds). `severity_text` maps to `severity` verbatim — it is copied straight
// from the LogEntry, so equality against a valid LogSeverity name is exact.
//
// `service_name` is deliberately *not* pushed, which is where this diverges from duckdb-datadog's
// `service:` term. There, the column is one API field. Here it is derived by falling back across
// `resource.labels.service_name`, several `jsonPayload` keys, `labels`, and
// `resource.labels.{function_name,container_name,job}` — so any single filter term
// (`resource.labels.service_name="x"`) would match strictly fewer rows than the SQL predicate and
// would drop legitimate GKE/Cloud Functions results. `trace_id` is excluded for the same reason:
// ExtractTraceId accepts both the "projects/P/traces/ID" form and a bare id.

static ExpressionType ReverseComparison(ExpressionType type) {
	switch (type) {
	case ExpressionType::COMPARE_LESSTHAN:
		return ExpressionType::COMPARE_GREATERTHAN;
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
		return ExpressionType::COMPARE_GREATERTHANOREQUALTO;
	case ExpressionType::COMPARE_GREATERTHAN:
		return ExpressionType::COMPARE_LESSTHAN;
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		return ExpressionType::COMPARE_LESSTHANOREQUALTO;
	default:
		return type;
	}
}

static constexpr int64_t NANOS_PER_SECOND = 1000000000;

//! Round toward -infinity, so a lower bound never excludes a matching row.
static int64_t FloorNanosecondsToSeconds(int64_t nanos) {
	auto seconds = nanos / NANOS_PER_SECOND;
	if (nanos % NANOS_PER_SECOND < 0) {
		seconds--;
	}
	return seconds;
}

//! Round toward +infinity, so an upper bound never excludes a matching row.
static int64_t CeilNanosecondsToSeconds(int64_t nanos) {
	auto seconds = nanos / NANOS_PER_SECOND;
	if (nanos % NANOS_PER_SECOND > 0) {
		seconds++;
	}
	return seconds;
}

//! Resolve `expression` to the source column name it references in `get`, or "" if it is not a
//! plain column reference into this scan.
static string GetPushdownColumnName(const LogicalGet &get, const Expression &expression) {
	if (expression.GetExpressionClass() != ExpressionClass::BOUND_COLUMN_REF) {
		return string();
	}
	const auto &column = expression.Cast<BoundColumnRefExpression>();
	const auto &column_ids = get.GetColumnIds();
	if (column.depth != 0 || column.binding.table_index != get.table_index ||
	    column.binding.column_index >= column_ids.size()) {
		return string();
	}
	auto source_column = column_ids[column.binding.column_index].GetPrimaryIndex();
	if (source_column >= get.names.size()) {
		return string();
	}
	return get.names[source_column];
}

//! Record a `severity_text` value, uppercased so it names a LogSeverity enum member. Returns false
//! when the constant cannot be a valid severity, in which case nothing is pushed for this
//! predicate (SQL still filters locally, so the result stays correct).
static bool AddSeverity(GcloudFilterPushdown &pushdown, const Value &constant) {
	if (constant.IsNull() || constant.type().id() != LogicalTypeId::VARCHAR) {
		return false;
	}
	auto severity = StringUtil::Upper(constant.GetValue<string>());
	if (!IsLogSeverityName(severity)) {
		return false;
	}
	for (const auto &existing : pushdown.severities) {
		if (existing == severity) {
			return true;
		}
	}
	pushdown.severities.push_back(std::move(severity));
	return true;
}

static void AddLowerBound(GcloudFilterPushdown &pushdown, int64_t seconds) {
	if (!pushdown.has_lower_bound_seconds || seconds > pushdown.lower_bound_seconds) {
		pushdown.has_lower_bound_seconds = true;
		pushdown.lower_bound_seconds = seconds;
	}
}

static void AddUpperBound(GcloudFilterPushdown &pushdown, int64_t seconds) {
	if (!pushdown.has_upper_bound_seconds || seconds < pushdown.upper_bound_seconds) {
		pushdown.has_upper_bound_seconds = true;
		pushdown.upper_bound_seconds = seconds;
	}
}

static void TryPushComparison(const LogicalGet &get, const BoundComparisonExpression &comparison,
                              GcloudFilterPushdown &pushdown) {
	const Expression *column_side = nullptr;
	const BoundConstantExpression *constant = nullptr;
	auto comparison_type = comparison.type;

	if (comparison.right->GetExpressionClass() == ExpressionClass::BOUND_CONSTANT) {
		column_side = comparison.left.get();
		constant = &comparison.right->Cast<BoundConstantExpression>();
	} else if (comparison.left->GetExpressionClass() == ExpressionClass::BOUND_CONSTANT) {
		column_side = comparison.right.get();
		constant = &comparison.left->Cast<BoundConstantExpression>();
		comparison_type = ReverseComparison(comparison_type);
	} else {
		return;
	}

	auto column_name = GetPushdownColumnName(get, *column_side);
	if (column_name.empty() || constant->value.IsNull()) {
		return;
	}

	if (column_name == "severity_text" && comparison_type == ExpressionType::COMPARE_EQUAL) {
		AddSeverity(pushdown, constant->value);
		return;
	}

	if (column_name != "time_unix_nano" || constant->value.type().id() != LogicalTypeId::TIMESTAMP_NS) {
		return;
	}
	auto nanos = constant->value.GetValue<timestamp_ns_t>().value;
	switch (comparison_type) {
	case ExpressionType::COMPARE_EQUAL:
		// An equality pins both ends; the outward rounding keeps the second containing it.
		AddLowerBound(pushdown, FloorNanosecondsToSeconds(nanos));
		AddUpperBound(pushdown, CeilNanosecondsToSeconds(nanos));
		break;
	case ExpressionType::COMPARE_GREATERTHAN:
	case ExpressionType::COMPARE_GREATERTHANOREQUALTO:
		AddLowerBound(pushdown, FloorNanosecondsToSeconds(nanos));
		break;
	case ExpressionType::COMPARE_LESSTHAN:
	case ExpressionType::COMPARE_LESSTHANOREQUALTO:
		AddUpperBound(pushdown, CeilNanosecondsToSeconds(nanos));
		break;
	default:
		break;
	}
}

//! `severity_text IN ('ERROR', 'CRITICAL')` becomes an OR of severity equalities. All children must
//! be constants that name a real LogSeverity, otherwise the whole IN is skipped — pushing only the
//! recognized subset would narrow the match and drop rows.
static void TryPushInClause(const LogicalGet &get, const BoundOperatorExpression &operator_expression,
                            GcloudFilterPushdown &pushdown) {
	if (operator_expression.children.size() < 2) {
		return;
	}
	if (GetPushdownColumnName(get, *operator_expression.children[0]) != "severity_text") {
		return;
	}
	vector<Value> constants;
	for (idx_t i = 1; i < operator_expression.children.size(); i++) {
		const auto &child = *operator_expression.children[i];
		if (child.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
			return;
		}
		auto value = child.Cast<BoundConstantExpression>().value;
		if (value.IsNull() || value.type().id() != LogicalTypeId::VARCHAR ||
		    !IsLogSeverityName(StringUtil::Upper(value.GetValue<string>()))) {
			return;
		}
		constants.push_back(std::move(value));
	}
	for (const auto &value : constants) {
		AddSeverity(pushdown, value);
	}
}

//! DuckDB's optimizer rewrites `x >= a AND x <= b` into a single BETWEEN before this callback runs,
//! so handling only BOUND_COMPARISON would silently miss the most common way a time window is
//! written. Inclusivity is irrelevant here: the bounds are rounded outward to whole seconds anyway.
static void TryPushBetween(const LogicalGet &get, const BoundBetweenExpression &between,
                           GcloudFilterPushdown &pushdown) {
	if (GetPushdownColumnName(get, *between.input) != "time_unix_nano") {
		return;
	}
	auto push_side = [&](const Expression &bound, bool is_lower) {
		if (bound.GetExpressionClass() != ExpressionClass::BOUND_CONSTANT) {
			return;
		}
		const auto &value = bound.Cast<BoundConstantExpression>().value;
		if (value.IsNull() || value.type().id() != LogicalTypeId::TIMESTAMP_NS) {
			return;
		}
		auto nanos = value.GetValue<timestamp_ns_t>().value;
		if (is_lower) {
			AddLowerBound(pushdown, FloorNanosecondsToSeconds(nanos));
		} else {
			AddUpperBound(pushdown, CeilNanosecondsToSeconds(nanos));
		}
	};
	push_side(*between.lower, true);
	push_side(*between.upper, false);
}

static void TryPushExpression(const LogicalGet &get, const Expression &expression, GcloudFilterPushdown &pushdown) {
	switch (expression.GetExpressionClass()) {
	case ExpressionClass::BOUND_COMPARISON:
		TryPushComparison(get, expression.Cast<BoundComparisonExpression>(), pushdown);
		return;
	case ExpressionClass::BOUND_BETWEEN:
		TryPushBetween(get, expression.Cast<BoundBetweenExpression>(), pushdown);
		return;
	case ExpressionClass::BOUND_OPERATOR:
		if (expression.type == ExpressionType::COMPARE_IN) {
			TryPushInClause(get, expression.Cast<BoundOperatorExpression>(), pushdown);
		}
		return;
	case ExpressionClass::BOUND_CONJUNCTION:
		// Only AND: each conjunct independently constrains the result, so pushing any subset stays a
		// superset. An OR would need every branch pushed together to remain safe.
		if (expression.type == ExpressionType::CONJUNCTION_AND) {
			for (const auto &child : expression.Cast<BoundConjunctionExpression>().children) {
				TryPushExpression(get, *child, pushdown);
			}
		}
		return;
	default:
		return;
	}
}

static void GcloudLogsPushdownComplexFilter(ClientContext &, LogicalGet &get, FunctionData *bind_data,
                                            vector<unique_ptr<Expression>> &filters) {
	auto &bind = bind_data->Cast<GcloudLogsBindData>();
	bind.pushdown = GcloudFilterPushdown();
	if (bind.max_rows > 0) {
		// `max_rows` caps rows as they come back from the API, before the SQL WHERE is evaluated, so
		// narrowing the request would change which rows compete for that budget:
		// `max_rows => 1 WHERE severity_text = 'ERROR'` would return the newest ERROR entry with
		// pushdown but the newest entry (then filtered away) without it. Leaving the request
		// unnarrowed keeps the cap's meaning fixed and independent of what the optimizer chose to
		// push. Matches duckdb-datadog.
		return;
	}
	for (const auto &filter : filters) {
		TryPushExpression(get, *filter, bind.pushdown);
	}
	if (bind.pushdown.has_lower_bound_seconds && bind.pushdown.has_upper_bound_seconds &&
	    bind.pushdown.lower_bound_seconds > bind.pushdown.upper_bound_seconds) {
		bind.pushdown.empty_result = true;
	}
	// Deliberately leave every expression in `filters`. DuckDB retains a residual filter above the
	// scan, guaranteeing exact SQL semantics even where the Logging query language is broader (it
	// compares timestamps at whole-second granularity here, and severity matching is by enum name).
}

//===--------------------------------------------------------------------===//
// Bind / init / scan
//===--------------------------------------------------------------------===//

//! Apply resolved credentials to `bind`. Shared by the table function and the catalog tables so
//! both honor the same secret, endpoint, and quota-project rules.
static void ApplyCredentials(GcloudLogsBindData &bind, const GcloudCredentials &credentials) {
	bind.client.endpoint = GcloudLoggingEndpoint(credentials);
	bind.client.insecure_tls = credentials.insecure_tls;
	bind.client.auth.token = credentials.token;
	bind.client.auth.credentials_file = credentials.credentials_file;
	bind.client.auth.quota_project = credentials.quota_project;
	bind.client.auth.insecure_tls = credentials.insecure_tls;
	bind.client.auth.timeout_seconds = bind.client.timeout_seconds;
}

//! Turn a project id into the single resource name entries.list expects, throwing the guidance
//! message when nothing supplied one.
static vector<string> ResolveResourceNames(const string &project, const GcloudCredentials &credentials) {
	auto resolved = project.empty() ? credentials.project : project;
	if (resolved.empty()) {
		resolved = TryDiscoverAdcProject();
	}
	if (resolved.empty()) {
		throw InvalidInputException("read_gcloud_logs: no Google Cloud project configured. Pass one explicitly:\n"
		                            "  SELECT * FROM read_gcloud_logs(project => 'my-project');\n"
		                            "or store it in a secret:\n"
		                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project');\n"
		                            "or set one for the gcloud CLI:\n"
		                            "  gcloud auth application-default set-quota-project my-project");
	}
	return {"projects/" + resolved};
}

static unique_ptr<FunctionData> GcloudLogsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<GcloudLogsBindData>();
	GcloudLogsSettings settings;
	string secret_name;
	string project;
	string start_time;
	string end_time;
	vector<string> resource_names;

	for (auto &param : input.named_parameters) {
		auto key = StringUtil::Lower(param.first);
		if (param.second.IsNull()) {
			continue;
		}
		if (key == "project") {
			project = param.second.ToString();
		} else if (key == "resource_names") {
			for (const auto &child : ListValue::GetChildren(param.second)) {
				if (!child.IsNull() && !child.ToString().empty()) {
					resource_names.push_back(child.ToString());
				}
			}
		} else if (key == "filter") {
			result->filter = param.second.ToString();
		} else if (key == "order_by") {
			settings.order_by = param.second.ToString();
		} else if (key == "start_time") {
			start_time = param.second.ToString();
		} else if (key == "end_time") {
			end_time = param.second.ToString();
		} else if (key == "max_rows") {
			settings.max_rows = param.second.GetValue<int64_t>();
		} else if (key == "page_size") {
			settings.page_size = param.second.GetValue<int64_t>();
		} else if (key == "retries") {
			settings.retries = param.second.GetValue<int64_t>();
		} else if (key == "timeout") {
			settings.timeout_seconds = param.second.GetValue<int64_t>();
		} else if (key == "secret") {
			secret_name = param.second.ToString();
		}
	}

	// Validation runs before credential resolution so the offline tests hit these errors whether or
	// not the host has Application Default Credentials configured.
	ValidateGcloudLogsSettings(settings, "read_gcloud_logs");
	result->order_by = settings.order_by;
	result->max_rows = settings.max_rows;
	result->page_size = settings.page_size;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);

	auto credentials = GetGcloudCredentials(context, secret_name);
	ApplyCredentials(*result, credentials);

	// `resource_names` is the API's own parameter and wins; `project` is the ergonomic shorthand for
	// the overwhelmingly common single-project case.
	if (!resource_names.empty()) {
		result->resource_names = std::move(resource_names);
	} else {
		result->resource_names = ResolveResourceNames(project, credentials);
	}

	result->filter = BuildGcloudFilter(result->filter, start_time, end_time);

	GetGcloudLogsSchema(return_types, names);
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> GcloudLogsInitGlobal(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<GcloudLogsGlobalState>();
	auto &bind = input.bind_data->Cast<GcloudLogsBindData>();
	state->column_ids = input.column_ids;
	state->request_filter = ApplyGcloudPushdown(bind.filter, bind.pushdown);
	// Contradictory bounds (e.g. ts > x AND ts < y with x > y) can never match; skip the request.
	state->finished = bind.pushdown.empty_result;
	return std::move(state);
}

static void GcloudLogsScan(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind = data_p.bind_data->Cast<GcloudLogsBindData>();
	auto &state = data_p.global_state->Cast<GcloudLogsGlobalState>();

	if (GcloudLogsMaxRowsReached(bind.max_rows, state.total_emitted)) {
		// Row cap already reached — stop before issuing another request.
		state.finished = true;
		state.buffer.clear();
	}

	// Refill the buffer, fetching as many pages as needed to get at least one row (or finish). More
	// than one page can be needed here: Cloud Logging returns empty pages that still carry a cursor.
	while (state.buffer.empty() && !state.finished) {
		FetchNextPage(context, bind, state);
	}

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t col = 0; col < row.size(); col++) {
			output.SetValue(col, count, row[col]);
		}
		state.buffer.pop_front();
		count++;
		state.total_emitted++;
		if (GcloudLogsMaxRowsReached(bind.max_rows, state.total_emitted)) {
			state.finished = true;
			state.buffer.clear();
			break;
		}
	}

	output.SetCardinality(count);
}

//! EXPLAIN detail. Shows the filter actually sent to Cloud Logging, so a user can see exactly which
//! predicates were pushed and which stayed local.
static InsertionOrderPreservingMap<string> GcloudLogsToString(TableFunctionToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	auto &bind = input.bind_data->Cast<GcloudLogsBindData>();
	result["Function"] = input.table_function.name;
	result["Google Cloud Resources"] = StringUtil::Join(bind.resource_names, ", ");
	auto request_filter = ApplyGcloudPushdown(bind.filter, bind.pushdown);
	if (!request_filter.empty()) {
		result["Google Cloud Filter"] = request_filter;
	}
	if (bind.pushdown.empty_result) {
		result["Google Cloud Filter"] = "(contradictory time bounds — no request is issued)";
	}
	result["Google Cloud Order By"] = bind.order_by;
	result["Google Cloud Page Size"] = std::to_string(bind.page_size);
	result["Google Cloud Max Rows"] = std::to_string(bind.max_rows);
	result["Google Cloud Retries"] = std::to_string(bind.client.retries);
	result["Google Cloud Timeout"] = std::to_string(bind.client.timeout_seconds);
	return result;
}

static BindInfo GcloudLogsGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &bind = bind_data->Cast<GcloudLogsBindData>();
	D_ASSERT(bind.table);
	return BindInfo(*bind.table);
}

//! Wire up the parts shared by read_gcloud_logs and the catalog-backed table.
static void ConfigureLogsScan(TableFunction &function) {
	// Only projected columns are mapped from the response; a count(*) or GROUP BY service_name never
	// pays the per-row log_attributes JSON serialization.
	function.projection_pushdown = true;
	function.pushdown_complex_filter = GcloudLogsPushdownComplexFilter;
	function.to_string = GcloudLogsToString;
}

void RegisterGcloudLogsFunction(ExtensionLoader &loader) {
	TableFunction function("read_gcloud_logs", {}, GcloudLogsScan, GcloudLogsBind, GcloudLogsInitGlobal);
	function.named_parameters["project"] = LogicalType::VARCHAR;
	function.named_parameters["resource_names"] = LogicalType::LIST(LogicalType::VARCHAR);
	function.named_parameters["filter"] = LogicalType::VARCHAR;
	function.named_parameters["order_by"] = LogicalType::VARCHAR;
	function.named_parameters["start_time"] = LogicalType::VARCHAR;
	function.named_parameters["end_time"] = LogicalType::VARCHAR;
	function.named_parameters["max_rows"] = LogicalType::BIGINT;
	function.named_parameters["page_size"] = LogicalType::BIGINT;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	ConfigureLogsScan(function);
	loader.RegisterFunction(function);
}

TableFunction GetGcloudLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                     const string &project, const GcloudLogsSettings &settings,
                                     unique_ptr<FunctionData> &bind_data) {
	auto result = make_uniq<GcloudLogsBindData>();
	result->table = &table;
	result->order_by = settings.order_by;
	result->max_rows = settings.max_rows;
	result->page_size = settings.page_size;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);

	auto credentials = GetGcloudCredentials(context, secret_name);
	ApplyCredentials(*result, credentials);
	result->resource_names = ResolveResourceNames(project, credentials);
	result->filter = BuildGcloudFilter(settings.filter, settings.start_time, settings.end_time);
	bind_data = std::move(result);

	TableFunction function("gcloud_logs_scan", {}, GcloudLogsScan, nullptr, GcloudLogsInitGlobal);
	ConfigureLogsScan(function);
	function.get_bind_info = GcloudLogsGetBindInfo;
	return function;
}

} // namespace duckdb
