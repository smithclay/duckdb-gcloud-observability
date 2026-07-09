#include "logs_table.hpp"

#include "gcloud_client.hpp"
#include "gcloud_secret.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include "yyjson.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <initializer_list>
#include <memory>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

//===--------------------------------------------------------------------===//
// yyjson RAII helpers — free docs/buffers on every path (incl. exceptions)
//===--------------------------------------------------------------------===//
namespace {
struct YyjsonDocDeleter {
	void operator()(yyjson_doc *doc) const {
		yyjson_doc_free(doc);
	}
};
struct YyjsonMutDocDeleter {
	void operator()(yyjson_mut_doc *doc) const {
		yyjson_mut_doc_free(doc);
	}
};
struct YyjsonFreeDeleter {
	void operator()(char *ptr) const {
		free(ptr);
	}
};
using YyjsonDocPtr = std::unique_ptr<yyjson_doc, YyjsonDocDeleter>;
using YyjsonMutDocPtr = std::unique_ptr<yyjson_mut_doc, YyjsonMutDocDeleter>;
using YyjsonStrPtr = std::unique_ptr<char, YyjsonFreeDeleter>;
} // namespace

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

static void GetLogsSchema(vector<LogicalType> &types, vector<string> &names) {
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

//===--------------------------------------------------------------------===//
// Small yyjson accessors
//===--------------------------------------------------------------------===//

static const char *GetStr(yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	return (v && yyjson_is_str(v)) ? yyjson_get_str(v) : nullptr;
}

//! Return the object at `key`, or nullptr when absent or not an object.
static yyjson_val *GetObj(yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	return (v && yyjson_is_obj(v)) ? v : nullptr;
}

//! Look up a string under any of `keys`, checking each source object in priority order. Returns the
//! first match, or nullptr.
static const char *LookupStr(std::initializer_list<yyjson_val *> sources, std::initializer_list<const char *> keys) {
	for (yyjson_val *source : sources) {
		for (const char *key : keys) {
			if (const char *v = GetStr(source, key)) {
				return v;
			}
		}
	}
	return nullptr;
}

//! Google encodes int64 fields as JSON *strings* (proto3 JSON mapping) but int32 fields as numbers,
//! so `status` arrives as 200 while `requestSize` arrives as "1234". Accept either.
static bool GetInt64Flexible(yyjson_val *obj, const char *key, int64_t &out) {
	if (!obj) {
		return false;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	if (!v) {
		return false;
	}
	if (yyjson_is_int(v)) {
		out = yyjson_get_sint(v);
		return true;
	}
	if (yyjson_is_num(v)) {
		out = static_cast<int64_t>(yyjson_get_num(v));
		return true;
	}
	if (yyjson_is_str(v)) {
		const char *str = yyjson_get_str(v);
		char *end = nullptr;
		long long parsed = std::strtoll(str, &end, 10);
		if (end && end != str && *end == '\0') {
			out = static_cast<int64_t>(parsed);
			return true;
		}
	}
	return false;
}

static bool GetBool(yyjson_val *obj, const char *key, bool &out) {
	if (!obj) {
		return false;
	}
	yyjson_val *v = yyjson_obj_get(obj, key);
	if (v && yyjson_is_bool(v)) {
		out = yyjson_get_bool(v);
		return true;
	}
	return false;
}

//===--------------------------------------------------------------------===//
// Mutable-JSON builders for the two attribute bags
//===--------------------------------------------------------------------===//

//! Both key and value are copied into `doc`, so callers may pass transient strings.
static void PutStr(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key, const char *value) {
	if (!key || !value || !*value) {
		return;
	}
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, key), yyjson_mut_strcpy(doc, value));
}

static void PutInt(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key, int64_t value) {
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, key), yyjson_mut_sint(doc, value));
}

static void PutBool(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key, bool value) {
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, key), yyjson_mut_bool(doc, value));
}

static void PutDouble(yyjson_mut_doc *doc, yyjson_mut_val *root, const char *key, double value) {
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc, key), yyjson_mut_real(doc, value));
}

//! Serialize a mutable doc, returning "" when the object ended up empty (so the column stays NULL
//! rather than holding a useless "{}").
static string WriteIfAny(yyjson_mut_doc *doc, yyjson_mut_val *root) {
	if (yyjson_mut_obj_size(root) == 0) {
		return string();
	}
	YyjsonStrPtr json(yyjson_mut_write(doc, 0, nullptr));
	return json ? string(json.get()) : string();
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
		PutStr(doc, root, attribute_key.c_str(), yyjson_get_str(val));
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

//! Parse an RFC 3339 timestamp (e.g. "2026-07-09T10:30:45.123456789Z") into nanoseconds since epoch.
//! Cloud Logging timestamps carry up to nanosecond precision, so the microsecond-truncating path is
//! not enough on its own — `sub_micro_nanos` recovers the last three digits.
static bool ParseRfc3339ToNanos(const char *str, int64_t &out_nanos) {
	if (!str) {
		return false;
	}
	idx_t len = strlen(str);

	timestamp_t ts;
	bool has_offset = false;
	string_t tz;
	int32_t sub_micro_nanos = 0;
	auto result = Timestamp::TryConvertTimestampTZ(str, len, ts, /*use_offset=*/true, has_offset, tz, &sub_micro_nanos);
	if (result != TimestampCastResult::SUCCESS) {
		// Fall back to the strict (offset-less) nanosecond parser.
		timestamp_ns_t ts_ns;
		if (Timestamp::TryConvertTimestamp(str, len, ts_ns) != TimestampCastResult::SUCCESS) {
			return false;
		}
		out_nanos = ts_ns.value;
		return true;
	}

	int64_t epoch_nanos;
	if (!Timestamp::TryGetEpochNanoSeconds(ts, epoch_nanos)) {
		return false;
	}
	out_nanos = epoch_nanos + sub_micro_nanos;
	return true;
}

//! Read a LogEntry timestamp field into a TIMESTAMP_NS Value; NULL when absent or unparseable.
static Value TimestampValue(yyjson_val *entry, const char *key) {
	int64_t nanos;
	if (ParseRfc3339ToNanos(GetStr(entry, key), nanos)) {
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
		PutStr(doc, root, parent.attribute, parent_id.c_str());
		PutStr(doc, root, "cloud.resource_id", log_id.c_str());
		return;
	}
}

//! resource_attributes: identity of the monitored resource the entry came from.
static string BuildResourceAttributes(yyjson_val *entry, yyjson_val *resource, yyjson_val *resource_labels) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	PutLogNameAttributes(doc.get(), root, GetStr(entry, "logName"));
	PutStr(doc.get(), root, "gcp.resource_type", GetStr(resource, "type"));
	PutLabels(doc.get(), root, resource_labels);

	return WriteIfAny(doc.get(), root);
}

//! LogEntry.httpRequest -> OpenTelemetry HTTP semantic-convention attributes.
static void PutHttpRequest(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *request) {
	if (!request) {
		return;
	}
	PutStr(doc, root, "http.request.method", GetStr(request, "requestMethod"));
	PutStr(doc, root, "url.full", GetStr(request, "requestUrl"));
	PutStr(doc, root, "user_agent.original", GetStr(request, "userAgent"));
	PutStr(doc, root, "network.peer.address", GetStr(request, "remoteIp"));
	PutStr(doc, root, "server.address", GetStr(request, "serverIp"));
	PutStr(doc, root, "http.request.header.referer", GetStr(request, "referer"));

	int64_t status = 0;
	if (GetInt64Flexible(request, "status", status)) {
		PutInt(doc, root, "http.response.status_code", status);
	}
	int64_t request_size = 0;
	if (GetInt64Flexible(request, "requestSize", request_size)) {
		PutInt(doc, root, "http.request.body.size", request_size);
	}
	int64_t response_size = 0;
	if (GetInt64Flexible(request, "responseSize", response_size)) {
		PutInt(doc, root, "http.response.body.size", response_size);
	}
	int64_t cache_fill_bytes = 0;
	if (GetInt64Flexible(request, "cacheFillBytes", cache_fill_bytes)) {
		PutInt(doc, root, "gcp.cache.fill_bytes", cache_fill_bytes);
	}

	// `latency` is a proto Duration in JSON form: a decimal number of seconds with an "s" suffix.
	if (const char *latency = GetStr(request, "latency")) {
		string value(latency);
		if (!value.empty() && value.back() == 's') {
			value.pop_back();
			char *end = nullptr;
			double seconds = std::strtod(value.c_str(), &end);
			if (end && end != value.c_str() && *end == '\0') {
				PutDouble(doc, root, "http.request.server.duration", seconds);
			}
		}
	}

	// "HTTP/1.1" -> name "http", version "1.1"; anything unrecognized is kept whole, lowercased.
	if (const char *protocol = GetStr(request, "protocol")) {
		string value(protocol);
		auto slash = value.find('/');
		if (slash != string::npos && slash + 1 < value.size()) {
			auto name = StringUtil::Lower(value.substr(0, slash));
			PutStr(doc, root, "network.protocol.name", name.c_str());
			PutStr(doc, root, "network.protocol.version", value.substr(slash + 1).c_str());
		} else {
			auto name = StringUtil::Lower(value);
			PutStr(doc, root, "network.protocol.name", name.c_str());
		}
	}

	bool flag = false;
	if (GetBool(request, "cacheLookup", flag)) {
		PutBool(doc, root, "gcp.cache.lookup", flag);
	}
	if (GetBool(request, "cacheHit", flag)) {
		PutBool(doc, root, "gcp.cache.hit", flag);
	}
	if (GetBool(request, "cacheValidatedWithOriginServer", flag)) {
		PutBool(doc, root, "gcp.cache.validated_with_origin_server", flag);
	}
}

//! LogEntry.sourceLocation -> OpenTelemetry code.* attributes.
static void PutSourceLocation(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *location) {
	if (!location) {
		return;
	}
	PutStr(doc, root, "code.file.path", GetStr(location, "file"));
	PutStr(doc, root, "code.function.name", GetStr(location, "function"));
	int64_t line = 0;
	if (GetInt64Flexible(location, "line", line)) {
		PutInt(doc, root, "code.line.number", line);
	}
}

//! LogEntry.operation -> gcp.operation.* attributes.
static void PutOperation(yyjson_mut_doc *doc, yyjson_mut_val *root, yyjson_val *operation) {
	if (!operation) {
		return;
	}
	PutStr(doc, root, "gcp.operation.id", GetStr(operation, "id"));
	PutStr(doc, root, "gcp.operation.producer", GetStr(operation, "producer"));
	bool flag = false;
	if (GetBool(operation, "first", flag)) {
		PutBool(doc, root, "gcp.operation.first", flag);
	}
	if (GetBool(operation, "last", flag)) {
		PutBool(doc, root, "gcp.operation.last", flag);
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

	PutStr(doc.get(), root, "log.record.uid", GetStr(entry, "insertId"));
	PutLabels(doc.get(), root, yyjson_obj_get(entry, "labels"));
	PutHttpRequest(doc.get(), root, GetObj(entry, "httpRequest"));
	PutSourceLocation(doc.get(), root, GetObj(entry, "sourceLocation"));
	PutOperation(doc.get(), root, GetObj(entry, "operation"));
	MergeJsonPayload(doc.get(), root, json_payload);

	return WriteIfAny(doc.get(), root);
}

//! Serialize an arbitrary JSON value back to compact text (used for a structured payload body).
static string WriteValue(yyjson_val *value) {
	if (!value) {
		return string();
	}
	YyjsonStrPtr json(yyjson_val_write(value, 0, nullptr));
	return json ? string(json.get()) : string();
}

//! The log message. Cloud Logging entries carry exactly one payload; a textPayload *is* the message,
//! while a structured payload conventionally holds the human-readable text under `message`. Falling
//! back to the serialized payload keeps `body` non-NULL for entries that follow neither convention
//! (audit logs, VPC flow logs), whose fields remain individually queryable via `log_attributes`.
static string BuildBody(yyjson_val *entry, yyjson_val *json_payload) {
	if (const char *text = GetStr(entry, "textPayload")) {
		return string(text);
	}
	if (json_payload) {
		if (const char *message = LookupStr({json_payload}, {"message", "msg"})) {
			return string(message);
		}
		return WriteValue(json_payload);
	}
	if (yyjson_val *proto_payload = GetObj(entry, "protoPayload")) {
		return WriteValue(proto_payload);
	}
	return string();
}

//! Map one LogEntry to the projected columns of a row. `column_ids[c]` is the source column for
//! output slot c (projection pushdown); only projected columns are computed. `jsonPayload`,
//! `resource.labels` and the severity string are each shared by several columns, so each is resolved
//! once, up front, at negligible cost (they are plain object lookups, not parses).
static void MapEntry(yyjson_val *entry, const vector<column_t> &column_ids, vector<Value> &row) {
	row.assign(column_ids.size(), Value()); // all projected columns NULL by default

	yyjson_val *resource = GetObj(entry, "resource");
	yyjson_val *resource_labels = GetObj(resource, "labels");
	yyjson_val *labels = GetObj(entry, "labels");
	yyjson_val *json_payload = GetObj(entry, "jsonPayload");

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
			auto trace_id = ExtractTraceId(GetStr(entry, "trace"));
			if (!trace_id.empty()) {
				row[c] = Value(trace_id);
			}
			break;
		}
		case COL_SPAN_ID:
			if (const char *span_id = GetStr(entry, "spanId")) {
				row[c] = Value(string(span_id));
			}
			break;
		case COL_SERVICE_NAME: {
			// Cloud Run / Cloud Functions / GKE name the workload in different resource labels;
			// structured loggers usually carry it in the payload. Check the explicit ones first.
			const char *service = LookupStr({resource_labels}, {"service_name"});
			if (!service) {
				service = LookupStr({json_payload}, {"service", "service_name", "serviceName", "service.name"});
			}
			if (!service) {
				service = LookupStr({labels}, {"service_name", "service"});
			}
			if (!service) {
				service = LookupStr({resource_labels}, {"function_name", "container_name", "job"});
			}
			if (service) {
				row[c] = Value(string(service));
			}
			break;
		}
		case COL_SERVICE_NAMESPACE:
			if (const char *namespace_name = LookupStr({resource_labels}, {"namespace_name", "namespace_id"})) {
				row[c] = Value(string(namespace_name));
			}
			break;
		case COL_SERVICE_INSTANCE_ID:
			if (const char *instance =
			        LookupStr({resource_labels}, {"instance_id", "pod_name", "revision_name", "task_id"})) {
				row[c] = Value(string(instance));
			}
			break;
		case COL_SEVERITY_NUMBER:
			if (const char *severity = GetStr(entry, "severity")) {
				row[c] = Value::INTEGER(SeverityToNumber(severity));
			}
			break;
		case COL_SEVERITY_TEXT:
			if (const char *severity = GetStr(entry, "severity")) {
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
			if (GetBool(entry, "traceSampled", sampled)) {
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
// Request building
//===--------------------------------------------------------------------===//

//! Format epoch seconds as an RFC 3339 UTC timestamp, the only form the Logging query language
//! accepts in a `timestamp` comparison.
static string FormatRfc3339(int64_t epoch_seconds) {
	std::time_t as_time = static_cast<std::time_t>(epoch_seconds);
	struct tm utc;
	gmtime_r(&as_time, &utc);
	char buffer[32];
	strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
	return string(buffer);
}

//! Interpret a `start_time`/`end_time` argument. Accepts `now`, a relative offset (`-15m`, `-2h`,
//! `-7d`, `-30s`) resolved against the current time, or an RFC 3339 instant passed through as-is.
static string ResolveTimeSpec(const string &parameter, const string &spec) {
	string trimmed = spec;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return string();
	}

	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	if (StringUtil::CIEquals(trimmed, "now")) {
		return FormatRfc3339(now);
	}
	if (trimmed[0] == '-') {
		char unit = trimmed.back();
		auto digits = trimmed.substr(1, trimmed.size() - 2);
		int64_t multiplier = 0;
		switch (unit) {
		case 's':
			multiplier = 1;
			break;
		case 'm':
			multiplier = 60;
			break;
		case 'h':
			multiplier = 3600;
			break;
		case 'd':
			multiplier = 86400;
			break;
		default:
			multiplier = 0;
		}
		char *end = nullptr;
		long long amount = digits.empty() ? -1 : std::strtoll(digits.c_str(), &end, 10);
		if (multiplier > 0 && amount >= 0 && end && *end == '\0') {
			return FormatRfc3339(now - static_cast<int64_t>(amount) * multiplier);
		}
		throw InvalidInputException("read_gcloud_logs: %s '%s' is not a valid relative offset; expected a number and "
		                            "one of s/m/h/d, e.g. '-15m'",
		                            parameter, spec);
	}
	// Absolute: require something that at least looks like RFC 3339 so a typo fails here rather
	// than as an opaque INVALID_ARGUMENT from the API.
	int64_t nanos;
	if (!ParseRfc3339ToNanos(trimmed.c_str(), nanos)) {
		throw InvalidInputException("read_gcloud_logs: %s '%s' is neither a relative offset (e.g. '-15m') nor an "
		                            "RFC 3339 timestamp (e.g. '2026-07-09T00:00:00Z')",
		                            parameter, spec);
	}
	return trimmed;
}

//! Compose the final Logging query-language filter from the user's `filter` plus any time bounds.
//! The user's filter is parenthesized so a top-level `OR` inside it cannot swallow the time bound.
static string BuildFilter(const string &filter, const string &start_time, const string &end_time) {
	vector<string> clauses;
	string trimmed_filter = filter;
	StringUtil::Trim(trimmed_filter);
	if (!trimmed_filter.empty()) {
		clauses.push_back("(" + trimmed_filter + ")");
	}
	if (!start_time.empty()) {
		clauses.push_back("timestamp >= \"" + ResolveTimeSpec("start_time", start_time) + "\"");
	}
	if (!end_time.empty()) {
		clauses.push_back("timestamp <= \"" + ResolveTimeSpec("end_time", end_time) + "\"");
	}
	return StringUtil::Join(clauses, " AND ");
}

//! Build the JSON body for POST /v2/entries:list. yyjson handles escaping, so a filter containing
//! quotes or backslashes cannot corrupt the request.
static string BuildListBody(const vector<string> &resource_names, const string &filter, const string &order_by,
                            int64_t page_size, const string &page_token) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	yyjson_mut_val *names = yyjson_mut_arr(doc.get());
	for (const auto &name : resource_names) {
		yyjson_mut_arr_add_strcpy(doc.get(), names, name.c_str());
	}
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), "resourceNames"), names);

	if (!filter.empty()) {
		PutStr(doc.get(), root, "filter", filter.c_str());
	}
	PutStr(doc.get(), root, "orderBy", order_by.c_str());
	PutInt(doc.get(), root, "pageSize", page_size);
	if (!page_token.empty()) {
		PutStr(doc.get(), root, "pageToken", page_token.c_str());
	}

	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	if (!json) {
		throw InternalException("read_gcloud_logs: could not serialize the entries.list request body");
	}
	return string(json.get());
}

//===--------------------------------------------------------------------===//
// Table function state
//===--------------------------------------------------------------------===//

struct GcloudLogsBindData : public TableFunctionData {
	vector<string> resource_names;
	string filter;
	string order_by = "timestamp desc";
	int64_t max_rows = 0;     // 0 = unlimited
	int64_t page_size = 1000; // entries per API request
	GcloudClient client;
};

struct GcloudLogsGlobalState : public GlobalTableFunctionState {
	//! Source column for each output slot (projection pushdown); may contain virtual-column
	//! sentinels (e.g. rowid for a bare count(*)), which MapEntry leaves NULL.
	vector<column_t> column_ids;
	//! Rows (projected columns only) from the pages fetched so far, waiting to be emitted. Holds at
	//! most one page, so an unbounded scan streams rather than materializing the whole result set.
	std::deque<vector<Value>> buffer;
	//! Next-page cursor from `nextPageToken` ("" = request the first page).
	string page_token;
	idx_t total_emitted = 0;
	bool finished = false;

	idx_t MaxThreads() const override {
		return 1; // Cursor pagination is inherently sequential.
	}
};

//! Fetch the next page of entries.list and update pagination state.
//!
//! Cloud Logging may return a page with *zero* entries and still hand back a nextPageToken — it
//! scans a time slice per page, not a fixed number of matches. So, unlike the sibling
//! duckdb-datadog reader, this must NOT treat an empty page as the end of the stream: it keys
//! termination off the token alone. A server echoing a non-advancing cursor would otherwise spin
//! forever, so that case ends the scan too.
static void FetchNextPage(ClientContext &context, const GcloudLogsBindData &bind, GcloudLogsGlobalState &state) {
	// Never ask for more rows than the query can still use, so the last page is not over-fetched.
	int64_t page_size = bind.page_size;
	if (bind.max_rows > 0) {
		auto buffered = static_cast<int64_t>(state.total_emitted + state.buffer.size());
		auto remaining = bind.max_rows - buffered;
		if (remaining <= 0) {
			state.finished = true;
			return;
		}
		page_size = MinValue<int64_t>(page_size, remaining);
	}

	auto body = BuildListBody(bind.resource_names, bind.filter, bind.order_by, page_size, state.page_token);
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

	const char *next = GetStr(root, "nextPageToken");
	if (!next || next[0] == '\0' || state.page_token == next) {
		state.finished = true;
	} else {
		state.page_token = next; // copies the C-string before `doc` is freed at scope end
	}
}

static unique_ptr<FunctionData> GcloudLogsBind(ClientContext &context, TableFunctionBindInput &input,
                                               vector<LogicalType> &return_types, vector<string> &names) {
	auto result = make_uniq<GcloudLogsBindData>();
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
			result->order_by = param.second.ToString();
		} else if (key == "start_time") {
			start_time = param.second.ToString();
		} else if (key == "end_time") {
			end_time = param.second.ToString();
		} else if (key == "max_rows") {
			result->max_rows = param.second.GetValue<int64_t>();
		} else if (key == "page_size") {
			result->page_size = param.second.GetValue<int64_t>();
		} else if (key == "retries") {
			auto retries = param.second.GetValue<int64_t>();
			if (retries < 0) {
				throw InvalidInputException("read_gcloud_logs: retries must be >= 0 (0 disables retrying)");
			}
			result->client.retries = static_cast<uint64_t>(retries);
		} else if (key == "timeout") {
			auto timeout = param.second.GetValue<int64_t>();
			if (timeout < 1) {
				throw InvalidInputException("read_gcloud_logs: timeout must be >= 1 (seconds)");
			}
			result->client.timeout_seconds = static_cast<uint64_t>(timeout);
		} else if (key == "secret") {
			secret_name = param.second.ToString();
		}
	}

	if (result->max_rows < 0) {
		throw InvalidInputException("read_gcloud_logs: max_rows must be >= 0 (0 means unlimited)");
	}
	if (result->page_size < 1 || result->page_size > 1000) {
		throw InvalidInputException("read_gcloud_logs: page_size must be between 1 and 1000");
	}
	// entries.list rejects anything else, and silently sorting the wrong way is worse than failing.
	if (!StringUtil::CIEquals(result->order_by, "timestamp desc") &&
	    !StringUtil::CIEquals(result->order_by, "timestamp asc")) {
		throw InvalidInputException("read_gcloud_logs: order_by must be 'timestamp desc' or 'timestamp asc' (got '%s')",
		                            result->order_by);
	}

	auto credentials = GetGcloudCredentials(context, secret_name);
	result->client.endpoint = GcloudLoggingEndpoint(credentials);
	result->client.insecure_tls = credentials.insecure_tls;
	result->client.auth.token = credentials.token;
	result->client.auth.credentials_file = credentials.credentials_file;
	result->client.auth.quota_project = credentials.quota_project;
	result->client.auth.insecure_tls = credentials.insecure_tls;
	result->client.auth.timeout_seconds = result->client.timeout_seconds;

	// `resource_names` is the API's own parameter and wins; `project` is the ergonomic shorthand for
	// the overwhelmingly common single-project case.
	if (!resource_names.empty()) {
		result->resource_names = std::move(resource_names);
	} else {
		if (project.empty()) {
			project = credentials.project;
		}
		if (project.empty()) {
			project = TryDiscoverAdcProject();
		}
		if (project.empty()) {
			throw InvalidInputException("read_gcloud_logs: no Google Cloud project configured. Pass one explicitly:\n"
			                            "  SELECT * FROM read_gcloud_logs(project => 'my-project');\n"
			                            "or store it in a secret:\n"
			                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project');\n"
			                            "or set one for the gcloud CLI:\n"
			                            "  gcloud auth application-default set-quota-project my-project");
		}
		result->resource_names = {"projects/" + project};
	}

	result->filter = BuildFilter(result->filter, start_time, end_time);

	GetLogsSchema(return_types, names);
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> GcloudLogsInitGlobal(ClientContext &context,
                                                                 TableFunctionInitInput &input) {
	auto state = make_uniq<GcloudLogsGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

static void GcloudLogsScan(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind = data_p.bind_data->Cast<GcloudLogsBindData>();
	auto &state = data_p.global_state->Cast<GcloudLogsGlobalState>();

	if (bind.max_rows > 0 && state.total_emitted >= static_cast<idx_t>(bind.max_rows)) {
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
		if (bind.max_rows > 0 && state.total_emitted >= static_cast<idx_t>(bind.max_rows)) {
			state.finished = true;
			state.buffer.clear();
			break;
		}
		auto &row = state.buffer.front();
		for (idx_t col = 0; col < row.size(); col++) {
			output.SetValue(col, count, row[col]);
		}
		state.buffer.pop_front();
		count++;
		state.total_emitted++;
	}

	output.SetCardinality(count);
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
	// Only projected columns are mapped from the response; a count(*) or GROUP BY service_name never
	// pays the per-row log_attributes JSON serialization.
	function.projection_pushdown = true;
	loader.RegisterFunction(function);
}

} // namespace duckdb
