#include "send_logs.hpp"

#include "gcloud_auth.hpp"
#include "gcloud_client.hpp"
#include "gcloud_json.hpp"
#include "gcloud_secret.hpp"
#include "gcloud_yyjson.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/execution/expression_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/planner/expression/bound_function_expression.hpp"

#include <atomic>
#include <chrono>
#include <limits>
#include <mutex>
#include <sstream>
#include <unordered_map>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

//! Cloud Logging accepts 10 MiB entries.write requests. Eight MiB leaves room for JSON escaping and
//! the request envelope; 1000 entries also keeps vector-sized calls and API resource fanout bounded.
static constexpr idx_t GCLOUD_WRITE_MAX_BATCH = 1000;
static constexpr idx_t GCLOUD_WRITE_MAX_BATCH_BYTES = 8 * 1024 * 1024;

struct SendLogsFieldIndices {
	int32_t body = -1;
	int32_t service_name = -1;
	int32_t service_namespace = -1;
	int32_t service_instance_id = -1;
	int32_t severity_text = -1;
	int32_t severity_number = -1;
	int32_t timestamp = -1;
	int32_t observed_timestamp = -1;
	int32_t trace_id = -1;
	int32_t span_id = -1;
	int32_t flags = -1;
	int32_t trace_sampled = -1;
	int32_t insert_id = -1;
	int32_t log_name = -1;
	int32_t log_id = -1;
	int32_t resource_type = -1;
	int32_t resource_attributes = -1;
	int32_t log_attributes = -1;
	bool timestamp_is_nanos = false;

	bool operator==(const SendLogsFieldIndices &other) const {
		return body == other.body && service_name == other.service_name &&
		       service_namespace == other.service_namespace && service_instance_id == other.service_instance_id &&
		       severity_text == other.severity_text && severity_number == other.severity_number &&
		       timestamp == other.timestamp && observed_timestamp == other.observed_timestamp &&
		       trace_id == other.trace_id && span_id == other.span_id && flags == other.flags &&
		       trace_sampled == other.trace_sampled && insert_id == other.insert_id && log_name == other.log_name &&
		       log_id == other.log_id && resource_type == other.resource_type &&
		       resource_attributes == other.resource_attributes && log_attributes == other.log_attributes &&
		       timestamp_is_nanos == other.timestamp_is_nanos;
	}
};

struct GcloudSendLogsBindData : public FunctionData {
	SendLogsFieldIndices fields;
	string project;
	GcloudClient client;
	mutable std::mutex send_mutex;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<GcloudSendLogsBindData>();
		result->fields = fields;
		result->project = project;
		result->client.endpoint = client.endpoint;
		result->client.auth = client.auth;
		result->client.send_quota_project = client.send_quota_project;
		result->client.insecure_tls = client.insecure_tls;
		result->client.timeout_seconds = client.timeout_seconds;
		result->client.retries = client.retries;
		return std::move(result);
	}

	bool Equals(const FunctionData &other_p) const override {
		auto &other = other_p.Cast<GcloudSendLogsBindData>();
		return fields == other.fields && project == other.project && client.endpoint == other.client.endpoint &&
		       client.auth.token == other.client.auth.token &&
		       client.auth.credentials_file == other.client.auth.credentials_file &&
		       client.auth.quota_project == other.client.auth.quota_project;
	}
};

static int32_t PickField(const std::unordered_map<string, idx_t> &by_name, const vector<const char *> &names) {
	for (const auto *name : names) {
		auto entry = by_name.find(name);
		if (entry != by_name.end()) {
			return static_cast<int32_t>(entry->second);
		}
	}
	return -1;
}

static string ResolveProject(const GcloudCredentials &credentials) {
	auto project = credentials.project;
	if (!project.empty()) {
		return project;
	}
	// A static token has no trustworthy project identity. In particular, never borrow the process
	// ADC quota project: that can authenticate one principal and silently write to another project.
	if (!credentials.token.empty()) {
		throw InvalidInputException(
		    "send_gcloud_logs: a gcloud secret with TOKEN must also set PROJECT; the process ADC project "
		    "is not used with explicitly selected credentials");
	}
	if (!credentials.credentials_file.empty()) {
		project = TryDiscoverServiceAccountProject(credentials.credentials_file);
		if (!project.empty()) {
			return project;
		}
		throw InvalidInputException(
		    "send_gcloud_logs: CREDENTIALS does not identify a service-account project; set PROJECT explicitly "
		    "when using this credentials file");
	}
	project = TryDiscoverAdcProject();
	if (!project.empty()) {
		return project;
	}
	throw InvalidInputException("send_gcloud_logs: no Google Cloud project configured. Store it in a secret:\n"
	                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project');\n"
	                            "or configure the ADC quota project:\n"
	                            "  gcloud auth application-default set-quota-project my-project");
}

static unique_ptr<FunctionData> GcloudSendLogsBind(ClientContext &context, ScalarFunction &bound_function,
                                                   vector<unique_ptr<Expression>> &arguments) {
	if (arguments.empty() || arguments[0]->return_type.id() != LogicalTypeId::STRUCT) {
		throw BinderException("send_gcloud_logs: the first argument must be a STRUCT of OTLP-shaped log columns "
		                      "(e.g. send_gcloud_logs(logs) where 'logs' is the source table)");
	}

	auto result = make_uniq<GcloudSendLogsBindData>();
	const auto &struct_type = arguments[0]->return_type;
	std::unordered_map<string, idx_t> by_name;
	for (idx_t i = 0; i < StructType::GetChildCount(struct_type); i++) {
		by_name.emplace(StringUtil::Lower(StructType::GetChildName(struct_type, i)), i);
	}
	auto &fields = result->fields;
	fields.body = PickField(by_name, {"body", "message"});
	fields.service_name = PickField(by_name, {"service_name", "service"});
	fields.service_namespace = PickField(by_name, {"service_namespace"});
	fields.service_instance_id = PickField(by_name, {"service_instance_id"});
	fields.severity_text = PickField(by_name, {"severity_text", "severity", "status"});
	fields.severity_number = PickField(by_name, {"severity_number"});
	fields.timestamp = PickField(by_name, {"time_unix_nano", "timestamp"});
	fields.timestamp_is_nanos = by_name.count("time_unix_nano") > 0;
	fields.observed_timestamp = PickField(by_name, {"observed_time_unix_nano"});
	fields.trace_id = PickField(by_name, {"trace_id"});
	fields.span_id = PickField(by_name, {"span_id"});
	fields.flags = PickField(by_name, {"flags"});
	fields.trace_sampled = PickField(by_name, {"trace_sampled"});
	fields.insert_id = PickField(by_name, {"insert_id"});
	fields.log_name = PickField(by_name, {"log_name"});
	fields.log_id = PickField(by_name, {"log_id"});
	fields.resource_type = PickField(by_name, {"resource_type"});
	fields.resource_attributes = PickField(by_name, {"resource_attributes"});
	fields.log_attributes = PickField(by_name, {"log_attributes"});

	string secret_name;
	if (arguments.size() == 2) {
		if (!arguments[1]->IsFoldable()) {
			throw BinderException("send_gcloud_logs: the secret name must be a constant string");
		}
		auto secret_value = ExpressionExecutor::EvaluateScalar(context, *arguments[1]);
		if (!secret_value.IsNull()) {
			secret_name = secret_value.ToString();
		}
	}
	auto credentials = GetGcloudCredentials(context, secret_name);
	result->project = ResolveProject(credentials);
	result->client.endpoint = GcloudLoggingEndpoint(credentials);
	result->client.insecure_tls = credentials.insecure_tls;
	result->client.auth.token = credentials.token;
	result->client.auth.credentials_file = credentials.credentials_file;
	result->client.auth.quota_project = credentials.quota_project;
	result->client.auth.scope = kLoggingWriteScope;
	result->client.auth.insecure_tls = credentials.insecure_tls;
	result->client.auth.timeout_seconds = result->client.timeout_seconds;

	bound_function.return_type = LogicalType::VARCHAR;
	return std::move(result);
}

static string ReadStringField(vector<unique_ptr<Vector>> &children, int32_t index, idx_t row) {
	if (index < 0) {
		return string();
	}
	auto value = children[index]->GetValue(row);
	return value.IsNull() ? string() : value.ToString();
}

static bool ReadIntegerField(vector<unique_ptr<Vector>> &children, int32_t index, idx_t row, int64_t &result) {
	if (index < 0) {
		return false;
	}
	auto value = children[index]->GetValue(row);
	if (value.IsNull()) {
		return false;
	}
	Value integer;
	if (!value.DefaultTryCastAs(LogicalType::BIGINT, integer, nullptr) || integer.IsNull()) {
		return false;
	}
	result = integer.GetValue<int64_t>();
	return true;
}

static bool ReadTimestampNanos(vector<unique_ptr<Vector>> &children, int32_t index, bool integer_is_nanos, idx_t row,
                               int64_t &result) {
	if (index < 0) {
		return false;
	}
	auto value = children[index]->GetValue(row);
	if (value.IsNull()) {
		return false;
	}
	if (value.type().IsIntegral()) {
		Value integer;
		if (!value.DefaultTryCastAs(LogicalType::BIGINT, integer, nullptr) || integer.IsNull()) {
			return false;
		}
		auto raw = integer.GetValue<int64_t>();
		if (!integer_is_nanos && (raw > std::numeric_limits<int64_t>::max() / 1000000 ||
		                          raw < std::numeric_limits<int64_t>::min() / 1000000)) {
			return false;
		}
		result = integer_is_nanos ? raw : raw * 1000000;
		return true;
	}
	Value nanos;
	if (!value.DefaultTryCastAs(LogicalType::TIMESTAMP_NS, nanos, nullptr) || nanos.IsNull()) {
		return false;
	}
	result = nanos.GetValue<timestamp_ns_t>().value;
	return true;
}

static string SeverityNumberToGcloud(int64_t number) {
	if (number >= 1 && number <= 8) {
		return "DEBUG";
	}
	if (number >= 9 && number <= 12) {
		return "INFO";
	}
	if (number >= 13 && number <= 16) {
		return "WARNING";
	}
	if (number >= 17 && number <= 20) {
		return "ERROR";
	}
	if (number == 21) {
		return "CRITICAL";
	}
	if (number == 22) {
		return "ALERT";
	}
	if (number >= 23 && number <= 24) {
		return "EMERGENCY";
	}
	return "DEFAULT";
}

static string NormalizeSeverity(string severity) {
	StringUtil::Trim(severity);
	severity = StringUtil::Upper(severity);
	if (severity == "TRACE") {
		return "DEBUG";
	}
	if (severity == "WARN") {
		return "WARNING";
	}
	if (severity == "FATAL") {
		return "CRITICAL";
	}
	if (severity == "PANIC") {
		return "EMERGENCY";
	}
	return IsLogSeverityName(severity) ? severity : string();
}

static string GeneratedInsertId(int64_t timestamp_nanos) {
	static std::atomic<uint64_t> sequence(0);
	std::ostringstream result;
	result << "duckdb-" << std::hex << static_cast<uint64_t>(timestamp_nanos) << "-" << sequence.fetch_add(1);
	return result.str();
}

static string ReadJsonStringAttribute(const string &json, const char *key) {
	if (json.empty()) {
		return string();
	}
	YyjsonDocPtr doc(yyjson_read(json.c_str(), json.size(), 0));
	auto *root = doc ? yyjson_doc_get_root(doc.get()) : nullptr;
	if (!root || !yyjson_is_obj(root)) {
		return string();
	}
	const char *value = GcloudGetStr(root, key);
	return value ? string(value) : string();
}

static void ValidateAttributesJson(const string &json, const char *field_name) {
	if (json.empty()) {
		return;
	}
	YyjsonDocPtr doc(yyjson_read(json.c_str(), json.size(), 0));
	auto *root = doc ? yyjson_doc_get_root(doc.get()) : nullptr;
	if (!root || !yyjson_is_obj(root)) {
		throw InvalidInputException("send_gcloud_logs: %s must be a valid JSON object", field_name);
	}
}

static GcloudWriteLog BuildWriteLog(const SendLogsFieldIndices &fields, vector<unique_ptr<Vector>> &children, idx_t row,
                                    const string &project) {
	GcloudWriteLog log;
	log.project = project;
	log.body = ReadStringField(children, fields.body, row);
	log.service_name = ReadStringField(children, fields.service_name, row);
	log.service_namespace = ReadStringField(children, fields.service_namespace, row);
	log.service_instance_id = ReadStringField(children, fields.service_instance_id, row);
	log.severity = NormalizeSeverity(ReadStringField(children, fields.severity_text, row));
	if (log.severity.empty()) {
		int64_t severity_number;
		log.severity = ReadIntegerField(children, fields.severity_number, row, severity_number)
		                   ? SeverityNumberToGcloud(severity_number)
		                   : "DEFAULT";
	}
	log.trace_id = ReadStringField(children, fields.trace_id, row);
	log.span_id = ReadStringField(children, fields.span_id, row);
	log.insert_id = ReadStringField(children, fields.insert_id, row);
	log.log_name = ReadStringField(children, fields.log_name, row);
	log.log_id = ReadStringField(children, fields.log_id, row);
	log.resource_type = ReadStringField(children, fields.resource_type, row);
	log.resource_attributes_json = ReadStringField(children, fields.resource_attributes, row);
	log.log_attributes_json = ReadStringField(children, fields.log_attributes, row);
	// Validate the whole input chunk before the first batch is sent. Silently discarding malformed
	// attributes would return `ok` after losing caller data, while discovering them batch-by-batch
	// could write an earlier batch before a later row fails.
	ValidateAttributesJson(log.resource_attributes_json, "resource_attributes");
	ValidateAttributesJson(log.log_attributes_json, "log_attributes");
	if (!ReadTimestampNanos(children, fields.timestamp, fields.timestamp_is_nanos, row, log.timestamp_nanos) &&
	    !ReadTimestampNanos(children, fields.observed_timestamp, true, row, log.timestamp_nanos)) {
		log.timestamp_nanos =
		    std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
		        .count();
	}
	log.has_timestamp_nanos = true;
	if (log.insert_id.empty()) {
		log.insert_id = ReadJsonStringAttribute(log.log_attributes_json, "log.record.uid");
	}
	if (log.insert_id.empty()) {
		log.insert_id = GeneratedInsertId(log.timestamp_nanos);
	}
	int64_t sampled = 0;
	if (ReadIntegerField(children, fields.trace_sampled, row, sampled)) {
		log.trace_sampled = sampled != 0;
	} else if (ReadIntegerField(children, fields.flags, row, sampled)) {
		log.trace_sampled = (sampled & 1) != 0;
	}
	return log;
}

static void GcloudSendLogsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &func_expr = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = func_expr.bind_info->Cast<GcloudSendLogsBindData>();
	auto &context = state.GetContext();
	auto count = args.size();
	auto &input = args.data[0];
	input.Flatten(count);
	auto &children = StructVector::GetEntries(input);
	auto &input_validity = FlatVector::Validity(input);

	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto &result_validity = FlatVector::Validity(result);
	vector<GcloudWriteLog> logs;
	vector<idx_t> source_rows;
	logs.reserve(count);
	source_rows.reserve(count);
	for (idx_t row = 0; row < count; row++) {
		if (!input_validity.RowIsValid(row)) {
			result_validity.SetInvalid(row);
			continue;
		}
		logs.push_back(BuildWriteLog(bind.fields, children, row, bind.project));
		source_rows.push_back(row);
	}

	// Projection threads can evaluate the same scalar concurrently, while GcloudClient owns one
	// keep-alive socket. Serialize both batching and writes around that shared connection.
	std::lock_guard<std::mutex> send_guard(bind.send_mutex);
	idx_t offset = 0;
	while (offset < logs.size()) {
		idx_t batch_end = offset;
		idx_t batch_bytes = 0;
		while (batch_end < logs.size() && batch_end - offset < GCLOUD_WRITE_MAX_BATCH) {
			auto next_bytes = EstimateGcloudWriteLogBytes(logs[batch_end]);
			if (batch_end > offset && batch_bytes + next_bytes > GCLOUD_WRITE_MAX_BATCH_BYTES) {
				break;
			}
			batch_bytes += next_bytes;
			batch_end++;
		}
		auto body = BuildGcloudWriteBody(logs.data() + offset, batch_end - offset);
		bind.client.WriteEntries(context, body);
		for (idx_t i = offset; i < batch_end; i++) {
			result.SetValue(source_rows[i], Value("ok"));
		}
		offset = batch_end;
	}
}

static YyjsonDocPtr ParseAttributes(const string &json, const char *field_name) {
	if (json.empty()) {
		return YyjsonDocPtr();
	}
	YyjsonDocPtr doc(yyjson_read(json.c_str(), json.size(), 0));
	if (!doc || !yyjson_is_obj(yyjson_doc_get_root(doc.get()))) {
		throw InvalidInputException("send_gcloud_logs: %s must be a valid JSON object", field_name);
	}
	return doc;
}

static bool IsHex(char value) {
	return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

static string EncodeLogId(const string &input) {
	auto log_id = input.empty() ? string("duckdb") : input;
	if (log_id.size() >= 512) {
		throw InvalidInputException("send_gcloud_logs: log_id must be shorter than 512 characters");
	}
	string result;
	for (idx_t i = 0; i < log_id.size(); i++) {
		auto ch = log_id[i];
		if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' ||
		    ch == '-' || ch == '.') {
			result += ch;
		} else if (ch == '/') {
			result += "%2F";
		} else if (ch == '%' && i + 2 < log_id.size() && IsHex(log_id[i + 1]) && IsHex(log_id[i + 2])) {
			result.append(log_id, i, 3);
			i += 2;
		} else {
			throw InvalidInputException(
			    "send_gcloud_logs: log_id '%s' contains a character Cloud Logging does not allow", log_id);
		}
	}
	return result;
}

static void PutStringLabels(yyjson_mut_doc *doc, yyjson_mut_val *target, yyjson_val *attributes, const string &prefix) {
	if (!attributes) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *value;
	yyjson_obj_foreach(attributes, idx, max, key, value) {
		const char *name = yyjson_get_str(key);
		if (!name || !StringUtil::StartsWith(name, prefix) || !yyjson_is_str(value)) {
			continue;
		}
		auto label_name = string(name).substr(prefix.size());
		if (!label_name.empty() && !yyjson_mut_obj_get(target, label_name.c_str())) {
			GcloudPutStr(doc, target, label_name.c_str(), yyjson_get_str(value));
		}
	}
}

static void MergePayloadAttributes(yyjson_mut_doc *doc, yyjson_mut_val *payload, yyjson_val *attributes) {
	if (!attributes) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *value;
	yyjson_obj_foreach(attributes, idx, max, key, value) {
		const char *name = yyjson_get_str(key);
		if (!name || StringUtil::StartsWith(name, "gcp.label.") || strcmp(name, "log.record.uid") == 0 ||
		    yyjson_mut_obj_get(payload, name)) {
			continue;
		}
		yyjson_mut_obj_add(payload, yyjson_mut_strcpy(doc, name), yyjson_val_mut_copy(doc, value));
	}
}

static bool HasPayloadAttributes(yyjson_val *attributes) {
	if (!attributes) {
		return false;
	}
	size_t idx, max;
	yyjson_val *key, *value;
	yyjson_obj_foreach(attributes, idx, max, key, value) {
		const char *name = yyjson_get_str(key);
		if (name && !StringUtil::StartsWith(name, "gcp.label.") && strcmp(name, "log.record.uid") != 0) {
			return true;
		}
	}
	return false;
}

static const char *AttributeString(yyjson_val *attributes, const char *key) {
	return attributes ? GcloudGetStr(attributes, key) : nullptr;
}

} // namespace

idx_t EstimateGcloudWriteLogBytes(const GcloudWriteLog &log) {
	// JSON's longest escape is six bytes (a one-byte control character rendered as a Unicode
	// escape). Six times all variable data plus a fixed envelope therefore bounds request bytes.
	return 1024 + 6 * (log.project.size() + log.log_name.size() + log.log_id.size() + log.body.size() +
	                   log.service_name.size() + log.service_namespace.size() + log.service_instance_id.size() +
	                   log.severity.size() + log.trace_id.size() + log.span_id.size() + log.insert_id.size() +
	                   log.resource_type.size() + log.resource_attributes_json.size() + log.log_attributes_json.size());
}

string BuildGcloudWriteBody(const GcloudWriteLog *logs, idx_t count) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	auto *entries = yyjson_mut_arr(doc.get());
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), "entries"), entries);
	GcloudPutBool(doc.get(), root, "partialSuccess", false);

	for (idx_t i = 0; i < count; i++) {
		const auto &log = logs[i];
		auto resource_doc = ParseAttributes(log.resource_attributes_json, "resource_attributes");
		auto log_doc = ParseAttributes(log.log_attributes_json, "log_attributes");
		auto *resource_attributes = resource_doc ? yyjson_doc_get_root(resource_doc.get()) : nullptr;
		auto *log_attributes = log_doc ? yyjson_doc_get_root(log_doc.get()) : nullptr;

		auto *entry = yyjson_mut_obj(doc.get());
		yyjson_mut_arr_add_val(entries, entry);
		string log_name = log.log_name;
		if (log_name.empty()) {
			auto log_id = log.log_id;
			if (log_id.empty()) {
				if (const char *attribute_log_id = AttributeString(resource_attributes, "cloud.resource_id")) {
					log_id = attribute_log_id;
				}
			}
			log_name = "projects/" + log.project + "/logs/" + EncodeLogId(log_id);
		} else if (!StringUtil::StartsWith(log_name, "projects/" + log.project + "/logs/")) {
			throw InvalidInputException(
			    "send_gcloud_logs: log_name must name a log in the configured project '%s' (got '%s')", log.project,
			    log_name);
		}
		GcloudPutStr(doc.get(), entry, "logName", log_name.c_str());

		auto *resource = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(entry, yyjson_mut_strcpy(doc.get(), "resource"), resource);
		auto resource_type = log.resource_type;
		if (resource_type.empty()) {
			if (const char *attribute_type = AttributeString(resource_attributes, "gcp.resource_type")) {
				resource_type = attribute_type;
			}
		}
		if (resource_type.empty()) {
			resource_type = "global";
		}
		GcloudPutStr(doc.get(), resource, "type", resource_type.c_str());
		auto *resource_labels = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(resource, yyjson_mut_strcpy(doc.get(), "labels"), resource_labels);
		GcloudPutStr(doc.get(), resource_labels, "project_id", log.project.c_str());
		PutStringLabels(doc.get(), resource_labels, resource_attributes, "gcp.label.");

		if (log.has_timestamp_nanos) {
			auto timestamp = FormatRfc3339Nanos(log.timestamp_nanos);
			GcloudPutStr(doc.get(), entry, "timestamp", timestamp.c_str());
		}
		GcloudPutStr(doc.get(), entry, "severity", log.severity.c_str());
		auto insert_id = log.insert_id;
		if (insert_id.empty()) {
			if (const char *attribute_insert_id = AttributeString(log_attributes, "log.record.uid")) {
				insert_id = attribute_insert_id;
			}
		}
		GcloudPutStr(doc.get(), entry, "insertId", insert_id.c_str());
		GcloudPutStr(doc.get(), entry, "trace", log.trace_id.c_str());
		GcloudPutStr(doc.get(), entry, "spanId", log.span_id.c_str());
		if (!log.trace_id.empty()) {
			GcloudPutBool(doc.get(), entry, "traceSampled", log.trace_sampled);
		}

		auto *labels = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(entry, yyjson_mut_strcpy(doc.get(), "labels"), labels);
		// Dedicated columns win provider-attribute collisions. Add them first so PutStringLabels'
		// existing-key guard also prevents duplicate JSON keys.
		GcloudPutStr(doc.get(), labels, "service_name", log.service_name.c_str());
		GcloudPutStr(doc.get(), labels, "service_namespace", log.service_namespace.c_str());
		GcloudPutStr(doc.get(), labels, "service_instance_id", log.service_instance_id.c_str());
		PutStringLabels(doc.get(), labels, log_attributes, "gcp.label.");

		if (HasPayloadAttributes(log_attributes)) {
			// Structured payload preserves arbitrary OTLP log attributes. Dedicated row fields win over
			// colliding attribute keys; provider-control attributes become LogEntry/resource fields above.
			auto *payload = yyjson_mut_obj(doc.get());
			GcloudPutStr(doc.get(), payload, "message", log.body.c_str());
			GcloudPutStr(doc.get(), payload, "service", log.service_name.c_str());
			MergePayloadAttributes(doc.get(), payload, log_attributes);
			yyjson_mut_obj_add(entry, yyjson_mut_strcpy(doc.get(), "jsonPayload"), payload);
		} else {
			GcloudPutStr(doc.get(), entry, "textPayload", log.body.c_str());
		}
	}

	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	if (!json) {
		throw InternalException("send_gcloud_logs: could not serialize entries.write request");
	}
	return string(json.get());
}

void RegisterGcloudSendLogsFunction(ExtensionLoader &loader) {
	ScalarFunctionSet set("send_gcloud_logs");
	for (auto &arguments : vector<vector<LogicalType>> {{LogicalType::ANY}, {LogicalType::ANY, LogicalType::VARCHAR}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, GcloudSendLogsFunction, GcloudSendLogsBind);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
