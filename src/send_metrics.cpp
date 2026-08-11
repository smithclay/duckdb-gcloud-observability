#include "send_metrics.hpp"

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

#include <algorithm>
#include <cstring>
#include <limits>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {
namespace {

//! timeSeries.create accepts at most 200 TimeSeries per request, and each of them must carry
//! exactly one point. Unlike entries.write there is no byte budget to track: 200 single-point
//! series cannot approach the request size limit.
static constexpr idx_t GCLOUD_METRICS_MAX_BATCH = 200;

//! Metric types under a Google-owned domain are passed through; anything else is qualified as a
//! user-defined metric. `custom.googleapis.com/` is the domain a project may write to freely.
static constexpr const char *GCLOUD_CUSTOM_METRIC_DOMAIN = "custom.googleapis.com/";

//! A metric type is capped at 200 bytes including its domain (Cloud Monitoring naming rules).
static constexpr idx_t GCLOUD_METRIC_TYPE_MAX_BYTES = 200;

struct SendMetricsFieldIndices {
	int32_t name = -1;
	int32_t description = -1;
	int32_t unit = -1;
	int32_t metric_kind = -1;
	int32_t double_value = -1;
	int32_t int_value = -1;
	int32_t timestamp = -1;
	int32_t start_timestamp = -1;
	int32_t service_name = -1;
	int32_t service_namespace = -1;
	int32_t service_instance_id = -1;
	int32_t resource_type = -1;
	int32_t resource_attributes = -1;
	int32_t metric_attributes = -1;
	bool timestamp_is_nanos = false;
	bool start_timestamp_is_nanos = false;

	bool operator==(const SendMetricsFieldIndices &other) const {
		return name == other.name && description == other.description && unit == other.unit &&
		       metric_kind == other.metric_kind && double_value == other.double_value && int_value == other.int_value &&
		       timestamp == other.timestamp && start_timestamp == other.start_timestamp &&
		       service_name == other.service_name && service_namespace == other.service_namespace &&
		       service_instance_id == other.service_instance_id && resource_type == other.resource_type &&
		       resource_attributes == other.resource_attributes && metric_attributes == other.metric_attributes &&
		       timestamp_is_nanos == other.timestamp_is_nanos &&
		       start_timestamp_is_nanos == other.start_timestamp_is_nanos;
	}
};

struct GcloudSendMetricsBindData : public FunctionData {
	SendMetricsFieldIndices fields;
	string project;
	GcloudClient client;
	mutable std::mutex send_mutex;

	unique_ptr<FunctionData> Copy() const override {
		auto result = make_uniq<GcloudSendMetricsBindData>();
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
		auto &other = other_p.Cast<GcloudSendMetricsBindData>();
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

//! Mirrors send_gcloud_logs' project resolution, including its refusal to borrow the process ADC
//! project when credentials were selected explicitly — writing metrics into an unrelated project is
//! as damaging as writing logs there, and just as hard to notice.
static string ResolveProject(const GcloudCredentials &credentials) {
	auto project = credentials.project;
	if (!project.empty()) {
		return project;
	}
	if (!credentials.token.empty()) {
		throw InvalidInputException(
		    "send_gcloud_metrics: a gcloud secret with TOKEN must also set PROJECT; the process ADC project "
		    "is not used with explicitly selected credentials");
	}
	if (!credentials.credentials_file.empty()) {
		project = TryDiscoverServiceAccountProject(credentials.credentials_file);
		if (!project.empty()) {
			return project;
		}
		throw InvalidInputException(
		    "send_gcloud_metrics: CREDENTIALS does not identify a service-account project; set PROJECT explicitly "
		    "when using this credentials file");
	}
	project = TryDiscoverAdcProject();
	if (!project.empty()) {
		return project;
	}
	throw InvalidInputException("send_gcloud_metrics: no Google Cloud project configured. Store it in a secret:\n"
	                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project');\n"
	                            "or configure the ADC quota project:\n"
	                            "  gcloud auth application-default set-quota-project my-project");
}

static unique_ptr<FunctionData> GcloudSendMetricsBind(ClientContext &context, ScalarFunction &bound_function,
                                                      vector<unique_ptr<Expression>> &arguments) {
	if (arguments.empty() || arguments[0]->return_type.id() != LogicalTypeId::STRUCT) {
		throw BinderException("send_gcloud_metrics: the first argument must be a STRUCT of OTLP-shaped metric columns "
		                      "(e.g. send_gcloud_metrics(metrics) where 'metrics' is the source table)");
	}

	auto result = make_uniq<GcloudSendMetricsBindData>();
	const auto &struct_type = arguments[0]->return_type;
	std::unordered_map<string, idx_t> by_name;
	for (idx_t i = 0; i < StructType::GetChildCount(struct_type); i++) {
		by_name.emplace(StringUtil::Lower(StructType::GetChildName(struct_type, i)), i);
	}
	auto &fields = result->fields;
	fields.name = PickField(by_name, {"name", "metric_name", "metric", "metric_type"});
	if (fields.name < 0) {
		throw BinderException("send_gcloud_metrics: the input struct has no metric name column "
		                      "(expected one of: name, metric_name, metric, metric_type)");
	}
	fields.description = PickField(by_name, {"description"});
	fields.unit = PickField(by_name, {"unit"});
	fields.metric_kind = PickField(by_name, {"metric_kind", "metrickind"});
	fields.double_value = PickField(by_name, {"double_value", "value"});
	fields.int_value = PickField(by_name, {"int_value"});
	fields.timestamp = PickField(by_name, {"time_unix_nano", "timestamp", "end_time"});
	fields.timestamp_is_nanos = by_name.count("time_unix_nano") > 0;
	fields.start_timestamp = PickField(by_name, {"start_time_unix_nano", "start_time"});
	fields.start_timestamp_is_nanos = by_name.count("start_time_unix_nano") > 0;
	fields.service_name = PickField(by_name, {"service_name", "service"});
	fields.service_namespace = PickField(by_name, {"service_namespace"});
	fields.service_instance_id = PickField(by_name, {"service_instance_id"});
	fields.resource_type = PickField(by_name, {"resource_type"});
	fields.resource_attributes = PickField(by_name, {"resource_attributes"});
	fields.metric_attributes = PickField(by_name, {"metric_attributes", "attributes"});

	string secret_name;
	if (arguments.size() == 2) {
		if (!arguments[1]->IsFoldable()) {
			throw BinderException("send_gcloud_metrics: the secret name must be a constant string");
		}
		auto secret_value = ExpressionExecutor::EvaluateScalar(context, *arguments[1]);
		if (!secret_value.IsNull()) {
			secret_name = secret_value.ToString();
		}
	}
	auto credentials = GetGcloudCredentials(context, secret_name);
	result->project = ResolveProject(credentials);
	result->client.endpoint = GcloudMonitoringEndpoint(credentials);
	result->client.insecure_tls = credentials.insecure_tls;
	result->client.auth.token = credentials.token;
	result->client.auth.credentials_file = credentials.credentials_file;
	result->client.auth.quota_project = credentials.quota_project;
	result->client.auth.scope = kMonitoringWriteScope;
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

static bool ReadDoubleField(vector<unique_ptr<Vector>> &children, int32_t index, idx_t row, double &result) {
	if (index < 0) {
		return false;
	}
	auto value = children[index]->GetValue(row);
	if (value.IsNull()) {
		return false;
	}
	Value decimal;
	if (!value.DefaultTryCastAs(LogicalType::DOUBLE, decimal, nullptr) || decimal.IsNull()) {
		return false;
	}
	result = decimal.GetValue<double>();
	return true;
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

static YyjsonDocPtr ParseAttributes(const string &json, const char *field_name) {
	if (json.empty()) {
		return YyjsonDocPtr();
	}
	YyjsonDocPtr doc(yyjson_read(json.c_str(), json.size(), 0));
	if (!doc || !yyjson_is_obj(yyjson_doc_get_root(doc.get()))) {
		throw InvalidInputException("send_gcloud_metrics: %s must be a valid JSON object", field_name);
	}
	return doc;
}

//! Add `key`=`value` unless the key is already present. Dedicated columns are added before
//! attribute-derived labels, so this is what makes a column win a collision.
static void AddLabel(vector<pair<string, string>> &labels, const string &key, const string &value) {
	if (key.empty() || value.empty()) {
		return;
	}
	for (const auto &existing : labels) {
		if (existing.first == key) {
			return;
		}
	}
	labels.emplace_back(key, value);
}

static void SortLabels(vector<pair<string, string>> &labels) {
	std::sort(labels.begin(), labels.end(),
	          [](const pair<string, string> &a, const pair<string, string> &b) { return a.first < b.first; });
}

//! Resource labels come from `gcp.label.*` attributes, exactly as in send_gcloud_logs, because the
//! valid keys are fixed by the monitored resource type rather than chosen by the caller.
static void CollectResourceLabels(vector<pair<string, string>> &labels, yyjson_val *attributes) {
	if (!attributes) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *value;
	yyjson_obj_foreach(attributes, idx, max, key, value) {
		const char *name = yyjson_get_str(key);
		if (!name || !StringUtil::StartsWith(name, "gcp.label.") || !yyjson_is_str(value)) {
			continue;
		}
		AddLabel(labels, string(name).substr(strlen("gcp.label.")), yyjson_get_str(value));
	}
}

//! Every metric attribute becomes a metric label. Cloud Monitoring has no free-form payload to fall
//! back on the way a LogEntry does, so a key that cannot be normalized is an error rather than a
//! silently dropped field.
static void CollectMetricLabels(vector<pair<string, string>> &labels, yyjson_val *attributes) {
	if (!attributes) {
		return;
	}
	size_t idx, max;
	yyjson_val *key, *value;
	yyjson_obj_foreach(attributes, idx, max, key, value) {
		const char *name = yyjson_get_str(key);
		if (!name) {
			continue;
		}
		// Non-string values are serialized rather than dropped: a label value is always a string, so
		// `{"retries": 3}` becomes "3" instead of disappearing.
		auto text = yyjson_is_str(value) ? string(yyjson_get_str(value)) : GcloudWriteValue(value);
		AddLabel(labels, NormalizeGcloudMetricLabelKey(name), text);
	}
}

static const char *AttributeString(yyjson_val *attributes, const char *key) {
	return attributes ? GcloudGetStr(attributes, key) : nullptr;
}

static string NormalizeMetricKind(const string &kind) {
	auto upper = StringUtil::Upper(kind);
	StringUtil::Trim(upper);
	if (upper.empty()) {
		return "GAUGE";
	}
	if (upper != "GAUGE" && upper != "CUMULATIVE" && upper != "DELTA") {
		throw InvalidInputException("send_gcloud_metrics: metric_kind must be GAUGE, CUMULATIVE, or DELTA, not '%s'",
		                            kind);
	}
	return upper;
}

static GcloudWriteMetric BuildWriteMetric(const SendMetricsFieldIndices &fields, vector<unique_ptr<Vector>> &children,
                                          idx_t row, const string &project) {
	GcloudWriteMetric metric;
	metric.project = project;
	metric.metric_type = NormalizeGcloudMetricType(ReadStringField(children, fields.name, row));
	metric.description = ReadStringField(children, fields.description, row);
	metric.unit = ReadStringField(children, fields.unit, row);
	metric.metric_kind = NormalizeMetricKind(ReadStringField(children, fields.metric_kind, row));

	// A DOUBLE column wins when both are populated: it is the wider type, so choosing it cannot
	// silently truncate a value the caller supplied.
	if (ReadDoubleField(children, fields.double_value, row, metric.double_value)) {
		metric.is_integer = false;
	} else if (ReadIntegerField(children, fields.int_value, row, metric.integer_value)) {
		metric.is_integer = true;
	} else {
		throw InvalidInputException("send_gcloud_metrics: '%s' has no value in this row; every point needs a non-NULL "
		                            "double_value or int_value",
		                            metric.metric_type);
	}

	if (!ReadTimestampNanos(children, fields.timestamp, fields.timestamp_is_nanos, row, metric.end_time_nanos)) {
		throw InvalidInputException("send_gcloud_metrics: '%s' has no timestamp in this row; a point's end time "
		                            "cannot be defaulted the way a log entry's can, because it decides which "
		                            "interval the value belongs to",
		                            metric.metric_type);
	}
	metric.has_start_time_nanos = ReadTimestampNanos(children, fields.start_timestamp, fields.start_timestamp_is_nanos,
	                                                 row, metric.start_time_nanos);
	if (metric.metric_kind != "GAUGE" && !metric.has_start_time_nanos) {
		throw InvalidInputException("send_gcloud_metrics: a %s point needs a start time, which measures the "
		                            "interval the value accumulated over ('%s' has none)",
		                            metric.metric_kind, metric.metric_type);
	}
	if (metric.has_start_time_nanos && metric.start_time_nanos > metric.end_time_nanos) {
		throw InvalidInputException("send_gcloud_metrics: '%s' has a start time after its end time",
		                            metric.metric_type);
	}

	auto resource_attributes_json = ReadStringField(children, fields.resource_attributes, row);
	auto metric_attributes_json = ReadStringField(children, fields.metric_attributes, row);
	// Parsed while the chunk is mapped, so a malformed attribute object fails before any batch has
	// been written rather than after an earlier one already landed.
	auto resource_doc = ParseAttributes(resource_attributes_json, "resource_attributes");
	auto metric_doc = ParseAttributes(metric_attributes_json, "metric_attributes");
	auto *resource_attributes = resource_doc ? yyjson_doc_get_root(resource_doc.get()) : nullptr;
	auto *metric_attributes = metric_doc ? yyjson_doc_get_root(metric_doc.get()) : nullptr;

	metric.resource_type = ReadStringField(children, fields.resource_type, row);
	if (metric.resource_type.empty()) {
		if (const char *attribute_type = AttributeString(resource_attributes, "gcp.resource_type")) {
			metric.resource_type = attribute_type;
		}
	}
	if (metric.resource_type.empty()) {
		metric.resource_type = "global";
	}
	AddLabel(metric.resource_labels, "project_id", project);
	CollectResourceLabels(metric.resource_labels, resource_attributes);

	// OTel semantic-convention keys, which is also what read_gcloud_metrics looks for when it fills
	// the service columns — so a table written by this function reads back with them populated.
	AddLabel(metric.metric_labels, "service.name", ReadStringField(children, fields.service_name, row));
	AddLabel(metric.metric_labels, "service.namespace", ReadStringField(children, fields.service_namespace, row));
	AddLabel(metric.metric_labels, "service.instance.id", ReadStringField(children, fields.service_instance_id, row));
	CollectMetricLabels(metric.metric_labels, metric_attributes);

	SortLabels(metric.metric_labels);
	SortLabels(metric.resource_labels);
	return metric;
}

static void GcloudSendMetricsFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &func_expr = state.expr.Cast<BoundFunctionExpression>();
	auto &bind = func_expr.bind_info->Cast<GcloudSendMetricsBindData>();
	auto &context = state.GetContext();
	auto count = args.size();
	auto &input = args.data[0];
	input.Flatten(count);
	auto &children = StructVector::GetEntries(input);
	auto &input_validity = FlatVector::Validity(input);

	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto &result_validity = FlatVector::Validity(result);
	vector<GcloudWriteMetric> metrics;
	vector<idx_t> source_rows;
	vector<string> series_keys;
	metrics.reserve(count);
	source_rows.reserve(count);
	series_keys.reserve(count);
	for (idx_t row = 0; row < count; row++) {
		if (!input_validity.RowIsValid(row)) {
			result_validity.SetInvalid(row);
			continue;
		}
		metrics.push_back(BuildWriteMetric(bind.fields, children, row, bind.project));
		source_rows.push_back(row);
		series_keys.push_back(GcloudMetricSeriesKey(metrics.back()));
	}

	// Projection threads can evaluate the same scalar concurrently, while GcloudClient owns one
	// keep-alive socket. Serialize both batching and writes around that shared connection.
	std::lock_guard<std::mutex> send_guard(bind.send_mutex);

	// One request may carry a series only once, so rather than cutting a batch short at the first
	// repeat, each pass takes the earliest still-pending point of every distinct series and leaves
	// the rest for the next pass. A table sorted by series (all of one series' points adjacent) then
	// costs the same number of requests as one sorted by time, and because a series' points are
	// still taken in input order, the ascending-end-time requirement holds across passes too.
	vector<idx_t> pending;
	pending.reserve(metrics.size());
	for (idx_t i = 0; i < metrics.size(); i++) {
		pending.push_back(i);
	}
	while (!pending.empty()) {
		vector<GcloudWriteMetric> batch;
		vector<idx_t> batch_rows;
		vector<idx_t> deferred;
		std::unordered_set<string> seen;
		for (auto index : pending) {
			if (batch.size() < GCLOUD_METRICS_MAX_BATCH && seen.insert(series_keys[index]).second) {
				batch.push_back(metrics[index]);
				batch_rows.push_back(source_rows[index]);
			} else {
				deferred.push_back(index);
			}
		}
		bind.client.WriteTimeSeries(context, "/v3/projects/" + bind.project + "/timeSeries",
		                            BuildGcloudTimeSeriesBody(batch));
		for (auto row : batch_rows) {
			result.SetValue(row, Value("ok"));
		}
		pending = std::move(deferred);
	}
}

} // namespace

string NormalizeGcloudMetricLabelKey(const string &key) {
	// `gcp.label.` is stripped for symmetry with send_gcloud_logs, where that prefix is what marks an
	// attribute as a provider label rather than payload.
	auto name = StringUtil::StartsWith(key, "gcp.label.") ? key.substr(strlen("gcp.label.")) : key;
	// Cloud Monitoring label keys are lower-case only, so an OTLP attribute that differs from an
	// existing label only in case would otherwise be rejected as an unknown key.
	name = StringUtil::Lower(name);
	if (name.empty() || name.size() > 100 || !(name[0] >= 'a' && name[0] <= 'z')) {
		throw InvalidInputException("send_gcloud_metrics: '%s' is not a usable metric label key; Cloud Monitoring "
		                            "label keys must start with a letter and be at most 100 characters",
		                            key);
	}
	for (auto ch : name) {
		if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '.')) {
			throw InvalidInputException(
			    "send_gcloud_metrics: '%s' is not a usable metric label key; Cloud Monitoring label keys hold only "
			    "lower-case letters, digits, underscores, and dots",
			    key);
		}
	}
	return name;
}

string NormalizeGcloudMetricType(const string &name) {
	auto trimmed = name;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		throw InvalidInputException("send_gcloud_metrics: the metric name is empty; every point needs one");
	}
	// A name that already names a Google metric domain is a fully-qualified type (say
	// "workload.googleapis.com/requests"); anything else is a user-defined metric of this project.
	auto first_slash = trimmed.find('/');
	auto domain = first_slash == string::npos ? string() : trimmed.substr(0, first_slash);
	auto type = StringUtil::EndsWith(domain, ".googleapis.com") ? trimmed : GCLOUD_CUSTOM_METRIC_DOMAIN + trimmed;
	if (type.size() > GCLOUD_METRIC_TYPE_MAX_BYTES) {
		throw InvalidInputException("send_gcloud_metrics: metric type '%s' is longer than the %llu bytes Cloud "
		                            "Monitoring allows",
		                            type, static_cast<unsigned long long>(GCLOUD_METRIC_TYPE_MAX_BYTES));
	}
	// Every path element must be non-empty and start with a letter or digit; within an element only
	// letters, digits, and `._:-` are legal. Rejecting rather than rewriting keeps the metric a
	// caller queries by identical to the one they named.
	bool element_start = true;
	for (auto ch : type) {
		if (ch == '/') {
			if (element_start) {
				throw InvalidInputException("send_gcloud_metrics: metric type '%s' has an empty path element", type);
			}
			element_start = true;
			continue;
		}
		bool alphanumeric = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
		if (element_start && !alphanumeric) {
			throw InvalidInputException(
			    "send_gcloud_metrics: metric type '%s' has a path element starting with '%s'; Cloud Monitoring "
			    "requires a letter or digit there",
			    type, string(1, ch));
		}
		if (!alphanumeric && ch != '.' && ch != '_' && ch != ':' && ch != '-') {
			throw InvalidInputException(
			    "send_gcloud_metrics: metric name '%s' contains a character Cloud Monitoring does not allow ('%s'); "
			    "metric types hold letters, digits, and '._:-', with '/' separating path elements",
			    name, string(1, ch));
		}
		element_start = false;
	}
	if (element_start) {
		throw InvalidInputException("send_gcloud_metrics: metric type '%s' ends with an empty path element", type);
	}
	return type;
}

string GcloudMetricSeriesKey(const GcloudWriteMetric &metric) {
	// Labels are sorted at map time, so equal series produce byte-identical keys. '\x1f' (unit
	// separator) cannot appear in a metric type, a label key, or a resource type, so no combination
	// of legal values can collide by running two fields together.
	string key = metric.metric_type;
	for (const auto &label : metric.metric_labels) {
		key += "\x1f" + label.first + "\x1f" + label.second;
	}
	key += "\x1e" + metric.resource_type;
	for (const auto &label : metric.resource_labels) {
		key += "\x1f" + label.first + "\x1f" + label.second;
	}
	return key;
}

string BuildGcloudTimeSeriesBody(const GcloudWriteMetric *metrics, idx_t count) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	auto *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);
	auto *series_array = yyjson_mut_arr(doc.get());
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), "timeSeries"), series_array);

	for (idx_t i = 0; i < count; i++) {
		const auto &metric = metrics[i];
		auto *series = yyjson_mut_obj(doc.get());
		yyjson_mut_arr_add_val(series_array, series);

		auto *metric_object = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(series, yyjson_mut_strcpy(doc.get(), "metric"), metric_object);
		GcloudPutStr(doc.get(), metric_object, "type", metric.metric_type.c_str());
		auto *metric_labels = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(metric_object, yyjson_mut_strcpy(doc.get(), "labels"), metric_labels);
		for (const auto &label : metric.metric_labels) {
			GcloudPutStr(doc.get(), metric_labels, label.first.c_str(), label.second.c_str());
		}

		auto *resource = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(series, yyjson_mut_strcpy(doc.get(), "resource"), resource);
		GcloudPutStr(doc.get(), resource, "type", metric.resource_type.c_str());
		auto *resource_labels = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(resource, yyjson_mut_strcpy(doc.get(), "labels"), resource_labels);
		for (const auto &label : metric.resource_labels) {
			GcloudPutStr(doc.get(), resource_labels, label.first.c_str(), label.second.c_str());
		}

		// Both are optional on create, and both are checked against the descriptor when it already
		// exists. Sending them makes an auto-created descriptor describe the data accurately instead
		// of inheriting a default, and turns a kind/type mismatch into an error at the first write
		// rather than a silently wrong descriptor.
		GcloudPutStr(doc.get(), series, "metricKind", metric.metric_kind.c_str());
		GcloudPutStr(doc.get(), series, "valueType", metric.is_integer ? "INT64" : "DOUBLE");
		GcloudPutStr(doc.get(), series, "unit", metric.unit.c_str());
		GcloudPutStr(doc.get(), series, "description", metric.description.c_str());

		auto *points = yyjson_mut_arr(doc.get());
		yyjson_mut_obj_add(series, yyjson_mut_strcpy(doc.get(), "points"), points);
		auto *point = yyjson_mut_obj(doc.get());
		yyjson_mut_arr_add_val(points, point);
		auto *interval = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(point, yyjson_mut_strcpy(doc.get(), "interval"), interval);
		auto end_time = FormatRfc3339Nanos(metric.end_time_nanos);
		GcloudPutStr(doc.get(), interval, "endTime", end_time.c_str());
		// A GAUGE's start time, if it is sent at all, must equal its end time; the row's own start
		// time describes the rollup bucket the value summarizes, which is a different claim. Send it
		// only for the kinds where it means what the caller wrote.
		if (metric.has_start_time_nanos && metric.metric_kind != "GAUGE") {
			auto start_time = FormatRfc3339Nanos(metric.start_time_nanos);
			GcloudPutStr(doc.get(), interval, "startTime", start_time.c_str());
		}
		auto *value = yyjson_mut_obj(doc.get());
		yyjson_mut_obj_add(point, yyjson_mut_strcpy(doc.get(), "value"), value);
		if (metric.is_integer) {
			// int64 travels as a JSON string in proto3 JSON, which is also how the reader parses it.
			auto integer = StringUtil::Format("%lld", static_cast<long long>(metric.integer_value));
			GcloudPutStr(doc.get(), value, "int64Value", integer.c_str());
		} else {
			GcloudPutDouble(doc.get(), value, "doubleValue", metric.double_value);
		}
	}

	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	if (!json) {
		throw InternalException("send_gcloud_metrics: could not serialize the timeSeries.create request");
	}
	return string(json.get());
}

void RegisterGcloudSendMetricsFunction(ExtensionLoader &loader) {
	ScalarFunctionSet set("send_gcloud_metrics");
	for (auto &arguments : vector<vector<LogicalType>> {{LogicalType::ANY}, {LogicalType::ANY, LogicalType::VARCHAR}}) {
		ScalarFunction function(arguments, LogicalType::VARCHAR, GcloudSendMetricsFunction, GcloudSendMetricsBind);
		function.SetStability(FunctionStability::VOLATILE);
		function.SetNullHandling(FunctionNullHandling::SPECIAL_HANDLING);
		set.AddFunction(function);
	}
	loader.RegisterFunction(set);
}

} // namespace duckdb
