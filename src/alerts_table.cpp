#include "alerts_table.hpp"

#include "gcloud_client.hpp"
#include "gcloud_json.hpp"
#include "gcloud_secret.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/timestamp.hpp"
#include "duckdb/function/table_function.hpp"

#include <deque>

namespace duckdb {
namespace {

static constexpr const char *kMonitoringApiName = "Cloud Monitoring";

//===--------------------------------------------------------------------===//
// alerts.open
//===--------------------------------------------------------------------===//

static constexpr idx_t COL_ALERT_INCIDENT_ID = 0;
static constexpr idx_t COL_ALERT_POLICY_ID = 1;
static constexpr idx_t COL_ALERT_POLICY_NAME = 2;
static constexpr idx_t COL_ALERT_STATE = 3;
static constexpr idx_t COL_ALERT_SUMMARY = 4;
static constexpr idx_t COL_ALERT_RESOURCE_TYPE = 5;
static constexpr idx_t COL_ALERT_RESOURCE_LABELS = 6;
static constexpr idx_t COL_ALERT_OPENED_AT = 7;
static constexpr idx_t COL_ALERT_CLOSED_AT = 8;
static constexpr idx_t ALERT_COLUMN_COUNT = 9;

//===--------------------------------------------------------------------===//
// alerts.policies
//===--------------------------------------------------------------------===//

static constexpr idx_t COL_POLICY_ID = 0;
static constexpr idx_t COL_POLICY_DISPLAY_NAME = 1;
static constexpr idx_t COL_POLICY_ENABLED = 2;
static constexpr idx_t COL_POLICY_SEVERITY = 3;
static constexpr idx_t COL_POLICY_COMBINER = 4;
static constexpr idx_t COL_POLICY_CONDITION_COUNT = 5;
static constexpr idx_t COL_POLICY_NOTIFICATION_CHANNELS = 6;
static constexpr idx_t COL_POLICY_USER_LABELS = 7;
static constexpr idx_t COL_POLICY_DOCUMENTATION = 8;
static constexpr idx_t COL_POLICY_CREATED_AT = 9;
static constexpr idx_t COL_POLICY_UPDATED_AT = 10;
static constexpr idx_t POLICY_COLUMN_COUNT = 11;

//! Which of the two listings a bound scan reads. Both share every piece of machinery below —
//! pagination, projection, cancellation — and differ only in the path they request and the mapper
//! they run over the parsed page.
enum class AlertsKind { OPEN_INCIDENTS, POLICIES };

struct GcloudAlertsBindData : public TableFunctionData {
	AlertsKind kind = AlertsKind::OPEN_INCIDENTS;
	string project;
	int64_t page_size = 100;
	int64_t max_rows = 0;
	TableCatalogEntry *table = nullptr;
	GcloudClient client;
};

struct GcloudAlertsGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	std::deque<vector<Value>> buffer;
	string page_token;
	//! Distinguishes "no cursor yet, fetch the first page" from "cursor exhausted".
	bool first_page = true;
	idx_t total_emitted = 0;
	bool finished = false;

	idx_t MaxThreads() const override {
		return 1; // Cursor pagination is inherently sequential.
	}
};

//! TIMESTAMP (microseconds) rather than the logs table's TIMESTAMP_NS: incident times are
//! second-granularity, and TIMESTAMP is the friendlier type to compare against. The two still join
//! directly, since DuckDB casts between them implicitly.
static Value TimestampFromNanos(bool present, int64_t nanos) {
	if (!present) {
		return Value();
	}
	return Value::TIMESTAMP(Timestamp::FromEpochNanoSeconds(nanos));
}

static Value OptionalString(bool present, const string &value) {
	return present ? Value(value) : Value();
}

//! A serialized JSON object, or NULL when the API sent nothing (never a useless "{}").
static Value OptionalJson(const string &serialized) {
	return serialized.empty() ? Value() : Value(serialized);
}

static Value ToVarcharList(const vector<string> &strings) {
	vector<Value> values;
	values.reserve(strings.size());
	for (const auto &value : strings) {
		values.emplace_back(value);
	}
	return Value::LIST(LogicalType::VARCHAR, std::move(values));
}

static void MapAlert(const GcloudAlert &alert, const vector<column_t> &column_ids, vector<Value> &row) {
	row.assign(column_ids.size(), Value());
	for (idx_t c = 0; c < column_ids.size(); c++) {
		switch (column_ids[c]) {
		case COL_ALERT_INCIDENT_ID:
			row[c] = OptionalString(alert.has_incident_id, alert.incident_id);
			break;
		case COL_ALERT_POLICY_ID:
			row[c] = OptionalString(alert.has_policy_id, alert.policy_id);
			break;
		case COL_ALERT_POLICY_NAME:
			row[c] = OptionalString(alert.has_policy_name, alert.policy_name);
			break;
		case COL_ALERT_STATE:
			row[c] = OptionalString(alert.has_state, alert.state);
			break;
		case COL_ALERT_SUMMARY:
			row[c] = OptionalString(alert.has_summary, alert.summary);
			break;
		case COL_ALERT_RESOURCE_TYPE:
			row[c] = OptionalString(alert.has_resource_type, alert.resource_type);
			break;
		case COL_ALERT_RESOURCE_LABELS:
			row[c] = OptionalJson(alert.resource_labels);
			break;
		case COL_ALERT_OPENED_AT:
			row[c] = TimestampFromNanos(alert.has_opened_at, alert.opened_at_nanos);
			break;
		case COL_ALERT_CLOSED_AT:
			row[c] = TimestampFromNanos(alert.has_closed_at, alert.closed_at_nanos);
			break;
		default:
			// Virtual columns such as the count(*) row-id sentinel stay NULL.
			break;
		}
	}
}

static void MapPolicy(const GcloudAlertPolicy &policy, const vector<column_t> &column_ids, vector<Value> &row) {
	row.assign(column_ids.size(), Value());
	for (idx_t c = 0; c < column_ids.size(); c++) {
		switch (column_ids[c]) {
		case COL_POLICY_ID:
			row[c] = OptionalString(policy.has_policy_id, policy.policy_id);
			break;
		case COL_POLICY_DISPLAY_NAME:
			row[c] = OptionalString(policy.has_display_name, policy.display_name);
			break;
		case COL_POLICY_ENABLED:
			if (policy.has_enabled) {
				row[c] = Value::BOOLEAN(policy.enabled);
			}
			break;
		case COL_POLICY_SEVERITY:
			row[c] = OptionalString(policy.has_severity, policy.severity);
			break;
		case COL_POLICY_COMBINER:
			row[c] = OptionalString(policy.has_combiner, policy.combiner);
			break;
		case COL_POLICY_CONDITION_COUNT:
			if (policy.has_condition_count) {
				row[c] = Value::INTEGER(static_cast<int32_t>(policy.condition_count));
			}
			break;
		case COL_POLICY_NOTIFICATION_CHANNELS:
			if (policy.has_notification_channels) {
				row[c] = ToVarcharList(policy.notification_channels);
			}
			break;
		case COL_POLICY_USER_LABELS:
			row[c] = OptionalJson(policy.user_labels);
			break;
		case COL_POLICY_DOCUMENTATION:
			row[c] = OptionalString(policy.has_documentation, policy.documentation);
			break;
		case COL_POLICY_CREATED_AT:
			row[c] = TimestampFromNanos(policy.has_created_at, policy.created_at_nanos);
			break;
		case COL_POLICY_UPDATED_AT:
			row[c] = TimestampFromNanos(policy.has_updated_at, policy.updated_at_nanos);
			break;
		default:
			break;
		}
	}
}

//! Fetch one page and buffer its projected rows.
//!
//! Like entries.list, termination keys off the page token alone rather than an empty result array:
//! a filtered listing can legitimately return a page with no matches and still hand back a cursor.
//! A server echoing a non-advancing cursor would otherwise spin forever, so that ends the scan too.
static void FetchNextPage(ClientContext &context, const GcloudAlertsBindData &bind, GcloudAlertsGlobalState &state) {
	auto accounted = state.total_emitted + state.buffer.size();
	auto page_size = GetGcloudLogsPageSize(bind.page_size, bind.max_rows, accounted);
	if (page_size <= 0) {
		state.finished = true;
		return;
	}

	string next_token;
	if (bind.kind == AlertsKind::OPEN_INCIDENTS) {
		auto path = BuildGcloudOpenAlertsPath(bind.project, page_size, state.page_token);
		auto page = ParseGcloudAlertsPage(bind.client.Get(context, path, kMonitoringApiName));
		for (const auto &alert : page.alerts) {
			// The request already filters to state=open; this preserves the table's contract if an
			// incident resolves concurrently with pagination.
			if (alert.has_state && !StringUtil::CIEquals(alert.state, "open")) {
				continue;
			}
			vector<Value> row;
			MapAlert(alert, state.column_ids, row);
			state.buffer.push_back(std::move(row));
		}
		next_token = std::move(page.next_page_token);
	} else {
		auto path = BuildGcloudAlertPoliciesPath(bind.project, page_size, state.page_token);
		auto page = ParseGcloudAlertPoliciesPage(bind.client.Get(context, path, kMonitoringApiName));
		for (const auto &policy : page.policies) {
			vector<Value> row;
			MapPolicy(policy, state.column_ids, row);
			state.buffer.push_back(std::move(row));
		}
		next_token = std::move(page.next_page_token);
	}

	if (next_token.empty() || (!state.first_page && next_token == state.page_token)) {
		state.finished = true;
	} else {
		state.page_token = std::move(next_token);
	}
	state.first_page = false;
}

static unique_ptr<GlobalTableFunctionState> GcloudAlertsInitGlobal(ClientContext &, TableFunctionInitInput &input) {
	auto state = make_uniq<GcloudAlertsGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

static void GcloudAlertsScan(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind = data_p.bind_data->Cast<GcloudAlertsBindData>();
	auto &state = data_p.global_state->Cast<GcloudAlertsGlobalState>();

	if (GcloudLogsMaxRowsReached(bind.max_rows, state.total_emitted)) {
		state.finished = true;
		state.buffer.clear();
	}

	while (state.buffer.empty() && !state.finished) {
		FetchNextPage(context, bind, state);
	}

	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.buffer.empty()) {
		auto &row = state.buffer.front();
		for (idx_t column = 0; column < row.size(); column++) {
			output.SetValue(column, count, row[column]);
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

static BindInfo GcloudAlertsGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &bind = bind_data->Cast<GcloudAlertsBindData>();
	D_ASSERT(bind.table);
	return BindInfo(*bind.table);
}

static InsertionOrderPreservingMap<string> GcloudAlertsToString(TableFunctionToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	auto &bind = input.bind_data->Cast<GcloudAlertsBindData>();
	result["Function"] = input.table_function.name;
	result["Google Cloud Project"] = bind.project;
	result["Google Cloud Endpoint"] = bind.client.endpoint;
	if (bind.kind == AlertsKind::OPEN_INCIDENTS) {
		result["Google Cloud Filter"] = "state=open";
	}
	result["Google Cloud Page Size"] = std::to_string(bind.page_size);
	result["Google Cloud Max Rows"] = std::to_string(bind.max_rows);
	result["Google Cloud Retries"] = std::to_string(bind.client.retries);
	result["Google Cloud Timeout"] = std::to_string(bind.client.timeout_seconds);
	return result;
}

//! Resolve credentials and build the bind data shared by both alert tables.
static unique_ptr<GcloudAlertsBindData> BindAlertsScan(ClientContext &context, TableCatalogEntry &table,
                                                       const string &secret_name, const GcloudAlertsSettings &settings,
                                                       AlertsKind kind) {
	auto result = make_uniq<GcloudAlertsBindData>();
	result->kind = kind;
	result->table = &table;
	result->page_size = settings.page_size;
	result->max_rows = settings.max_rows;
	result->client.retries = static_cast<uint64_t>(settings.retries);
	result->client.timeout_seconds = static_cast<uint64_t>(settings.timeout_seconds);

	auto credentials = GetGcloudCredentials(context, secret_name);
	result->client.endpoint = GcloudMonitoringEndpoint(credentials);
	result->client.insecure_tls = credentials.insecure_tls;
	result->client.auth.token = credentials.token;
	result->client.auth.credentials_file = credentials.credentials_file;
	result->client.auth.quota_project = credentials.quota_project;
	result->client.auth.insecure_tls = credentials.insecure_tls;
	result->client.auth.timeout_seconds = result->client.timeout_seconds;
	// Ask for monitoring authority rather than the logging scope the reader defaults to.
	result->client.auth.scope = kMonitoringReadScope;

	result->project = settings.project.empty() ? credentials.project : settings.project;
	if (result->project.empty()) {
		result->project = TryDiscoverAdcProject();
	}
	if (result->project.empty()) {
		throw InvalidInputException("gcloud alerts: no Google Cloud project configured. Set one on the attachment:\n"
		                            "  ATTACH 'gcloud:' AS gcp (TYPE gcloud, PROJECT 'my-project');\n"
		                            "or store it in a secret:\n"
		                            "  CREATE SECRET (TYPE gcloud, PROJECT 'my-project');");
	}
	return result;
}

static TableFunction MakeAlertsFunction(const char *name) {
	TableFunction function(name, {}, GcloudAlertsScan, nullptr, GcloudAlertsInitGlobal);
	// Only projected columns are materialized, so a count(*) never pays the per-row JSON
	// serialization of resource_labels / user_labels.
	function.projection_pushdown = true;
	function.to_string = GcloudAlertsToString;
	function.get_bind_info = GcloudAlertsGetBindInfo;
	return function;
}

} // namespace

void GetGcloudOpenAlertsSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"incident_id", "policy_id",     "policy_name",     "state",    "summary",
	         "resource_type", "resource_labels", "opened_at", "closed_at"};
	types = {LogicalType::VARCHAR,   LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,   LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,   LogicalType::TIMESTAMP, LogicalType::TIMESTAMP};
	D_ASSERT(names.size() == ALERT_COLUMN_COUNT && types.size() == ALERT_COLUMN_COUNT);
}

void GetGcloudAlertPoliciesSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"policy_id",   "display_name",          "enabled",     "severity",
	         "combiner",    "condition_count",       "notification_channels", "user_labels",
	         "documentation", "created_at",          "updated_at"};
	types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::BOOLEAN,
	         LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::INTEGER,
	         LogicalType::LIST(LogicalType::VARCHAR),    LogicalType::VARCHAR,
	         LogicalType::VARCHAR, LogicalType::TIMESTAMP, LogicalType::TIMESTAMP};
	D_ASSERT(names.size() == POLICY_COLUMN_COUNT && types.size() == POLICY_COLUMN_COUNT);
}

TableFunction GetGcloudOpenAlertsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                           const GcloudAlertsSettings &settings, unique_ptr<FunctionData> &bind_data) {
	bind_data = BindAlertsScan(context, table, secret_name, settings, AlertsKind::OPEN_INCIDENTS);
	return MakeAlertsFunction("gcloud_open_alerts_scan");
}

TableFunction GetGcloudAlertPoliciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                              const string &secret_name, const GcloudAlertsSettings &settings,
                                              unique_ptr<FunctionData> &bind_data) {
	bind_data = BindAlertsScan(context, table, secret_name, settings, AlertsKind::POLICIES);
	return MakeAlertsFunction("gcloud_alert_policies_scan");
}

} // namespace duckdb
