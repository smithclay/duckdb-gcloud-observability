#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ClientContext;
class FunctionData;
class TableCatalogEntry;
class TableFunction;

//! Shared request settings for the two catalog-backed alert tables.
struct GcloudAlertsSettings {
	string project;
	int64_t page_size = 100;
	int64_t max_rows = 0; // 0 = unlimited
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
};

//! Schema for `alerts.open` — currently-open incidents from the Cloud Monitoring alerts API.
void GetGcloudOpenAlertsSchema(vector<LogicalType> &types, vector<string> &names);

//! Schema for `alerts.policies` — alerting policies from projects.alertPolicies.list.
void GetGcloudAlertPoliciesSchema(vector<LogicalType> &types, vector<string> &names);

//! Create the already-bound scan for `alerts.open`. Credentials are resolved at table bind time,
//! matching the catalog log table and preserving secret replacement semantics.
TableFunction GetGcloudOpenAlertsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                           const GcloudAlertsSettings &settings, unique_ptr<FunctionData> &bind_data);

//! Create the already-bound scan for `alerts.policies`.
TableFunction GetGcloudAlertPoliciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                              const string &secret_name, const GcloudAlertsSettings &settings,
                                              unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
