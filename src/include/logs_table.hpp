#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;
class ClientContext;
class FunctionData;
class TableFunction;
class TableCatalogEntry;

//! Request and scan settings shared by `read_gcloud_logs` and the catalog-backed log table.
//! `max_rows = 0` leaves the relation unlimited. The defaults match the table function's, so an
//! ATTACH that specifies nothing behaves exactly like a bare `read_gcloud_logs(project => ...)`.
struct GcloudLogsSettings {
	//! Cloud Logging query-language filter, ANDed with the time bounds below.
	string filter;
	//! Relative offset (`-15m`), `now`, or an RFC 3339 instant. Empty means unbounded on that side.
	string start_time;
	string end_time;
	string order_by = "timestamp desc";
	int64_t max_rows = 0;     // 0 = unlimited
	int64_t page_size = 1000; // entries per API request
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
};

//! Validate the shared settings, naming the calling interface in the error message. Called before
//! any credential resolution so validation errors never depend on the host's ADC state.
void ValidateGcloudLogsSettings(const GcloudLogsSettings &settings, const string &error_prefix);

//! Register the `read_gcloud_logs(...)` table function.
void RegisterGcloudLogsFunction(ExtensionLoader &loader);

//! The 18-column output schema, matching duckdb-otlp's `read_otlp_logs`.
void GetGcloudLogsSchema(vector<LogicalType> &types, vector<string> &names);

//! Create the already-bound scan for the catalog's `logs.entries` table. Credentials are resolved
//! at table-bind time, matching the alerts tables and preserving secret replacement semantics.
TableFunction GetGcloudLogsTableScan(ClientContext &context, TableCatalogEntry &table, const string &secret_name,
                                     const string &project, const GcloudLogsSettings &settings,
                                     unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
