#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ClientContext;
class ExtensionLoader;
class FunctionData;
class TableCatalogEntry;
class TableFunction;

struct GcloudServiceMapSettings {
	string project;
	string endpoint;
	int64_t retries = 4;
	int64_t timeout_seconds = 60;
	int64_t max_rows = 0;
};

void RegisterGcloudServiceDependenciesFunction(ExtensionLoader &loader);
void GetGcloudServiceDependenciesSchema(vector<LogicalType> &types, vector<string> &names);
void ValidateGcloudServiceMapSettings(const GcloudServiceMapSettings &settings, const string &error_prefix);
TableFunction GetGcloudServiceDependenciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                                    const string &secret_name, const GcloudServiceMapSettings &settings,
                                                    unique_ptr<FunctionData> &bind_data);

} // namespace duckdb
