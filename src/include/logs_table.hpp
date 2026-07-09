#pragma once

namespace duckdb {
class ExtensionLoader;

//! Register the `read_gcloud_logs` table function.
void RegisterGcloudLogsFunction(ExtensionLoader &loader);

} // namespace duckdb
