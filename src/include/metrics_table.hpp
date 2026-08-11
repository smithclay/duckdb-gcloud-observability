#pragma once
#include "duckdb.hpp"
namespace duckdb {
class ExtensionLoader;
void RegisterGcloudMetricsFunction(ExtensionLoader &loader);
} // namespace duckdb
