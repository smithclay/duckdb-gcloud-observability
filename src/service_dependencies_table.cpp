#include "service_dependencies_table.hpp"

#include "gcloud_auth.hpp"
#include "gcloud_client.hpp"
#include "gcloud_secret.hpp"
#include "gcloud_topology.hpp"

#include "duckdb/catalog/catalog_entry/table_catalog_entry.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

#include <deque>

namespace duckdb {
namespace {

static constexpr const char *kAppTopologyApiName = "App Topology";
static constexpr const char *kGenerateTopologyMethod =
    "/google.cloud.apptopology.v1alpha.AppTopology/GenerateDiscoveredResourcesTopology";
static constexpr idx_t COLUMN_COUNT = 17;

struct GcloudServiceDependenciesBindData : public TableFunctionData {
	GcloudServiceMapSettings settings;
	TableCatalogEntry *table = nullptr;
	GcloudClient client;
};

struct GcloudServiceDependenciesGlobalState : public GlobalTableFunctionState {
	vector<column_t> column_ids;
	std::deque<GcloudServiceDependency> rows;
	bool loaded = false;

	idx_t MaxThreads() const override {
		return 1;
	}
};

static string ResolveProject(const GcloudServiceMapSettings &settings, const GcloudCredentials &credentials) {
	auto project = settings.project.empty() ? credentials.project : settings.project;
	if (project.empty()) {
		project = TryDiscoverAdcProject();
	}
	if (project.empty()) {
		throw InvalidInputException(
		    "gcloud service map: no Google Cloud project configured. Pass project => 'my-project', set PROJECT "
		    "on the attachment, or store PROJECT in a gcloud secret");
	}
	return project;
}

static void ConfigureClient(ClientContext &context, GcloudServiceDependenciesBindData &bind,
                            const string &secret_name) {
	auto credentials = GetGcloudCredentials(context, secret_name);
	bind.settings.project = ResolveProject(bind.settings, credentials);
	if (!bind.settings.endpoint.empty()) {
		credentials.app_topology_endpoint = bind.settings.endpoint;
	}
	bind.client.endpoint = GcloudAppTopologyEndpoint(credentials);
	bind.client.retries = static_cast<uint64_t>(bind.settings.retries);
	bind.client.timeout_seconds = static_cast<uint64_t>(bind.settings.timeout_seconds);
	bind.client.insecure_tls = credentials.insecure_tls;
	bind.client.auth.token = credentials.token;
	bind.client.auth.credentials_file = credentials.credentials_file;
	bind.client.auth.quota_project = credentials.quota_project;
	bind.client.auth.scope = kCloudPlatformScope;
	bind.client.auth.insecure_tls = credentials.insecure_tls;
	bind.client.auth.timeout_seconds = bind.client.timeout_seconds;
	bind.client.send_quota_project = false;
}

static unique_ptr<FunctionData> GcloudServiceDependenciesBind(ClientContext &context, TableFunctionBindInput &input,
                                                              vector<LogicalType> &return_types,
                                                              vector<string> &names) {
	auto result = make_uniq<GcloudServiceDependenciesBindData>();
	string secret_name;
	for (const auto &parameter : input.named_parameters) {
		if (parameter.second.IsNull()) {
			continue;
		}
		auto key = StringUtil::Lower(parameter.first);
		if (key == "project") {
			result->settings.project = parameter.second.GetValue<string>();
		} else if (key == "secret") {
			secret_name = parameter.second.GetValue<string>();
		} else if (key == "app_topology_endpoint") {
			result->settings.endpoint = parameter.second.GetValue<string>();
		} else if (key == "retries") {
			result->settings.retries = parameter.second.GetValue<int64_t>();
		} else if (key == "timeout") {
			result->settings.timeout_seconds = parameter.second.GetValue<int64_t>();
		} else if (key == "max_rows") {
			result->settings.max_rows = parameter.second.GetValue<int64_t>();
		}
	}
	ValidateGcloudServiceMapSettings(result->settings, "read_gcloud_service_dependencies");
	ConfigureClient(context, *result, secret_name);
	GetGcloudServiceDependenciesSchema(return_types, names);
	return std::move(result);
}

static unique_ptr<GlobalTableFunctionState> GcloudServiceDependenciesInit(ClientContext &,
                                                                          TableFunctionInitInput &input) {
	auto state = make_uniq<GcloudServiceDependenciesGlobalState>();
	state->column_ids = input.column_ids;
	return std::move(state);
}

static Value OptionalString(const string &value) {
	return value.empty() ? Value() : Value(value);
}

static Value DependencyValue(const GcloudServiceDependency &dependency, column_t column) {
	switch (column) {
	case 0:
		return Value("gcloud");
	case 1:
		return OptionalString(dependency.source_service);
	case 2:
		return OptionalString(dependency.target_service);
	case 3:
		return OptionalString(dependency.source_type);
	case 4:
		return OptionalString(dependency.target_type);
	case 5:
		return OptionalString(dependency.edge_type);
	case 6:
		return OptionalString(dependency.environment);
	case 14:
		return OptionalString(dependency.source_attributes);
	case 15:
		return OptionalString(dependency.target_attributes);
	case 16:
		return OptionalString(dependency.edge_attributes);
	default:
		// App Topology returns a current graph with relationship attributes, not a user-selected
		// aggregation window or request/error/fault/throttle counters. Those canonical fields stay
		// SQL NULL instead of inventing statistics from the underlying traces.
		return Value();
	}
}

static void LoadDependencies(ClientContext &context, const GcloudServiceDependenciesBindData &bind,
                             GcloudServiceDependenciesGlobalState &state) {
	auto request = BuildGcloudServiceDependenciesRequest(bind.settings.project);
	auto response = bind.client.GrpcUnary(context, kGenerateTopologyMethod, request, kAppTopologyApiName);
	auto dependencies = ParseGcloudServiceDependenciesResponse(response);
	auto limit = bind.settings.max_rows > 0
	                 ? MinValue<idx_t>(dependencies.size(), static_cast<idx_t>(bind.settings.max_rows))
	                 : dependencies.size();
	for (idx_t i = 0; i < limit; i++) {
		state.rows.push_back(std::move(dependencies[i]));
	}
	state.loaded = true;
}

static void GcloudServiceDependenciesScan(ClientContext &context, TableFunctionInput &input, DataChunk &output) {
	auto &bind = input.bind_data->Cast<GcloudServiceDependenciesBindData>();
	auto &state = input.global_state->Cast<GcloudServiceDependenciesGlobalState>();
	if (!state.loaded) {
		LoadDependencies(context, bind, state);
	}
	idx_t count = 0;
	while (count < STANDARD_VECTOR_SIZE && !state.rows.empty()) {
		auto &dependency = state.rows.front();
		for (idx_t output_column = 0; output_column < state.column_ids.size(); output_column++) {
			output.SetValue(output_column, count, DependencyValue(dependency, state.column_ids[output_column]));
		}
		state.rows.pop_front();
		count++;
	}
	output.SetCardinality(count);
}

static InsertionOrderPreservingMap<string> GcloudServiceDependenciesToString(TableFunctionToStringInput &input) {
	InsertionOrderPreservingMap<string> result;
	auto &bind = input.bind_data->Cast<GcloudServiceDependenciesBindData>();
	result["Function"] = input.table_function.name;
	result["Google Cloud Project"] = bind.settings.project;
	result["Google Cloud Endpoint"] = bind.client.endpoint;
	result["App Topology Domain"] = "SRE";
	result["App Topology Edge"] = "Observability/SENDS_TRAFFIC";
	result["Google Cloud Max Rows"] = std::to_string(bind.settings.max_rows);
	result["Google Cloud Retries"] = std::to_string(bind.settings.retries);
	result["Google Cloud Timeout"] = std::to_string(bind.settings.timeout_seconds);
	return result;
}

static BindInfo GcloudServiceDependenciesGetBindInfo(const optional_ptr<FunctionData> bind_data) {
	auto &data = bind_data->Cast<GcloudServiceDependenciesBindData>();
	D_ASSERT(data.table);
	return BindInfo(*data.table);
}

static TableFunction MakeServiceDependenciesFunction(const char *name, table_function_bind_t bind) {
	TableFunction function(name, {}, GcloudServiceDependenciesScan, bind, GcloudServiceDependenciesInit);
	function.projection_pushdown = true;
	function.to_string = GcloudServiceDependenciesToString;
	return function;
}

} // namespace

void ValidateGcloudServiceMapSettings(const GcloudServiceMapSettings &settings, const string &error_prefix) {
	if (settings.retries < 0 || settings.retries > 100) {
		throw InvalidInputException("%s: retries must be between 0 and 100", error_prefix);
	}
	if (settings.timeout_seconds < 1) {
		throw InvalidInputException("%s: timeout must be >= 1 second", error_prefix);
	}
	if (settings.max_rows < 0) {
		throw InvalidInputException("%s: max_rows must be >= 0", error_prefix);
	}
}

void GetGcloudServiceDependenciesSchema(vector<LogicalType> &types, vector<string> &names) {
	names = {"provider",          "source_service",
	         "target_service",    "source_type",
	         "target_type",       "edge_type",
	         "environment",       "window_start",
	         "window_end",        "request_count",
	         "error_count",       "fault_count",
	         "throttle_count",    "total_response_time_seconds",
	         "source_attributes", "target_attributes",
	         "edge_attributes"};
	types = {LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR,      LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::TIMESTAMP_NS,
	         LogicalType::TIMESTAMP_NS, LogicalType::BIGINT,  LogicalType::BIGINT,  LogicalType::BIGINT,
	         LogicalType::BIGINT,       LogicalType::DOUBLE,  LogicalType::VARCHAR, LogicalType::VARCHAR,
	         LogicalType::VARCHAR};
	D_ASSERT(names.size() == COLUMN_COUNT && types.size() == COLUMN_COUNT);
}

void RegisterGcloudServiceDependenciesFunction(ExtensionLoader &loader) {
	auto function = MakeServiceDependenciesFunction("read_gcloud_service_dependencies", GcloudServiceDependenciesBind);
	function.named_parameters["project"] = LogicalType::VARCHAR;
	function.named_parameters["secret"] = LogicalType::VARCHAR;
	function.named_parameters["app_topology_endpoint"] = LogicalType::VARCHAR;
	function.named_parameters["retries"] = LogicalType::BIGINT;
	function.named_parameters["timeout"] = LogicalType::BIGINT;
	function.named_parameters["max_rows"] = LogicalType::BIGINT;
	loader.RegisterFunction(function);
}

TableFunction GetGcloudServiceDependenciesTableScan(ClientContext &context, TableCatalogEntry &table,
                                                    const string &secret_name, const GcloudServiceMapSettings &settings,
                                                    unique_ptr<FunctionData> &bind_data) {
	auto result = make_uniq<GcloudServiceDependenciesBindData>();
	result->settings = settings;
	result->table = &table;
	ValidateGcloudServiceMapSettings(result->settings, "gcloud service map catalog");
	ConfigureClient(context, *result, secret_name);
	bind_data = std::move(result);
	auto function = MakeServiceDependenciesFunction("gcloud_service_dependencies_scan", nullptr);
	function.get_bind_info = GcloudServiceDependenciesGetBindInfo;
	return function;
}

} // namespace duckdb
