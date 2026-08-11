#define DUCKDB_EXTENSION_MAIN

#include "gcloud_observability_extension.hpp"

#include "gcloud_catalog.hpp"
#include "gcloud_secret.hpp"
#include "logs_table.hpp"
#include "metrics_table.hpp"
#include "send_logs.hpp"
#include "send_metrics.hpp"
#include "service_dependencies_table.hpp"

#include "duckdb.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

static void LoadInternal(ExtensionLoader &loader) {
	// Credentials: CREATE SECRET (TYPE gcloud, PROJECT '...', ...). With no secret at all the
	// reader still works, falling back to Application Default Credentials.
	RegisterGcloudSecretType(loader);
	// Reader: SELECT * FROM read_gcloud_logs(project => '...', filter => '...').
	// Catalog: ATTACH 'gcloud:' AS gcp (TYPE gcloud, PROJECT '...').
	RegisterGcloudCatalog(loader);
	RegisterGcloudLogsFunction(loader);
	RegisterGcloudMetricsFunction(loader);
	// Senders: SELECT send_gcloud_logs(l) FROM logs l, SELECT send_gcloud_metrics(m) FROM metrics m.
	RegisterGcloudSendLogsFunction(loader);
	RegisterGcloudSendMetricsFunction(loader);
	// App Topology: SELECT * FROM read_gcloud_service_dependencies(project => '...').
	RegisterGcloudServiceDependenciesFunction(loader);
}

void GcloudObservabilityExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}
std::string GcloudObservabilityExtension::Name() {
	return "gcloud_observability";
}

std::string GcloudObservabilityExtension::Version() const {
#ifdef EXT_VERSION_GCLOUD_OBSERVABILITY
	return EXT_VERSION_GCLOUD_OBSERVABILITY;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(gcloud_observability, loader) {
	duckdb::LoadInternal(loader);
}
}
