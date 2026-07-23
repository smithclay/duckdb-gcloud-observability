#pragma once

namespace duckdb {

class ExtensionLoader;

//! Register the `gcloud` storage extension used by ATTACH 'gcloud:' ... (TYPE gcloud).
void RegisterGcloudCatalog(ExtensionLoader &loader);

} // namespace duckdb
