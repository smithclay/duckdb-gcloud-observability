# Browser build. DuckDB-WASM supplies its own HTTPUtil, so this build pulls in neither OpenSSL nor
# native sockets (see CMakeLists.txt and the __EMSCRIPTEN__ branches in src/gcloud_client.cpp and
# src/gcloud_auth.cpp).
#
# Auth in the browser is TOKEN-only: there is no filesystem to discover Application Default
# Credentials on and no OpenSSL to sign a service-account assertion with.
#
#   CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<access token>',
#                  ENDPOINT 'https://<your-proxy>/api/gcloud/logging',
#                  MONITORING_ENDPOINT 'https://<your-proxy>/api/gcloud/monitoring');
duckdb_extension_load(gcloud_observability SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR})
