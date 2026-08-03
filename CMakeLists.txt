cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME gcloud_observability)

# OpenSSL (declared in ./vcpkg.json) does double duty in native builds: it is the TLS backend for
# HTTPS *and* the RS256 signer for the service-account JWT assertion (see src/gcloud_auth.cpp). For
# HTTP and JSON we deliberately reuse DuckDB's own bundled, header-accessible libraries so this
# extension pulls in nothing extra. HTTP uses duckdb/third_party/httplib (cpp-httplib, header-only);
# compiling it with CPPHTTPLIB_OPENSSL_SUPPORT selects the duckdb_httplib_openssl namespace, so it
# does not clash with core DuckDB's non-SSL duckdb_httplib symbols. JSON uses
# duckdb/third_party/yyjson, already compiled into libduckdb as duckdb_yyjson.
#
# DuckDB-WASM supplies a browser-backed HTTPUtil, so Emscripten builds intentionally avoid both
# OpenSSL and native sockets. Losing the RS256 signer there also costs the service-account
# credential path, which is why a browser build authenticates with a pre-minted TOKEN only.
if(NOT EMSCRIPTEN)
  find_package(OpenSSL REQUIRED)
endif()

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD
    "17"
    CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Locate DuckDB's bundled third-party headers (httplib + yyjson).
set(GCLOUD_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/duckdb")
if(NOT EXISTS "${GCLOUD_DUCKDB_DIR}/third_party/httplib/httplib.hpp")
  # When built from within the DuckDB tree the submodule may live one level up.
  set(GCLOUD_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../duckdb")
endif()

include_directories(src/include)

set(EXTENSION_SOURCES src/gcloud_observability_extension.cpp src/gcloud_secret.cpp src/gcloud_auth.cpp
                      src/gcloud_client.cpp src/gcloud_json.cpp src/logs_table.cpp
                      src/alerts_table.cpp src/gcloud_catalog.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
  # Bundled yyjson headers (both builds).
  target_include_directories(${target} PRIVATE "${GCLOUD_DUCKDB_DIR}/third_party/yyjson/include")
  if(NOT EMSCRIPTEN)
    # Bundled httplib (header-only), plus cpp-httplib's OpenSSL-enabled (and separately-namespaced)
    # build.
    target_include_directories(${target} PRIVATE "${GCLOUD_DUCKDB_DIR}/third_party/httplib")
    target_compile_definitions(${target} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
    target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto)
  endif()
endforeach()

# Offline C++ test for the pure request-building and response-parsing helpers. Deliberately a C++
# test rather than test-only SQL functions, keeping internals out of the extension's SQL surface.
if(NOT EMSCRIPTEN)
  add_executable(gcloud_json_test EXCLUDE_FROM_ALL test/cpp/gcloud_json_test.cpp src/gcloud_json.cpp)
  target_include_directories(
    gcloud_json_test PRIVATE src/include
                             "${GCLOUD_DUCKDB_DIR}/third_party/yyjson/include")
  # Keep DuckDB before the dummy extension loader: GNU ld resolves static
  # archives left-to-right, and duckdb_static introduces loader references.
  target_link_libraries(gcloud_json_test duckdb_static dummy_static_extension_loader)
  set_target_properties(
    gcloud_json_test PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                "${CMAKE_BINARY_DIR}/extension/gcloud_observability")
endif()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
