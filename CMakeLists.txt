cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME gcloud_observability)

# OpenSSL (declared in ./vcpkg.json) does double duty here: it is the TLS backend for HTTPS *and*
# the RS256 signer for the service-account JWT assertion (see src/gcloud_auth.cpp). For HTTP and
# JSON we deliberately reuse DuckDB's own bundled, header-accessible libraries so this extension
# pulls in nothing extra. HTTP uses duckdb/third_party/httplib (cpp-httplib, header-only);
# compiling it with CPPHTTPLIB_OPENSSL_SUPPORT selects the duckdb_httplib_openssl namespace, so it
# does not clash with core DuckDB's non-SSL duckdb_httplib symbols. JSON uses
# duckdb/third_party/yyjson, already compiled into libduckdb as duckdb_yyjson.
find_package(OpenSSL REQUIRED)

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
                      src/gcloud_client.cpp src/logs_table.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
  # Bundled httplib (header-only) + yyjson headers.
  target_include_directories(
    ${target} PRIVATE "${GCLOUD_DUCKDB_DIR}/third_party/httplib"
                      "${GCLOUD_DUCKDB_DIR}/third_party/yyjson/include")
  # Select cpp-httplib's OpenSSL-enabled (and separately-namespaced) build.
  target_compile_definitions(${target} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
  target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto)
endforeach()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
