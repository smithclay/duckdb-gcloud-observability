PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Configuration of extension
EXT_NAME=gcloud_observability
EXT_CONFIG=${PROJ_DIR}extension_config.cmake

# Include the Makefile from extension-ci-tools
include extension-ci-tools/makefiles/duckdb_extension.Makefile

.PHONY: test_gcloud_json
test: test_gcloud_json

test_gcloud_json: release
	cmake --build build/release --config Release --target gcloud_json_test
	./build/release/extension/gcloud_observability/gcloud_json_test
