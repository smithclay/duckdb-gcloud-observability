#pragma once

//! Shared yyjson plumbing: RAII owners plus the small typed accessors and builders that every
//! Google API reader in this extension needs. Header-only and `inline` so `gcloud_json.cpp`,
//! `logs_table.cpp`, and `alerts_table.cpp` each get one copy without a link-time clash.
//!
//! This uses DuckDB's bundled yyjson (`duckdb_yyjson`), so nothing extra is pulled in.

#include "duckdb.hpp"

#include "yyjson.hpp"

#include <cstdlib>
#include <initializer_list>
#include <memory>

namespace duckdb {

//===--------------------------------------------------------------------===//
// RAII helpers — free docs/buffers on every path (incl. exceptions)
//===--------------------------------------------------------------------===//

struct YyjsonDocDeleter {
	void operator()(duckdb_yyjson::yyjson_doc *doc) const {
		duckdb_yyjson::yyjson_doc_free(doc);
	}
};
struct YyjsonMutDocDeleter {
	void operator()(duckdb_yyjson::yyjson_mut_doc *doc) const {
		duckdb_yyjson::yyjson_mut_doc_free(doc);
	}
};
struct YyjsonFreeDeleter {
	void operator()(char *ptr) const {
		free(ptr);
	}
};
using YyjsonDocPtr = std::unique_ptr<duckdb_yyjson::yyjson_doc, YyjsonDocDeleter>;
using YyjsonMutDocPtr = std::unique_ptr<duckdb_yyjson::yyjson_mut_doc, YyjsonMutDocDeleter>;
using YyjsonStrPtr = std::unique_ptr<char, YyjsonFreeDeleter>;

//===--------------------------------------------------------------------===//
// Typed read accessors
//===--------------------------------------------------------------------===//

inline const char *GcloudGetStr(duckdb_yyjson::yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	auto *v = duckdb_yyjson::yyjson_obj_get(obj, key);
	return (v && duckdb_yyjson::yyjson_is_str(v)) ? duckdb_yyjson::yyjson_get_str(v) : nullptr;
}

//! Return the object at `key`, or nullptr when absent or not an object.
inline duckdb_yyjson::yyjson_val *GcloudGetObj(duckdb_yyjson::yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	auto *v = duckdb_yyjson::yyjson_obj_get(obj, key);
	return (v && duckdb_yyjson::yyjson_is_obj(v)) ? v : nullptr;
}

//! Return the array at `key`, or nullptr when absent or not an array.
inline duckdb_yyjson::yyjson_val *GcloudGetArr(duckdb_yyjson::yyjson_val *obj, const char *key) {
	if (!obj) {
		return nullptr;
	}
	auto *v = duckdb_yyjson::yyjson_obj_get(obj, key);
	return (v && duckdb_yyjson::yyjson_is_arr(v)) ? v : nullptr;
}

//! Return the object at `camel`, falling back to `snake`. Google's proto3 JSON emits lowerCamelCase
//! by default but also accepts (and documents) the snake_case spelling, so readers accept both.
inline duckdb_yyjson::yyjson_val *GcloudLookupObj(duckdb_yyjson::yyjson_val *obj, const char *camel,
                                                  const char *snake) {
	if (auto *v = GcloudGetObj(obj, camel)) {
		return v;
	}
	return GcloudGetObj(obj, snake);
}

//! Array counterpart of GcloudLookupObj.
inline duckdb_yyjson::yyjson_val *GcloudLookupArr(duckdb_yyjson::yyjson_val *obj, const char *camel,
                                                  const char *snake) {
	if (auto *v = GcloudGetArr(obj, camel)) {
		return v;
	}
	return GcloudGetArr(obj, snake);
}

//! Look up a string under any of `keys`, checking each source object in priority order. Returns the
//! first match, or nullptr.
inline const char *GcloudLookupStr(std::initializer_list<duckdb_yyjson::yyjson_val *> sources,
                                   std::initializer_list<const char *> keys) {
	for (auto *source : sources) {
		for (const char *key : keys) {
			if (const char *v = GcloudGetStr(source, key)) {
				return v;
			}
		}
	}
	return nullptr;
}

//! Google encodes int64 fields as JSON *strings* (proto3 JSON mapping) but int32 fields as numbers,
//! so `status` arrives as 200 while `requestSize` arrives as "1234". Accept either.
inline bool GcloudGetInt64Flexible(duckdb_yyjson::yyjson_val *obj, const char *key, int64_t &out) {
	if (!obj) {
		return false;
	}
	auto *v = duckdb_yyjson::yyjson_obj_get(obj, key);
	if (!v) {
		return false;
	}
	if (duckdb_yyjson::yyjson_is_int(v)) {
		out = duckdb_yyjson::yyjson_get_sint(v);
		return true;
	}
	if (duckdb_yyjson::yyjson_is_num(v)) {
		out = static_cast<int64_t>(duckdb_yyjson::yyjson_get_num(v));
		return true;
	}
	if (duckdb_yyjson::yyjson_is_str(v)) {
		const char *str = duckdb_yyjson::yyjson_get_str(v);
		char *end = nullptr;
		long long parsed = std::strtoll(str, &end, 10);
		if (end && end != str && *end == '\0') {
			out = static_cast<int64_t>(parsed);
			return true;
		}
	}
	return false;
}

inline bool GcloudGetBool(duckdb_yyjson::yyjson_val *obj, const char *key, bool &out) {
	if (!obj) {
		return false;
	}
	auto *v = duckdb_yyjson::yyjson_obj_get(obj, key);
	if (v && duckdb_yyjson::yyjson_is_bool(v)) {
		out = duckdb_yyjson::yyjson_get_bool(v);
		return true;
	}
	return false;
}

//===--------------------------------------------------------------------===//
// Mutable-JSON builders
//===--------------------------------------------------------------------===//

//! Both key and value are copied into `doc`, so callers may pass transient strings.
inline void GcloudPutStr(duckdb_yyjson::yyjson_mut_doc *doc, duckdb_yyjson::yyjson_mut_val *root, const char *key,
                         const char *value) {
	if (!key || !value || !*value) {
		return;
	}
	duckdb_yyjson::yyjson_mut_obj_add(root, duckdb_yyjson::yyjson_mut_strcpy(doc, key),
	                                  duckdb_yyjson::yyjson_mut_strcpy(doc, value));
}

inline void GcloudPutInt(duckdb_yyjson::yyjson_mut_doc *doc, duckdb_yyjson::yyjson_mut_val *root, const char *key,
                         int64_t value) {
	duckdb_yyjson::yyjson_mut_obj_add(root, duckdb_yyjson::yyjson_mut_strcpy(doc, key),
	                                  duckdb_yyjson::yyjson_mut_sint(doc, value));
}

inline void GcloudPutBool(duckdb_yyjson::yyjson_mut_doc *doc, duckdb_yyjson::yyjson_mut_val *root, const char *key,
                          bool value) {
	duckdb_yyjson::yyjson_mut_obj_add(root, duckdb_yyjson::yyjson_mut_strcpy(doc, key),
	                                  duckdb_yyjson::yyjson_mut_bool(doc, value));
}

inline void GcloudPutDouble(duckdb_yyjson::yyjson_mut_doc *doc, duckdb_yyjson::yyjson_mut_val *root, const char *key,
                            double value) {
	duckdb_yyjson::yyjson_mut_obj_add(root, duckdb_yyjson::yyjson_mut_strcpy(doc, key),
	                                  duckdb_yyjson::yyjson_mut_real(doc, value));
}

//! Serialize a mutable doc, returning "" when the object ended up empty (so the column stays NULL
//! rather than holding a useless "{}").
inline string GcloudWriteIfAny(duckdb_yyjson::yyjson_mut_doc *doc, duckdb_yyjson::yyjson_mut_val *root) {
	if (duckdb_yyjson::yyjson_mut_obj_size(root) == 0) {
		return string();
	}
	YyjsonStrPtr json(duckdb_yyjson::yyjson_mut_write(doc, 0, nullptr));
	return json ? string(json.get()) : string();
}

//! Serialize an arbitrary JSON value back to compact text.
inline string GcloudWriteValue(duckdb_yyjson::yyjson_val *value) {
	if (!value) {
		return string();
	}
	YyjsonStrPtr json(duckdb_yyjson::yyjson_val_write(value, 0, nullptr));
	return json ? string(json.get()) : string();
}

} // namespace duckdb
