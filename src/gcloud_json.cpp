#include "gcloud_json.hpp"

#include "gcloud_yyjson.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/date.hpp"
#include "duckdb/common/types/time.hpp"
#include "duckdb/common/types/timestamp.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>

using namespace duckdb_yyjson; // NOLINT

namespace duckdb {

//===--------------------------------------------------------------------===//
// Timestamps
//===--------------------------------------------------------------------===//

bool ParseRfc3339ToNanos(const char *str, int64_t &out_nanos) {
	if (!str) {
		return false;
	}
	idx_t len = strlen(str);

	timestamp_t ts;
	bool has_offset = false;
	string_t tz;
	int32_t sub_micro_nanos = 0;
	auto result = Timestamp::TryConvertTimestampTZ(str, len, ts, /*use_offset=*/true, has_offset, tz, &sub_micro_nanos);
	if (result != TimestampCastResult::SUCCESS) {
		// Fall back to the strict (offset-less) nanosecond parser.
		timestamp_ns_t ts_ns;
		if (Timestamp::TryConvertTimestamp(str, len, ts_ns) != TimestampCastResult::SUCCESS) {
			return false;
		}
		out_nanos = ts_ns.value;
		return true;
	}

	int64_t epoch_nanos;
	if (!Timestamp::TryGetEpochNanoSeconds(ts, epoch_nanos)) {
		return false;
	}
	out_nanos = epoch_nanos + sub_micro_nanos;
	return true;
}

string FormatRfc3339(int64_t epoch_seconds) {
	// DuckDB's own conversion instead of gmtime_r/strftime: gmtime_r does not exist on MSVC.
	date_t date;
	dtime_t time;
	Timestamp::Convert(Timestamp::FromEpochSeconds(epoch_seconds), date, time);
	int32_t year, month, day;
	Date::Convert(date, year, month, day);
	int32_t hour, minute, second, micros;
	Time::Convert(time, hour, minute, second, micros);
	return StringUtil::Format("%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second);
}

string FormatRfc3339Nanos(int64_t epoch_nanos) {
	auto seconds = epoch_nanos / 1000000000;
	auto fraction = epoch_nanos % 1000000000;
	// C++ truncates division toward zero, so a pre-epoch instant lands one second late with a
	// negative remainder. Borrow a second to bring the fraction back into [0, 1e9).
	if (fraction < 0) {
		fraction += 1000000000;
		seconds--;
	}
	auto base = FormatRfc3339(seconds);
	if (fraction == 0) {
		return base;
	}
	base.pop_back(); // the 'Z', re-appended after the fractional digits
	return base + StringUtil::Format(".%09lldZ", static_cast<long long>(fraction));
}

string ResolveTimeSpec(const string &parameter, const string &spec) {
	string trimmed = spec;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		return string();
	}

	auto now =
	    std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
	if (StringUtil::CIEquals(trimmed, "now")) {
		return FormatRfc3339(now);
	}
	if (trimmed[0] == '-') {
		char unit = trimmed.back();
		auto digits = trimmed.substr(1, trimmed.size() - 2);
		int64_t multiplier = 0;
		switch (unit) {
		case 's':
			multiplier = 1;
			break;
		case 'm':
			multiplier = 60;
			break;
		case 'h':
			multiplier = 3600;
			break;
		case 'd':
			multiplier = 86400;
			break;
		default:
			multiplier = 0;
		}
		char *end = nullptr;
		long long amount = digits.empty() ? -1 : std::strtoll(digits.c_str(), &end, 10);
		if (multiplier > 0 && amount >= 0 && end && *end == '\0') {
			return FormatRfc3339(now - static_cast<int64_t>(amount) * multiplier);
		}
		throw InvalidInputException("read_gcloud_logs: %s '%s' is not a valid relative offset; expected a number and "
		                            "one of s/m/h/d, e.g. '-15m'",
		                            parameter, spec);
	}
	// Absolute: require something that at least looks like RFC 3339 so a typo fails here rather
	// than as an opaque INVALID_ARGUMENT from the API.
	int64_t nanos;
	if (!ParseRfc3339ToNanos(trimmed.c_str(), nanos)) {
		throw InvalidInputException("read_gcloud_logs: %s '%s' is neither a relative offset (e.g. '-15m') nor an "
		                            "RFC 3339 timestamp (e.g. '2026-07-09T00:00:00Z')",
		                            parameter, spec);
	}
	return trimmed;
}

//===--------------------------------------------------------------------===//
// Filter pushdown
//===--------------------------------------------------------------------===//

bool IsLogSeverityName(const string &name) {
	// Cloud Logging's LogSeverity is a fixed nine-value enum, not a freeform level string.
	static const char *const kNames[] = {"DEFAULT", "DEBUG",    "INFO",  "NOTICE",   "WARNING",
	                                     "ERROR",   "CRITICAL", "ALERT", "EMERGENCY"};
	for (const char *candidate : kNames) {
		if (name == candidate) {
			return true;
		}
	}
	return false;
}

string BuildGcloudFilter(const string &filter, const string &start_time, const string &end_time) {
	vector<string> clauses;
	string trimmed_filter = filter;
	StringUtil::Trim(trimmed_filter);
	if (!trimmed_filter.empty()) {
		clauses.push_back("(" + trimmed_filter + ")");
	}
	if (!start_time.empty()) {
		clauses.push_back("timestamp >= \"" + ResolveTimeSpec("start_time", start_time) + "\"");
	}
	if (!end_time.empty()) {
		clauses.push_back("timestamp <= \"" + ResolveTimeSpec("end_time", end_time) + "\"");
	}
	return StringUtil::Join(clauses, " AND ");
}

string ApplyGcloudPushdown(const string &filter, const GcloudFilterPushdown &pushdown) {
	vector<string> clauses;
	string trimmed = filter;
	StringUtil::Trim(trimmed);
	if (!trimmed.empty()) {
		// Wrap the bind-time filter whole: it is already an AND-chain, but parenthesizing costs
		// nothing and keeps this correct no matter how that string is later composed.
		clauses.push_back("(" + trimmed + ")");
	}
	if (pushdown.has_lower_bound_seconds) {
		clauses.push_back("timestamp >= \"" + FormatRfc3339(pushdown.lower_bound_seconds) + "\"");
	}
	if (pushdown.has_upper_bound_seconds) {
		clauses.push_back("timestamp <= \"" + FormatRfc3339(pushdown.upper_bound_seconds) + "\"");
	}
	if (!pushdown.severities.empty()) {
		vector<string> terms;
		for (const auto &severity : pushdown.severities) {
			terms.push_back("severity = \"" + severity + "\"");
		}
		clauses.push_back(terms.size() == 1 ? terms[0] : "(" + StringUtil::Join(terms, " OR ") + ")");
	}
	return StringUtil::Join(clauses, " AND ");
}

//===--------------------------------------------------------------------===//
// Endpoints
//===--------------------------------------------------------------------===//

void SplitGcloudEndpoint(const string &endpoint, string &origin, string &path_prefix) {
	auto scheme_end = endpoint.find("://");
	auto host_start = (scheme_end == string::npos) ? 0 : scheme_end + 3;
	auto path_start = endpoint.find('/', host_start);
	if (path_start == string::npos) {
		origin = endpoint;
		path_prefix = string();
		return;
	}
	origin = endpoint.substr(0, path_start);
	path_prefix = endpoint.substr(path_start);
	// A bare trailing '/' is not a prefix; keeping it would double the separator in every path.
	while (!path_prefix.empty() && path_prefix.back() == '/') {
		path_prefix.pop_back();
	}
}

//===--------------------------------------------------------------------===//
// entries.list
//===--------------------------------------------------------------------===//

string BuildGcloudListBody(const vector<string> &resource_names, const string &filter, const string &order_by,
                           int64_t page_size, const string &page_token) {
	YyjsonMutDocPtr doc(yyjson_mut_doc_new(nullptr));
	yyjson_mut_val *root = yyjson_mut_obj(doc.get());
	yyjson_mut_doc_set_root(doc.get(), root);

	yyjson_mut_val *names = yyjson_mut_arr(doc.get());
	for (const auto &name : resource_names) {
		yyjson_mut_arr_add_strcpy(doc.get(), names, name.c_str());
	}
	yyjson_mut_obj_add(root, yyjson_mut_strcpy(doc.get(), "resourceNames"), names);

	if (!filter.empty()) {
		GcloudPutStr(doc.get(), root, "filter", filter.c_str());
	}
	GcloudPutStr(doc.get(), root, "orderBy", order_by.c_str());
	GcloudPutInt(doc.get(), root, "pageSize", page_size);
	if (!page_token.empty()) {
		GcloudPutStr(doc.get(), root, "pageToken", page_token.c_str());
	}

	YyjsonStrPtr json(yyjson_mut_write(doc.get(), 0, nullptr));
	if (!json) {
		throw InternalException("read_gcloud_logs: could not serialize the entries.list request body");
	}
	return string(json.get());
}

int64_t GetGcloudLogsPageSize(int64_t page_size, int64_t max_rows, idx_t rows_accounted) {
	if (max_rows <= 0) {
		return page_size;
	}
	if (rows_accounted >= static_cast<idx_t>(max_rows)) {
		return 0;
	}
	auto remaining = static_cast<int64_t>(static_cast<idx_t>(max_rows) - rows_accounted);
	return MinValue<int64_t>(page_size, remaining);
}

bool GcloudLogsMaxRowsReached(int64_t max_rows, idx_t total_emitted) {
	return max_rows > 0 && total_emitted >= static_cast<idx_t>(max_rows);
}

bool AdvanceGcloudPageToken(const string &next_page_token, unordered_set<string> &seen_page_tokens,
                            string &page_token) {
	if (next_page_token.empty() || !seen_page_tokens.insert(next_page_token).second) {
		return false;
	}
	page_token = next_page_token;
	return true;
}

//===--------------------------------------------------------------------===//
// Cloud Monitoring alerts
//===--------------------------------------------------------------------===//

string PercentEncode(const string &value) {
	static const char *const kHex = "0123456789ABCDEF";
	string out;
	out.reserve(value.size());
	for (char ch : value) {
		auto c = static_cast<unsigned char>(ch);
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
		    c == '.' || c == '~') {
			out += ch;
		} else {
			out += '%';
			out += kHex[c >> 4];
			out += kHex[c & 0x0F];
		}
	}
	return out;
}

//! Shared shape for both listing endpoints: /v3/projects/{project}/{collection}?pageSize=...
static string BuildAlertsPath(const string &project, const char *collection, const string &query_filter,
                              int64_t page_size, const string &page_token) {
	string path = "/v3/projects/" + PercentEncode(project) + "/" + collection;
	vector<string> params;
	if (!query_filter.empty()) {
		params.push_back("filter=" + PercentEncode(query_filter));
	}
	params.push_back("pageSize=" + std::to_string(page_size));
	if (!page_token.empty()) {
		params.push_back("pageToken=" + PercentEncode(page_token));
	}
	return path + "?" + StringUtil::Join(params, "&");
}

string BuildGcloudOpenAlertsPath(const string &project, int64_t page_size, const string &page_token) {
	return BuildAlertsPath(project, "alerts", "state=OPEN", page_size, page_token);
}

string BuildGcloudAlertPoliciesPath(const string &project, int64_t page_size, const string &page_token) {
	return BuildAlertsPath(project, "alertPolicies", string(), page_size, page_token);
}

//! Parse the document root, rejecting anything that is not a JSON object.
static yyjson_val *ReadRoot(const string &response_json, YyjsonDocPtr &doc, const char *what) {
	doc.reset(yyjson_read(response_json.c_str(), response_json.size(), 0));
	if (!doc) {
		throw IOException("Cloud Monitoring API returned a non-JSON response for %s", what);
	}
	yyjson_val *root = yyjson_doc_get_root(doc.get());
	if (!root || !yyjson_is_obj(root)) {
		throw IOException("Cloud Monitoring API returned an unexpected response shape for %s", what);
	}
	return root;
}

//! Read an RFC 3339 field, accepting both the lowerCamelCase name proto3 JSON emits and the
//! snake_case spelling Google's own documentation shows for this endpoint.
static bool ReadTimestampField(yyjson_val *obj, const char *camel, const char *snake, int64_t &out_nanos) {
	const char *raw = GcloudLookupStr({obj}, {camel, snake});
	return raw && ParseRfc3339ToNanos(raw, out_nanos);
}

//! Last path segment of a resource name ("projects/p/alerts/abc" -> "abc").
static string LastPathSegment(const string &resource_name) {
	auto slash = resource_name.rfind('/');
	return slash == string::npos ? resource_name : resource_name.substr(slash + 1);
}

GcloudAlertsPage ParseGcloudAlertsPage(const string &response_json) {
	YyjsonDocPtr doc;
	yyjson_val *root = ReadRoot(response_json, doc, "the incident list");

	GcloudAlertsPage page;
	yyjson_val *alerts = GcloudGetArr(root, "alerts");
	if (alerts) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(alerts, idx, max, item) {
			if (!yyjson_is_obj(item)) {
				continue;
			}
			GcloudAlert alert;
			if (const char *name = GcloudGetStr(item, "name")) {
				alert.has_alert_name = true;
				alert.alert_name = name;
				alert.has_incident_id = true;
				alert.incident_id = LastPathSegment(string(name));
			}
			if (const char *state = GcloudGetStr(item, "state")) {
				alert.has_state = true;
				alert.state = state;
			}
			if (const char *summary = GcloudLookupStr({item}, {"summaryText", "summary_text"})) {
				alert.has_summary = true;
				alert.summary = summary;
			}
			if (yyjson_val *policy = GcloudGetObj(item, "policy")) {
				if (const char *policy_id = GcloudGetStr(policy, "name")) {
					alert.has_policy_id = true;
					alert.policy_id = policy_id;
				}
				if (const char *policy_name = GcloudLookupStr({policy}, {"displayName", "display_name"})) {
					alert.has_policy_name = true;
					alert.policy_name = policy_name;
				}
				if (const char *severity = GcloudGetStr(policy, "severity")) {
					alert.has_policy_severity = true;
					alert.policy_severity = severity;
				}
				if (yyjson_val *labels = GcloudLookupObj(policy, "userLabels", "user_labels")) {
					alert.policy_user_labels = GcloudWriteValue(labels);
				}
			}
			if (yyjson_val *resource = GcloudGetObj(item, "resource")) {
				if (const char *type = GcloudGetStr(resource, "type")) {
					alert.has_resource_type = true;
					alert.resource_type = type;
				}
				if (yyjson_val *labels = GcloudGetObj(resource, "labels")) {
					alert.resource_labels = GcloudWriteValue(labels);
				}
			}
			if (yyjson_val *metadata = GcloudGetObj(item, "metadata")) {
				if (yyjson_val *labels = GcloudLookupObj(metadata, "systemLabels", "system_labels")) {
					alert.resource_system_labels = GcloudWriteValue(labels);
				}
				if (yyjson_val *labels = GcloudLookupObj(metadata, "userLabels", "user_labels")) {
					alert.resource_user_labels = GcloudWriteValue(labels);
				}
			}
			if (yyjson_val *metric = GcloudGetObj(item, "metric")) {
				if (const char *type = GcloudGetStr(metric, "type")) {
					alert.has_metric_type = true;
					alert.metric_type = type;
				}
				if (yyjson_val *labels = GcloudGetObj(metric, "labels")) {
					alert.metric_labels = GcloudWriteValue(labels);
				}
			}
			if (yyjson_val *log = GcloudGetObj(item, "log")) {
				if (yyjson_val *labels = GcloudLookupObj(log, "extractedLabels", "extracted_labels")) {
					alert.log_extracted_labels = GcloudWriteValue(labels);
				}
			}
			alert.has_opened_at = ReadTimestampField(item, "openTime", "open_time", alert.opened_at_nanos);
			alert.has_closed_at = ReadTimestampField(item, "closeTime", "close_time", alert.closed_at_nanos);
			page.alerts.push_back(std::move(alert));
		}
	}
	if (const char *next = GcloudLookupStr({root}, {"nextPageToken", "next_page_token"})) {
		page.next_page_token = next;
	}
	return page;
}

GcloudAlertPoliciesPage ParseGcloudAlertPoliciesPage(const string &response_json) {
	YyjsonDocPtr doc;
	yyjson_val *root = ReadRoot(response_json, doc, "the alerting-policy list");

	GcloudAlertPoliciesPage page;
	yyjson_val *policies = GcloudGetArr(root, "alertPolicies");
	if (policies) {
		size_t idx, max;
		yyjson_val *item;
		yyjson_arr_foreach(policies, idx, max, item) {
			if (!yyjson_is_obj(item)) {
				continue;
			}
			GcloudAlertPolicy policy;
			if (const char *name = GcloudGetStr(item, "name")) {
				policy.has_policy_id = true;
				policy.policy_id = name;
			}
			if (const char *display_name = GcloudLookupStr({item}, {"displayName", "display_name"})) {
				policy.has_display_name = true;
				policy.display_name = display_name;
			}
			policy.has_enabled = GcloudGetBool(item, "enabled", policy.enabled);
			if (const char *severity = GcloudGetStr(item, "severity")) {
				policy.has_severity = true;
				policy.severity = severity;
			}
			if (const char *combiner = GcloudGetStr(item, "combiner")) {
				policy.has_combiner = true;
				policy.combiner = combiner;
			}
			if (yyjson_val *conditions = GcloudGetArr(item, "conditions")) {
				policy.has_condition_count = true;
				policy.condition_count = static_cast<int64_t>(yyjson_arr_size(conditions));
			}
			if (yyjson_val *channels = GcloudLookupArr(item, "notificationChannels", "notification_channels")) {
				policy.has_notification_channels = true;
				size_t channel_idx, channel_max;
				yyjson_val *channel;
				yyjson_arr_foreach(channels, channel_idx, channel_max, channel) {
					if (yyjson_is_str(channel)) {
						policy.notification_channels.emplace_back(yyjson_get_str(channel));
					}
				}
			}
			if (yyjson_val *labels = GcloudLookupObj(item, "userLabels", "user_labels")) {
				policy.user_labels = GcloudWriteValue(labels);
			}
			if (yyjson_val *documentation = GcloudGetObj(item, "documentation")) {
				if (const char *content = GcloudGetStr(documentation, "content")) {
					policy.has_documentation = true;
					policy.documentation = content;
				}
			}
			if (yyjson_val *record = GcloudLookupObj(item, "creationRecord", "creation_record")) {
				policy.has_created_at =
				    ReadTimestampField(record, "mutateTime", "mutate_time", policy.created_at_nanos);
			}
			if (yyjson_val *record = GcloudLookupObj(item, "mutationRecord", "mutation_record")) {
				policy.has_updated_at =
				    ReadTimestampField(record, "mutateTime", "mutate_time", policy.updated_at_nanos);
			}
			page.policies.push_back(std::move(policy));
		}
	}
	if (const char *next = GcloudLookupStr({root}, {"nextPageToken", "next_page_token"})) {
		page.next_page_token = next;
	}
	return page;
}

} // namespace duckdb
