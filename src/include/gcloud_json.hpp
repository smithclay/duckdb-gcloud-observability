#pragma once

//! Pure request-building and response-parsing for the Google Cloud APIs this extension reads.
//! Nothing here touches the network, the catalog, or DuckDB's planner, which is what lets
//! `test/cpp/gcloud_json_test.cpp` exercise it offline without a Google Cloud project.

#include "duckdb.hpp"

namespace duckdb {

//===--------------------------------------------------------------------===//
// Timestamps
//===--------------------------------------------------------------------===//

//! Parse an RFC 3339 timestamp (e.g. "2026-07-09T10:30:45.123456789Z") into nanoseconds since
//! epoch. Cloud Logging timestamps carry up to nanosecond precision, so the microsecond-truncating
//! path is not enough on its own — the parser recovers the last three digits.
bool ParseRfc3339ToNanos(const char *str, int64_t &out_nanos);

//! Format epoch seconds as an RFC 3339 UTC timestamp, the only form the Logging query language
//! accepts in a `timestamp` comparison.
string FormatRfc3339(int64_t epoch_seconds);

//! Format epoch nanoseconds as an RFC 3339 UTC timestamp, keeping the sub-second part when there is
//! one. Both write paths need it and neither may truncate to whole seconds: Cloud Logging preserves
//! a LogEntry timestamp to the nanosecond, and Cloud Monitoring requires consecutive points in one
//! time series to be at least five seconds apart, which is a judgment about the exact end times.
string FormatRfc3339Nanos(int64_t epoch_nanos);

//! Interpret a `start_time`/`end_time` argument. Accepts `now`, a relative offset (`-15m`, `-2h`,
//! `-7d`, `-30s`) resolved against the current time, or an RFC 3339 instant passed through as-is.
//! Throws InvalidInputException on anything else, naming `parameter` in the message.
string ResolveTimeSpec(const string &parameter, const string &spec);

//===--------------------------------------------------------------------===//
// Filter pushdown
//===--------------------------------------------------------------------===//

//! Conservative predicates translated from a DuckDB WHERE clause into Logging query-language terms.
//!
//! Every field here must describe a condition **implied by** the SQL predicate, never one merely
//! correlated with it: the pushed filter has to match a *superset* of the rows the SQL matches, or
//! the scan would silently drop results. DuckDB re-evaluates the original predicate above the scan
//! regardless, so a term that is too broad only costs bandwidth, while one that is too narrow is a
//! correctness bug. Timestamp bounds are therefore rounded *outward* to whole seconds.
struct GcloudFilterPushdown {
	bool has_lower_bound_seconds = false;
	int64_t lower_bound_seconds = 0;
	bool has_upper_bound_seconds = false;
	int64_t upper_bound_seconds = 0;
	//! Cloud Logging LogSeverity enum names from `severity_text = '...'` / `IN (...)`, uppercased and
	//! validated against the fixed nine-value enum. Empty means no severity was pushed.
	vector<string> severities;
	//! Set when the pushed bounds are contradictory (lower > upper), so the scan can return no rows
	//! without issuing a request at all.
	bool empty_result = false;
};

//! True when `name` is one of Cloud Logging's nine LogSeverity enum names (DEFAULT, DEBUG, INFO,
//! NOTICE, WARNING, ERROR, CRITICAL, ALERT, EMERGENCY). `name` must already be uppercased.
bool IsLogSeverityName(const string &name);

//! AND the pushed terms onto `filter` (the filter already resolved at bind time from the user's
//! `filter` plus `start_time`/`end_time`). Returns `filter` unchanged when nothing was pushed.
string ApplyGcloudPushdown(const string &filter, const GcloudFilterPushdown &pushdown);

//! Compose the bind-time filter from the user's `filter` plus any time bounds. The user's filter is
//! parenthesized so a top-level `OR` inside it cannot swallow the time bound.
string BuildGcloudFilter(const string &filter, const string &start_time, const string &end_time);

//===--------------------------------------------------------------------===//
// Endpoints
//===--------------------------------------------------------------------===//

//! Split a base URL into the scheme+host[:port] origin (what httplib's Client takes) and any path
//! prefix, which must be prepended to each request path. A base with no path yields "", and a bare
//! trailing '/' is not treated as a prefix. The prefix is what lets a browser build aim the client
//! at a CORS proxy route ("https://lab.example.com/api/gcloud/logging") instead of Google directly.
void SplitGcloudEndpoint(const string &endpoint, string &origin, string &path_prefix);

//===--------------------------------------------------------------------===//
// entries.list
//===--------------------------------------------------------------------===//

//! Build the JSON body for POST /v2/entries:list. yyjson handles escaping, so a filter containing
//! quotes or backslashes cannot corrupt the request.
string BuildGcloudListBody(const vector<string> &resource_names, const string &filter, const string &order_by,
                           int64_t page_size, const string &page_token);

//! Return the next outgoing page size. A positive `max_rows` reduces the request to the rows the
//! query can still use, so the final page is never over-fetched. Returns 0 once the cap is covered.
int64_t GetGcloudLogsPageSize(int64_t page_size, int64_t max_rows, idx_t rows_accounted);

//! True once a positive `max_rows` cap has been emitted.
bool GcloudLogsMaxRowsReached(int64_t max_rows, idx_t total_emitted);

//! Advance a cursor only when `next_page_token` is non-empty and has not appeared before. Returns
//! false at exhaustion or on any token cycle (including A -> B -> A), preventing unbounded scans.
bool AdvanceGcloudPageToken(const string &next_page_token, unordered_set<string> &seen_page_tokens, string &page_token);

//===--------------------------------------------------------------------===//
// Cloud Monitoring alerts (incidents)
//===--------------------------------------------------------------------===//

//! One incident from the Cloud Monitoring alerts API. Presence flags distinguish a missing/null API
//! field from a legitimate empty value so scans preserve SQL NULL semantics.
struct GcloudAlert {
	bool has_alert_name = false;
	string alert_name;
	bool has_incident_id = false;
	string incident_id;
	bool has_policy_id = false;
	string policy_id;
	bool has_policy_name = false;
	string policy_name;
	bool has_policy_severity = false;
	string policy_severity;
	//! Serialized JSON object, "" when the policy carries no user labels.
	string policy_user_labels;
	bool has_state = false;
	string state;
	bool has_summary = false;
	string summary;
	bool has_resource_type = false;
	string resource_type;
	//! Serialized JSON object, "" when the API sent no labels.
	string resource_labels;
	//! Serialized JSON objects from MonitoredResourceMetadata.
	string resource_system_labels;
	string resource_user_labels;
	bool has_metric_type = false;
	string metric_type;
	string metric_labels;
	string log_extracted_labels;
	bool has_opened_at = false;
	int64_t opened_at_nanos = 0;
	bool has_closed_at = false;
	int64_t closed_at_nanos = 0;
};

struct GcloudAlertsPage {
	vector<GcloudAlert> alerts;
	string next_page_token;
};

//! One Cloud Monitoring alerting policy.
struct GcloudAlertPolicy {
	bool has_policy_id = false;
	string policy_id;
	bool has_display_name = false;
	string display_name;
	bool has_enabled = false;
	bool enabled = false;
	bool has_severity = false;
	string severity;
	bool has_combiner = false;
	string combiner;
	bool has_condition_count = false;
	int64_t condition_count = 0;
	bool has_notification_channels = false;
	vector<string> notification_channels;
	//! Serialized JSON object, "" when the policy carries no user labels.
	string user_labels;
	bool has_documentation = false;
	string documentation;
	bool has_created_at = false;
	int64_t created_at_nanos = 0;
	bool has_updated_at = false;
	int64_t updated_at_nanos = 0;
};

struct GcloudAlertPoliciesPage {
	vector<GcloudAlertPolicy> policies;
	string next_page_token;
};

//! Percent-encode `value` for use in a URL query string (RFC 3986 unreserved set kept as-is).
string PercentEncode(const string &value);

//! Build the path for the open-incident listing:
//!   GET /v3/projects/{project}/alerts?filter=state%3DOPEN&pageSize=N[&pageToken=T]
string BuildGcloudOpenAlertsPath(const string &project, int64_t page_size, const string &page_token);

//! Build the path for the (GA) alerting-policy listing:
//!   GET /v3/projects/{project}/alertPolicies?pageSize=N[&pageToken=T]
string BuildGcloudAlertPoliciesPath(const string &project, int64_t page_size, const string &page_token);

//! Parse one response from the alerts endpoint. Accepts both the lowerCamelCase field names proto3
//! JSON emits by default (`openTime`) and the snake_case spellings the API also honors
//! (`open_time`), since Google's own documentation shows the latter.
GcloudAlertsPage ParseGcloudAlertsPage(const string &response_json);

//! Parse one response from projects.alertPolicies.list.
GcloudAlertPoliciesPage ParseGcloudAlertPoliciesPage(const string &response_json);

} // namespace duckdb
