#include "gcloud_json.hpp"

#include <iostream>
#include <stdexcept>

using namespace duckdb;

static void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

int main() {
	try {
		//===------------------------------------------------------------===//
		// Timestamps
		//===------------------------------------------------------------===//
		int64_t nanos = 0;
		Require(ParseRfc3339ToNanos("1970-01-01T00:00:00Z", nanos) && nanos == 0, "epoch should parse to zero nanos");
		Require(ParseRfc3339ToNanos("2026-07-09T10:30:45.123456789Z", nanos),
		        "a nanosecond-precision timestamp should parse");
		Require(nanos % 1000 == 789, "the sub-microsecond digits must survive the microsecond-truncating path");
		Require(!ParseRfc3339ToNanos("yesterday", nanos), "a non-timestamp should be rejected");
		Require(!ParseRfc3339ToNanos(nullptr, nanos), "a null timestamp should be rejected");

		Require(FormatRfc3339(0) == "1970-01-01T00:00:00Z", "epoch seconds should format as RFC 3339 UTC");

		//===------------------------------------------------------------===//
		// Severity names
		//===------------------------------------------------------------===//
		Require(IsLogSeverityName("EMERGENCY") && IsLogSeverityName("DEFAULT") && IsLogSeverityName("ERROR"),
		        "every LogSeverity enum member should be recognized");
		Require(!IsLogSeverityName("error"), "IsLogSeverityName expects an already-uppercased name");
		Require(!IsLogSeverityName("FATAL"), "FATAL is not a Cloud Logging severity");

		//===------------------------------------------------------------===//
		// Filter composition
		//===------------------------------------------------------------===//
		Require(BuildGcloudFilter("", "", "").empty(), "an unconstrained request should send no filter");
		// A top-level OR in the user's filter must not swallow the time bound.
		auto filter = BuildGcloudFilter("severity=ERROR OR severity=ALERT", "2026-07-01T00:00:00Z", "");
		Require(filter == "(severity=ERROR OR severity=ALERT) AND timestamp >= \"2026-07-01T00:00:00Z\"",
		        "the user filter should be parenthesized before time bounds are ANDed on");

		GcloudFilterPushdown pushdown;
		Require(ApplyGcloudPushdown("logName=\"x\"", pushdown) == "(logName=\"x\")",
		        "an empty pushdown should leave the bind-time filter semantically unchanged");

		pushdown.has_lower_bound_seconds = true;
		pushdown.lower_bound_seconds = 0;
		pushdown.has_upper_bound_seconds = true;
		pushdown.upper_bound_seconds = 60;
		Require(ApplyGcloudPushdown("", pushdown) ==
		            "timestamp >= \"1970-01-01T00:00:00Z\" AND timestamp <= \"1970-01-01T00:01:00Z\"",
		        "pushed time bounds should become Logging query-language timestamp comparisons");

		pushdown.severities.push_back("ERROR");
		Require(ApplyGcloudPushdown("", pushdown).find("severity = \"ERROR\"") != string::npos,
		        "a single pushed severity should become a bare equality");
		pushdown.severities.push_back("CRITICAL");
		Require(ApplyGcloudPushdown("", pushdown).find("(severity = \"ERROR\" OR severity = \"CRITICAL\")") !=
		            string::npos,
		        "multiple pushed severities should become a parenthesized OR so the AND-chain is not broken");

		//===------------------------------------------------------------===//
		// Endpoint splitting (the CORS-proxy seam for browser builds)
		//===------------------------------------------------------------===//
		string origin, prefix;
		SplitGcloudEndpoint("https://logging.googleapis.com", origin, prefix);
		Require(origin == "https://logging.googleapis.com" && prefix.empty(),
		        "a bare API host should yield no path prefix");
		SplitGcloudEndpoint("https://logging.googleapis.com/", origin, prefix);
		Require(origin == "https://logging.googleapis.com" && prefix.empty(),
		        "a trailing slash is not a path prefix");
		SplitGcloudEndpoint("https://lab.example.com/api/gcloud/logging", origin, prefix);
		Require(origin == "https://lab.example.com" && prefix == "/api/gcloud/logging",
		        "a proxy route should split into origin and prefix so request paths append to it");
		SplitGcloudEndpoint("http://localhost:8080/proxy", origin, prefix);
		Require(origin == "http://localhost:8080" && prefix == "/proxy",
		        "an explicit port must stay with the origin, not start the path");

		//===------------------------------------------------------------===//
		// entries.list request body
		//===------------------------------------------------------------===//
		auto body = BuildGcloudListBody({"projects/p"}, "severity = \"ERROR\"", "timestamp desc", 500, "");
		Require(body.find("\"resourceNames\":[\"projects/p\"]") != string::npos, "resource names should be sent");
		Require(body.find("\"pageSize\":500") != string::npos, "the page size should be sent");
		Require(body.find("\"pageToken\"") == string::npos, "an empty cursor should omit pageToken entirely");
		// yyjson escapes the embedded quotes, so a filter cannot corrupt the request.
		Require(body.find("severity = \\\"ERROR\\\"") != string::npos, "filter quotes should be JSON-escaped");
		Require(BuildGcloudListBody({"projects/p"}, "", "timestamp asc", 1, "abc").find("\"pageToken\":\"abc\"") !=
		            string::npos,
		        "a non-empty cursor should be sent as pageToken");

		//===------------------------------------------------------------===//
		// Row budget
		//===------------------------------------------------------------===//
		Require(GetGcloudLogsPageSize(1000, 0, 0) == 1000, "an unlimited relation should request the full page size");
		Require(GetGcloudLogsPageSize(1000, 10, 0) == 10, "max_rows should shrink the first request");
		Require(GetGcloudLogsPageSize(1000, 10, 4) == 6, "the last page should not be over-fetched");
		Require(GetGcloudLogsPageSize(1000, 10, 10) == 0, "a covered row budget should stop pagination");
		Require(!GcloudLogsMaxRowsReached(0, 1000000), "max_rows = 0 means unlimited");
		Require(GcloudLogsMaxRowsReached(10, 10), "the cap is reached once max_rows rows are emitted");

		//===------------------------------------------------------------===//
		// Cloud Monitoring paths
		//===------------------------------------------------------------===//
		Require(PercentEncode("state=open") == "state%3Dopen", "reserved characters should be percent-encoded");
		Require(PercentEncode("a-b_c.d~e") == "a-b_c.d~e", "unreserved characters should pass through");
		Require(BuildGcloudOpenAlertsPath("my-project", 100, "") ==
		            "/v3/projects/my-project/alerts?filter=state%3Dopen&pageSize=100",
		        "the incident listing should filter server-side to open alerts");
		Require(BuildGcloudOpenAlertsPath("p", 50, "tok/en").find("&pageToken=tok%2Fen") != string::npos,
		        "a page token must be percent-encoded into the query string");
		Require(BuildGcloudAlertPoliciesPath("my-project", 100, "") ==
		            "/v3/projects/my-project/alertPolicies?pageSize=100",
		        "the policy listing takes no filter");

		//===------------------------------------------------------------===//
		// Cloud Monitoring responses
		//===------------------------------------------------------------===//
		auto alerts = ParseGcloudAlertsPage(R"({
			"alerts":[
				{"name":"projects/p/alerts/0.abc123","state":"open","openTime":"2026-07-20T10:00:00Z",
				 "summaryText":"CPU high","resource":{"type":"gce_instance","labels":{"instance_id":"42"}},
				 "policy":{"name":"projects/p/alertPolicies/9","displayName":"CPU"}},
				{"name":"projects/p/alerts/0.def456","state":"closed"}
			],
			"nextPageToken":"next"
		})");
		Require(alerts.alerts.size() == 2, "every returned alert should be parsed");
		Require(alerts.next_page_token == "next", "the cursor should be retained");
		Require(alerts.alerts[0].has_incident_id && alerts.alerts[0].incident_id == "0.abc123",
		        "the incident id should be the last path segment of the resource name");
		Require(alerts.alerts[0].has_policy_name && alerts.alerts[0].policy_name == "CPU",
		        "the policy display name should be parsed");
		Require(alerts.alerts[0].resource_labels == R"({"instance_id":"42"})",
		        "resource labels should be preserved as serialized JSON");
		Require(alerts.alerts[0].has_opened_at, "openTime should parse");
		Require(!alerts.alerts[0].has_closed_at, "a missing closeTime should preserve SQL NULL semantics");
		Require(alerts.alerts[1].resource_labels.empty(),
		        "an absent label map should stay empty rather than becoming \"{}\"");

		// Google's own docs for this endpoint show snake_case, while proto3 JSON emits lowerCamelCase.
		auto snake = ParseGcloudAlertsPage(
		    R"({"alerts":[{"name":"projects/p/alerts/1","open_time":"2026-07-20T10:00:00Z","summary_text":"s"}]})");
		Require(snake.alerts[0].has_opened_at, "the snake_case open_time spelling should also parse");
		Require(snake.alerts[0].has_summary && snake.alerts[0].summary == "s",
		        "the snake_case summary_text spelling should also parse");
		Require(ParseGcloudAlertsPage(R"({})").alerts.empty(), "a response with no alerts array should be empty");

		auto policies = ParseGcloudAlertPoliciesPage(R"({
			"alertPolicies":[
				{"name":"projects/p/alertPolicies/9","displayName":"CPU","enabled":true,"severity":"WARNING",
				 "combiner":"OR","conditions":[{"name":"c1"},{"name":"c2"}],
				 "notificationChannels":["projects/p/notificationChannels/1"],
				 "userLabels":{"team":"infra"},"documentation":{"content":"runbook"},
				 "creationRecord":{"mutateTime":"2026-01-01T00:00:00Z"},
				 "mutationRecord":{"mutateTime":"2026-06-01T00:00:00Z"}},
				{"name":"projects/p/alertPolicies/10","enabled":false}
			]
		})");
		Require(policies.policies.size() == 2, "every returned policy should be parsed");
		Require(policies.policies[0].has_condition_count && policies.policies[0].condition_count == 2,
		        "the condition count should come from the conditions array length");
		Require(policies.policies[0].notification_channels.size() == 1, "notification channels should be a list");
		Require(policies.policies[0].user_labels == R"({"team":"infra"})",
		        "user labels should be preserved as serialized JSON");
		Require(policies.policies[0].has_documentation && policies.policies[0].documentation == "runbook",
		        "documentation content should be flattened to a column");
		Require(policies.policies[0].has_created_at && policies.policies[0].has_updated_at,
		        "creation and mutation records should supply the timestamps");
		Require(policies.policies[1].has_enabled && !policies.policies[1].enabled,
		        "a false `enabled` must stay distinguishable from a missing one");
		Require(!policies.policies[1].has_severity, "an absent severity should preserve SQL NULL semantics");
		Require(!policies.policies[1].has_condition_count, "an absent conditions array should not report a count");

		bool malformed_rejected = false;
		try {
			ParseGcloudAlertsPage("not json");
		} catch (const IOException &) {
			malformed_rejected = true;
		}
		Require(malformed_rejected, "a non-JSON response should be rejected");
	} catch (const std::exception &error) {
		std::cerr << "gcloud_json_test failed: " << error.what() << std::endl;
		return 1;
	}
	return 0;
}
