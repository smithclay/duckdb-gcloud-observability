#include "gcloud_auth.hpp"
#include "gcloud_json.hpp"
#include "gcloud_topology.hpp"
#include "send_logs.hpp"

#include "duckdb/common/exception.hpp"

#include <cstring>
#include <iostream>
#include <stdexcept>

using namespace duckdb;

static void Require(bool condition, const char *message) {
	if (!condition) {
		throw std::runtime_error(message);
	}
}

static void PutTestVarint(string &out, uint64_t value) {
	while (value >= 0x80) {
		out.push_back(static_cast<char>((value & 0x7f) | 0x80));
		value >>= 7;
	}
	out.push_back(static_cast<char>(value));
}

static void PutTestBytes(string &out, uint32_t field, const string &value) {
	PutTestVarint(out, (static_cast<uint64_t>(field) << 3) | 2);
	PutTestVarint(out, value.size());
	out += value;
}

static string TestStringValue(const string &value) {
	string result;
	PutTestBytes(result, 3, value);
	return result;
}

static string TestDoubleValue(double value) {
	uint64_t bits = 0;
	memcpy(&bits, &value, sizeof(bits));
	string result;
	PutTestVarint(result, (uint64_t(2) << 3) | 1);
	for (idx_t i = 0; i < 8; i++) {
		result.push_back(static_cast<char>((bits >> (8 * i)) & 0xff));
	}
	return result;
}

static void PutTestProperty(string &proto_struct, const string &key, const string &value) {
	string entry;
	PutTestBytes(entry, 1, key);
	PutTestBytes(entry, 2, TestStringValue(value));
	PutTestBytes(proto_struct, 1, entry);
}

static string TestNode(const string &id, const string &display_name, const string &environment) {
	string properties;
	PutTestProperty(properties, "Base/displayName", display_name);
	PutTestProperty(properties, "Base/environment", environment);
	PutTestProperty(properties, "Base/resourceType", "k8s.io/Service");
	string node;
	PutTestBytes(node, 3, properties);
	PutTestBytes(node, 4, id);
	PutTestBytes(node, 5, "Base/Resource");
	PutTestBytes(node, 5, "Base/DiscoveredService");
	PutTestBytes(node, 5, "Base/k8s.io/Service");
	return node;
}

static string TestTopologyResponse() {
	string edge_properties;
	string error_rate_entry;
	PutTestBytes(error_rate_entry, 1, "Observability/errorRate");
	PutTestBytes(error_rate_entry, 2, TestDoubleValue(0.25));
	PutTestBytes(edge_properties, 1, error_rate_entry);

	string edge;
	PutTestBytes(edge, 5, edge_properties);
	PutTestBytes(edge, 6, "//gke/services/checkout");
	PutTestBytes(edge, 7, "//gke/services/payment");
	PutTestBytes(edge, 8, "Observability/SENDS_TRAFFIC");

	string topology;
	PutTestBytes(topology, 1, TestNode("//gke/services/checkout", "checkout", "prod"));
	PutTestBytes(topology, 1, TestNode("//gke/services/payment", "payment", "prod"));
	PutTestBytes(topology, 2, edge);
	string response;
	PutTestBytes(response, 1, topology);
	return response;
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
		Require(TryDiscoverServiceAccountProject("test/fixtures/gcloud_service_account_minimal.json") ==
		            "sender-fixture-project",
		        "an explicit service-account credentials file should supply its own destination project");

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
		Require(origin == "https://logging.googleapis.com" && prefix.empty(), "a trailing slash is not a path prefix");
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
		// App Topology protobuf
		//===------------------------------------------------------------===//
		auto topology_request = BuildGcloudServiceDependenciesRequest("my-project");
		Require(topology_request.find("projects/my-project/locations/global/discoveredResourcesTopology") !=
		            string::npos,
		        "the topology request should be project-scoped");
		Require(topology_request.find("projects/my-project/locations/global/domains/SRE") != string::npos,
		        "service traffic should query the SRE topology domain");
		Require(topology_request.find("Base/DiscoveredService") != string::npos,
		        "the graph endpoints should match discovered services");
		Require(topology_request.find("Observability/SENDS_TRAFFIC") != string::npos,
		        "the graph should request traffic edges rather than scanning spans");

		auto dependencies = ParseGcloudServiceDependenciesResponse(TestTopologyResponse());
		Require(dependencies.size() == 1, "one protobuf topology edge should become one dependency row");
		Require(dependencies[0].source_service == "checkout" && dependencies[0].target_service == "payment",
		        "display names should identify both ends of the dependency");
		Require(dependencies[0].source_type == "k8s.io/Service" && dependencies[0].target_type == "k8s.io/Service",
		        "the most specific node label should become the canonical service type");
		Require(dependencies[0].edge_type == "sends traffic to",
		        "the provider edge label should map to its documented relationship name");
		Require(dependencies[0].environment == "prod", "the source service environment should be retained");
		Require(dependencies[0].source_attributes.find("_app_topology_id") != string::npos,
		        "node attributes should retain the provider resource id");
		Require(dependencies[0].edge_attributes.find("0.25") != string::npos,
		        "traffic relationship properties should be preserved as JSON");
		Require(ParseGcloudServiceDependenciesResponse(string()).empty(),
		        "an empty topology response should produce no dependency rows");

		//===------------------------------------------------------------===//
		// entries.write request (send_gcloud_logs)
		//===------------------------------------------------------------===//
		GcloudWriteLog write_log;
		write_log.project = "my-project";
		write_log.body = "checkout failed";
		write_log.service_name = "checkout";
		write_log.service_namespace = "store";
		write_log.service_instance_id = "checkout-7";
		write_log.severity = "ERROR";
		write_log.trace_id = "0123456789abcdef0123456789abcdef";
		write_log.span_id = "0123456789abcdef";
		write_log.trace_sampled = true;
		write_log.has_timestamp_nanos = true;
		write_log.timestamp_nanos = 123456789;
		write_log.resource_attributes_json =
		    R"({"cloud.resource_id":"run.googleapis.com%2Fstdout","gcp.resource_type":"cloud_run_revision","gcp.label.location":"us-west1"})";
		write_log.log_attributes_json =
		    R"({"log.record.uid":"stable-id","gcp.label.team":"payments","gcp.label.service_name":"must-not-win","attempt":3,"message":"must-not-win"})";
		auto write_body = BuildGcloudWriteBody({write_log});
		Require(write_body.find(R"("partialSuccess":false)") != string::npos,
		        "entries.write should use all-or-error batch semantics");
		Require(write_body.find(R"("logName":"projects/my-project/logs/run.googleapis.com%2Fstdout")") != string::npos,
		        "cloud.resource_id should select the URL-encoded log id under the configured project");
		Require(write_body.find(R"("type":"cloud_run_revision")") != string::npos &&
		            write_body.find(R"("location":"us-west1")") != string::npos,
		        "gcp resource attributes should map to MonitoredResource");
		Require(write_body.find(R"("timestamp":"1970-01-01T00:00:00.123456789Z")") != string::npos,
		        "OTLP nanoseconds should retain all nine fractional digits");
		Require(write_body.find(R"("severity":"ERROR")") != string::npos &&
		            write_body.find(R"("insertId":"stable-id")") != string::npos,
		        "severity and log.record.uid should map to LogEntry fields");
		Require(write_body.find(R"("trace":"0123456789abcdef0123456789abcdef")") != string::npos &&
		            write_body.find(R"("spanId":"0123456789abcdef")") != string::npos &&
		            write_body.find(R"("traceSampled":true)") != string::npos,
		        "trace correlation fields should map without losing the sampled flag");
		Require(write_body.find(R"("team":"payments")") != string::npos &&
		            write_body.find(R"("service_name":"checkout")") != string::npos &&
		            write_body.find(R"("service_namespace":"store")") != string::npos &&
		            write_body.find(R"("service_instance_id":"checkout-7")") != string::npos,
		        "gcp labels and complete service identity should become LogEntry labels");
		Require(write_body.find(R"("message":"checkout failed")") != string::npos &&
		            write_body.find(R"("attempt":3)") != string::npos &&
		            write_body.find("must-not-win") == string::npos,
		        "dedicated body/service fields should win label and payload conflicts");
		Require(EstimateGcloudWriteLogBytes(write_log) > write_log.body.size(),
		        "the batch estimator should include escaping and envelope slack");

		GcloudWriteLog plain_log;
		plain_log.project = "my-project";
		plain_log.body = "plain text";
		plain_log.severity = "INFO";
		plain_log.insert_id = "plain-id";
		plain_log.has_timestamp_nanos = true;
		auto plain_body = BuildGcloudWriteBody({plain_log});
		Require(plain_body.find(R"("logName":"projects/my-project/logs/duckdb")") != string::npos,
		        "the configured project and duckdb log id should form the default log name");
		Require(plain_body.find(R"("textPayload":"plain text")") != string::npos &&
		            plain_body.find("jsonPayload") == string::npos,
		        "a log with no custom attributes should use LogEntry textPayload");

		GcloudWriteLog medium_log = plain_log;
		medium_log.body = string(64 * 1024, 'a');
		auto medium_body = BuildGcloudWriteBody({medium_log});
		Require(medium_body.size() > 64 * 1024,
		        "an ordinary medium ASCII log should serialize instead of being rejected by worst-case escaping");

		bool malformed_attributes_rejected = false;
		try {
			plain_log.log_attributes_json = "not-json";
			BuildGcloudWriteBody({plain_log});
		} catch (const InvalidInputException &) {
			malformed_attributes_rejected = true;
		}
		Require(malformed_attributes_rejected, "malformed non-empty log_attributes must not be silently dropped");
		bool non_object_attributes_rejected = false;
		try {
			plain_log.log_attributes_json.clear();
			plain_log.resource_attributes_json = "[]";
			BuildGcloudWriteBody({plain_log});
		} catch (const InvalidInputException &) {
			non_object_attributes_rejected = true;
		}
		Require(non_object_attributes_rejected, "non-object resource_attributes must not be silently dropped");

		//===------------------------------------------------------------===//
		// Row budget
		//===------------------------------------------------------------===//
		Require(GetGcloudLogsPageSize(1000, 0, 0) == 1000, "an unlimited relation should request the full page size");
		Require(GetGcloudLogsPageSize(1000, 10, 0) == 10, "max_rows should shrink the first request");
		Require(GetGcloudLogsPageSize(1000, 10, 4) == 6, "the last page should not be over-fetched");
		Require(GetGcloudLogsPageSize(1000, 10, 10) == 0, "a covered row budget should stop pagination");
		Require(!GcloudLogsMaxRowsReached(0, 1000000), "max_rows = 0 means unlimited");
		Require(GcloudLogsMaxRowsReached(10, 10), "the cap is reached once max_rows rows are emitted");

		unordered_set<string> seen_page_tokens;
		string page_token;
		Require(AdvanceGcloudPageToken("A", seen_page_tokens, page_token) && page_token == "A",
		        "the first cursor should advance pagination");
		Require(AdvanceGcloudPageToken("B", seen_page_tokens, page_token) && page_token == "B",
		        "a new cursor should advance pagination");
		Require(!AdvanceGcloudPageToken("A", seen_page_tokens, page_token) && page_token == "B",
		        "a non-adjacent cursor cycle should stop without replacing the current cursor");
		Require(!AdvanceGcloudPageToken("", seen_page_tokens, page_token),
		        "an empty cursor should mark pagination exhausted");

		//===------------------------------------------------------------===//
		// Cloud Monitoring paths
		//===------------------------------------------------------------===//
		Require(PercentEncode("state=open") == "state%3Dopen", "reserved characters should be percent-encoded");
		Require(PercentEncode("a-b_c.d~e") == "a-b_c.d~e", "unreserved characters should pass through");
		Require(BuildGcloudOpenAlertsPath("my-project", 100, "") ==
		            "/v3/projects/my-project/alerts?filter=state%3DOPEN&pageSize=100",
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
				{"name":"projects/p/alerts/0.abc123","state":"OPEN","openTime":"2026-07-20T10:00:00Z",
				 "summaryText":"CPU high","resource":{"type":"gce_instance","labels":{"instance_id":"42"}},
				 "metadata":{"systemLabels":{"name":"vm-1","spot":false},"userLabels":{"team":"infra"}},
				 "metric":{"type":"compute.googleapis.com/instance/cpu/utilization","labels":{"zone":"us-west1-a"}},
				 "log":{"extractedLabels":{"request_id":"abc"}},
				 "policy":{"name":"projects/p/alertPolicies/9","displayName":"CPU","severity":"WARNING",
				           "userLabels":{"owner":"platform"}}},
				{"name":"projects/p/alerts/0.def456","state":"CLOSED"}
			],
			"nextPageToken":"next"
		})");
		Require(alerts.alerts.size() == 2, "every returned alert should be parsed");
		Require(alerts.next_page_token == "next", "the cursor should be retained");
		Require(alerts.alerts[0].has_incident_id && alerts.alerts[0].incident_id == "0.abc123",
		        "the incident id should be the last path segment of the resource name");
		Require(alerts.alerts[0].has_alert_name && alerts.alerts[0].alert_name == "projects/p/alerts/0.abc123",
		        "the full v3 alert resource name should be retained");
		Require(alerts.alerts[0].has_policy_name && alerts.alerts[0].policy_name == "CPU",
		        "the policy display name should be parsed");
		Require(alerts.alerts[0].resource_labels == R"({"instance_id":"42"})",
		        "resource labels should be preserved as serialized JSON");
		Require(alerts.alerts[0].resource_system_labels == R"({"name":"vm-1","spot":false})",
		        "system resource metadata should be preserved as serialized JSON");
		Require(alerts.alerts[0].resource_user_labels == R"({"team":"infra"})",
		        "user resource metadata should be preserved as serialized JSON");
		Require(alerts.alerts[0].has_metric_type &&
		            alerts.alerts[0].metric_type == "compute.googleapis.com/instance/cpu/utilization",
		        "the metric type should be parsed");
		Require(alerts.alerts[0].metric_labels == R"({"zone":"us-west1-a"})",
		        "metric labels should be preserved as serialized JSON");
		Require(alerts.alerts[0].log_extracted_labels == R"({"request_id":"abc"})",
		        "log-alert extracted labels should be preserved as serialized JSON");
		Require(alerts.alerts[0].has_policy_severity && alerts.alerts[0].policy_severity == "WARNING",
		        "the policy snapshot severity should be parsed");
		Require(alerts.alerts[0].policy_user_labels == R"({"owner":"platform"})",
		        "policy snapshot labels should be preserved as serialized JSON");
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
