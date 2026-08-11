#pragma once

#include "duckdb.hpp"

namespace duckdb {

class ExtensionLoader;

//! One Cloud Monitoring TimeSeries point assembled from an OTLP-shaped DuckDB row.
//!
//! Labels are resolved (and their keys normalized) while the input chunk is mapped, not while the
//! request is built, for two reasons: a malformed attribute object must fail before any batch is
//! sent, and the batcher needs the same resolved identity the request will carry in order to keep
//! one series out of a request twice.
struct GcloudWriteMetric {
	string project;
	//! Fully-qualified metric type, e.g. "custom.googleapis.com/obsbench/http.server.request.count".
	string metric_type;
	//! Input-only on create; becomes the auto-created MetricDescriptor's description.
	string description;
	string unit;
	//! GAUGE (the default), CUMULATIVE, or DELTA.
	string metric_kind = "GAUGE";
	bool is_integer = false;
	int64_t integer_value = 0;
	double double_value = 0;
	int64_t end_time_nanos = 0;
	bool has_start_time_nanos = false;
	int64_t start_time_nanos = 0;
	//! Monitored resource type; "global" when the row names none.
	string resource_type;
	//! Sorted by key, so a series identity has one spelling.
	vector<pair<string, string>> metric_labels;
	vector<pair<string, string>> resource_labels;
};

//! Build one timeSeries.create request body. Every element becomes a TimeSeries carrying exactly
//! one point, which is all the API accepts. The caller must have ensured no two elements name the
//! same series (see GcloudMetricSeriesKey).
string BuildGcloudTimeSeriesBody(const GcloudWriteMetric *metrics, idx_t count);
inline string BuildGcloudTimeSeriesBody(const vector<GcloudWriteMetric> &metrics) {
	return BuildGcloudTimeSeriesBody(metrics.data(), metrics.size());
}

//! Identity of the time series a point belongs to: metric type + metric labels + monitored
//! resource. Cloud Monitoring rejects a request containing two points for one series, so the
//! batcher uses this to spread them across consecutive requests.
string GcloudMetricSeriesKey(const GcloudWriteMetric &metric);

//! Qualify a metric name into a Cloud Monitoring metric type. A name that already carries a
//! Google metric domain ("workload.googleapis.com/foo") is kept verbatim; anything else is placed
//! under `custom.googleapis.com/`. Throws InvalidInputException when the result is not a legal
//! metric type (illegal character, empty or non-alphanumeric-initial path element, over 200 bytes).
string NormalizeGcloudMetricType(const string &name);

//! Normalize an attribute key into a Cloud Monitoring label key: a leading `gcp.label.` is stripped
//! (as in `send_gcloud_logs`) and the rest is lower-cased. Throws InvalidInputException when the
//! result is not a legal label key, which must start with a letter and hold only lower-case
//! letters, digits, underscores, and dots.
string NormalizeGcloudMetricLabelKey(const string &key);

//! Register `send_gcloud_metrics(struct [, secret])`. The first argument is normally a whole row
//! from an OTLP-shaped metrics relation. Recognized fields are mapped by name; unknown fields are
//! ignored.
void RegisterGcloudSendMetricsFunction(ExtensionLoader &loader);

} // namespace duckdb
