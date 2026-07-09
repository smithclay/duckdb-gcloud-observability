# duckdb-gcloud-observability

A DuckDB extension for querying **Google Cloud Observability** telemetry as SQL tables. Today it
reads Cloud Logging; the name leaves room for metrics and traces.

`read_gcloud_logs()` queries the [Cloud Logging `entries.list` API][entries-list] and returns rows in
the same flat 18-column OTLP schema as [`duckdb-otlp`][duckdb-otlp]'s `read_otlp_logs`, so logs from
Google Cloud, Splunk, Datadog, and an OTLP collector can be `UNION ALL`-ed together.

```sql
LOAD gcloud_observability;

-- Credentials come from Application Default Credentials. Nothing else to configure.
SELECT time_unix_nano, severity_text, service_name, body
FROM read_gcloud_logs(
    project    => 'my-project',
    filter     => 'severity >= WARNING',
    start_time => '-1h'
)
ORDER BY time_unix_nano DESC
LIMIT 20;
```

## Authentication

The extension mints OAuth2 tokens itself, the way Google's own client libraries do. The usual setup
is the gcloud CLI:

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project my-project
```

That is enough — **no `CREATE SECRET` is required**, and `project` is inferred from the credentials
if you omit it. Credentials are resolved in this order:

1. A `TOKEN` on the secret (a pre-minted access token, e.g. `gcloud auth print-access-token`).
2. A `CREDENTIALS` path on the secret (a service-account key, or an authorized-user JSON file).
3. Application Default Credentials: `$GOOGLE_APPLICATION_CREDENTIALS`, then
   `$CLOUDSDK_CONFIG/application_default_credentials.json`, then
   `$HOME/.config/gcloud/application_default_credentials.json`.

Both `authorized_user` credentials (refresh-token grant) and `service_account` keys (RS256
self-signed JWT assertion) are supported. Tokens are cached in-process and refreshed a minute before
they expire.

The principal needs `roles/logging.viewer` (or `logging.logEntries.list`) on the project.

### Secrets

A secret is only needed to pin a project, point at a non-default endpoint, or supply credentials
explicitly.

```sql
-- Pin a project, still using Application Default Credentials.
CREATE SECRET (TYPE gcloud, PROJECT 'my-project');

-- Use a service-account key, billing quota to another project.
CREATE SECRET (TYPE gcloud,
    PROJECT       'my-project',
    CREDENTIALS   '/path/to/service-account.json',
    QUOTA_PROJECT 'billing-project');

-- Use a token you minted yourself (workload identity federation, impersonation, ...).
CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<access token>');
```

| Secret option     | Default            | Purpose |
|-------------------|--------------------|---------|
| `PROJECT`         | inferred from ADC  | Project whose logs are read |
| `TOKEN`           | –                  | Pre-minted OAuth2 access token; redacted in `duckdb_secrets()` |
| `CREDENTIALS`     | ADC discovery      | Path to a service-account key or authorized-user JSON |
| `QUOTA_PROJECT`   | file's `quota_project_id` | Sent as `x-goog-user-project` |
| `UNIVERSE_DOMAIN` | `googleapis.com`   | Sovereign Cloud / non-standard universes |
| `ENDPOINT`        | derived            | Full API base override, e.g. `https://logging.googleapis.com` |
| `INSECURE_TLS`    | `false`            | Skip TLS verification (test doubles only) |

## `read_gcloud_logs` parameters

| Parameter        | Type           | Default          | Purpose |
|------------------|----------------|------------------|---------|
| `project`        | VARCHAR        | secret, then ADC | Shorthand for `resource_names => ['projects/<project>']` |
| `resource_names` | VARCHAR[]      | –                | Parents to query: `projects/…`, `folders/…`, `organizations/…`, `billingAccounts/…`, or a log view. Wins over `project` |
| `filter`         | VARCHAR        | –                | A [Logging query language][filter] expression |
| `start_time`     | VARCHAR        | –                | `-15m` / `-2h` / `-7d` / `now`, or an RFC 3339 instant. ANDed onto `filter` |
| `end_time`       | VARCHAR        | –                | Same forms as `start_time` |
| `order_by`       | VARCHAR        | `timestamp desc` | Or `timestamp asc` |
| `max_rows`       | BIGINT         | `0` (unlimited)  | Stop after N rows |
| `page_size`      | BIGINT         | `1000`           | Entries per API request (1–1000) |
| `timeout`        | BIGINT         | `60`             | Per-request timeout, seconds |
| `retries`        | BIGINT         | `4`              | Retry budget for 429 / 5xx / transport errors |
| `secret`         | VARCHAR        | first `gcloud` secret | Name of the secret to use |

Bad parameters, a missing secret, and an unresolvable project all fail at **bind** time, before any
network call. The first scan mints the token and pages through the results.

## Mapping to OTLP

`LogEntry` fields map to the OTLP log-record columns, following the OpenTelemetry Collector's
[`googlecloudlogentryencodingextension`][encoding-ext] so attribute keys interoperate with
collector-produced OTLP.

| LogEntry                     | Column / attribute |
|------------------------------|--------------------|
| `timestamp`                  | `time_unix_nano` (nanosecond precision preserved) |
| `receiveTimestamp`           | `observed_time_unix_nano` (falls back to `timestamp`) |
| `severity`                   | `severity_text` + `severity_number` |
| `trace`                      | `trace_id` (the hex id after `/traces/`) |
| `spanId`, `traceSampled`     | `span_id`, `flags` |
| `textPayload` / `jsonPayload` / `protoPayload` | `body` |
| `logName`                    | `gcp.project` (or `gcp.organization` / `gcp.billing_account` / `gcp.folder`) + `cloud.resource_id`, in `resource_attributes` |
| `resource.type`, `resource.labels` | `gcp.resource_type`, `gcp.label.*`, in `resource_attributes` |
| `insertId`                   | `log.record.uid`, in `log_attributes` |
| `labels`                     | `gcp.label.*`, in `log_attributes` |
| `httpRequest`                | `http.*`, `url.full`, `network.*`, `user_agent.original`, `gcp.cache.*` |
| `sourceLocation`             | `code.file.path`, `code.function.name`, `code.line.number` |
| `operation`                  | `gcp.operation.*` |

Severity follows the collector exactly, including two values that are not the obvious neighbours:
`NOTICE` → **10** (`INFO2`) and `EMERGENCY` → **24** (`FATAL4`). Cloud Logging's `LogSeverity` is a
fixed nine-value enum, so above `ERROR` these numbers differ from the sibling `duckdb-splunk` /
`duckdb-datadog` readers, which map *freeform* level strings via the OTel data model's Appendix B
(`critical` 18, `alert` 19, `emergency` 21). The bands agree across all three — `>= 17` is
error-class, `>= 21` is fatal-class — so threshold filters remain portable across a `UNION ALL`.

| Cloud Logging | `severity_number` |
|---|---|
| `DEFAULT` | 0 |
| `DEBUG` | 5 |
| `INFO` | 9 |
| `NOTICE` | 10 |
| `WARNING` | 13 |
| `ERROR` | 17 |
| `CRITICAL` | 21 |
| `ALERT` | 22 |
| `EMERGENCY` | 24 |

`resource_attributes` and `log_attributes` are **VARCHAR columns holding JSON**, not OTLP maps —
this is a flat table. Use DuckDB's JSON functions to reach into them:

```sql
SELECT log_attributes->>'$."http.request.method"' AS method, count(*)
FROM read_gcloud_logs(project => 'my-project', filter => 'httpRequest.status >= 500')
GROUP BY 1;
```

Because `body` is a single string, a structured `jsonPayload` is *also* merged field-by-field into
`log_attributes`, so its fields stay individually queryable without re-parsing `body`.

## Building

Requires the submodules and OpenSSL:

```bash
git submodule update --init --recursive
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3   # macOS/Homebrew
make release      # ./build/release/duckdb + the loadable extension
make test         # offline SQL logic tests; no Google Cloud needed
```

## End-to-end test

Google publishes no Cloud Logging emulator, so the e2e test runs against a real project: it writes a
uniquely-marked entry with `gcloud logging write`, reads it back through `read_gcloud_logs`, and
asserts the OTLP mapping.

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <project>
./test/e2e/run_e2e.sh                  # or GCLOUD_PROJECT=<project> ./test/e2e/run_e2e.sh
```

It needs `roles/logging.logWriter` in addition to `roles/logging.viewer`, and writes to the log name
`duckdb-gcloud-e2e`. An ADC login is all it needs — the script hands the gcloud CLI the ADC token, so
no separate `gcloud auth login` is required.

[entries-list]: https://cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
[filter]: https://cloud.google.com/logging/docs/view/logging-query-language
[encoding-ext]: https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/extension/encoding/googlecloudlogentryencodingextension
[duckdb-otlp]: https://github.com/duckdb/duckdb
