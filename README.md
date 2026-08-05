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

The principal needs `roles/logging.viewer` (or `logging.logEntries.list`) for log queries and
`roles/monitoring.viewer` for the alert tables.

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
| `ENDPOINT`        | derived            | Cloud Logging API base override, e.g. `https://logging.googleapis.com` |
| `MONITORING_ENDPOINT` | derived        | Cloud Monitoring API base override (the alert tables) |
| `INSECURE_TLS`    | `false`            | Skip TLS verification (test doubles only) |

`ENDPOINT` and `MONITORING_ENDPOINT` are separate because the two APIs live on different hosts, so
one override cannot stand in for both.

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

## Filter pushdown

A small, conservative subset of the SQL `WHERE` clause is translated into the Logging query language
and sent with the request, so the API returns less data. DuckDB still evaluates the original `WHERE`
above the scan, so results are always exactly what the SQL says.

| SQL predicate | Sent to Cloud Logging |
|---|---|
| `time_unix_nano >= / > / <= / < / = <ts>` | `timestamp >= "..."` / `timestamp <= "..."`, rounded **outward** to whole seconds |
| `time_unix_nano BETWEEN a AND b` | both bounds (the optimizer folds `>=`/`<=` into a BETWEEN before pushdown runs) |
| `severity_text = 'ERROR'` | `severity = "ERROR"` |
| `severity_text IN ('ERROR','CRITICAL')` | `(severity = "ERROR" OR severity = "CRITICAL")` |

Only predicates whose translation matches a **superset** of the SQL match are pushed. A term that is
too broad merely costs bandwidth; one that is too narrow would silently drop rows.

Deliberately **not** pushed:

- **`service_name`** — unlike the sibling `duckdb-datadog`, where the column maps to one API field,
  here it is derived by falling back across `resource.labels.service_name`, several `jsonPayload`
  keys, `labels`, and `resource.labels.{function_name,container_name,job}`. Any single filter term
  would match strictly fewer rows and drop legitimate GKE / Cloud Functions results.
- **`trace_id`** — the mapping accepts both `projects/P/traces/ID` and a bare id.
- **`OR` branches** — pushing one branch alone would drop rows matching only the other. Only the
  conjuncts of a top-level `AND` are considered.
- **anything, when `max_rows > 0`** — the cap applies to rows as they arrive from the API, before the
  SQL `WHERE` runs. Narrowing the request would change which rows compete for that budget, so
  `max_rows => 1 WHERE severity_text = 'ERROR'` would mean something different with pushdown than
  without. Matches `duckdb-datadog`.

`EXPLAIN` shows exactly what was pushed:

```sql
EXPLAIN SELECT body FROM read_gcloud_logs(project => 'my-project')
WHERE severity_text = 'ERROR'
  AND time_unix_nano >= TIMESTAMP_NS '2026-07-20 10:00:00';
--   Google Cloud Filter: timestamp >= "2026-07-20T10:00:00Z" AND severity = "ERROR"
```

## Catalog (`ATTACH`)

`ATTACH 'gcloud:'` exposes the project as a read-only database, so log entries and Cloud Monitoring
alerts are ordinary tables that joins, views, and BI tools can reach without naming a table function.

```sql
ATTACH 'gcloud:' AS gcp (TYPE gcloud, PROJECT 'my-project', START_TIME '-1h', MAX_ROWS 1000);

SELECT severity_text, count(*) FROM gcp.logs.entries GROUP BY 1 ORDER BY 2 DESC;

SELECT policy_name, policy_severity, metric_type, opened_at
FROM gcp.alerts.open
ORDER BY opened_at DESC;
```

| Table | Source | Notes |
|---|---|---|
| `logs.entries` | `entries.list` | The same 18 columns as `read_gcloud_logs`, and the same pushdown |
| `alerts.open` | `projects.alerts.list`, filtered to `state=OPEN` | Currently-open incidents and their resource, metric, log, and policy metadata |
| `alerts.policies` | `projects.alertPolicies.list` | Alerting policy configuration (GA) |

ATTACH options: `SECRET`, `PROJECT`, `FILTER`, `START_TIME`, `END_TIME`, `ORDER_BY`, `PAGE_SIZE`,
`MAX_ROWS`, `RETRIES`, `TIMEOUT`. They are validated by the same code as the table function's
parameters, so the two interfaces cannot drift. The log settings apply to `logs.entries`;
`MAX_ROWS`, `RETRIES`, and `TIMEOUT` also apply to the alert tables.

The secret is resolved at attach time (so a bad name fails immediately) but only its *name* is
retained, so a later `CREATE OR REPLACE SECRET` is picked up on the next query.

### Alert metadata

- **`alerts.policies`** reads [`projects.alertPolicies.list`][policies].
- **`alerts.open`** reads the documented [`projects.alerts.list`][alerts-list] v3 endpoint with the
  server-side filter `state=OPEN`. Google currently exposes the matching CLI command under
  `gcloud beta monitoring alerts list`, so consumers that require only long-stable surfaces should
  account for that CLI/API maturity signal.

The first nine `alerts.open` columns are retained from the extension's original Preview-era reader.
The appended columns expose the full documented Alert resource: `alert_name`, policy severity and
labels, resource system/user labels, metric type/labels, and log-extracted labels. JSON maps remain
`VARCHAR` so their original structure and unknown keys are preserved. `summary` remains for older
responses that include `summaryText`; it can be `NULL` because it is not part of the current REST
resource schema. The reader accepts both lowerCamelCase and snake_case proto JSON spellings.

Both tables need the `monitoring.read` scope, which is requested separately from `logging.read`, so
a logs-only query never asks for monitoring authority.

[policies]: https://cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.alertPolicies/list
[alerts-list]: https://cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.alerts/list

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

## DuckDB-WASM (browser)

The extension builds for WASM (`make wasm_mvp` / `wasm_eh` / `wasm_threads`, using
`extension_config_wasm.cmake`). Two things differ from a native build, and both are hard
constraints rather than choices.

**Authentication is `TOKEN`-only.** A browser has no filesystem to discover Application Default
Credentials on and no OpenSSL to sign a service-account assertion with — and here OpenSSL is not
just the TLS backend, it is the RS256 signer. That removes both of the native credential paths and
leaves the one that needs neither:

```sql
CREATE SECRET (TYPE gcloud, PROJECT 'my-project', TOKEN '<gcloud auth print-access-token>');
```

Google access tokens expire after about an hour, so a browser session should refresh the secret
rather than hold one indefinitely; expiry surfaces as HTTP 401. (This is a sharper constraint than
the sibling `duckdb-datadog` / `duckdb-splunk` extensions face: their credential is a static API key,
so their auth works in a browser unchanged.)

**Requests must go through a CORS proxy.** Google's APIs send no `Access-Control-Allow-Origin`, so a
page cannot call them directly. Point the endpoints at your proxy's routes:

```sql
CREATE SECRET (TYPE gcloud,
    PROJECT             'my-project',
    TOKEN               '<access token>',
    ENDPOINT            'https://your-proxy.example.com/api/gcloud/logging',
    MONITORING_ENDPOINT 'https://your-proxy.example.com/api/gcloud/monitoring');
```

An endpoint may carry a path prefix, which is preserved ahead of the request path — so the route
above becomes `POST /api/gcloud/logging/v2/entries:list`. The proxy needs to:

- forward `/api/gcloud/logging/*` to `https://logging.googleapis.com/*` (POST) and
  `/api/gcloud/monitoring/*` to `https://monitoring.googleapis.com/*` (GET), query string included;
- allow the **`Authorization`** and **`x-goog-user-project`** request headers in
  `Access-Control-Allow-Headers` — without the latter, end-user credentials fail with
  `USER_PROJECT_DENIED`;
- answer `OPTIONS` preflight, and allow both `GET` and `POST`.

`~/workspace/duckdb-tero`'s `wasm-query-lab/worker/` is a working Cloudflare Worker of exactly this
shape (it proxies Tero and Datadog); adding two `gcloud` routes to it is the quickest path to a
browser demo.

Retry and TLS are the browser's job in this build: DuckDB-WASM's `HTTPUtil` issues the request
through `fetch()`, so the native retry loop, keep-alive connection, and 401 re-mint are compiled
out (there is nothing to re-mint — the token is static).

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
