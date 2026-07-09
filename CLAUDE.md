# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A DuckDB extension (`read_gcloud_logs` table function + `gcloud` secret type) that queries logs from
the Google Cloud Logging API (`entries.list`) and returns rows in the flat 18-column `duckdb-otlp`
`read_otlp_logs` schema. It was ported from the sibling reference extensions at
`~/workspace/duckdb-splunk` and `~/workspace/duckdb-datadog` — when a pattern here is unclear, those
repos are the canonical templates for extension structure, the secret pattern, retry/backoff, RAII
yyjson helpers, and projection pushdown.

## Build / test

Requires the git submodules (`duckdb`, `extension-ci-tools`) — `git submodule update --init --recursive`.

This repo builds against **system OpenSSL via Homebrew, not vcpkg** (vcpkg is declared in
`vcpkg.json` for CI but is not installed locally). You must pass `OPENSSL_ROOT_DIR` or the build
won't find OpenSSL:

```bash
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
make            # == make release; builds ./build/release/duckdb + the loadable extension (first build compiles DuckDB from source, ~10 min)
make test       # runs the offline SQL logic tests (test/sql/*.test); fully offline, no GCP needed
```

Incremental rebuilds after editing `src/` are fast (~15s) since DuckDB itself is cached. There is no
"run a single test" flag for the SQL logic tests — there is one `.test` file
(`test/sql/gcloud_observability.test`); add cases to it. Its `require gcloud_observability` line
loads the just-built loadable extension.

Artifacts: `./build/release/duckdb` (shell with extension preloaded),
`./build/release/extension/gcloud_observability/gcloud_observability.duckdb_extension`.

Two naming constraints the build system enforces — **do not rename around them**:

- **DuckDB builds extensions as C++11**, whatever `CMAKE_CXX_STANDARD` says. A struct with a default
  member initializer is therefore *not* an aggregate and cannot be brace-initialized (this is why
  `CachedToken` in `gcloud_auth.cpp` is filled field-by-field).
- The static build's codegen emits `#include "<EXT_NAME>_extension.hpp"` and
  `LoadStaticExtension<CamelCase(EXT_NAME)>Extension>`. With `EXT_NAME=gcloud_observability` that
  pins the header to `src/include/gcloud_observability_extension.hpp` and the class to
  `GcloudObservabilityExtension`. Only the loadable extension builds if these drift.

## End-to-end test (real Google Cloud)

`test/e2e/run_e2e.sh` runs the full round trip against a **real** project: `gcloud logging write` of
a uniquely-marked entry → `entries.list` → `read_gcloud_logs` → assert the OTLP mapping. Google
publishes no Cloud Logging emulator, so unlike the splunk/datadog e2e scripts there is no container
to start; the script writes to the log name `duckdb-gcloud-e2e`, whose entries age out on the
project's default retention.

```bash
gcloud auth application-default login
gcloud auth application-default set-quota-project <project>
make release && ./test/e2e/run_e2e.sh          # or GCLOUD_PROJECT=<project> ./test/e2e/run_e2e.sh
```

Two environment quirks the script now absorbs, so don't be surprised by them:

- **`application-default login` does not give the `gcloud` CLI an active account.** It configures ADC
  for *libraries* (all the extension needs), but `gcloud logging write` authenticates separately and
  fails with "You do not currently have an active account". Rather than require a second
  `gcloud auth login`, the script exports `CLOUDSDK_AUTH_ACCESS_TOKEN` with the ADC token.
- **The Homebrew cask's `gcloud` wrapper hard-codes a Python path** that a later Python upgrade
  removes, so gcloud dies with `python3: No such file or directory`. The script probes for a working
  interpreter and sets `CLOUDSDK_PYTHON` itself.

User credentials also need a quota project: without `x-goog-user-project`, `entries.list` fails with
`USER_PROJECT_DENIED`. Hence the `set-quota-project` step.

## Architecture

Five source files under `src/` (+ headers in `src/include/`):

- `gcloud_observability_extension.cpp` — entry point; registers the secret type and the table function.
- `gcloud_secret.cpp` — the `gcloud` KeyValueSecret (`PROJECT`, `TOKEN`, `CREDENTIALS`,
  `QUOTA_PROJECT`, `UNIVERSE_DOMAIN`, `ENDPOINT`, `INSECURE_TLS`). `TOKEN` is redacted;
  `CREDENTIALS` is only a path, so it stays visible.
- `gcloud_auth.cpp` — Application Default Credentials discovery and the OAuth2 token exchange.
- `gcloud_client.cpp` — `GcloudClient`: one keep-alive httplib connection, `POST /v2/entries:list`,
  and the retry loop (429/5xx/transport, exponential backoff, ~100ms-granular cancellation via
  `context.interrupted`).
- `logs_table.cpp` — the bulk. Request building, response parsing, and the LogEntry→OTLP mapping.

### Auth is the part that differs most from the siblings

Datadog and Splunk take a static API key or password. Google takes a **short-lived OAuth2 bearer
token that this extension must mint itself**, mirroring what the OpenTelemetry Collector's
`googlecloudmonitoringreceiver` does with `google.FindDefaultCredentials(ctx, <read scope>)`.

- **No secret is required at all.** `GetGcloudCredentials` returns defaults instead of throwing when
  no `gcloud` secret exists, so `read_gcloud_logs(project => '...')` works straight after
  `gcloud auth application-default login`. This is a deliberate divergence from the siblings, whose
  `Get*Credentials` throw on a missing secret. Don't "fix" it.
- **ADC discovery** (`DiscoverAdcPath`): `$GOOGLE_APPLICATION_CREDENTIALS`, then
  `$CLOUDSDK_CONFIG/application_default_credentials.json`, then
  `$HOME/.config/gcloud/application_default_credentials.json`.
- **Two credential types.** `authorized_user` (what `gcloud auth application-default login` writes)
  uses the refresh-token grant — note it sends *no* scope, because a refresh grant returns the scopes
  originally consented to. `service_account` builds an RS256 self-signed JWT assertion (OpenSSL
  `EVP_DigestSign*`) and exchanges it, requesting `logging.read` explicitly. `external_account` and
  `impersonated_service_account` are rejected with a pointer to the `TOKEN` escape hatch.
- **`x-goog-user-project` is load-bearing.** End-user credentials have no project of their own, so
  Google bills `entries.list` against this header; without it such requests fail with
  `USER_PROJECT_DENIED`. It comes from the secret's `QUOTA_PROJECT` or the credentials file's
  `quota_project_id`.
- **Tokens are cached process-wide**, keyed by credentials path + file mtime + quota project, and
  reused until 60s before expiry. The mtime is in the key so a fresh `application-default login`
  never replays a token minted from the previous file. A `401` drops the cached token and re-mints
  **exactly once** (`GcloudClient::ListEntries`); a second 401 is a real authorization failure.
- Authorization travels only in the request header — never the URL, argv, or an error message.

### Other load-bearing details in `logs_table.cpp`

- **Output schema is exactly 18 columns** matching `read_otlp_logs`; `GetLogsSchema` and the `COL_*`
  indices must stay in sync (`D_ASSERT` guards the count). Attribute columns are VARCHAR JSON
  strings (flat table, not OTLP pdata maps) — a deliberate representational divergence from the
  collector. Attribute *keys*, however, align with the collector's
  `googlecloudlogentryencodingextension` (`gcp.project`, `cloud.resource_id`, `gcp.resource_type`,
  `gcp.label.*`, `log.record.uid`, and the `http.*`/`code.*` semconv names) for interop.
- **The severity mapping is not the obvious one.** Following the collector: `NOTICE` → 10 (INFO2)
  and `EMERGENCY` → **24** (FATAL4, not 23). `DEFAULT` and anything unrecognized → 0. This is the one
  place the readers intentionally disagree: `duckdb-splunk`/`duckdb-datadog` map freeform level
  strings via the OTel data model's Appendix B (`critical` 18, `alert` 19, `emergency` 21), whereas
  Cloud Logging's LogSeverity is a fixed nine-value enum whose top three the collector spreads across
  FATAL/FATAL2/FATAL4. Matching the collector wins here, because GCP logs also reach OTLP through it.
  The *bands* still agree across all three (`>= 17` error-class, `>= 21` fatal-class).
- **`jsonPayload` is merged into `log_attributes`.** The collector puts the whole payload in the log
  record's Body, but `body` here is a single VARCHAR, so the payload's fields would only be reachable
  by re-parsing `body` in SQL. `MergeJsonPayload` copies them in, skipping keys a higher-priority
  source already claimed. `body` itself prefers `textPayload`, then `jsonPayload.message`/`.msg`,
  then the serialized payload.
- **Pagination must key off `nextPageToken`, never off an empty `entries` array.** `entries.list`
  scans a time slice per page, so it routinely returns a page with zero entries *and* a next cursor.
  `FetchNextPage` also stops if the server echoes the same cursor, which would otherwise spin
  forever. Note this is exactly where the otherwise-identical `duckdb-datadog` `FetchNextPage`
  differs: it treats `page_rows == 0` as end-of-stream, which here would silently truncate results.
- **Google encodes int64 fields as JSON strings** (proto3 JSON mapping) but int32 fields as numbers:
  `status` arrives as `200`, `requestSize` as `"1234"`. `GetInt64Flexible` accepts either. Same trap
  for `sourceLocation.line` and `cacheFillBytes`.
- **Projection pushdown** (`function.projection_pushdown = true`): `MapEntry` only computes projected
  columns, so a `count(*)` or `GROUP BY service_name` never pays the per-row `log_attributes` JSON
  serialization.
- **Streaming fetch:** the scan holds at most one page in `buffer` and fetches the next only when it
  drains, so an unbounded scan does not materialize the whole result set. `max_rows` is enforced at
  emit time and also shrinks the next `pageSize`, so the final page is not over-fetched.
- **The request body is built with yyjson**, not string concatenation, so a `filter` containing
  quotes or backslashes cannot corrupt the request.
- `filter` is parenthesized before `start_time`/`end_time` are ANDed on, so a top-level `OR` inside a
  user filter cannot swallow the time bound.

### Bind-time vs scan-time

Parameter validation (`max_rows >= 0`, `page_size` in [1,1000], `order_by`, `timeout >= 1`,
`retries >= 0`, time specs, unknown params), secret resolution, and project resolution all happen in
`GcloudLogsBind` — **no network call, and no token is minted**. The first `GcloudLogsScan` triggers
`FetchAll`, which mints the token on its first request. `MaxThreads() == 1`.

This split is what lets `test/sql/gcloud_observability.test` be fully offline: every case there
binds (via `DESCRIBE`) or fails during validation. Parameter validation deliberately runs *before*
credential resolution, so those cases pass whether or not the host has ADC configured. Don't add an
offline test that depends on ADC being absent — a developer's laptop usually has it.

## Dependencies

OpenSSL via `find_package`, doing double duty: TLS backend for HTTPS *and* the RS256 signer for the
service-account JWT. HTTP (cpp-httplib) and JSON (yyjson) reuse DuckDB's bundled copies under
`duckdb/third_party/` — nothing extra is pulled in. `CPPHTTPLIB_OPENSSL_SUPPORT` selects the
separately-namespaced `duckdb_httplib_openssl` build so symbols don't clash with core DuckDB's
non-SSL httplib.
