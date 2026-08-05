#!/usr/bin/env bash
#
# End-to-end test for the duckdb-gcloud-observability extension.
#
# It proves the full round trip against real Google Cloud Logging:
#   build -> CLI write/read mapping check -> send_gcloud_logs -> Cloud Logging entries.list
#   -> read_gcloud_logs, including trace/span/service round-trip.
#
# Unlike the sibling duckdb-splunk / duckdb-datadog e2e scripts there is no local container to
# start: Google publishes no Cloud Logging emulator, so this talks to a real project. It writes a
# handful of log entries under a dedicated log name (`LOG_ID`, default `duckdb-gcloud-e2e`), which
# expire on the project's default 30-day retention.
#
# Prerequisites:
#   * gcloud CLI, authenticated for Application Default Credentials:
#       gcloud auth application-default login
#       gcloud auth application-default set-quota-project <project>
#   * The Cloud Logging API enabled on the project, and roles/logging.viewer +
#     roles/logging.logWriter for the authenticated principal.
#   * A release build: `OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3 make release`
#
# Configuration comes from the environment (all optional):
#   GCLOUD_PROJECT   project to write to / read from (default: `gcloud config get-value project`,
#                    falling back to the ADC file's quota_project_id)
#   LOG_ID           log name to write under        (default: duckdb-gcloud-e2e)
#   DUCKDB_BIN       path to the duckdb shell       (default: ./build/release/duckdb)
#   POLL_TIMEOUT     seconds to wait for the entry to become queryable (default: 120)
#   POLL_INTERVAL    seconds between polls          (default: 5)
#   CLOUDSDK_PYTHON  interpreter for the gcloud CLI (default: whatever gcloud picks)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${REPO_DIR}"

DUCKDB_BIN="${DUCKDB_BIN:-./build/release/duckdb}"
LOG_ID="${LOG_ID:-duckdb-gcloud-e2e}"
POLL_TIMEOUT="${POLL_TIMEOUT:-120}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

log()  { printf '\033[1;34m[e2e]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[e2e] PASS\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[e2e] FAIL\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
command -v gcloud >/dev/null 2>&1 || fail "gcloud CLI is required (brew install --cask gcloud-cli)"
[ -x "${DUCKDB_BIN}" ] || fail "duckdb binary not found/executable at '${DUCKDB_BIN}' (run 'make release' first, or set DUCKDB_BIN)"

# The Homebrew cask's gcloud wrapper hard-codes a pythonN.NN path that a later Python upgrade
# removes, so `gcloud` dies with "python3: No such file or directory". Point it at a working
# interpreter rather than making every caller discover this.
if ! gcloud --version >/dev/null 2>&1; then
	for candidate in "${CLOUDSDK_PYTHON:-}" /opt/homebrew/bin/python3 "$(command -v python3 || true)"; do
		if [ -n "${candidate}" ] && [ -x "${candidate}" ] && CLOUDSDK_PYTHON="${candidate}" gcloud --version >/dev/null 2>&1; then
			export CLOUDSDK_PYTHON="${candidate}"
			log "using CLOUDSDK_PYTHON=${candidate} (the gcloud wrapper's default interpreter is missing)"
			break
		fi
	done
	gcloud --version >/dev/null 2>&1 || fail "the gcloud CLI is installed but not runnable; set CLOUDSDK_PYTHON to a working python3"
fi

# The SQL temp file is removed on exit. It holds no secrets — credentials come from ADC, never from
# the SQL text or the process command line — but there is no reason to leave it behind.
SQL_FILE=""
cleanup() { rm -f "${SQL_FILE}" 2>/dev/null || true; }
trap cleanup EXIT

# Resolve the project: explicit env, then the gcloud config, then the ADC quota project. This is
# exactly the chain the extension itself walks, so a working script implies a working extension default.
PROJECT="${GCLOUD_PROJECT:-}"
if [ -z "${PROJECT}" ]; then
	PROJECT="$(gcloud config get-value project 2>/dev/null || true)"
	[ "${PROJECT}" = "(unset)" ] && PROJECT=""
fi
if [ -z "${PROJECT}" ] && [ -f "${HOME}/.config/gcloud/application_default_credentials.json" ]; then
	PROJECT="$(python3 -c 'import json,os,sys; print(json.load(open(os.path.expanduser("~/.config/gcloud/application_default_credentials.json"))).get("quota_project_id",""))' 2>/dev/null || true)"
fi
[ -n "${PROJECT}" ] || fail "no project configured; set GCLOUD_PROJECT or run 'gcloud config set project <project>'"

# Fail early, with the remediation command, rather than deep inside a duckdb scan.
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
	fail "Application Default Credentials are missing or expired. Run:
  gcloud auth application-default login
  gcloud auth application-default set-quota-project ${PROJECT}"
fi

# `gcloud auth application-default login` configures ADC for *libraries* (which is all the extension
# needs) but leaves the CLI itself without an active account, so `gcloud logging write` below would
# fail. Rather than demand a second, separate `gcloud auth login`, hand the CLI the ADC token — the
# documented way to drive gcloud with an externally-obtained credential.
if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | grep -q .; then
	CLOUDSDK_AUTH_ACCESS_TOKEN="$(gcloud auth application-default print-access-token 2>/dev/null)"
	export CLOUDSDK_AUTH_ACCESS_TOKEN
	log "no active gcloud account; driving the CLI with the ADC access token"
fi

log "project=${PROJECT} log_id=${LOG_ID}"

# ---------------------------------------------------------------------------
# 1. Write a uniquely-marked structured entry via the gcloud CLI
# ---------------------------------------------------------------------------
MARKER="duckdbe2e-$(date +%s)-${RANDOM}"
TRACE_ID="$(printf '%032x' "$((RANDOM * RANDOM))")"
SPAN_ID="$(printf '%016x' "$((RANDOM * RANDOM))")"

# `gcloud logging write` sets severity and the jsonPayload; `trace`/`spanId` are LogEntry fields that
# the CLI cannot set, so the trace columns are exercised only insofar as they stay NULL. The payload
# carries `service`, which is where the mapping looks for service_name on a structured entry.
payload=$(cat <<JSON
{"message": "duckdb-gcloud-observability e2e test ${MARKER}", "service": "duckdb-gcloud-e2e", "marker": "${MARKER}", "trace_id": "${TRACE_ID}", "span_id": "${SPAN_ID}"}
JSON
)

log "Writing test entry with marker '${MARKER}'..."
gcloud logging write "${LOG_ID}" "${payload}" \
	--payload-type=json \
	--severity=ERROR \
	--project="${PROJECT}" >/dev/null 2>&1 \
	|| fail "gcloud logging write failed; does the principal have roles/logging.logWriter on ${PROJECT}?"
ok "entry accepted by Cloud Logging"

# ---------------------------------------------------------------------------
# 2. Read it back through the extension, polling until it is queryable
# ---------------------------------------------------------------------------
# Scope the filter to our log name and marker. Cloud Logging's ingest path is asynchronous, so a
# freshly written entry can take a few seconds to appear in entries.list.
FILTER="logName=\"projects/${PROJECT}/logs/${LOG_ID}\" AND jsonPayload.marker=\"${MARKER}\""

SQL_FILE="$(mktemp -t duckdb_gcloud_e2e.XXXXXX.sql)"
chmod 600 "${SQL_FILE}"

# The reader picks credentials up from ADC, so no CREATE SECRET is needed at all — that is the
# behavior this script is here to prove. `start_time` bounds the scan so the query stays cheap.
READ_SQL="read_gcloud_logs(project => '${PROJECT}', filter => '${FILTER}', start_time => '-15m')"

run_duckdb_scalar() { # $1 = SQL producing a single value
	printf '%s\n' "$1" > "${SQL_FILE}"
	"${DUCKDB_BIN}" -unsigned -noheader -list -init /dev/null < "${SQL_FILE}"
}

count_sql="SELECT count(*) FROM ${READ_SQL};"

log "Polling read_gcloud_logs for the entry (timeout ${POLL_TIMEOUT}s)..."
elapsed=0
found=0
while [ "${elapsed}" -lt "${POLL_TIMEOUT}" ]; do
	# `|| true` so a transient API error during polling doesn't abort the run under set -e.
	count="$(run_duckdb_scalar "${count_sql}" 2>/dev/null | tr -d '[:space:]')" || true
	if [[ "${count}" =~ ^[0-9]+$ ]] && [ "${count}" -ge 1 ]; then
		found=1
		break
	fi
	log "  not queryable yet (matches=${count:-0}); retrying in ${POLL_INTERVAL}s (${elapsed}/${POLL_TIMEOUT}s)"
	sleep "${POLL_INTERVAL}"
	elapsed=$((elapsed + POLL_INTERVAL))
done
if [ "${found}" -ne 1 ]; then
	# Re-run once without suppressing stderr so the actual API error reaches the operator.
	log "Last attempt, showing the raw error:"
	run_duckdb_scalar "${count_sql}" || true
	fail "entry with marker '${MARKER}' never became queryable within ${POLL_TIMEOUT}s"
fi
ok "read_gcloud_logs returned the entry (matches=${count})"

# ---------------------------------------------------------------------------
# 3. Assert the row is OTLP-shaped and mapped correctly
# ---------------------------------------------------------------------------
# Materialize the matching rows once into a temp table, then run every assertion against that local
# table (one scan keeps the test simple and light on the Logging API quota).
cat > "${SQL_FILE}" <<SQL
.output /dev/null
CREATE TEMP TABLE e2e_rows AS SELECT * FROM ${READ_SQL};
.output
SELECT (SELECT count(*) FROM (DESCRIBE e2e_rows))::VARCHAR || '|' ||
  (SELECT (count(*) >= 1
    AND bool_and(service_name = 'duckdb-gcloud-e2e')
    AND bool_and(severity_text = 'ERROR')
    AND bool_and(severity_number = 17)
    AND bool_and(body LIKE '%${MARKER}%')
    AND bool_and(time_unix_nano IS NOT NULL)
    AND bool_and(observed_time_unix_nano IS NOT NULL)
    AND bool_and(log_attributes LIKE '%${MARKER}%')
    AND bool_and(log_attributes LIKE '%log.record.uid%')
    AND bool_and(resource_attributes LIKE '%"gcp.project":"${PROJECT}"%')
    AND bool_and(resource_attributes LIKE '%"cloud.resource_id":"${LOG_ID}"%')
    AND bool_and(resource_attributes LIKE '%gcp.resource_type%')) FROM e2e_rows)::VARCHAR;
.print ---SAMPLE---
SELECT time_unix_nano, service_name, severity_text, severity_number, body FROM e2e_rows LIMIT 1;
.print ---RESOURCEATTRS---
SELECT resource_attributes FROM e2e_rows LIMIT 1;
.print ---LOGATTRS---
SELECT log_attributes FROM e2e_rows LIMIT 1;
SQL
assert_out="$("${DUCKDB_BIN}" -unsigned -noheader -list -init /dev/null < "${SQL_FILE}")"

summary_line="$(printf '%s\n' "${assert_out}" | head -n1 | tr -d '[:space:]')"
column_count="${summary_line%%|*}"
checks="${summary_line##*|}"

[ "${column_count}" = "18" ] || fail "expected 18 OTLP columns, got '${column_count}'"
ok "output schema has the 18 OTLP columns"
[ "${checks}" = "true" ] || fail "row content assertions failed (got '${checks}')"
ok "row content maps correctly (service_name, severity ERROR->17, body, timestamps, attributes)"

# ---------------------------------------------------------------------------
# 4. Assert projection pushdown and max_rows behave
# ---------------------------------------------------------------------------
# A bare count(*) projects no real column: MapEntry must still produce one row per entry rather than
# tripping over the rowid sentinel in column_ids.
projected="$(run_duckdb_scalar "SELECT count(*) FROM ${READ_SQL};" | tr -d '[:space:]')"
[ "${projected}" = "${count}" ] || fail "count(*) with projection pushdown returned '${projected}', expected '${count}'"
ok "projection pushdown: bare count(*) returns ${projected}"

capped="$(run_duckdb_scalar "SELECT count(*) FROM read_gcloud_logs(project => '${PROJECT}', start_time => '-15m', max_rows => 1);" | tr -d '[:space:]')"
[ "${capped}" = "1" ] || fail "max_rows => 1 returned '${capped}' rows, expected 1"
ok "max_rows caps the scan at 1 row"

# ---------------------------------------------------------------------------
# 5. Send through the extension and read the entry back
# ---------------------------------------------------------------------------
SEND_MARKER="duckdbsend-$(date +%s)-${RANDOM}"
SEND_TRACE_ID="$(printf '%032x' "$((RANDOM * RANDOM))")"
SEND_SPAN_ID="$(printf '%016x' "$((RANDOM * RANDOM))")"
log "Sending an OTLP-shaped row through send_gcloud_logs (marker '${SEND_MARKER}')..."
send_result="$(run_duckdb_scalar "
CREATE TEMP SECRET gcloud_e2e (TYPE gcloud, PROJECT '${PROJECT}');
WITH to_send AS (
  SELECT current_timestamp::TIMESTAMP_NS AS time_unix_nano,
         '${SEND_TRACE_ID}' AS trace_id,
         '${SEND_SPAN_ID}' AS span_id,
         1 AS flags,
         'duckdb-gcloud-sender' AS service_name,
         17 AS severity_number,
         'sent through send_gcloud_logs ${SEND_MARKER}' AS body,
         '${LOG_ID}' AS log_id,
         '{\"gcp.resource_type\":\"global\"}' AS resource_attributes,
         '{\"marker\":\"${SEND_MARKER}\",\"gcp.label.sender\":\"duckdb-extension\"}' AS log_attributes
)
SELECT send_gcloud_logs(t, 'gcloud_e2e') FROM to_send t;
" | tail -n1 | tr -d '[:space:]')"
[ "${send_result}" = "ok" ] || fail "send_gcloud_logs did not return 'ok' (got '${send_result:-<empty>}')"
ok "send_gcloud_logs accepted the row"

SEND_FILTER="logName=\"projects/${PROJECT}/logs/${LOG_ID}\" AND jsonPayload.marker=\"${SEND_MARKER}\""
SEND_READ_SQL="read_gcloud_logs(project => '${PROJECT}', filter => '${SEND_FILTER}', start_time => '-15m')"
send_count_sql="SELECT count(*) FROM ${SEND_READ_SQL};"
elapsed=0
send_found=0
while [ "${elapsed}" -lt "${POLL_TIMEOUT}" ]; do
	send_count="$(run_duckdb_scalar "${send_count_sql}" 2>/dev/null | tr -d '[:space:]')" || true
	if [[ "${send_count}" =~ ^[0-9]+$ ]] && [ "${send_count}" -ge 1 ]; then
		send_found=1
		break
	fi
	log "  sent row not queryable yet (matches=${send_count:-0}); retrying in ${POLL_INTERVAL}s"
	sleep "${POLL_INTERVAL}"
	elapsed=$((elapsed + POLL_INTERVAL))
done
if [ "${send_found}" -ne 1 ]; then
	run_duckdb_scalar "${send_count_sql}" || true
	fail "row sent through send_gcloud_logs never became queryable within ${POLL_TIMEOUT}s"
fi

send_checks="$(run_duckdb_scalar "
SELECT count(*) >= 1
   AND bool_and(service_name = 'duckdb-gcloud-sender')
   AND bool_and(severity_text = 'ERROR')
   AND bool_and(trace_id = '${SEND_TRACE_ID}')
   AND bool_and(span_id = '${SEND_SPAN_ID}')
   AND bool_and(flags = 1)
   AND bool_and(body LIKE '%${SEND_MARKER}%')
   AND bool_and(log_attributes LIKE '%duckdb-extension%')
FROM ${SEND_READ_SQL};
" | tr -d '[:space:]')"
[ "${send_checks}" = "true" ] || fail "send/read round-trip field assertions failed (got '${send_checks}')"
ok "send_gcloud_logs round-trip preserves service, severity, body, trace/span, flags, and labels"

log "Sample row:"
printf '%s\n' "${assert_out}" | sed -n '/---SAMPLE---/,/---RESOURCEATTRS---/p' | sed '1d;$d'
log "resource_attributes:"
printf '%s\n' "${assert_out}" | sed -n '/---RESOURCEATTRS---/,/---LOGATTRS---/p' | sed '1d;$d'
log "log_attributes:"
printf '%s\n' "${assert_out}" | sed -n '/---LOGATTRS---/,$p' | tail -n +2

ok "end-to-end test succeeded"
