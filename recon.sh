#!/usr/bin/env bash
# reconkit orchestrator.
#
#   ./recon.sh example.com
#   ./recon.sh example.com --authorized "Jane Doe, signed ROE 2026-01-01" --enable-vuln-scan
#   ./recon.sh --scope-file config/scope.yaml
#   ./recon.sh --check
#   ./recon.sh --confirm 42 --by "jane.doe" --note "manually verified, see evidence/lead-42.png"
#
# Bash's only jobs here are: parse args, create the run's directory
# layout, and call one `python3 -m reconkit.cli <stage>` per pipeline
# stage, in order. All parsing, scope logic, HTTP/DNS/crawl/scan calls,
# SQLite writes and HTML rendering happen in reconkit/ (Python) - see
# that package's docstrings for the contract each stage follows.
#
# Failure isolation: every stage is invoked through run_stage(), which
# never lets a single stage's crash/timeout stop the pipeline. If the
# python subprocess itself dies unexpectedly (not a tool-level failure,
# which reconkit already records on its own), run_stage logs a `failed`
# tool_run row for that stage and continues.
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
PY="python3 -m reconkit.cli"
STAGE_TIMEOUT_S="${STAGE_TIMEOUT_S:-900}"   # circuit breaker per stage, independent of each tool's own timeout

DOMAIN=""
SCOPE_FILE=""
OUTPUT_ROOT="recon"
AUTHORIZED=""
MAX_HOSTS="1000"
ENABLE_PORTSCAN=0
ENABLE_CONTENT_DISCOVERY=0
ENABLE_VULN_SCAN=0
DO_CHECK=0
DO_CONFIRM=0
CONFIRM_LEAD_ID=""
CONFIRM_BY=""
CONFIRM_NOTE=""

usage() {
  cat >&2 <<'EOF'
Usage:
  recon.sh <domain> [--authorized "text"] [--output-root DIR] [--max-hosts N]
           [--enable-portscan] [--enable-content-discovery] [--enable-vuln-scan]
  recon.sh --scope-file config/scope.yaml [--output-root DIR]
  recon.sh --check
  recon.sh --confirm <lead-id> --by "name" --note "evidence summary"

See config/scope.example.yaml for the full set of options the scope file
accepts (per-module toggles, rate limits, include/exclude patterns,
authorization fields). SAFE_ACTIVE and OPTIONAL_ACTIVE stages refuse to
run without authorization - pass --authorized on the simple path, or
fill in engagement.authorized_by/authorization_reference in the scope file.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope-file) SCOPE_FILE="$2"; shift 2 ;;
    --authorized) AUTHORIZED="$2"; shift 2 ;;
    --output-root) OUTPUT_ROOT="$2"; shift 2 ;;
    --max-hosts) MAX_HOSTS="$2"; shift 2 ;;
    --enable-portscan) ENABLE_PORTSCAN=1; shift ;;
    --enable-content-discovery) ENABLE_CONTENT_DISCOVERY=1; shift ;;
    --enable-vuln-scan) ENABLE_VULN_SCAN=1; shift ;;
    --check) DO_CHECK=1; shift ;;
    --confirm) DO_CONFIRM=1; CONFIRM_LEAD_ID="$2"; shift 2 ;;
    --by) CONFIRM_BY="$2"; shift 2 ;;
    --note) CONFIRM_NOTE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "Unknown flag: $1" >&2; usage; exit 2 ;;
    *) DOMAIN="$1"; shift ;;
  esac
done

if (( DO_CHECK )); then
  exec $PY check-deps
fi

if (( DO_CONFIRM )); then
  if [[ -z "$CONFIRM_BY" || -z "$CONFIRM_NOTE" ]]; then
    echo "--confirm requires --by and --note (evidence summary)." >&2
    exit 2
  fi
  DB_PATH="${OUTPUT_ROOT%/}/${DOMAIN}/recon.db"
  if [[ ! -f "$DB_PATH" ]]; then
    # domain may not be known yet if confirming against a scope-file run; search for any recon.db
    FOUND="$(find "${OUTPUT_ROOT%/}" -maxdepth 2 -name recon.db 2>/dev/null | head -n1 || true)"
    [[ -n "$FOUND" ]] && DB_PATH="$FOUND"
  fi
  [[ -f "$DB_PATH" ]] || { echo "Could not find recon.db under ${OUTPUT_ROOT}" >&2; exit 1; }
  exec $PY confirm --db-path "$DB_PATH" --lead-id "$CONFIRM_LEAD_ID" --by "$CONFIRM_BY" --note "$CONFIRM_NOTE"
fi

if [[ -z "$DOMAIN" && -z "$SCOPE_FILE" ]]; then
  usage; exit 2
fi

SCOPE_ARGS=()
if [[ -n "$SCOPE_FILE" ]]; then
  SCOPE_ARGS=(--scope-file "$SCOPE_FILE")
else
  SCOPE_ARGS=(--domain "$DOMAIN" --max-hosts "$MAX_HOSTS")
  [[ -n "$AUTHORIZED" ]] && SCOPE_ARGS+=(--authorized "$AUTHORIZED")
  (( ENABLE_PORTSCAN )) && SCOPE_ARGS+=(--enable-portscan)
  (( ENABLE_CONTENT_DISCOVERY )) && SCOPE_ARGS+=(--enable-content-discovery)
  (( ENABLE_VULN_SCAN )) && SCOPE_ARGS+=(--enable-vuln-scan)
fi

# Resolve the domain name for directory layout even in --scope-file mode.
SCOPE_JSON="$($PY scope-check "${SCOPE_ARGS[@]}" 2>&1)" || {
  echo "Scope validation failed:" >&2
  echo "$SCOPE_JSON" >&2
  exit 2
}
RESOLVED_DOMAIN="$(printf '%s' "$SCOPE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"])')"
IS_AUTHORIZED="$(printf '%s' "$SCOPE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["authorized"])')"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="${OUTPUT_ROOT%/}/${RESOLVED_DOMAIN}"
RAW="${BASE}/raw/${RUN_ID}"
DB_PATH="${BASE}/recon.db"

mkdir -p "${BASE}/assets" "${BASE}/endpoints" "${BASE}/findings" "${BASE}/evidence" "$RAW"

printf 'Domain: %s\nRun: %s\nAuthorized: %s\nOutput: %s\n\n' \
  "$RESOLVED_DOMAIN" "$RUN_ID" "$IS_AUTHORIZED" "$BASE"
if [[ "$IS_AUTHORIZED" != "True" ]]; then
  printf 'NOTE: no authorization on record. Only PASSIVE stages will produce results;\n'
  printf '      SAFE_ACTIVE/OPTIONAL_ACTIVE stages will record status=not_run.\n\n'
fi

run_stage() {
  local stage_name="$1"; shift
  printf '==> %s\n' "$stage_name"
  if timeout --signal=TERM --kill-after=10 "${STAGE_TIMEOUT_S}" $PY "$@" "${SCOPE_ARGS[@]}" \
      --db-path "$DB_PATH" --run-id "$RUN_ID" --raw-dir "$RAW"; then
    return 0
  else
    local rc=$?
    printf '    [stage process exited with code %s - continuing pipeline]\n' "$rc" >&2
    $PY log-stage-failure --db-path "$DB_PATH" --run-id "$RUN_ID" --stage "$stage_name" \
      --exit-code "$rc" || true
    return 0
  fi
}

$PY init-db --db-path "$DB_PATH"
$PY new-run "${SCOPE_ARGS[@]}" --db-path "$DB_PATH" --run-id "$RUN_ID" --raw-dir "$RAW"

run_stage passive          passive
run_stage subdomains       subdomains
run_stage dns_validate     dns-validate
run_stage http_map         http-map
run_stage port_scan        port-scan
run_stage historical       historical
run_stage crawl            crawl
run_stage content_discovery content-discovery --wordlist "${SCRIPT_DIR}/config/ffuf_seed_wordlist.txt"
run_stage vuln_scan        vuln-scan

run_stage correlate        correlate
run_stage confidence       confidence

$PY finish-run --db-path "$DB_PATH" --run-id "$RUN_ID"
REPORT_PATH="$($PY report "${SCOPE_ARGS[@]}" --db-path "$DB_PATH" --run-id "$RUN_ID" \
  --raw-dir "$RAW" --out "${BASE}/report.html")"

printf '\nDone.\nReport:  %s\nDatabase: %s\nRaw evidence: %s\n' "$REPORT_PATH" "$DB_PATH" "$RAW"
printf '\nOpen leads needing manual review:\n'
printf '  ./recon.sh --output-root %s --confirm <id> --by "you" --note "evidence summary"\n' "$OUTPUT_ROOT"
