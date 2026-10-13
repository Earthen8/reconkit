#!/usr/bin/env bash
# reconkit orchestrator.
#
#   ./recon.sh example.com
#   ./recon.sh example.com --authorized --enable-vuln-scan
#   ./recon.sh --ip 203.0.113.10 --authorized
#   ./recon.sh --scope-file config/scope.yaml
#   ./recon.sh --check
#   ./recon.sh --confirm 42 --by "jane.doe" --note "manually verified, see evidence/lead-42.png"
#
# Target type (hostname vs. bare IP) is always an explicit choice - the
# <domain> positional and --ip are mutually exclusive, and nothing here
# ever guesses which one a string "looks like". In --ip mode the scope
# is exactly that one address (no CIDR, no other IP); CT-log lookup,
# subdomain enumeration and DNS wildcard detection are domain-only
# techniques and are skipped entirely - see reconkit/passive.py,
# reconkit/subdomains.py and reconkit/dns_validate.py.
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
IP_TARGET=""
SCOPE_FILE=""
OUTPUT_ROOT="recon"
AUTHORIZED=0
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
  recon.sh <domain> [--authorized] [--output-root DIR] [--max-hosts N]
           [--enable-portscan] [--enable-content-discovery] [--enable-vuln-scan]
  recon.sh --ip <address> [--authorized] [--output-root DIR]
           [--enable-portscan] [--enable-content-discovery] [--enable-vuln-scan]
  recon.sh --scope-file config/scope.yaml [--output-root DIR]
  recon.sh --check
  recon.sh --confirm <lead-id> --by "name" --note "evidence summary"

Exactly one of: <domain>, --ip, or --scope-file. Target type is never
guessed from the string - an IPv4/IPv6-looking value passed as <domain>
is rejected with a message telling you to use --ip instead. --ip accepts
a single bare address only (no CIDR); the run's scope is exactly that
address, and domain-only stages (crt.sh, subdomain enumeration, DNS
wildcard detection) are not run in that mode.

See config/scope.example.yaml (and config/scope.example-ip.yaml) for the
full set of options the scope file accepts (per-module toggles, rate
limits, include/exclude patterns, authorization fields). SAFE_ACTIVE and
OPTIONAL_ACTIVE stages refuse to run without authorization - pass
--authorized on the simple path, or
fill in engagement.authorized_by/authorization_reference in the scope file.
The --authorized flag is an operator assertion; it does not verify
authorization independently.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip) IP_TARGET="$2"; shift 2 ;;
    --scope-file) SCOPE_FILE="$2"; shift 2 ;;
    --authorized) AUTHORIZED=1; shift ;;
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

# Exactly one target source. Counted explicitly rather than guessed, so
# e.g. `recon.sh 203.0.113.10` (an IP passed as the positional <domain>)
# is caught here-ish and then definitively rejected by scope-check below
# (which knows the real validation rules) rather than silently "working".
TARGET_COUNT=0
[[ -n "$DOMAIN" ]] && TARGET_COUNT=$((TARGET_COUNT + 1))
[[ -n "$IP_TARGET" ]] && TARGET_COUNT=$((TARGET_COUNT + 1))
[[ -n "$SCOPE_FILE" ]] && TARGET_COUNT=$((TARGET_COUNT + 1))

if (( TARGET_COUNT == 0 )); then
  usage; exit 2
fi
if (( TARGET_COUNT > 1 )); then
  echo "Specify exactly one of: <domain>, --ip, or --scope-file - not more than one." >&2
  exit 2
fi

SCOPE_ARGS=()
if [[ -n "$SCOPE_FILE" ]]; then
  SCOPE_ARGS=(--scope-file "$SCOPE_FILE")
elif [[ -n "$IP_TARGET" ]]; then
  SCOPE_ARGS=(--ip "$IP_TARGET" --max-hosts "$MAX_HOSTS")
  (( AUTHORIZED )) && SCOPE_ARGS+=(--authorized)
  (( ENABLE_PORTSCAN )) && SCOPE_ARGS+=(--enable-portscan)
  (( ENABLE_CONTENT_DISCOVERY )) && SCOPE_ARGS+=(--enable-content-discovery)
  (( ENABLE_VULN_SCAN )) && SCOPE_ARGS+=(--enable-vuln-scan)
else
  SCOPE_ARGS=(--domain "$DOMAIN" --max-hosts "$MAX_HOSTS")
  (( AUTHORIZED )) && SCOPE_ARGS+=(--authorized)
  (( ENABLE_PORTSCAN )) && SCOPE_ARGS+=(--enable-portscan)
  (( ENABLE_CONTENT_DISCOVERY )) && SCOPE_ARGS+=(--enable-content-discovery)
  (( ENABLE_VULN_SCAN )) && SCOPE_ARGS+=(--enable-vuln-scan)
fi

# Resolve the target for directory layout even in --scope-file mode. This
# is the authoritative validation step - invalid domain, invalid/CIDR IP,
# an IP passed as --domain, or a scope.yaml with an ambiguous/ missing
# target are all rejected here with scope-check's error message.
SCOPE_JSON="$($PY scope-check "${SCOPE_ARGS[@]}" 2>&1)" || {
  echo "Scope validation failed:" >&2
  echo "$SCOPE_JSON" >&2
  exit 2
}
RESOLVED_TARGET="$(printf '%s' "$SCOPE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["domain"])')"
TARGET_TYPE="$(printf '%s' "$SCOPE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_type"])')"
IS_AUTHORIZED="$(printf '%s' "$SCOPE_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["authorized"])')"

# IPv6 addresses contain ':', which is awkward (though technically legal)
# in a directory name - sanitize only the directory name, never the value
# used for actual scope matching (that's re-derived fresh from SCOPE_ARGS
# by every Python stage via ipaddress.ip_address(), not from this string).
DIR_NAME="${RESOLVED_TARGET//:/-}"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
BASE="${OUTPUT_ROOT%/}/${DIR_NAME}"
RAW="${BASE}/raw/${RUN_ID}"
DB_PATH="${BASE}/recon.db"

mkdir -p "${BASE}/assets" "${BASE}/endpoints" "${BASE}/findings" "${BASE}/evidence" "$RAW"

printf 'Target (%s): %s\nRun: %s\nAuthorized: %s\nOutput: %s\n\n' \
  "$TARGET_TYPE" "$RESOLVED_TARGET" "$RUN_ID" "$IS_AUTHORIZED" "$BASE"
if [[ "$TARGET_TYPE" == "ip" ]]; then
  printf 'Scope is exactly this one address - no CIDR, no other IP. crt.sh, subdomain\n'
  printf 'enumeration and DNS wildcard detection are domain-only and will not run.\n\n'
fi
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
