"""Stage: OPTIONAL_ACTIVE - nuclei, restricted to non-intrusive template
tags, off by default.

Every match lands in `vuln_leads` with classification defaulting to
OBSERVATION/LEAD - never VULNERABILITY_CANDIDATE or CONFIRMED_FINDING on
its own. confidence.py is the only place that may promote a lead to
VULNERABILITY_CANDIDATE, and only a human (via `recon.sh --confirm`)
can set status='confirmed'. We pass an explicit -etags exclude-list so
templates tagged exposure/token/creds/intrusive/dos/fuzz/rce/sqli/
default-login never run, even if the operator's installed template set
changes.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import db, scope as scope_mod, util

STAGE = "vuln_scan"
CLASSIFICATION = "OPTIONAL_ACTIVE"

SAFE_TAGS = "tech,ssl,headers,dns,waf,favicon"
EXCLUDE_TAGS = (
    "intrusive,dos,fuzz,fuzzing,rce,sqli,sqli-ba,xxe,ssrf,lfi,rfi,"
    "exposure,token,creds,default-login,takeover,bruteforce,injection"
)


def run(run_id: str, raw_dir: str, scope: "scope_mod.Scope", conn, target_urls: list,
        timeout: float = 600.0) -> dict:
    started = util.utc_now_iso()

    if not scope.module_enabled("vuln_scan"):
        db.record_tool_run(conn, run_id, STAGE, "nuclei", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run"}

    auth_error = scope_mod.require_authorization_or_die(scope, STAGE)
    if auth_error:
        db.record_tool_run(conn, run_id, STAGE, "nuclei", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", auth_error)
        return {"status": "not_run", "error": auth_error}

    exe = util.which("nuclei")
    in_scope_urls = sorted({u for u in target_urls if scope.is_in_scope(urlparse(u).hostname or "")})
    raw_path = f"{raw_dir}/nuclei.jsonl"
    if not exe or not in_scope_urls:
        status = "unavailable" if not exe else "nothing_found"
        db.record_tool_run(conn, run_id, STAGE, "nuclei", CLASSIFICATION, started,
                            util.utc_now_iso(), None, status,
                            None if status == "nothing_found" else "nuclei not found on PATH")
        return {"status": status}

    list_path = raw_path.replace(".jsonl", ".urls.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(in_scope_urls) + "\n")

    rate = max(1, int(scope.rate_limits.get("nuclei_rate", 10)))
    result = util.run_cmd(
        [exe, "-silent", "-jsonl", "-l", list_path, "-tags", SAFE_TAGS,
         "-etags", EXCLUDE_TAGS, "-severity", "info,low,medium",
         "-rate-limit", str(rate), "-o", raw_path],
        timeout=timeout,
    )

    rows = util.read_jsonl(raw_path)
    if result.timed_out:
        status = "timed_out"
    elif not rows and result.returncode not in (0, None):
        status = "failed"
    else:
        status = "ok" if rows else "nothing_found"

    observed_at = util.utc_now_iso()
    for row in rows:
        host = urlparse(row.get("matched-at", row.get("host", ""))).hostname or ""
        if host and not scope.is_in_scope(host):
            continue  # defense in depth; should already be excluded by the input list
        info = row.get("info", {}) or {}
        conn.execute(
            "INSERT INTO vuln_leads(run_id, template_id, name, severity, matched_at, tags, "
            "evidence_path, classification, confidence, confidence_reason, status, observed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                run_id, row.get("template-id", "unknown"), info.get("name", ""),
                info.get("severity", "info"), row.get("matched-at", ""),
                ",".join(info.get("tags", []) or []), raw_path,
                "LEAD", "LOW",
                "single-source nuclei (safe tags only) match, not yet cross-validated",
                "open", observed_at,
            ),
        )

    db.record_tool_run(conn, run_id, STAGE, "nuclei", CLASSIFICATION, started, util.utc_now_iso(),
                        result.returncode, status,
                        None if status in ("ok", "nothing_found") else result.stderr[:500],
                        item_count=len(rows))
    return {"status": status, "leads": len(rows)}
