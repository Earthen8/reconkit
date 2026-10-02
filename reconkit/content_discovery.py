"""Stage: OPTIONAL_ACTIVE - controlled content discovery via ffuf.

Off by default; requires both modules.content_discovery=true *and* a
recorded authorization. Uses a small built-in wordlist (see
config/ffuf_seed_wordlist.txt) rather than a large brute-force list, and
never does credential/login brute forcing.

False-positive control: before fuzzing, we request 2 random
near-certainly-nonexistent paths per host and record their
(status_code, content_length) as a baseline signature. ffuf's own
autocalibration (-ac) is enabled *and* we independently re-filter every
"hit" against our baseline signature, so a custom-404-that-returns-200
page can't be reported as discovered content just because one of the
two filtering mechanisms missed it.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import db, scope as scope_mod, util

STAGE = "content_discovery"
CLASSIFICATION = "OPTIONAL_ACTIVE"


def _baseline(base_url: str, timeout: float = 10.0) -> set:
    curl = util.which("curl")
    sigs = set()
    if not curl:
        return sigs
    for _ in range(2):
        probe = f"{base_url.rstrip('/')}/{util.random_token(16)}"
        result = util.run_cmd(
            [curl, "-sS", "-o", "/dev/null", "-m", str(int(timeout)),
             "-w", "%{http_code} %{size_download}", probe],
            timeout=timeout + 5,
        )
        if not result.timed_out and result.stdout.strip():
            parts = result.stdout.strip().split()
            if len(parts) == 2:
                sigs.add((parts[0], parts[1]))
    return sigs


def run(run_id: str, raw_dir: str, scope: "scope_mod.Scope", conn, base_urls: list,
        wordlist_path: str, timeout: float = 300.0) -> dict:
    started = util.utc_now_iso()

    if not scope.module_enabled("content_discovery"):
        db.record_tool_run(conn, run_id, STAGE, "ffuf", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run"}

    auth_error = scope_mod.require_authorization_or_die(scope, STAGE)
    if auth_error:
        db.record_tool_run(conn, run_id, STAGE, "ffuf", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", auth_error)
        return {"status": "not_run", "error": auth_error}

    exe = util.which("ffuf")
    in_scope_bases = [u for u in base_urls if scope.is_in_scope(urlparse(u).hostname or "")]
    if not exe or not in_scope_bases:
        status = "unavailable" if not exe else "nothing_found"
        db.record_tool_run(conn, run_id, STAGE, "ffuf", CLASSIFICATION, started,
                            util.utc_now_iso(), None, status,
                            None if status == "nothing_found" else "ffuf not found on PATH")
        return {"status": status}

    rps = max(1, int(scope.rate_limits.get("content_discovery_rps", 5)))
    observed_at = util.utc_now_iso()
    total_hits, total_filtered = 0, 0
    overall_status = "nothing_found"

    for base_url in in_scope_bases:
        host = urlparse(base_url).hostname or ""
        baseline_sigs = _baseline(base_url)
        raw_path = f"{raw_dir}/ffuf_{util.safe_filename(host)}.json"
        target = f"{base_url.rstrip('/')}/FUZZ"
        result = util.run_cmd(
            [exe, "-u", target, "-w", wordlist_path, "-ac", "-mc", "all",
             "-rate", str(rps), "-timeout", "8", "-of", "json", "-o", raw_path, "-s"],
            timeout=timeout,
        )
        if result.timed_out:
            db.record_tool_run(conn, run_id, STAGE, "ffuf", CLASSIFICATION, started,
                                util.utc_now_iso(), None, "timed_out", f"ffuf timed out on {host}")
            continue

        data = util.read_json(raw_path, default={})
        results = data.get("results", []) if isinstance(data, dict) else []
        overall_status = "ok"
        for row in results:
            status_code = str(row.get("status", ""))
            length = str(row.get("length", ""))
            path = row.get("input", {}).get("FUZZ", "") if isinstance(row.get("input"), dict) else ""
            url = row.get("url") or f"{base_url.rstrip('/')}/{path}"
            is_baseline_match = (status_code, length) in baseline_sigs
            conn.execute(
                "INSERT OR REPLACE INTO content_discovery(run_id, url, status_code, content_length, "
                "baseline_filtered, note, observed_at) VALUES (?,?,?,?,?,?,?)",
                (run_id, url, row.get("status"), row.get("length"), int(is_baseline_match),
                 "matches custom-404/wildcard baseline signature" if is_baseline_match else "",
                 observed_at),
            )
            if is_baseline_match:
                total_filtered += 1
            else:
                total_hits += 1

    db.record_tool_run(conn, run_id, STAGE, "ffuf", CLASSIFICATION, started, util.utc_now_iso(),
                        0, overall_status, None, item_count=total_hits)
    return {"status": overall_status, "hits": total_hits, "baseline_filtered": total_filtered}
