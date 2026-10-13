"""Stage: PASSIVE harvesting (gau/waybackurls query third-party archives) +
a small, bounded SAFE_ACTIVE liveness cross-check.

Every URL is stored with `historically_observed=1`. We only attempt to
mark `currently_reachable` for a capped sample (limits.max_urls_per_host
_history) so this stage can't silently turn into an unbounded crawl of
archive.org-indexed paths - that liveness check is itself just a normal
GET, same footprint as http_map.
"""
from __future__ import annotations

from urllib.parse import urlparse

from . import db, http_map, scope as scope_mod, util

STAGE = "historical"
CLASSIFICATION_PASSIVE = "PASSIVE"
CLASSIFICATION_ACTIVE = "SAFE_ACTIVE"


def _run_tool(tool: str, domain: str, raw_path: str, timeout: float) -> tuple:
    exe = util.which(tool)
    if not exe:
        return "unavailable", f"{tool} not found on PATH", []
    result = util.run_cmd([exe], input_data=domain + "\n", timeout=timeout)
    if result.timed_out:
        return "timed_out", f"{tool} exceeded timeout", []
    urls = [u.strip() for u in result.stdout.splitlines() if u.strip()]
    with open(raw_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(urls) + ("\n" if urls else ""))
    if not urls and result.returncode not in (0, None):
        return "failed", (result.stderr or f"{tool} returned non-zero exit")[:500], urls
    return ("ok" if urls else "nothing_found"), None, urls


def run(run_id: str, raw_dir: str, scope, conn, timeout: float = 180.0) -> dict:
    if not scope.module_enabled("historical_urls"):
        started = util.utc_now_iso()
        for tool, classification in (("gau", CLASSIFICATION_PASSIVE),
                                     ("waybackurls", CLASSIFICATION_PASSIVE),
                                     ("httpx", CLASSIFICATION_ACTIVE)):
            db.record_tool_run(conn, run_id, STAGE, tool, classification, started,
                                util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run", "total_historical": 0, "liveness_checked": 0,
                "currently_reachable": 0}

    all_urls: set = set()
    for tool in ("gau", "waybackurls"):
        started = util.utc_now_iso()
        raw_path = f"{raw_dir}/{tool}.txt"
        status, error, urls = _run_tool(tool, scope.domain, raw_path, timeout)
        db.record_tool_run(conn, run_id, STAGE, tool, CLASSIFICATION_PASSIVE, started,
                            util.utc_now_iso(), 0 if status in ("ok", "nothing_found") else None,
                            status, error, item_count=len(urls))
        all_urls.update(urls)

    observed_at = util.utc_now_iso()
    in_scope_urls = []
    for url in all_urls:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        host = (parsed.hostname or "").lower()
        if not host or not scope.is_in_scope(host):
            continue
        conn.execute(
            "INSERT OR IGNORE INTO historical_urls(run_id, url, hostname, source, "
            "historically_observed, currently_reachable, status_code, observed_at) "
            "VALUES (?,?,?,?,1,NULL,NULL,?)",
            (run_id, url, host, "gau/waybackurls", observed_at),
        )
        in_scope_urls.append((url, host))

    # bounded liveness cross-check, per host, via a lightweight httpx/curl pass
    cap = int(scope.limits.get("max_urls_per_host_history", 500))
    by_host: dict = {}
    for url, host in in_scope_urls:
        by_host.setdefault(host, []).append(url)
    sample = []
    for host, urls in by_host.items():
        sample.extend(urls[:cap])

    raw_path = f"{raw_dir}/historical_liveness.jsonl"
    exe = util.which("httpx")
    reachable = {}
    auth_error = scope_mod.require_authorization_or_die(scope, STAGE)
    liveness_checked = 0
    if not auth_error and exe and sample:
        list_path = raw_path.replace(".jsonl", ".urls.txt")
        with open(list_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sample) + "\n")
        rate = max(1, int(scope.rate_limits.get("http_rps", 10)))
        result = util.run_cmd(
            [exe, "-silent", "-json", "-l", list_path, "-status-code",
             "-rate-limit", str(rate), "-o", raw_path],
            timeout=timeout,
        )
        liveness_checked = len(sample)
        for row in util.read_jsonl(raw_path):
            u = row.get("url") or row.get("input")
            if u:
                reachable[u] = row.get("status_code")
        if result.timed_out:
            status, error, exit_code = "timed_out", "httpx exceeded timeout", None
        elif result.returncode not in (0, None):
            status, error, exit_code = "failed", (result.stderr or "httpx returned non-zero exit")[:500], result.returncode
        else:
            status, error, exit_code = ("ok" if reachable else "nothing_found"), None, 0
        db.record_tool_run(conn, run_id, STAGE, "httpx", CLASSIFICATION_ACTIVE,
                            util.utc_now_iso(), util.utc_now_iso(),
                            exit_code, status, error,
                            item_count=len(reachable))
        if status not in ("ok", "nothing_found"):
            liveness_checked = 0
    else:
        status = "not_run" if auth_error else ("unavailable" if not exe else "nothing_found")
        reason = auth_error or ("httpx not found on PATH" if not exe else "no in-scope URLs")
        db.record_tool_run(conn, run_id, STAGE, "httpx", CLASSIFICATION_ACTIVE,
                            util.utc_now_iso(), util.utc_now_iso(), 0, status, reason)

    if liveness_checked:
        sampled_urls = set(sample)
        for url, host in in_scope_urls:
            if url not in sampled_urls:
                continue
            conn.execute(
                "UPDATE historical_urls SET currently_reachable=?, status_code=? "
                "WHERE run_id=? AND url=? AND source='gau/waybackurls'",
                (int(url in reachable), reachable.get(url), run_id, url),
            )

    return {
        "total_historical": len(in_scope_urls),
        "liveness_checked": liveness_checked,
        "currently_reachable": len(reachable),
    }
