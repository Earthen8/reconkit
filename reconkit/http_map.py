"""Stage: SAFE_ACTIVE - HTTP/HTTPS mapping of in-scope resolved hosts.

Sends one (or a small, bounded number of) GET requests per host - the
same footprint a browser visiting the site would create. Collects
status, redirect chain, final URL, title, content-type/length, a small
allow-listed set of headers, basic technology hints, and TLS metadata.
A redirect that lands outside scope is recorded in
`third_party_observations` and the final (out-of-scope) URL is never
itself probed or crawled.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from . import db, util

STAGE = "http_map"
CLASSIFICATION = "SAFE_ACTIVE"

ALLOWED_HEADERS = {
    "server", "x-powered-by", "via", "x-aspnet-version", "x-generator",
    "content-type", "strict-transport-security", "x-frame-options",
}

TECH_HEADER_HINTS = {
    "x-powered-by": lambda v: [v.strip()],
    "server": lambda v: [v.strip()],
}

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _httpx_bulk(hosts: list, raw_path: str, timeout: float, rps: float) -> dict:
    exe = util.which("httpx")
    if not exe:
        return {"status": "unavailable", "rows": [], "tool": "httpx"}
    list_path = raw_path.replace(".jsonl", ".hosts.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hosts) + "\n")
    rate = max(1, int(rps))
    result = util.run_cmd(
        [exe, "-silent", "-json", "-l", list_path, "-status-code", "-title",
         "-content-type", "-content-length", "-follow-redirects", "-location",
         "-tech-detect", "-tls-grab", "-rate-limit", str(rate), "-o", raw_path],
        timeout=timeout,
    )
    if result.timed_out:
        return {"status": "timed_out", "rows": [], "tool": "httpx"}
    rows = util.read_jsonl(raw_path)
    if not rows and result.returncode not in (0, None):
        return {"status": "failed", "rows": [], "tool": "httpx", "error": result.stderr[:500]}
    return {"status": "ok" if rows else "nothing_found", "rows": rows, "tool": "httpx"}


def _curl_fallback(hosts: list, raw_dir: str, timeout_per_host: float, rps: float) -> dict:
    curl = util.which("curl")
    rows = []
    if not curl:
        return {"status": "unavailable", "rows": [], "tool": "curl"}
    limiter = util.RateLimiter(rps)
    for host in hosts:
        for scheme in ("https", "http"):
            limiter.wait()
            url = f"{scheme}://{host}/"
            result = util.run_cmd(
                [curl, "-sS", "-m", str(int(timeout_per_host)), "-D", "-", "-o", "/tmp/_body",
                 "-w", "\n__STATUS__:%{http_code}\n__FINAL_URL__:%{url_effective}\n",
                 "-L", "--max-redirs", "5", url],
                timeout=timeout_per_host + 5,
            )
            if result.timed_out or not result.stdout:
                continue
            status_match = re.search(r"__STATUS__:(\d+)", result.stdout)
            final_match = re.search(r"__FINAL_URL__:(\S+)", result.stdout)
            if not status_match:
                continue
            body = ""
            try:
                with open("/tmp/_body", encoding="utf-8", errors="replace") as fh:
                    body = fh.read(20000)
            except OSError:
                pass
            title_match = TITLE_RE.search(body)
            headers = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    k, _, v = line.partition(":")
                    k = k.strip().lower()
                    if k in ALLOWED_HEADERS:
                        headers[k] = v.strip()
            rows.append({
                "url": url,
                "status_code": int(status_match.group(1)),
                "final_url": final_match.group(1) if final_match else url,
                "title": title_match.group(1).strip()[:300] if title_match else "",
                "content_length": len(body),
                "headers": headers,
            })
            break  # https succeeded (or at least answered) - skip plain-http retry
    status = "ok" if rows else "nothing_found"
    return {"status": status, "rows": rows, "tool": "curl"}


def run(run_id: str, raw_dir: str, scope, conn, hosts: list, timeout: float = 300.0) -> dict:
    started = util.utc_now_iso()
    in_scope_hosts = sorted({h for h in hosts if scope.is_in_scope(h)})
    rps = scope.rate_limits.get("http_rps", 10)

    raw_path = f"{raw_dir}/httpx.jsonl"
    bulk = _httpx_bulk(in_scope_hosts, raw_path, timeout, rps)
    if bulk["status"] == "unavailable":
        bulk = _curl_fallback(in_scope_hosts, raw_dir, timeout_per_host=15, rps=rps)

    observed_at = util.utc_now_iso()
    count = 0
    for row in bulk["rows"]:
        url = row.get("url") or row.get("input") or ""
        if not url:
            continue
        host = urlparse(url).hostname or ""
        final_url = row.get("final_url") or row.get("final-url") or url
        final_host = urlparse(final_url).hostname or host
        final_in_scope = scope.is_in_scope(final_host)

        if not final_in_scope and final_host and final_host != host:
            conn.execute(
                "INSERT INTO third_party_observations(run_id, hostname, points_to, relationship, "
                "note, observed_at) VALUES (?,?,?,?,?,?)",
                (run_id, host, final_host, "redirect",
                 "HTTP redirect leaves scope; destination not probed/crawled", observed_at),
            )

        tech = []
        for t in row.get("tech", []) or []:
            tech.append({"name": str(t), "version": None, "source": "httpx"})
        headers = row.get("header", {}) or row.get("headers", {}) or {}
        if not tech:
            for hk, extractor in TECH_HEADER_HINTS.items():
                v = headers.get(hk) or headers.get(hk.title())
                if v:
                    for item in extractor(v):
                        tech.append({"name": item, "version": None, "source": f"header:{hk}"})

        fingerprint = util.sha256_hex(
            f"{row.get('status_code')}|{row.get('title','')}|{sorted(tech, key=str)}"
        )

        conn.execute(
            """
            INSERT OR REPLACE INTO http_responses
            (run_id, url, hostname, status_code, redirect_chain, final_url, final_host_in_scope,
             title, content_type, content_length, headers_json, tech_json, tls_json,
             fingerprint_hash, observed_at, source_tool)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                run_id, url, host, row.get("status_code"), json.dumps(row.get("chain", [])),
                final_url, int(final_in_scope), row.get("title", ""), row.get("content_type", ""),
                row.get("content_length"), json.dumps(headers), json.dumps(tech),
                json.dumps(row.get("tls", {}) or {}), fingerprint, observed_at, bulk["tool"],
            ),
        )
        for t in tech:
            db.upsert_tech_catalog(conn, host, t["name"], run_id)
        count += 1

    finished = util.utc_now_iso()
    db.record_tool_run(conn, run_id, STAGE, bulk["tool"], CLASSIFICATION, started, finished,
                        0 if bulk["status"] in ("ok", "nothing_found") else None,
                        bulk["status"], bulk.get("error"), item_count=count)

    return {"status": bulk["status"], "mapped": count, "hosts_considered": len(in_scope_hosts)}
