"""Stage: SAFE_ACTIVE - crawling (katana) plus static JS/endpoint/parameter
discovery.

Crawling is scoped (katana is pointed only at in-scope seed URLs, with
an explicit -depth cap) and rate-limited. JS files discovered during the
crawl are fetched once each (also rate-limited) and scanned with
regexes for: endpoint-shaped paths, absolute URLs to other hostnames,
GraphQL/WebSocket indicators, source-map references, and
*shapes* that look like tokens/keys. Matches on the latter are stored
redacted (see util.redact) - this stage reports that a secret-shaped
string exists at a location, it does not extract, store or validate the
value, and it never treats a regex match as a confirmed credential.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from . import db, scope as scope_mod, util

STAGE = "crawl"
CLASSIFICATION = "SAFE_ACTIVE"

JS_EXT_RE = re.compile(r"\.js(\?|$)", re.IGNORECASE)
ENDPOINT_PATH_RE = re.compile(r"""["'](/[a-zA-Z0-9_\-/{}.]{2,200})["']""")
ABS_URL_RE = re.compile(r"""https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^\s"'<>]*""")
GRAPHQL_RE = re.compile(r"/graphql\b", re.IGNORECASE)
WS_RE = re.compile(r"""wss?://[^\s"'<>]+""")
SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=([^\s]+)")
PARAM_RE = re.compile(r"[?&]([a-zA-Z0-9_\-]{1,40})=")
# shape-only heuristics - these flag "looks like a credential", never confirm one
SECRET_SHAPE_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic_bearer_token", re.compile(r"""\bBearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}""")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("high_entropy_assignment", re.compile(
        r"""\b(?:api[_-]?key|secret|token|password)\b\s*[:=]\s*["'][A-Za-z0-9\-_]{16,}["']""",
        re.IGNORECASE,
    )),
]


def _katana_crawl(seed_urls: list, raw_path: str, scope: "scope_mod.Scope", timeout: float) -> dict:
    exe = util.which("katana")
    if not exe or not seed_urls:
        return {"status": "unavailable" if not exe else "nothing_found", "urls": []}
    list_path = raw_path.replace(".jsonl", ".seeds.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(seed_urls) + "\n")
    depth = int(scope.limits.get("crawl_depth", 2))
    rps = max(1, int(scope.rate_limits.get("crawl_rps", 5)))
    allowed_hosts = sorted({
        urlparse(url).hostname.lower()
        for url in seed_urls
        if urlparse(url).hostname and scope.is_in_scope(urlparse(url).hostname)
    })
    if not allowed_hosts:
        return {"status": "nothing_found", "urls": []}
    host_regex = "|".join(
        re.escape(f"[{host}]" if ":" in host else host) for host in allowed_hosts
    )
    scope_regex = rf"^https?://(?:{host_regex})(?::\d+)?(?:/|$)"
    result = util.run_cmd(
        [exe, "-silent", "-jsonl", "-list", list_path, "-depth", str(depth),
         "-rate-limit", str(rps), "-cs", scope_regex, "-dr",
         "-o", raw_path],
        timeout=timeout,
    )
    if result.timed_out:
        return {"status": "timed_out", "urls": []}
    rows = util.read_jsonl(raw_path)
    urls = []
    for row in rows:
        u = row.get("request", {}).get("endpoint") or row.get("endpoint") or row.get("url")
        if u:
            urls.append(u)
    if not urls and result.returncode not in (0, None):
        return {"status": "failed", "urls": [], "error": result.stderr[:500]}
    return {"status": "ok" if urls else "nothing_found", "urls": urls}


def _normalize_endpoint(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path or '/'}"


def _classify_endpoint(url: str) -> str:
    low = url.lower()
    if "graphql" in low:
        return "graphql"
    if low.startswith("ws://") or low.startswith("wss://"):
        return "websocket"
    if JS_EXT_RE.search(low):
        return "js"
    if "/api/" in low or low.rstrip("/").endswith("/api"):
        return "api"
    return "page"


def _fetch_js(js_url: str, timeout: float = 10.0) -> str:
    curl = util.which("curl")
    if not curl:
        return ""
    result = util.run_cmd([curl, "-sS", "-m", str(int(timeout)), js_url], timeout=timeout + 5)
    if result.timed_out:
        return ""
    return result.stdout[:500_000]  # cap to keep regex scanning bounded


def run(run_id: str, raw_dir: str, scope: "scope_mod.Scope", conn, seed_urls: list,
        timeout: float = 300.0) -> dict:
    started = util.utc_now_iso()

    if not scope.module_enabled("crawl"):
        db.record_tool_run(conn, run_id, STAGE, "katana", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run"}

    auth_error = scope_mod.require_authorization_or_die(scope, STAGE)
    if auth_error:
        db.record_tool_run(conn, run_id, STAGE, "katana", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", auth_error)
        return {"status": "not_run", "error": auth_error}

    in_scope_seeds = [u for u in seed_urls if scope.is_in_scope(urlparse(u).hostname or "")]
    raw_path = f"{raw_dir}/katana.jsonl"
    crawl_result = _katana_crawl(in_scope_seeds, raw_path, scope, timeout)
    status = crawl_result["status"]
    observed_at = util.utc_now_iso()

    js_urls = set()
    endpoint_count = 0
    for url in crawl_result["urls"]:
        host = urlparse(url).hostname or ""
        if not scope.is_in_scope(host):
            conn.execute(
                "INSERT INTO third_party_observations(run_id, hostname, points_to, relationship, "
                "note, observed_at) VALUES (?,?,?,?,?,?)",
                (run_id, host, host, "crawl_discovered_out_of_scope",
                 "Link discovered during crawl points outside scope; not fetched", observed_at),
            )
            continue
        endpoint = _normalize_endpoint(url)
        etype = _classify_endpoint(url)
        db.upsert_endpoint_catalog(conn, endpoint, host, etype, run_id)
        conn.execute(
            "INSERT OR REPLACE INTO run_endpoints(run_id, endpoint, hostname, endpoint_type, "
            "method_guess, param_names_json, source_tool, source_url, evidence_path, observed_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run_id, endpoint, host, etype, "GET",
             "[]", "katana", url, raw_path, observed_at),
        )
        endpoint_count += 1
        if etype == "js":
            js_urls.add(url)

    # --- JS static analysis -----------------------------------------
    js_rate = max(1, int(scope.rate_limits.get("crawl_rps", 5)))
    limiter = util.RateLimiter(js_rate)
    js_evidence_dir = f"{raw_dir}/js"
    util.ensure_dirs(js_evidence_dir)
    js_finding_count = 0

    for js_url in sorted(js_urls):
        limiter.wait()
        body = _fetch_js(js_url)
        if not body:
            continue
        ev_path = f"{js_evidence_dir}/{util.safe_filename(js_url)}.js"
        with open(ev_path, "w", encoding="utf-8") as fh:
            fh.write(body)

        found_paths = set(m.group(1) for m in ENDPOINT_PATH_RE.finditer(body))
        for path in found_paths:
            endpoint = f"{urlparse(js_url).scheme}://{urlparse(js_url).hostname}{path}"
            params = sorted(set(PARAM_RE.findall(path)))
            db.upsert_endpoint_catalog(conn, endpoint, urlparse(js_url).hostname or "",
                                        "api" if "/api/" in path else "page", run_id)
            conn.execute(
                "INSERT OR REPLACE INTO run_endpoints(run_id, endpoint, hostname, endpoint_type, "
                "method_guess, param_names_json, source_tool, source_url, evidence_path, observed_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (run_id, endpoint, urlparse(js_url).hostname or "",
                 "api" if "/api/" in path else "page", None,
                 json.dumps(params),
                 "js_static_analysis", js_url, ev_path, observed_at),
            )

        for host_match in ABS_URL_RE.finditer(body):
            other_host = host_match.group(1).lower()
            if other_host and not scope.is_in_scope(other_host):
                conn.execute(
                    "INSERT INTO js_findings(run_id, js_url, finding_type, value_redacted, note, "
                    "evidence_path, observed_at) VALUES (?,?,?,?,?,?,?)",
                    (run_id, js_url, "hostname", other_host,
                     "External hostname referenced in JS (intelligence only)", ev_path, observed_at),
                )

        if GRAPHQL_RE.search(body):
            conn.execute(
                "INSERT INTO js_findings(run_id, js_url, finding_type, value_redacted, note, "
                "evidence_path, observed_at) VALUES (?,?,?,?,?,?,?)",
                (run_id, js_url, "endpoint", "/graphql", "GraphQL path reference in JS",
                 ev_path, observed_at),
            )

        for ws_match in WS_RE.finditer(body):
            conn.execute(
                "INSERT INTO js_findings(run_id, js_url, finding_type, value_redacted, note, "
                "evidence_path, observed_at) VALUES (?,?,?,?,?,?,?)",
                (run_id, js_url, "endpoint", util.redact(ws_match.group(0)),
                 "WebSocket URL referenced in JS", ev_path, observed_at),
            )

        sm_match = SOURCEMAP_RE.search(body)
        if sm_match:
            sm_url = urljoin(js_url, sm_match.group(1))
            conn.execute(
                "INSERT INTO js_findings(run_id, js_url, finding_type, value_redacted, note, "
                "evidence_path, observed_at) VALUES (?,?,?,?,?,?,?)",
                (run_id, js_url, "sourcemap", sm_url,
                 "Source map reference - may expose original source structure",
                 ev_path, observed_at),
            )

        for label, pattern in SECRET_SHAPE_PATTERNS:
            for m in pattern.finditer(body):
                js_finding_count += 1
                conn.execute(
                    "INSERT INTO js_findings(run_id, js_url, finding_type, value_redacted, note, "
                    "evidence_path, observed_at) VALUES (?,?,?,?,?,?,?)",
                    (run_id, js_url, "possible_secret_pattern", util.redact(m.group(0)),
                     f"Shape matched '{label}'; NOT validated or extracted - treat as LOW-confidence "
                     f"lead requiring manual review", ev_path, observed_at),
                )

    db.record_tool_run(conn, run_id, STAGE, "katana", CLASSIFICATION, started, util.utc_now_iso(),
                        0 if status in ("ok", "nothing_found") else None, status,
                        crawl_result.get("error"), item_count=endpoint_count)

    return {
        "status": status,
        "endpoints_found": endpoint_count,
        "js_files_analyzed": len(js_urls),
        "secret_shape_leads": js_finding_count,
    }
