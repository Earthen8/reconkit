"""SQLite canonical store: per-run facts plus cross-run history/diffing.

Design notes:
  - every fact table carries run_id, so a run never overwrites another
    run's evidence; "current state" is always "latest run for this
    domain", computed with a query, never by mutating old rows;
  - host_catalog/service_catalog/endpoint_catalog/tech_catalog hold
    first_seen_run/last_seen_run so correlate.py can diff "new since
    last run" / "missing since last run" without re-scanning;
  - tool_runs is the failure-isolation ledger: one row per (run, stage,
    tool) with an explicit status so a failed/unavailable tool is visible
    in the report instead of silently looking like "nothing found".
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Any, Iterable, Optional

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- `domain` holds the target identifier regardless of target_type: an
-- apex domain name, or (when target_type='ip') the exact, normalized IP
-- address string. It is reused as the scope key across host_catalog /
-- scope_rules / service_catalog / tech_catalog / endpoint_catalog below
-- so a run's identity is the same single string whichever target type
-- it is; target_type makes that explicit instead of leaving it implicit.
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'domain', -- 'domain' | 'ip'
    started_at TEXT NOT NULL,
    finished_at TEXT,
    config_json TEXT NOT NULL,
    authorized_by TEXT,
    authorization_reference TEXT
);

-- one row per (run, pipeline stage, underlying tool). status in:
-- ok | nothing_found | not_run | failed | timed_out | unavailable
CREATE TABLE IF NOT EXISTS tool_runs (
    run_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    tool TEXT NOT NULL,
    classification TEXT NOT NULL, -- PASSIVE | SAFE_ACTIVE | OPTIONAL_ACTIVE
    version TEXT,
    started_at TEXT,
    finished_at TEXT,
    exit_code INTEGER,
    status TEXT NOT NULL,
    error TEXT,
    item_count INTEGER DEFAULT 0,
    PRIMARY KEY (run_id, stage, tool)
);

CREATE TABLE IF NOT EXISTS scope_rules (
    domain TEXT NOT NULL,
    rule_type TEXT NOT NULL, -- include | exclude | third_party_suffix
    pattern TEXT NOT NULL,
    note TEXT
);

-- durable catalog: identity of a hostname across runs
CREATE TABLE IF NOT EXISTS host_catalog (
    hostname TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    in_scope INTEGER NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_hosts (
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    classification TEXT NOT NULL, -- input | candidate
    PRIMARY KEY (run_id, hostname)
);

CREATE TABLE IF NOT EXISTS dns_records (
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    source TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS wildcard_dns (
    run_id TEXT NOT NULL,
    base_label TEXT NOT NULL, -- the apex under which wildcard was tested, e.g. example.com
    is_wildcard INTEGER NOT NULL,
    evidence TEXT,
    PRIMARY KEY (run_id, base_label)
);

CREATE TABLE IF NOT EXISTS http_responses (
    run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    status_code INTEGER,
    redirect_chain TEXT,      -- JSON list
    final_url TEXT,
    final_host_in_scope INTEGER,
    title TEXT,
    content_type TEXT,
    content_length INTEGER,
    headers_json TEXT,
    tech_json TEXT,           -- JSON list of {name, version, source}
    tls_json TEXT,            -- JSON object
    fingerprint_hash TEXT,
    observed_at TEXT NOT NULL,
    source_tool TEXT NOT NULL,
    PRIMARY KEY (run_id, url)
);

CREATE TABLE IF NOT EXISTS service_catalog (
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    PRIMARY KEY (hostname, port)
);

CREATE TABLE IF NOT EXISTS run_services (
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    port INTEGER NOT NULL,
    proto TEXT,
    source_tool TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, hostname, port)
);

CREATE TABLE IF NOT EXISTS tech_catalog (
    hostname TEXT NOT NULL,
    technology TEXT NOT NULL,
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL,
    PRIMARY KEY (hostname, technology)
);

CREATE TABLE IF NOT EXISTS historical_urls (
    run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    hostname TEXT NOT NULL,
    source TEXT NOT NULL,
    historically_observed INTEGER NOT NULL DEFAULT 1,
    currently_reachable INTEGER,
    status_code INTEGER,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, url, source)
);

CREATE TABLE IF NOT EXISTS endpoint_catalog (
    endpoint TEXT PRIMARY KEY, -- scheme://host + normalized path
    hostname TEXT NOT NULL,
    endpoint_type TEXT NOT NULL, -- page|api|graphql|websocket|sourcemap|config|js
    first_seen_run TEXT NOT NULL,
    last_seen_run TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS run_endpoints (
    run_id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    hostname TEXT NOT NULL,
    endpoint_type TEXT NOT NULL,
    method_guess TEXT,
    param_names_json TEXT,
    source_tool TEXT NOT NULL,
    source_url TEXT,
    evidence_path TEXT,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, endpoint, source_tool)
);

CREATE TABLE IF NOT EXISTS js_findings (
    run_id TEXT NOT NULL,
    js_url TEXT NOT NULL,
    finding_type TEXT NOT NULL, -- endpoint|hostname|possible_secret_pattern|sourcemap
    value_redacted TEXT NOT NULL,
    note TEXT,
    evidence_path TEXT,
    observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS content_discovery (
    run_id TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    content_length INTEGER,
    baseline_filtered INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, url)
);

CREATE TABLE IF NOT EXISTS third_party_observations (
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    points_to TEXT NOT NULL,
    relationship TEXT NOT NULL, -- cname | redirect | asn
    note TEXT,
    observed_at TEXT NOT NULL
);

-- nuclei (safe-tag only) and any other detector output land here as leads,
-- never pre-classified as a confirmed vulnerability.
CREATE TABLE IF NOT EXISTS vuln_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    template_id TEXT NOT NULL,
    name TEXT,
    severity TEXT,
    matched_at TEXT NOT NULL,
    tags TEXT,
    evidence_path TEXT,
    classification TEXT NOT NULL DEFAULT 'LEAD', -- OBSERVATION|LEAD|VULNERABILITY_CANDIDATE
    confidence TEXT NOT NULL DEFAULT 'LOW',
    confidence_reason TEXT,
    status TEXT NOT NULL DEFAULT 'open', -- open|confirmed|false_positive
    confirmed_by TEXT,
    confirmed_at TEXT,
    confirmed_note TEXT,
    observed_at TEXT NOT NULL
);

-- confidence.py's output: one row per (run, hostname) classifying it as
-- ASSET or OBSERVATION with an explainable confidence tier + reason.
CREATE TABLE IF NOT EXISTS asset_assessment (
    run_id TEXT NOT NULL,
    hostname TEXT NOT NULL,
    classification TEXT NOT NULL, -- ASSET | OBSERVATION
    confidence TEXT NOT NULL,     -- CONFIRMED|HIGH|MEDIUM|LOW|INFORMATIONAL
    reason TEXT NOT NULL,
    sources_json TEXT NOT NULL,
    PRIMARY KEY (run_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_vuln_leads_run ON vuln_leads(run_id);
CREATE INDEX IF NOT EXISTS idx_http_run ON http_responses(run_id);
CREATE INDEX IF NOT EXISTS idx_hist_run ON historical_urls(run_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_run ON run_endpoints(run_id);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Lightweight forward-only migration for columns added after a
    recon.db already existed. CREATE TABLE IF NOT EXISTS alone can't add
    a column to a table that was created by an older schema version."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(runs)")}
    if "target_type" not in cols:
        conn.execute("ALTER TABLE runs ADD COLUMN target_type TEXT NOT NULL DEFAULT 'domain'")


def init_db(db_path: str) -> None:
    conn = connect(db_path)
    try:
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.commit()
    finally:
        conn.close()


@contextmanager
def cursor(db_path: str):
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def upsert_host_catalog(conn, hostname: str, domain: str, in_scope: bool, run_id: str) -> None:
    conn.execute(
        """
        INSERT INTO host_catalog(hostname, domain, in_scope, first_seen_run, last_seen_run)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            last_seen_run=excluded.last_seen_run,
            in_scope=excluded.in_scope
        """,
        (hostname, domain, int(in_scope), run_id, run_id),
    )


def upsert_service_catalog(conn, hostname: str, port: int, run_id: str) -> None:
    conn.execute(
        """
        INSERT INTO service_catalog(hostname, port, first_seen_run, last_seen_run)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(hostname, port) DO UPDATE SET last_seen_run=excluded.last_seen_run
        """,
        (hostname, port, run_id, run_id),
    )


def upsert_tech_catalog(conn, hostname: str, technology: str, run_id: str) -> None:
    conn.execute(
        """
        INSERT INTO tech_catalog(hostname, technology, first_seen_run, last_seen_run)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(hostname, technology) DO UPDATE SET last_seen_run=excluded.last_seen_run
        """,
        (hostname, technology, run_id, run_id),
    )


def upsert_endpoint_catalog(conn, endpoint: str, hostname: str, endpoint_type: str, run_id: str) -> None:
    conn.execute(
        """
        INSERT INTO endpoint_catalog(endpoint, hostname, endpoint_type, first_seen_run, last_seen_run)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(endpoint) DO UPDATE SET last_seen_run=excluded.last_seen_run
        """,
        (endpoint, hostname, endpoint_type, run_id, run_id),
    )


def record_tool_run(
    conn,
    run_id: str,
    stage: str,
    tool: str,
    classification: str,
    started_at: str,
    finished_at: Optional[str],
    exit_code: Optional[int],
    status: str,
    error: Optional[str],
    item_count: int = 0,
    version: Optional[str] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO tool_runs(run_id, stage, tool, classification, version, started_at,
                               finished_at, exit_code, status, error, item_count)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(run_id, stage, tool) DO UPDATE SET
            finished_at=excluded.finished_at, exit_code=excluded.exit_code,
            status=excluded.status, error=excluded.error, item_count=excluded.item_count,
            version=excluded.version
        """,
        (run_id, stage, tool, classification, version, started_at, finished_at, exit_code, status, error, item_count),
    )


def latest_previous_run(conn, domain: str, before_run_id: str) -> Optional[str]:
    row = conn.execute(
        "SELECT run_id FROM runs WHERE domain=? AND run_id < ? ORDER BY run_id DESC LIMIT 1",
        (domain, before_run_id),
    ).fetchone()
    return row["run_id"] if row else None


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list:
    return [dict(r) for r in rows]
