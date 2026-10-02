"""Stage: correlation layer - diffs the current run against the most
recent previous run for the same domain, using the *_catalog tables'
first_seen_run/last_seen_run bookkeeping (see db.py).

This is what lets the report say "3 new hosts since last Tuesday's run"
instead of just listing everything found today.
"""
from __future__ import annotations

from . import db


def _diff(conn, table: str, key_cols: list, run_id: str, previous_run_id: str) -> dict:
    key_expr = ", ".join(key_cols)
    new_rows = conn.execute(
        f"SELECT {key_expr} FROM {table} WHERE first_seen_run = ?", (run_id,)
    ).fetchall()
    missing_rows = conn.execute(
        f"SELECT {key_expr} FROM {table} WHERE last_seen_run = ? AND last_seen_run != ?",
        (previous_run_id, run_id),
    ).fetchall()
    return {
        "new": [dict(r) for r in new_rows],
        "missing_since_previous_run": [dict(r) for r in missing_rows],
    }


def run(run_id: str, scope, conn) -> dict:
    previous_run_id = db.latest_previous_run(conn, scope.domain, run_id)
    if not previous_run_id:
        return {"previous_run_id": None, "note": "first run for this domain - no diff available"}

    diffs = {
        "hosts": _diff(conn, "host_catalog", ["hostname"], run_id, previous_run_id),
        "services": _diff(conn, "service_catalog", ["hostname", "port"], run_id, previous_run_id),
        "technologies": _diff(conn, "tech_catalog", ["hostname", "technology"], run_id, previous_run_id),
        "endpoints": _diff(conn, "endpoint_catalog", ["endpoint"], run_id, previous_run_id),
    }
    diffs["previous_run_id"] = previous_run_id
    return diffs
