"""Stage: PASSIVE - Certificate Transparency log harvesting via crt.sh.

This is a direct, hardened port of the original script's crt.sh logic:
same endpoint, same name-validation regex, same "always write *something*
so the run never silently has an empty candidate file" behaviour. No
request is ever sent to the target itself.
"""
from __future__ import annotations

import json
import re
import time
from typing import Optional

from . import db, util

NAME_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

STAGE = "passive"
TOOL = "crt.sh"
CLASSIFICATION = "PASSIVE"


def _extract_names(raw_records, domain: str) -> set:
    names = {domain}
    if not isinstance(raw_records, list):
        return names
    for record in raw_records:
        if not isinstance(record, dict):
            continue
        value = record.get("name_value", "")
        if not isinstance(value, str):
            continue
        for candidate in value.splitlines():
            name = candidate.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            name = name.rstrip(".")
            if NAME_RE.match(name) and (name == domain or name.endswith("." + domain)):
                names.add(name)
    return names


def run(run_id: str, raw_dir: str, scope, conn, timeout: float = 30.0) -> dict:
    started = util.utc_now_iso()

    if scope.target_type == "ip":
        # Certificate Transparency is a domain-name technique; there is no
        # crt.sh query that means anything for a bare IP. Register the
        # target itself as the (only) in-scope host and stop - no HTTP
        # request to crt.sh is made at all in this mode.
        conn.execute(
            "INSERT OR IGNORE INTO run_hosts(run_id, hostname, source, classification) VALUES (?,?,?,?)",
            (run_id, scope.domain, "operator-provided", "input"),
        )
        db.upsert_host_catalog(conn, scope.domain, scope.domain, True, run_id)
        db.record_tool_run(conn, run_id, STAGE, TOOL, CLASSIFICATION, started, util.utc_now_iso(),
                            0, "not_run", "target is an IP address; crt.sh lookup is domain-only "
                            "and was not run")
        return {"status": "not_run", "candidates": [scope.domain], "raw_path": None}

    raw_path = f"{raw_dir}/crtsh.json"
    status, error, exit_code = "ok", None, 0

    curl = util.which("curl")
    raw_text = None
    if curl:
        result = util.run_cmd(
            [curl, "--fail", "--silent", "--show-error", "--max-time", str(int(timeout)),
             "--retry", "1", "-H", "Accept: application/json",
             f"https://crt.sh/?q=%25.{scope.domain}&output=json"],
            timeout=timeout + 10,
        )
        if result.returncode == 0 and not result.timed_out:
            raw_text = result.stdout
        else:
            status = "unavailable"
            error = result.stderr.strip()[:500] or "crt.sh request failed"
    else:
        status, error = "unavailable", "curl not found on PATH"

    with open(raw_path, "w", encoding="utf-8") as fh:
        fh.write(raw_text if raw_text else "[]")

    try:
        records = json.loads(raw_text) if raw_text else []
    except json.JSONDecodeError:
        records, status, error = [], "failed", "crt.sh response was not valid JSON"

    names = _extract_names(records, scope.domain)
    if status == "ok" and len(names) <= 1:
        status = "nothing_found"

    for name in sorted(names):
        in_scope = scope.is_in_scope(name)
        classification = "input" if name == scope.domain else "candidate"
        conn.execute(
            "INSERT OR REPLACE INTO run_hosts(run_id, hostname, source, classification) VALUES (?,?,?,?)",
            (run_id, name, "crt.sh", classification),
        )
        db.upsert_host_catalog(conn, name, scope.domain, in_scope, run_id)
        if not in_scope and not scope.is_third_party(name):
            # in-domain-looking name but excluded by scope rules - still worth a note
            pass

    finished = util.utc_now_iso()
    db.record_tool_run(conn, run_id, STAGE, TOOL, CLASSIFICATION, started, finished,
                        exit_code, status, error, item_count=len(names))
    return {"status": status, "candidates": sorted(names), "raw_path": raw_path}
