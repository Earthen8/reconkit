"""Stage: PASSIVE - subfinder and amass (passive mode only).

Both tools only query third-party OSINT sources (passive DNS, search
engines, transparency logs, etc.) - amass is explicitly invoked with
`-passive` so it never sends traffic to the target itself. Each tool's
raw output is preserved verbatim; failures/absence of either tool are
recorded individually and never abort the stage.
"""
from __future__ import annotations

import json

from . import db, util

STAGE = "subdomains"
CLASSIFICATION = "PASSIVE"


def _run_subfinder(domain: str, raw_dir: str, timeout: float) -> tuple[str, str, set]:
    started = util.utc_now_iso()
    exe = util.which("subfinder")
    names: set = set()
    if not exe:
        return "unavailable", "subfinder not found on PATH", names
    raw_path = f"{raw_dir}/subfinder.json"
    result = util.run_cmd([exe, "-d", domain, "-silent", "-json", "-o", raw_path], timeout=timeout)
    if result.timed_out:
        return "timed_out", "subfinder exceeded timeout", names
    if result.returncode not in (0, None) and not _file_has_content(raw_path):
        return "failed", (result.stderr or "subfinder returned non-zero exit")[:500], names
    for row in util.read_jsonl(raw_path):
        host = str(row.get("host", "")).strip().lower()
        if host:
            names.add(host)
    status = "ok" if names else "nothing_found"
    return status, None, names


def _run_amass(domain: str, raw_dir: str, timeout: float) -> tuple[str, str, set]:
    exe = util.which("amass")
    names: set = set()
    if not exe:
        return "unavailable", "amass not found on PATH", names
    raw_path = f"{raw_dir}/amass.txt"
    result = util.run_cmd(
        [exe, "enum", "-passive", "-d", domain, "-o", raw_path],
        timeout=timeout,
    )
    if result.timed_out:
        return "timed_out", "amass exceeded timeout", names
    try:
        with open(raw_path, encoding="utf-8") as fh:
            for line in fh:
                host = line.strip().lower()
                if host:
                    names.add(host)
    except OSError:
        pass
    if not names and result.returncode not in (0, None):
        return "failed", (result.stderr or "amass returned non-zero exit")[:500], names
    status = "ok" if names else "nothing_found"
    return status, None, names


def _file_has_content(path: str) -> bool:
    try:
        return any(line.strip() for line in open(path, encoding="utf-8"))
    except OSError:
        return False


def run(run_id: str, raw_dir: str, scope, conn, timeout_subfinder: float = 120.0,
        timeout_amass: float = 180.0) -> dict:
    all_names: set = set()

    for tool, runner, timeout in (
        ("subfinder", _run_subfinder, timeout_subfinder),
        ("amass", _run_amass, timeout_amass),
    ):
        started = util.utc_now_iso()
        status, error, names = runner(scope.domain, raw_dir, timeout)
        finished = util.utc_now_iso()
        db.record_tool_run(conn, run_id, STAGE, tool, CLASSIFICATION, started, finished,
                            0 if status in ("ok", "nothing_found") else None, status, error,
                            item_count=len(names))
        all_names |= names

    for name in sorted(all_names):
        name = name.rstrip(".")
        if not name:
            continue
        in_scope = scope.is_in_scope(name)
        conn.execute(
            "INSERT OR IGNORE INTO run_hosts(run_id, hostname, source, classification) VALUES (?,?,?,?)",
            (run_id, name, "subfinder/amass", "candidate"),
        )
        db.upsert_host_catalog(conn, name, scope.domain, in_scope, run_id)

    return {"candidates": sorted(all_names)}
