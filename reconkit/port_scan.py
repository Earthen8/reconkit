"""Stage: OPTIONAL_ACTIVE - conservative TCP port discovery via naabu.

Disabled unless the operator explicitly enables it (--enable-portscan or
modules.port_scan: true in scope.yaml) *and* the scope is authorized.
Deliberately conservative: a fixed top-100-ish common-port list rather
than a full 1-65535 sweep, SYN scan left to naabu's own safe default
(connect scan when unprivileged), and a configurable rate cap.
"""
from __future__ import annotations

from . import db, scope as scope_mod, util

STAGE = "port_scan"
CLASSIFICATION = "OPTIONAL_ACTIVE"

CONSERVATIVE_PORTS = (
    "21,22,23,25,53,80,81,88,110,111,135,139,143,161,389,443,445,465,"
    "587,631,636,993,995,1025,1433,1521,1723,2082,2083,2086,2087,2095,"
    "2096,3000,3128,3306,3389,443,5432,5601,5900,5985,5986,6379,7001,"
    "8000,8008,8080,8081,8088,8443,8888,9000,9090,9200,9300,9443,27017"
)


def run(run_id: str, raw_dir: str, scope: "scope_mod.Scope", conn, hosts: list,
        timeout: float = 300.0) -> dict:
    started = util.utc_now_iso()

    if not scope.module_enabled("port_scan"):
        db.record_tool_run(conn, run_id, STAGE, "naabu", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run"}

    auth_error = scope_mod.require_authorization_or_die(scope, STAGE)
    if auth_error:
        db.record_tool_run(conn, run_id, STAGE, "naabu", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", auth_error)
        return {"status": "not_run", "error": auth_error}

    in_scope_hosts = sorted({h for h in hosts if scope.is_in_scope(h)})
    exe = util.which("naabu")
    raw_path = f"{raw_dir}/naabu.jsonl"
    if not exe or not in_scope_hosts:
        status = "unavailable" if not exe else "nothing_found"
        db.record_tool_run(conn, run_id, STAGE, "naabu", CLASSIFICATION, started,
                            util.utc_now_iso(), None, status,
                            None if status == "nothing_found" else "naabu not found on PATH")
        return {"status": status}

    list_path = raw_path.replace(".jsonl", ".hosts.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(in_scope_hosts) + "\n")

    rate = max(10, int(scope.rate_limits.get("portscan_rate", 100)))
    result = util.run_cmd(
        [exe, "-silent", "-json", "-l", list_path, "-p", CONSERVATIVE_PORTS,
         "-rate", str(rate), "-o", raw_path],
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
    count = 0
    for row in rows:
        host = str(row.get("host") or row.get("ip") or "").strip().lower()
        port = row.get("port")
        if not host or not scope.is_in_scope(host) or not isinstance(port, int):
            continue
        conn.execute(
            "INSERT OR REPLACE INTO run_services(run_id, hostname, port, proto, source_tool, "
            "observed_at) VALUES (?,?,?,?,?,?)",
            (run_id, host, port, "tcp", "naabu", observed_at),
        )
        db.upsert_service_catalog(conn, host, port, run_id)
        count += 1

    db.record_tool_run(conn, run_id, STAGE, "naabu", CLASSIFICATION, started, util.utc_now_iso(),
                        result.returncode, status,
                        None if status in ("ok", "nothing_found") else result.stderr[:500],
                        item_count=count)
    return {"status": status, "open_ports": count}
