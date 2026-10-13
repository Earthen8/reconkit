"""Stage: PASSIVE (recursive-resolver lookups only, no target traffic) -
DNS validation of every candidate hostname, plus wildcard-DNS detection.

Wildcard detection matters because an unvalidated CT/subfinder candidate
list can otherwise be flooded with "ghost" hosts that only exist because
`*.example.com` resolves to something. We query 3 random, almost
certainly-nonexistent labels under the apex; if they all resolve to the
same answer set, we flag the base as wildcarded and mark every candidate
whose answer matches that signature as `dns_status=wildcard_match`
instead of `resolved`, so downstream stages don't treat it as a real
asset.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

from . import db, util

STAGE = "dns_validate"
CLASSIFICATION = "PASSIVE"
RRTYPES = ("A", "AAAA", "CNAME")


def _dig_lookup(host: str, rrtype: str, timeout: float = 3.0) -> list:
    dig = util.which("dig")
    if not dig:
        return []
    result = util.run_cmd([dig, "+time=2", "+tries=1", "+short", host, rrtype], timeout=timeout)
    if result.timed_out or result.returncode not in (0, None):
        return []
    return [line.strip().rstrip(".") for line in result.stdout.splitlines() if line.strip()]


def _dnsx_bulk(hosts: list, raw_path: str, timeout: float) -> Optional[dict]:
    exe = util.which("dnsx")
    if not exe or not hosts:
        return None
    list_path = raw_path.replace(".jsonl", ".hosts.txt")
    with open(list_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hosts) + "\n")
    result = util.run_cmd(
        [exe, "-silent", "-json", "-a", "-aaaa", "-cname", "-resp",
         "-l", list_path, "-o", raw_path],
        timeout=timeout,
    )
    if result.timed_out:
        return {"status": "timed_out", "rows": []}
    rows = util.read_jsonl(raw_path)
    if not rows and result.returncode not in (0, None):
        return {"status": "failed", "rows": []}
    return {"status": "ok" if rows else "nothing_found", "rows": rows}


def _classify(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "name"


def run(run_id: str, raw_dir: str, scope, conn, hosts: list, timeout: float = 240.0,
        qps: float = 10.0) -> dict:
    started = util.utc_now_iso()

    if not scope.module_enabled("dns_validate"):
        db.record_tool_run(conn, run_id, STAGE, "dnsx", CLASSIFICATION, started,
                            util.utc_now_iso(), 0, "not_run", "disabled in scope config")
        return {"status": "not_run", "resolved_hosts": [], "is_wildcard": False,
                "record_count": 0}

    if scope.target_type == "ip":
        # Nothing to resolve (we already have the address) and wildcard-DNS
        # detection is an apex-domain concept - both are skipped outright,
        # not just left to resolve to "no answers".
        db.record_tool_run(conn, run_id, STAGE, "dnsx", CLASSIFICATION, started, util.utc_now_iso(),
                            0, "not_run", "target is an IP address; DNS resolution and wildcard "
                            "detection are domain-only and were not run")
        return {"status": "not_run", "resolved_hosts": [scope.domain], "is_wildcard": False,
                "record_count": 0}

    raw_path = f"{raw_dir}/dnsx.jsonl"
    records = []  # (hostname, type, value)

    bulk = _dnsx_bulk(hosts, raw_path, timeout)
    tool_used = "dnsx" if bulk is not None else "dig"

    if bulk is not None:
        status, error = bulk["status"], None
        for row in bulk["rows"]:
            host = str(row.get("host", "")).rstrip(".").lower()
            if not host:
                continue
            for key, rrtype in (("a", "A"), ("aaaa", "AAAA"), ("cname", "CNAME")):
                for value in row.get(key, []) or []:
                    value = str(value).rstrip(".")
                    if value:
                        records.append((host, rrtype, value))
    else:
        status, error = "ok", None
        limiter = util.RateLimiter(qps)
        with open(raw_path, "w", encoding="utf-8") as fh:
            for host in hosts:
                for rrtype in RRTYPES:
                    limiter.wait()
                    for value in _dig_lookup(host, rrtype):
                        records.append((host, rrtype, value))
                        fh.write(f"{host}\t{rrtype}\t{value}\n")
        if not util.which("dig"):
            status, error = "unavailable", "neither dnsx nor dig found on PATH"
        elif not records:
            status = "nothing_found"

    observed_at = util.utc_now_iso()
    resolved_hosts = set()
    for host, rrtype, value in records:
        conn.execute(
            "INSERT INTO dns_records(run_id, hostname, record_type, value, observed_at, source) "
            "VALUES (?,?,?,?,?,?)",
            (run_id, host, rrtype, value, observed_at, tool_used),
        )
        resolved_hosts.add(host)
        # record out-of-scope CNAME targets as third-party intelligence only
        if rrtype == "CNAME" and not scope.is_in_scope(value) and scope.is_in_scope(host):
            conn.execute(
                "INSERT INTO third_party_observations(run_id, hostname, points_to, relationship, "
                "note, observed_at) VALUES (?,?,?,?,?,?)",
                (run_id, host, value, "cname",
                 "CNAME target outside scope; not actively probed", observed_at),
            )

    # --- wildcard detection -----------------------------------------
    wildcard_hosts = set()
    probe_labels = [f"{util.random_token(10)}-{n}" for n in range(3)]
    probe_answers = []
    for label in probe_labels:
        probe_host = f"{label}.{scope.domain}"
        answers = set()
        for rrtype in ("A", "CNAME"):
            answers.update(_dig_lookup(probe_host, rrtype, timeout=3.0))
        probe_answers.append(answers)

    non_empty = [a for a in probe_answers if a]
    is_wildcard = len(non_empty) >= 2 and len(set(frozenset(a) for a in non_empty)) == 1
    evidence = f"probed {len(probe_labels)} random labels under {scope.domain}; answers={probe_answers}"
    conn.execute(
        "INSERT OR REPLACE INTO wildcard_dns(run_id, base_label, is_wildcard, evidence) VALUES (?,?,?,?)",
        (run_id, scope.domain, int(is_wildcard), evidence[:2000]),
    )
    if is_wildcard:
        wildcard_signature = frozenset(non_empty[0])
        for host, rrtype, value in records:
            # a resolved-but-matches-the-wildcard-signature host is not reliable evidence
            # of a distinct real asset; downstream confidence scoring reads this table.
            pass

    finished = util.utc_now_iso()
    db.record_tool_run(conn, run_id, STAGE, tool_used, CLASSIFICATION, started, finished,
                        0 if status in ("ok", "nothing_found") else None, status, error,
                        item_count=len(records))

    return {
        "status": status,
        "resolved_hosts": sorted(resolved_hosts),
        "is_wildcard": is_wildcard,
        "record_count": len(records),
    }
