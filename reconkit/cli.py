"""CLI entry point: `python3 -m reconkit.cli <stage> [flags...]`.

recon.sh calls one subcommand per pipeline stage. Each subcommand opens
its own short-lived SQLite connection+transaction (commit on success) so
a crash in one stage can never leave a half-written transaction open for
the next one. Stages read whatever earlier stages already wrote to
`run_hosts` / `http_responses` / etc. for this run_id rather than having
bash thread long host lists through argv.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import (confidence, content_discovery, correlate, crawl, db, dns_validate,
               historical, http_map, passive, port_scan, report, scope as scope_mod,
               subdomains, util, vuln_scan)


def _add_scope_args(p: argparse.ArgumentParser) -> None:
    # Target type is always an explicit choice - never inferred from the
    # string's shape. Exactly one of these three selects both the target
    # and how it's validated/matched downstream.
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--domain", help="Hostname target, e.g. example.com")
    g.add_argument("--ip", help="Bare IPv4/IPv6 address target, e.g. 203.0.113.10 (no CIDR)")
    g.add_argument("--scope-file")
    p.add_argument("--authorized", default=None, help="Free-text authorization note (simple-target mode)")
    p.add_argument("--enable-portscan", action="store_true")
    p.add_argument("--enable-content-discovery", action="store_true")
    p.add_argument("--enable-vuln-scan", action="store_true")
    p.add_argument("--max-hosts", type=int, default=1000)


def _build_scope(args) -> scope_mod.Scope:
    if args.scope_file:
        try:
            sc = scope_mod.from_yaml_file(args.scope_file)
        except RuntimeError as exc:
            print(f"Scope file error: {exc}", file=sys.stderr)
            sys.exit(2)
    elif getattr(args, "ip", None):
        if not scope_mod.valid_ip(args.ip):
            print(f"Invalid IP address: {args.ip} (bare IPv4/IPv6 only - no CIDR, no hostname).",
                  file=sys.stderr)
            sys.exit(2)
        sc = scope_mod.from_simple_ip(
            args.ip, args.authorized, args.enable_portscan,
            args.enable_content_discovery, args.enable_vuln_scan, args.max_hosts,
        )
    else:
        if scope_mod.valid_ip(args.domain):
            print(f"'{args.domain}' is an IP address - use --ip, not --domain. Target type is "
                  f"always explicit and is never guessed from the string's shape.", file=sys.stderr)
            sys.exit(2)
        if not scope_mod.valid_domain(args.domain):
            print(f"Invalid domain: {args.domain}", file=sys.stderr)
            sys.exit(2)
        sc = scope_mod.from_simple_domain(
            args.domain, args.authorized, args.enable_portscan,
            args.enable_content_discovery, args.enable_vuln_scan, args.max_hosts,
        )

    if sc.target_type == "ip":
        if not scope_mod.valid_ip(sc.domain):
            print(f"Invalid IP in resolved scope: {sc.domain!r}", file=sys.stderr)
            sys.exit(2)
    else:
        if not scope_mod.valid_domain(sc.domain):
            print(f"Invalid domain in scope: {sc.domain!r}", file=sys.stderr)
            sys.exit(2)
    return sc


def _common_run_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--db-path", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--raw-dir", required=True)
    _add_scope_args(p)


def cmd_check_deps(args) -> None:
    tools = ["curl", "dig", "subfinder", "amass", "dnsx", "httpx", "naabu",
             "katana", "gau", "waybackurls", "ffuf", "nuclei"]
    result = {}
    for t in tools:
        path = util.which(t)
        version = None
        if path:
            vr = util.run_cmd([t, "-version"], timeout=5)
            if vr.returncode not in (0, None):
                vr = util.run_cmd([t, "--version"], timeout=5)
            version = (vr.stdout or vr.stderr).strip().splitlines()[0] if (vr.stdout or vr.stderr) else "unknown"
        result[t] = {"found": bool(path), "path": path, "version": version}
    try:
        import yaml  # noqa: F401
        result["pyyaml"] = {"found": True}
    except ImportError:
        result["pyyaml"] = {"found": False, "note": "needed only for --scope-file"}
    print(json.dumps(result, indent=2))
    required_core = ["curl", "dig"]
    missing_core = [t for t in required_core if not result[t]["found"]]
    if missing_core:
        print(f"\nMissing REQUIRED core dependencies: {', '.join(missing_core)}", file=sys.stderr)
        sys.exit(1)


def cmd_scope_check(args) -> None:
    sc = _build_scope(args)
    print(json.dumps({
        "domain": sc.domain, "target_type": sc.target_type,
        "include": sc.include, "exclude": sc.exclude,
        "authorized": sc.is_authorized, "authorized_by": sc.authorized_by,
        "modules": sc.modules, "rate_limits": sc.rate_limits, "limits": sc.limits,
    }, indent=2))


def cmd_init_db(args) -> None:
    db.init_db(args.db_path)


def cmd_new_run(args) -> None:
    sc = _build_scope(args)
    db.init_db(args.db_path)
    with db.cursor(args.db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO runs(run_id, domain, target_type, started_at, finished_at, "
            "config_json, authorized_by, authorization_reference) VALUES (?,?,?,?,?,?,?,?)",
            (args.run_id, sc.domain, sc.target_type, util.utc_now_iso(), None,
             json.dumps({"modules": sc.modules, "rate_limits": sc.rate_limits, "limits": sc.limits}),
             sc.authorized_by, sc.authorization_reference),
        )
        for pattern in sc.include:
            conn.execute("INSERT INTO scope_rules(domain, rule_type, pattern, note) VALUES (?,?,?,?)",
                         (sc.domain, "include", pattern, None))
        for pattern in sc.exclude:
            conn.execute("INSERT INTO scope_rules(domain, rule_type, pattern, note) VALUES (?,?,?,?)",
                         (sc.domain, "exclude", pattern, None))
    print(f"Run {args.run_id} recorded for domain {sc.domain}. Authorized={sc.is_authorized}")


def cmd_finish_run(args) -> None:
    with db.cursor(args.db_path) as conn:
        conn.execute("UPDATE runs SET finished_at=? WHERE run_id=?", (util.utc_now_iso(), args.run_id))


def cmd_log_stage_failure(args) -> None:
    with db.cursor(args.db_path) as conn:
        db.record_tool_run(conn, args.run_id, args.stage, args.stage, "UNKNOWN",
                            util.utc_now_iso(), util.utc_now_iso(), args.exit_code, "failed",
                            f"stage process exited unexpectedly with code {args.exit_code}")


def cmd_passive(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        out = passive.run(args.run_id, args.raw_dir, sc, conn)
    print(json.dumps(out, default=str))


def cmd_subdomains(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        out = subdomains.run(args.run_id, args.raw_dir, sc, conn)
    print(json.dumps(out, default=str))


def _candidate_hosts(conn, run_id: str, max_hosts: int) -> list:
    rows = conn.execute(
        "SELECT DISTINCT hostname FROM run_hosts WHERE run_id=? ORDER BY hostname LIMIT ?",
        (run_id, max_hosts),
    ).fetchall()
    return [r["hostname"] for r in rows]


def cmd_dns_validate(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        hosts = _candidate_hosts(conn, args.run_id, sc.limits["max_hosts"])
        out = dns_validate.run(args.run_id, args.raw_dir, sc, conn, hosts,
                                qps=sc.rate_limits.get("dns_qps", 10))
    print(json.dumps(out, default=str))


def cmd_http_map(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT hostname FROM dns_records WHERE run_id=?", (args.run_id,)
        ).fetchall()
        hosts = [r["hostname"] for r in rows]
        if not hosts:  # dns_validate found nothing / wasn't run - still try the apex
            hosts = [sc.domain]
        out = http_map.run(args.run_id, args.raw_dir, sc, conn, hosts)
    print(json.dumps(out, default=str))


def cmd_port_scan(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        rows = conn.execute(
            "SELECT DISTINCT hostname FROM dns_records WHERE run_id=?", (args.run_id,)
        ).fetchall()
        hosts = [r["hostname"] for r in rows]
        if not hosts:
            # dns_validate found nothing, wasn't run, or (IP mode) is always
            # skipped - fall back to the target itself, same as http_map.
            hosts = [sc.domain]
        out = port_scan.run(args.run_id, args.raw_dir, sc, conn, hosts)
    print(json.dumps(out, default=str))


def cmd_historical(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        out = historical.run(args.run_id, args.raw_dir, sc, conn)
    print(json.dumps(out, default=str))


def _live_urls(conn, run_id: str) -> list:
    rows = conn.execute(
        "SELECT url FROM http_responses WHERE run_id=? AND status_code IS NOT NULL", (run_id,)
    ).fetchall()
    return [r["url"] for r in rows]


def cmd_crawl(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        seeds = _live_urls(conn, args.run_id)
        out = crawl.run(args.run_id, args.raw_dir, sc, conn, seeds)
    print(json.dumps(out, default=str))


def cmd_content_discovery(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        bases = _live_urls(conn, args.run_id)
        out = content_discovery.run(args.run_id, args.raw_dir, sc, conn, bases, args.wordlist)
    print(json.dumps(out, default=str))


def cmd_vuln_scan(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        targets = _live_urls(conn, args.run_id)
        out = vuln_scan.run(args.run_id, args.raw_dir, sc, conn, targets)
    print(json.dumps(out, default=str))


def cmd_correlate(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        out = correlate.run(args.run_id, sc, conn)
    print(json.dumps(out, default=str))


def cmd_confidence(args) -> None:
    sc = _build_scope(args)
    with db.cursor(args.db_path) as conn:
        out = confidence.run(args.run_id, sc, conn)
    print(json.dumps(out, default=str))


def cmd_report(args) -> None:
    sc = _build_scope(args)
    path = report.render(args.run_id, sc, args.db_path, args.out)
    print(path)


def cmd_confirm(args) -> None:
    with db.cursor(args.db_path) as conn:
        row = conn.execute("SELECT * FROM vuln_leads WHERE id=?", (args.lead_id,)).fetchone()
        if not row:
            print(f"No lead with id {args.lead_id}", file=sys.stderr)
            sys.exit(1)
        conn.execute(
            "UPDATE vuln_leads SET status='confirmed', confirmed_by=?, confirmed_at=?, "
            "confirmed_note=?, classification='CONFIRMED_FINDING', confidence='CONFIRMED' WHERE id=?",
            (args.by, util.utc_now_iso(), args.note, args.lead_id),
        )
    print(f"Lead {args.lead_id} marked CONFIRMED_FINDING by {args.by}.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="reconkit")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check-deps").set_defaults(func=cmd_check_deps)

    p = sub.add_parser("scope-check"); _add_scope_args(p); p.set_defaults(func=cmd_scope_check)

    for name, fn in [("init-db", cmd_init_db)]:
        pp = sub.add_parser(name); pp.add_argument("--db-path", required=True); pp.set_defaults(func=fn)

    p = sub.add_parser("new-run"); _common_run_args(p); p.set_defaults(func=cmd_new_run)
    p = sub.add_parser("finish-run")
    p.add_argument("--db-path", required=True); p.add_argument("--run-id", required=True)
    p.set_defaults(func=cmd_finish_run)

    p = sub.add_parser("log-stage-failure")
    p.add_argument("--db-path", required=True); p.add_argument("--run-id", required=True)
    p.add_argument("--stage", required=True); p.add_argument("--exit-code", type=int, default=-1)
    p.set_defaults(func=cmd_log_stage_failure)

    for name, fn in [
        ("passive", cmd_passive), ("subdomains", cmd_subdomains),
        ("dns-validate", cmd_dns_validate), ("http-map", cmd_http_map),
        ("port-scan", cmd_port_scan), ("historical", cmd_historical),
        ("crawl", cmd_crawl), ("vuln-scan", cmd_vuln_scan),
        ("correlate", cmd_correlate), ("confidence", cmd_confidence),
    ]:
        pp = sub.add_parser(name); _common_run_args(pp); pp.set_defaults(func=fn)

    p = sub.add_parser("content-discovery"); _common_run_args(p)
    p.add_argument("--wordlist", required=True); p.set_defaults(func=cmd_content_discovery)

    p = sub.add_parser("report"); _common_run_args(p)
    p.add_argument("--out", required=True); p.set_defaults(func=cmd_report)

    p = sub.add_parser("confirm")
    p.add_argument("--db-path", required=True); p.add_argument("--lead-id", type=int, required=True)
    p.add_argument("--by", required=True); p.add_argument("--note", required=True)
    p.set_defaults(func=cmd_confirm)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
