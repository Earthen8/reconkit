"""Renders report.html from recon.db. All target-controlled strings
(titles, headers, hostnames, nuclei names, JS findings...) go through
html.escape before ever touching the page - the report itself is a
piece of untrusted-data-rendering code and is treated that way.
"""
from __future__ import annotations

import html
import json

from . import db

CSS = """
body{font:15px/1.5 -apple-system,system-ui,sans-serif;max-width:1200px;margin:32px auto;padding:0 18px;color:#182230;background:#fff}
h1{margin-bottom:4px} h2{margin-top:40px;border-bottom:2px solid #eee;padding-bottom:6px}
.badge{display:inline-block;padding:3px 9px;border-radius:12px;font-size:12px;font-weight:600;margin-right:4px}
.b-confirmed{background:#1b5e20;color:#fff} .b-high{background:#2e7d32;color:#fff}
.b-medium{background:#f9a825;color:#111} .b-low{background:#ef6c00;color:#fff}
.b-info{background:#90a4ae;color:#111}
.b-asset{background:#0d47a1;color:#fff} .b-observation{background:#607d8b;color:#fff}
.b-lead{background:#6a1b9a;color:#fff} .b-candidate{background:#c62828;color:#fff}
.b-ok{background:#2e7d32;color:#fff} .b-unavailable{background:#9e9e9e;color:#fff}
.b-failed{background:#c62828;color:#fff} .b-timed_out{background:#ef6c00;color:#fff}
.b-nothing_found{background:#607d8b;color:#fff} .b-not_run{background:#bdbdbd;color:#111}
table{border-collapse:collapse;width:100%;margin-top:10px;font-size:14px}
th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #e3e8ee;overflow-wrap:anywhere;vertical-align:top}
th{background:#f7f9fb}
small{color:#52606d} code{background:#f3f5f7;padding:1px 5px;border-radius:4px;font-size:12.5px}
.note{background:#fff8e1;border:1px solid #ffe082;padding:10px 14px;border-radius:6px;margin:14px 0}
"""


def _badge(cls: str, text: str) -> str:
    key = text.strip().lower().replace(" ", "_")
    return f'<span class="badge b-{key}">{html.escape(text)}</span>'


def _table(headers: list, rows: list) -> str:
    if not rows:
        return "<p><small>None.</small></p>"
    head = "".join(f"<th>{html.escape(h)}</th>" for h in headers)
    body = ""
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        body += f"<tr>{cells}</tr>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def render(run_id: str, scope, db_path: str, out_path: str) -> str:
    conn = db.connect(db_path)
    try:
        run_row = conn.execute("SELECT * FROM runs WHERE run_id=?", (run_id,)).fetchone()

        tool_rows = conn.execute(
            "SELECT * FROM tool_runs WHERE run_id=? ORDER BY stage, tool", (run_id,)
        ).fetchall()
        tool_table = _table(
            ["Stage", "Tool", "Class", "Status", "Items", "Error"],
            [
                [
                    html.escape(r["stage"]), html.escape(r["tool"]), html.escape(r["classification"]),
                    _badge("status", r["status"]), str(r["item_count"] or 0),
                    html.escape((r["error"] or "")[:200]),
                ]
                for r in tool_rows
            ],
        )

        assets = conn.execute(
            "SELECT * FROM asset_assessment WHERE run_id=? ORDER BY "
            "CASE confidence WHEN 'CONFIRMED' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 "
            "WHEN 'LOW' THEN 3 ELSE 4 END, hostname", (run_id,),
        ).fetchall()
        asset_table = _table(
            ["Hostname", "Classification", "Confidence", "Reason", "Sources"],
            [
                [
                    html.escape(a["hostname"]), _badge("class", a["classification"]),
                    _badge("conf", a["confidence"]), html.escape(a["reason"]),
                    html.escape(", ".join(json.loads(a["sources_json"]))),
                ]
                for a in assets
            ],
        )

        http_rows = conn.execute(
            "SELECT * FROM http_responses WHERE run_id=? ORDER BY hostname", (run_id,)
        ).fetchall()
        http_table = _table(
            ["URL", "Status", "Title", "Tech", "Final URL (in scope?)"],
            [
                [
                    f'<a href="{html.escape(h["url"])}" rel="noopener">{html.escape(h["url"])}</a>',
                    str(h["status_code"] or ""), html.escape((h["title"] or "")[:120]),
                    html.escape(", ".join(t.get("name", "") for t in json.loads(h["tech_json"] or "[]"))),
                    f'{html.escape(h["final_url"] or "")} ({"yes" if h["final_host_in_scope"] else "NO - external"})',
                ]
                for h in http_rows
            ],
        )

        svc_rows = conn.execute(
            "SELECT * FROM run_services WHERE run_id=? ORDER BY hostname, port", (run_id,)
        ).fetchall()
        svc_table = _table(
            ["Hostname", "Port", "Proto", "Source"],
            [[html.escape(s["hostname"]), str(s["port"]), html.escape(s["proto"] or ""),
              html.escape(s["source_tool"])] for s in svc_rows],
        )

        hist_rows = conn.execute(
            "SELECT * FROM historical_urls WHERE run_id=? ORDER BY hostname LIMIT 500", (run_id,)
        ).fetchall()
        hist_table = _table(
            ["URL", "Historically observed", "Currently reachable", "Status"],
            [
                [html.escape(u["url"]), "yes" if u["historically_observed"] else "no",
                 "yes" if u["currently_reachable"] else ("unknown" if u["currently_reachable"] is None else "no"),
                 str(u["status_code"] or "")]
                for u in hist_rows
            ],
        )

        ep_rows = conn.execute(
            "SELECT * FROM run_endpoints WHERE run_id=? ORDER BY endpoint_type, hostname LIMIT 1000",
            (run_id,),
        ).fetchall()
        ep_table = _table(
            ["Endpoint", "Type", "Source tool"],
            [[html.escape(e["endpoint"]), html.escape(e["endpoint_type"]), html.escape(e["source_tool"])]
             for e in ep_rows],
        )

        js_rows = conn.execute("SELECT * FROM js_findings WHERE run_id=?", (run_id,)).fetchall()
        js_table = _table(
            ["JS file", "Finding type", "Value (redacted where applicable)", "Note"],
            [[html.escape(j["js_url"]), html.escape(j["finding_type"]), html.escape(j["value_redacted"]),
              html.escape(j["note"] or "")] for j in js_rows],
        )

        cd_rows = conn.execute(
            "SELECT * FROM content_discovery WHERE run_id=? AND baseline_filtered=0 ORDER BY url",
            (run_id,),
        ).fetchall()
        cd_table = _table(
            ["URL", "Status", "Length"],
            [[html.escape(c["url"]), str(c["status_code"] or ""), str(c["content_length"] or "")]
             for c in cd_rows],
        )

        leads = conn.execute(
            "SELECT * FROM vuln_leads WHERE run_id=? ORDER BY "
            "CASE classification WHEN 'VULNERABILITY_CANDIDATE' THEN 0 ELSE 1 END, severity DESC",
            (run_id,),
        ).fetchall()
        lead_table = _table(
            ["Template", "Name", "Severity", "Matched at", "Classification", "Confidence", "Status", "Reason"],
            [
                [
                    html.escape(l["template_id"]), html.escape(l["name"] or ""),
                    html.escape(l["severity"] or ""), html.escape(l["matched_at"]),
                    _badge("class", l["classification"]), _badge("conf", l["confidence"]),
                    html.escape(l["status"]), html.escape(l["confidence_reason"] or ""),
                ]
                for l in leads
            ],
        )

        tp_rows = conn.execute(
            "SELECT * FROM third_party_observations WHERE run_id=?", (run_id,)
        ).fetchall()
        tp_table = _table(
            ["Hostname", "Points to / redirects to", "Relationship", "Note"],
            [[html.escape(t["hostname"]), html.escape(t["points_to"]), html.escape(t["relationship"]),
              html.escape(t["note"] or "")] for t in tp_rows],
        )

        scope_note = ""
        if scope.target_type == "ip":
            scope_note = (
                '<div class="note"><strong>Single-IP scope.</strong> This run\'s scope is exactly '
                f'one address: <code>{html.escape(scope.domain)}</code> — no CIDR range, no other '
                "address, and no hostname that merely resolves to it. Certificate Transparency "
                "lookup, subdomain enumeration, and DNS wildcard detection are domain-only "
                "techniques and were not run (see Pipeline execution below).</div>"
            )
        else:
            wc_row = conn.execute(
                "SELECT * FROM wildcard_dns WHERE run_id=? AND base_label=?", (run_id, scope.domain)
            ).fetchone()
            if wc_row and wc_row["is_wildcard"]:
                scope_note = (
                    '<div class="note"><strong>Wildcard DNS detected</strong> under '
                    f'{html.escape(scope.domain)}. DNS-only "resolved" candidates are capped at LOW '
                    "confidence and classified OBSERVATION rather than ASSET; see Asset Inventory "
                    "below.</div>"
                )

        domain_esc = html.escape(scope.domain)
        target_label = "IP address" if scope.target_type == "ip" else "Domain"
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Attack surface recon — {domain_esc}</title><style>{CSS}</style></head>
<body>
<h1>Prioritized attack-surface report</h1>
<p><strong>{target_label}:</strong> {domain_esc} &nbsp; <strong>Target type:</strong>
{html.escape(scope.target_type)} &nbsp; <strong>Run:</strong> {html.escape(run_id)} UTC</p>
<p><small>Evidence-driven: every row below traces back to raw tool output under
<code>raw/{html.escape(run_id)}/</code>. A LEAD or VULNERABILITY_CANDIDATE is not a confirmed
vulnerability until a human reviews the evidence and runs <code>recon.sh --confirm</code>.</small></p>
{scope_note}

<h2>Pipeline execution (tool-level status)</h2>
{tool_table}

<h2>Asset inventory</h2>
{asset_table}

<h2>HTTP/HTTPS mapping</h2>
{http_table}

<h2>Open ports (conservative, if enabled)</h2>
{svc_table}

<h2>Historical URLs</h2>
{hist_table}

<h2>Crawled / discovered endpoints</h2>
{ep_table}

<h2>JavaScript analysis findings</h2>
{js_table}

<h2>Content discovery (post baseline-filtering hits only)</h2>
{cd_table}

<h2>Vulnerability leads (nuclei, safe templates only)</h2>
{lead_table}

<h2>Third-party / out-of-scope intelligence</h2>
<p><small>Recorded for context; never actively scanned.</small></p>
{tp_table}

</body></html>
"""
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(page)
        return out_path
    finally:
        conn.close()
