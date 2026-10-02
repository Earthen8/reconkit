"""Confidence / correlation engine.

Rules, by design, are simple and stated explicitly so every classification
is explainable (the `reason` column is always a human-readable sentence,
never just a score). Two hard invariants enforced here:

  1. This module may raise a vuln_leads.classification from LEAD to
     VULNERABILITY_CANDIDATE when independent evidence types agree, but
     it never sets status='confirmed' and never assigns confidence
     higher than MEDIUM automatically. CONFIRMED is reserved for a human
     analyst using `recon.sh --confirm`.
  2. An asset's confidence can only reach CONFIRMED if it is the
     operator-supplied apex domain itself (classification='input').
     Every discovered/derived asset tops out at HIGH.

"no evidence, no finding": every row written here carries the specific
evidence it was computed from (sources_json / confidence_reason), so a
reviewer can trace *why* without re-running anything.
"""
from __future__ import annotations

import json

TECH_TAG_HINTS = {
    "wordpress": ["wordpress", "wp"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis", "microsoft-iis"],
    "php": ["php"],
    "tomcat": ["tomcat", "apache-tomcat"],
}


def _host_sources(conn, run_id: str, hostname: str) -> set:
    sources = set()
    row = conn.execute(
        "SELECT classification FROM run_hosts WHERE run_id=? AND hostname=?",
        (run_id, hostname),
    ).fetchone()
    if row and row["classification"] == "input":
        sources.add("input")
    elif row:
        sources.add("osint_candidate")
    dns_row = conn.execute(
        "SELECT 1 FROM dns_records WHERE run_id=? AND hostname=? LIMIT 1", (run_id, hostname)
    ).fetchone()
    if dns_row:
        sources.add("dns")
    http_row = conn.execute(
        "SELECT 1 FROM http_responses WHERE run_id=? AND hostname=? LIMIT 1", (run_id, hostname)
    ).fetchone()
    if http_row:
        sources.add("http")
    svc_row = conn.execute(
        "SELECT 1 FROM run_services WHERE run_id=? AND hostname=? LIMIT 1", (run_id, hostname)
    ).fetchone()
    if svc_row:
        sources.add("open_port")
    return sources


def score_assets(run_id: str, scope, conn) -> int:
    wc_row = conn.execute(
        "SELECT is_wildcard FROM wildcard_dns WHERE run_id=? AND base_label=?",
        (run_id, scope.domain),
    ).fetchone()
    is_wildcard = bool(wc_row and wc_row["is_wildcard"])

    hostnames = [
        r["hostname"] for r in conn.execute(
            "SELECT DISTINCT hostname FROM host_catalog WHERE domain=? AND "
            "hostname IN (SELECT hostname FROM run_hosts WHERE run_id=?)",
            (scope.domain, run_id),
        ).fetchall()
    ]

    count = 0
    for hostname in hostnames:
        sources = _host_sources(conn, run_id, hostname)
        if "input" in sources:
            classification, confidence = "ASSET", "CONFIRMED"
            reason = "Operator-supplied apex domain; identity is given, not inferred."
        elif "dns" in sources and "http" in sources:
            classification, confidence = "ASSET", "HIGH"
            reason = "Independently corroborated: resolves via DNS and answers an HTTP(S) request."
        elif "dns" in sources and is_wildcard:
            classification, confidence = "OBSERVATION", "LOW"
            reason = (f"{scope.domain} has wildcard DNS; a bare DNS answer for this name is weak "
                      "evidence of a distinct, intentionally-provisioned asset.")
        elif "dns" in sources:
            classification, confidence = "ASSET", "MEDIUM"
            reason = "Resolves via DNS; no corroborating HTTP response observed this run."
        elif "osint_candidate" in sources:
            classification, confidence = "OBSERVATION", "LOW"
            reason = "Named by a passive OSINT source (CT log / subfinder / amass) but did not resolve."
        else:
            classification, confidence = "OBSERVATION", "INFORMATIONAL"
            reason = "Insufficient evidence this run."

        conn.execute(
            "INSERT OR REPLACE INTO asset_assessment(run_id, hostname, classification, confidence, "
            "reason, sources_json) VALUES (?,?,?,?,?,?)",
            (run_id, hostname, classification, confidence, reason, json.dumps(sorted(sources))),
        )
        count += 1
    return count


def score_vuln_leads(run_id: str, scope, conn) -> int:
    rows = conn.execute(
        "SELECT id, template_id, name, tags, matched_at FROM vuln_leads WHERE run_id=? AND status='open'",
        (run_id,),
    ).fetchall()
    promoted = 0
    for row in rows:
        from urllib.parse import urlparse
        host = urlparse(row["matched_at"]).hostname or ""
        tags = {t.strip().lower() for t in (row["tags"] or "").split(",") if t.strip()}
        name_lower = (row["name"] or "").lower()

        tech_rows = conn.execute(
            "SELECT technology FROM tech_catalog WHERE hostname=?", (host,)
        ).fetchall()
        technologies = {r["technology"].lower() for r in tech_rows}

        matched_hint = None
        for tech_key, hint_words in TECH_TAG_HINTS.items():
            if any(h in tags or h in name_lower for h in hint_words):
                if any(tech_key in t or any(h in t for h in hint_words) for t in technologies):
                    matched_hint = tech_key
                    break

        if matched_hint:
            conn.execute(
                "UPDATE vuln_leads SET classification='VULNERABILITY_CANDIDATE', confidence='MEDIUM', "
                "confidence_reason=? WHERE id=?",
                (
                    f"nuclei template/tags reference '{matched_hint}', which independently matches a "
                    f"technology fingerprint observed on {host} during http_map. Still requires manual "
                    f"validation before it can be confirmed.",
                    row["id"],
                ),
            )
            promoted += 1
    return promoted


def run(run_id: str, scope, conn) -> dict:
    asset_count = score_assets(run_id, scope, conn)
    promoted = score_vuln_leads(run_id, scope, conn)
    return {"assets_scored": asset_count, "leads_promoted": promoted}
