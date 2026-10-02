"""Scope / ROE engine.

A hostname is only ever handed to an active tool (katana, ffuf, naabu,
nuclei) after passing `Scope.is_in_scope`. Anything that resolves or
redirects outside scope - including known CDN/SaaS/third-party
suffixes - is recorded as intelligence (`third_party_observations`) and
never actively probed.

Authorization is a hard gate, not a formality: SAFE_ACTIVE and
OPTIONAL_ACTIVE stages refuse to run unless the engine was given
non-empty authorization fields (either via scope.yaml, or via the
--authorized flag on the simple single-domain CLI path).
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Optional

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - degrade gracefully, see README
    yaml = None

DOMAIN_RE = re.compile(
    r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
)

DEFAULT_THIRD_PARTY_SUFFIXES = [
    "amazonaws.com", "cloudfront.net", "akamaized.net", "akamaihd.net",
    "fastly.net", "fastlylb.net", "azureedge.net", "windows.net",
    "herokuapp.com", "herokudns.com", "github.io", "githubusercontent.com",
    "googleusercontent.com", "googlehosted.com", "appspot.com",
    "cloudflare.net", "cloudflarenet.com", "wixdns.net", "myshopify.com",
    "zendesk.com", "freshdesk.com", "hubspot.net", "sendgrid.net",
    "netlify.app", "vercel.app", "pantheonsite.io", "wpengine.com",
]

DEFAULT_RATE_LIMITS = {
    "dns_qps": 10, "http_rps": 10, "crawl_rps": 5,
    "content_discovery_rps": 5, "portscan_rate": 100, "nuclei_rate": 10,
}

DEFAULT_MODULES = {
    "passive": True, "subdomain_discovery": True, "dns_validate": True,
    "http_map": True, "port_scan": False, "historical_urls": True,
    "crawl": True, "content_discovery": False, "vuln_scan": False,
}

DEFAULT_LIMITS = {
    "max_hosts": 1000, "max_urls_per_host_history": 500,
    "crawl_depth": 2, "content_discovery_wordlist_size": 60,
}


def valid_domain(name: str) -> bool:
    return bool(DOMAIN_RE.match(name))


@dataclass
class Scope:
    domain: str
    include: list = field(default_factory=list)
    exclude: list = field(default_factory=list)
    third_party_suffixes: list = field(default_factory=lambda: list(DEFAULT_THIRD_PARTY_SUFFIXES))
    authorized_by: Optional[str] = None
    authorization_reference: Optional[str] = None
    modules: dict = field(default_factory=lambda: dict(DEFAULT_MODULES))
    rate_limits: dict = field(default_factory=lambda: dict(DEFAULT_RATE_LIMITS))
    limits: dict = field(default_factory=lambda: dict(DEFAULT_LIMITS))

    @property
    def is_authorized(self) -> bool:
        return bool((self.authorized_by or "").strip()) and bool((self.authorization_reference or "").strip())

    def _matches_any(self, hostname: str, patterns: list) -> bool:
        h = hostname.lower().rstrip(".")
        for p in patterns:
            p = p.lower().strip()
            if not p:
                continue
            if p.startswith("*."):
                suffix = p[1:]  # ".example.com"
                if h.endswith(suffix) or h == p[2:]:
                    return True
            elif fnmatch.fnmatchcase(h, p):
                return True
        return False

    def is_apex_or_sub(self, hostname: str) -> bool:
        h = hostname.lower().rstrip(".")
        d = self.domain.lower()
        return h == d or h.endswith("." + d)

    def is_third_party(self, hostname: str) -> bool:
        h = hostname.lower().rstrip(".")
        return any(h == s or h.endswith("." + s) for s in self.third_party_suffixes)

    def is_in_scope(self, hostname: str) -> bool:
        h = hostname.lower().rstrip(".")
        if not h:
            return False
        if self.is_third_party(h):
            return False
        if self.exclude and self._matches_any(h, self.exclude):
            return False
        if self.include:
            return self._matches_any(h, self.include)
        return self.is_apex_or_sub(h)

    def module_enabled(self, name: str) -> bool:
        return bool(self.modules.get(name, False))


def from_simple_domain(domain: str, authorized_text: Optional[str], enable_portscan: bool,
                        enable_content_discovery: bool, enable_vuln_scan: bool,
                        max_hosts: int) -> Scope:
    domain = domain.strip().lower().rstrip(".")
    modules = dict(DEFAULT_MODULES)
    modules["port_scan"] = bool(enable_portscan)
    modules["content_discovery"] = bool(enable_content_discovery)
    modules["vuln_scan"] = bool(enable_vuln_scan)
    limits = dict(DEFAULT_LIMITS)
    limits["max_hosts"] = max_hosts
    authorized_by = authorized_text.strip() if authorized_text else None
    return Scope(
        domain=domain,
        include=[f"*.{domain}", domain],
        authorized_by=authorized_by,
        authorization_reference=("CLI --authorized flag" if authorized_by else None),
        modules=modules,
        limits=limits,
    )


def from_yaml_file(path: str) -> Scope:
    if yaml is None:
        raise RuntimeError(
            "PyYAML is not installed. Install it (pip install pyyaml / apt install "
            "python3-yaml) or use the simple `./recon.sh <domain>` invocation instead "
            "of --scope-file."
        )
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    domain = str(raw.get("domain", "")).strip().lower().rstrip(".")
    engagement = raw.get("engagement", {}) or {}
    modules = dict(DEFAULT_MODULES)
    modules.update(raw.get("modules", {}) or {})
    rate_limits = dict(DEFAULT_RATE_LIMITS)
    rate_limits.update(raw.get("rate_limits", {}) or {})
    limits = dict(DEFAULT_LIMITS)
    limits.update(raw.get("limits", {}) or {})

    suffixes = list(DEFAULT_THIRD_PARTY_SUFFIXES)
    suffixes.extend(raw.get("third_party_suffixes", []) or [])

    return Scope(
        domain=domain,
        include=list(raw.get("include", []) or [f"*.{domain}", domain]),
        exclude=list(raw.get("exclude", []) or []),
        third_party_suffixes=suffixes,
        authorized_by=engagement.get("authorized_by"),
        authorization_reference=engagement.get("authorization_reference"),
        modules=modules,
        rate_limits=rate_limits,
        limits=limits,
    )


def require_authorization_or_die(scope: Scope, stage: str) -> Optional[str]:
    """Return an error string (not raise) if an active stage lacks authorization."""
    if not scope.is_authorized:
        return (
            f"Refusing to run '{stage}': no authorization on record. Set "
            f"engagement.authorized_by / engagement.authorization_reference in "
            f"scope.yaml, or pass --authorized \"<text>\" on the simple CLI path."
        )
    return None
