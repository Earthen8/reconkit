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

Target type (domain vs. bare IP address) is always explicit, never
inferred from the string's shape: callers pick --domain, --ip, or a
scope.yaml `target_type` field. In IP mode, `is_in_scope` only ever
matches the single IP address the operator supplied - normalized
through `ipaddress.ip_address()` so "same address, different textual
form" (e.g. compressed vs. expanded IPv6) still matches, but a CIDR
range, a different IP, or a hostname that merely resolves to that IP
never do.
"""
from __future__ import annotations

import fnmatch
import ipaddress
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
    return bool(DOMAIN_RE.match(name)) and not valid_ip(name)


def valid_ip(value: str) -> bool:
    """True for a bare IPv4/IPv6 address - explicitly false for CIDR
    notation (e.g. '203.0.113.0/24'), which ipaddress.ip_address()
    already rejects with ValueError."""
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def normalize_ip(value: str) -> str:
    """Canonical string form, so '::1' and '0:0:0:0:0:0:0:1' compare equal."""
    return str(ipaddress.ip_address(value.strip()))


@dataclass
class Scope:
    domain: str
    target_type: str = "domain"  # "domain" | "ip" - always explicit, see module docstring
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

    def _is_exact_ip_match(self, value: str) -> bool:
        """IP-mode scope check: true only for the single configured address.

        No CIDR (ipaddress.ip_address rejects '/nn' notation outright), no
        other IP, and no hostname - a hostname that happens to resolve to
        this IP is not itself "the IP", so it is correctly rejected here;
        callers that discover a hostname (e.g. from a TLS cert or a
        redirect's Host header) must resolve it and compare the resulting
        address, not pass the hostname string to this function.
        """
        value = (value or "").strip()
        if not value:
            return False
        try:
            return ipaddress.ip_address(value) == ipaddress.ip_address(self.domain)
        except ValueError:
            return False

    def is_in_scope(self, hostname: str) -> bool:
        if self.target_type == "ip":
            return self._is_exact_ip_match(hostname)
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


def _active_module_overrides(enable_portscan: bool, enable_content_discovery: bool,
                              enable_vuln_scan: bool) -> dict:
    modules = dict(DEFAULT_MODULES)
    modules["port_scan"] = bool(enable_portscan)
    modules["content_discovery"] = bool(enable_content_discovery)
    modules["vuln_scan"] = bool(enable_vuln_scan)
    return modules


def from_simple_domain(domain: str, authorized: bool, enable_portscan: bool,
                        enable_content_discovery: bool, enable_vuln_scan: bool,
                        max_hosts: int) -> Scope:
    domain = domain.strip().lower().rstrip(".")
    modules = _active_module_overrides(enable_portscan, enable_content_discovery, enable_vuln_scan)
    limits = dict(DEFAULT_LIMITS)
    limits["max_hosts"] = max_hosts
    authorized_by = "CLI operator assertion" if authorized else None
    return Scope(
        domain=domain,
        target_type="domain",
        include=[f"*.{domain}", domain],
        authorized_by=authorized_by,
        authorization_reference=("Authorization asserted with --authorized; not independently verified"
                                 if authorized else None),
        modules=modules,
        limits=limits,
    )


def from_simple_ip(ip: str, authorized: bool, enable_portscan: bool,
                    enable_content_discovery: bool, enable_vuln_scan: bool,
                    max_hosts: int) -> Scope:
    """Single-IP scope. subdomain_discovery/passive(CT)/dns_validate are
    forced off here regardless of defaults - they are domain-only
    techniques and the per-stage code also hard-skips them for target_type
    == "ip", so this is belt-and-suspenders, not the only enforcement.
    """
    normalized = normalize_ip(ip)
    modules = _active_module_overrides(enable_portscan, enable_content_discovery, enable_vuln_scan)
    modules["passive"] = False
    modules["subdomain_discovery"] = False
    modules["dns_validate"] = False
    limits = dict(DEFAULT_LIMITS)
    limits["max_hosts"] = max_hosts
    authorized_by = "CLI operator assertion" if authorized else None
    return Scope(
        domain=normalized,
        target_type="ip",
        include=[normalized],
        exclude=[],
        third_party_suffixes=[],  # suffix matching is a hostname concept; not applicable to a bare IP
        authorized_by=authorized_by,
        authorization_reference=("Authorization asserted with --authorized; not independently verified"
                                 if authorized else None),
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

    target_type = str(raw.get("target_type", "domain")).strip().lower()
    if target_type not in ("domain", "ip"):
        raise RuntimeError(f"scope.yaml target_type must be 'domain' or 'ip', got {target_type!r}")

    engagement = raw.get("engagement", {}) or {}
    modules = dict(DEFAULT_MODULES)
    modules.update(raw.get("modules", {}) or {})
    rate_limits = dict(DEFAULT_RATE_LIMITS)
    rate_limits.update(raw.get("rate_limits", {}) or {})
    limits = dict(DEFAULT_LIMITS)
    limits.update(raw.get("limits", {}) or {})

    raw_domain = raw.get("domain")
    raw_ip = raw.get("ip")

    if target_type == "ip":
        if raw_domain:
            raise RuntimeError(
                "scope.yaml has both target_type: ip and a 'domain:' value set - remove 'domain' "
                "or change target_type, so the target is unambiguous."
            )
        ip_value = str(raw_ip or "").strip()
        if not ip_value:
            raise RuntimeError("scope.yaml target_type: ip requires a non-empty 'ip:' field.")
        if not valid_ip(ip_value):
            raise RuntimeError(
                f"'ip: {ip_value}' in scope.yaml is not a bare IPv4/IPv6 address (CIDR ranges "
                f"like '/24' are not accepted - a scope is always exactly one address)."
            )
        domain = normalize_ip(ip_value)
        modules["passive"] = False
        modules["subdomain_discovery"] = False
        modules["dns_validate"] = False
        return Scope(
            domain=domain,
            target_type="ip",
            include=[domain],
            exclude=[],
            third_party_suffixes=[],
            authorized_by=engagement.get("authorized_by"),
            authorization_reference=engagement.get("authorization_reference"),
            modules=modules,
            rate_limits=rate_limits,
            limits=limits,
        )

    # target_type == "domain"
    if raw_ip:
        raise RuntimeError(
            "scope.yaml has target_type: domain but an 'ip:' value is also set - remove 'ip' or "
            "change target_type, so the target is unambiguous."
        )
    domain = str(raw_domain or "").strip().lower().rstrip(".")
    if not domain:
        raise RuntimeError("scope.yaml target_type: domain requires a non-empty 'domain:' field.")
    if valid_ip(domain):
        raise RuntimeError(
            f"'domain: {domain}' in scope.yaml looks like an IP address. Set target_type: ip and "
            f"use the 'ip:' field instead - target type is never inferred from the string's shape."
        )

    suffixes = list(DEFAULT_THIRD_PARTY_SUFFIXES)
    suffixes.extend(raw.get("third_party_suffixes", []) or [])

    return Scope(
        domain=domain,
        target_type="domain",
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
            f"scope.yaml, or pass --authorized on the simple CLI path."
        )
    return None
