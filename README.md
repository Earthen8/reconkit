# reconkit

Evidence-driven, scope-aware attack-surface reconnaissance orchestrator
for **authorized** security testing (bug bounty, pentest, external ASM).

Architecture: a thin Bash orchestrator (`recon.sh`) sequences stages;
all parsing, scope logic, tool wrapping, SQLite writes and HTML
reporting live in the `reconkit/` Python package. SQLite (`recon.db`)
is the canonical, cross-run correlation layer.

## Quick start

```bash
./install.sh --yes          # Kali: apt + go-install the underlying tools
./recon.sh --check          # verify what's on PATH
./recon.sh example.com --authorized "Jane Doe, signed ROE 2026-01-01"
```

Or with a full scope file (see `config/scope.example.yaml`):

```bash
cp config/scope.example.yaml scope.yaml   # edit domain/include/exclude/modules
./recon.sh --scope-file scope.yaml
```

### IP targets

Target type is always an explicit choice - never guessed from the
string. Pass `--ip` instead of a domain to scope a run to exactly one
IPv4/IPv6 address:

```bash
./recon.sh --ip 203.0.113.10 --authorized "Jane Doe, signed ROE 2026-01-01"
# or: cp config/scope.example-ip.yaml scope.yaml  (edit ip/engagement) && ./recon.sh --scope-file scope.yaml
```

In this mode:
- the scope matches **exactly that address** - no CIDR range, no other
  IP, no hostname that merely resolves to it (`scope.py`'s
  `_is_exact_ip_match` compares normalized `ipaddress` objects, so it
  can't be tricked by alternate textual forms, and a CIDR string fails
  to parse as a single address at all);
- `passive` (crt.sh), `subdomain_discovery` (subfinder/amass) and the
  DNS-wildcard check inside `dns_validate` are domain-only techniques
  and are hard-skipped (`status=not_run`), regardless of what
  `modules:` says in a scope file;
- `http_map`/`crawl`/`content_discovery`/`vuln_scan` target the IP
  directly; any redirect, CNAME, or discovered link that leaves that
  single address (e.g. a login flow bouncing to an SSO provider) is
  recorded in `third_party_observations` and is never itself probed,
  crawled or fuzzed - this falls out of the same scope-engine check
  every other stage already uses, not a special case;
- a target passed as `--domain`/`domain:` that is IP-shaped is
  rejected with a message to use `--ip` instead, and a `scope.yaml`
  that sets both `domain:`/`ip:` for the wrong `target_type` (or omits
  the one it needs) is rejected rather than guessed at;
- `recon.db`'s `runs` table records `target_type` explicitly, and the
  output directory/report are named/labelled by the IP.

Output lands under `recon/<domain>/`: `assets/`, `endpoints/`,
`findings/`, `evidence/`, `raw/<run-id>/` (every tool's untouched
output), `recon.db`, and `report.html`.

Review and promote a lead after you've manually validated it:

```bash
./recon.sh --output-root recon --confirm 42 --by "jane.doe" \
  --note "Verified manually: endpoint returns stack trace with DB creds redacted; screenshot in evidence/"
```

Nothing in the pipeline sets `status=confirmed` or `classification=
CONFIRMED_FINDING` except this command.

## Pipeline stages, in order

| Stage | Tool(s) | Class | Default |
|---|---|---|---|
| passive | crt.sh | PASSIVE | on (domain only - `not_run` for `--ip`) |
| subdomains | subfinder, amass `-passive` | PASSIVE | on (domain only - `not_run` for `--ip`) |
| dns_validate | dnsx (or `dig` fallback) + wildcard probe | PASSIVE | on (domain only - `not_run` for `--ip`) |
| http_map | httpx (or `curl` fallback) | SAFE_ACTIVE | on |
| port_scan | naabu, ~60 common ports | OPTIONAL_ACTIVE | **off** |
| historical | gau / waybackurls + bounded liveness check | PASSIVE + SAFE_ACTIVE | on |
| crawl | katana + static JS/endpoint analysis | SAFE_ACTIVE | on |
| content_discovery | ffuf, small built-in wordlist | OPTIONAL_ACTIVE | **off** |
| vuln_scan | nuclei, safe tags only | OPTIONAL_ACTIVE | **off** |
| correlate | SQLite diff vs previous run | — | on |
| confidence | rules-based classification | — | on |
| report | `report.html` | — | on |

SAFE_ACTIVE/OPTIONAL_ACTIVE stages refuse to run without recorded
authorization (`--authorized` or `engagement.authorized_by` +
`authorization_reference` in scope.yaml) - they record
`status=not_run` with a reason instead of silently skipping.

HTTP mapping and historical-URL liveness checks do not follow redirects.
The crawler is restricted to the exact in-scope seed hostnames and has
redirect following disabled, so an off-scope redirect or link is not
requested. Module switches are enforced by their stages before invoking
the corresponding tools.

Missing tools, timeouts, and non-zero exits never stop the pipeline;
`tool_runs` in `recon.db` records `ok | nothing_found | not_run |
failed | timed_out | unavailable` for every (stage, tool) pair, and
`report.html`'s first table shows it.

## Confidence / correlation model

`confidence.py` classifies every host as `ASSET` or `OBSERVATION` with
a tier (`CONFIRMED > HIGH > MEDIUM > LOW > INFORMATIONAL`) and an
explicit, human-readable reason:

- the operator-supplied apex domain is the only thing that can reach
  `CONFIRMED` automatically;
- a host corroborated by two independent sources (resolves via DNS
  *and* answers HTTP) is `HIGH`;
- DNS-only resolution is `MEDIUM`, or `LOW`/`OBSERVATION` if the apex
  has wildcard DNS (detected by probing three random, near-certainly-
  nonexistent labels and checking whether they all resolve to the same
  answer set);
- a name seen only in a passive OSINT source (CT log / subfinder /
  amass) that never resolved is `LOW`/`OBSERVATION`.

`vuln_leads` from nuclei start at `LEAD`/`LOW`. The engine may promote
a lead to `VULNERABILITY_CANDIDATE`/`MEDIUM` **only** when an
independent signal corroborates it (e.g. the matched template's tags
reference a technology that `http_map` also fingerprinted on that
host via a separate code path). Confidence is capped at `MEDIUM`
automatically — `CONFIRMED` is human-only, via `--confirm`.

## False-positive reduction

- **Wildcard DNS detection** (see above) demotes DNS-only candidates
  under a wildcarded apex instead of reporting every `*.domain` guess
  as a live host.
- **Custom-404/soft-404 filtering** in `content_discovery`: two random,
  near-certainly-nonexistent paths are requested per host before
  fuzzing to capture a `(status_code, content_length)` baseline; ffuf's
  own `-ac` autocalibration runs *and* every hit is independently
  re-checked against that baseline, so a "catch-all 200" page can't
  slip through just because one filter missed it.
- **nuclei is template-tag-restricted**, not just severity-restricted:
  `-tags tech,ssl,headers,dns,waf,favicon -etags intrusive,dos,fuzz,
  rce,sqli,xxe,ssrf,lfi,rfi,exposure,token,creds,default-login,
  takeover,bruteforce,injection`. Matches are leads, never pre-labeled
  vulnerabilities.
- **JS "secret" patterns are shape-only and redacted at write time**
  (`util.redact`): the pipeline reports that a token/key-shaped string
  exists at a location, never extracts, stores, or validates the full
  value.
- **Scope engine** keeps third-party/CDN/SaaS hosts and any redirect
  or CNAME target outside scope out of every active stage; they're
  recorded in `third_party_observations` as intelligence only.

## Limitations

- Tool CLI flags (httpx/dnsx/naabu/katana/nuclei/subfinder) follow
  each ProjectDiscovery tool's documented conventions as of this
  writing; a future flag rename upstream can make a wrapper mis-parse
  output. `--check` reports installed versions - pin versions you've
  tested against in production use.
- `port_scan` uses a fixed conservative port list, not a full sweep -
  by design (speed/noise trade-off), but it means a service on an
  unusual port will be missed unless `http_map`/`crawl` finds it some
  other way.
- JS static analysis is regex-based, not a JS parser/AST; it will miss
  dynamically constructed endpoint strings and can occasionally match
  inside a comment or string literal that isn't really an endpoint.
- The "secret-shape" patterns in `crawl.py` are intentionally narrow
  (AWS key ID shape, JWT shape, bearer-token shape, a couple of
  generic `key=`/`token=` assignment shapes) to keep the false-positive
  rate manageable; this is not a comprehensive secret scanner.
- `historical` liveness-checks a capped sample per host
  (`limits.max_urls_per_host_history`), not every URL ever archived.
- `vuln_scan`'s auto-promotion to `VULNERABILITY_CANDIDATE` uses a
  small hand-written technology/tag hint table (`confidence.py:
  TECH_TAG_HINTS`) - extend it for your target's stack, or treat every
  `LEAD` as equally worth a manual look regardless of whether it got
  promoted.
- This toolkit does not replace manual verification, authenticated
  testing, business-logic testing, or a real penetration test; it
  produces a prioritized map of where to look, with evidence, not a
  substitute for looking.
