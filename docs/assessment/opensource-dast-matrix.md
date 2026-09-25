# Open-Source DAST Ecosystem Assessment

**Product:** Vantage DAST — a unified, license-governed dynamic application
security testing platform.
**Purpose of this document:** the Phase 0 ecosystem assessment. For every DAST
capability it records candidate open-source projects, their license,
maintenance, integration model, and a build/integrate/isolate/avoid
recommendation. Licenses were verified against each project's upstream `LICENSE`
file or package metadata on **2026-09-25**; re-verify before each release.

> Scope note: Vantage is a **defensive**, authorized-testing product. This
> assessment evaluates components at the level of *capability, license, and
> integration* — not attack technique.

## How to read the recommendation column

| Recommendation | Meaning |
|----------------|---------|
| `integrate-embed` | Permissive library, safe to link in-process |
| `integrate-isolated` | Run unmodified in a sandbox (container or host binary); arms-length |
| `optional-isolated` | Supported but off by default; enable per deployment |
| `reference-only` | Useful reference; not integrated |
| `build-own` | Vantage implements this natively (first-party) |
| `avoid` / `replace` | License or fit makes it unsuitable; use the named alternative |

## License classes (policy)

`GREEN` permissive (MIT/BSD/Apache-2.0/ISC…) — embed or isolate freely.
`YELLOW` weak/again­st-embedding copyleft (LGPL/MPL/EPL) — isolate + recorded review.
`RED` strong/network copyleft or source-available/commercial (GPL/AGPL/SSPL/BUSL/commercial) — never embed/redistribute; isolate as an unmodified separate program after legal review, or replace.

---

## A. HTTP proxy / interception / HAR

| Capability | Project | License | Class | Integration | Recommendation |
|---|---|---|---|---|---|
| Interception proxy, replay, HAR | **mitmproxy** | MIT | GREEN | isolated / library | optional-isolated |
| Interception + active/passive scan | **OWASP ZAP** (proxy) | Apache-2.0 | GREEN | container_api | integrate-isolated |
| HAR parsing | haralyzer, custom | MIT | GREEN | library | build-own (thin) |

**WHY / WHAT / NOT:** mitmproxy is the mature interception/replay engine; ZAP's
proxy doubles as a scanner. Vantage's own **scope-enforcing egress proxy** is
first-party (it must re-check every request against the ScopeEngine), so the
external proxy is optional. **Commercial:** both GREEN; safe. **Alternatives:**
Vantage native proxy.

## B. DAST / web scanning

| Project | License | Class | Integration | Recommendation |
|---|---|---|---|---|
| **OWASP ZAP** | Apache-2.0 | GREEN | container_api | integrate-isolated (primary active scanner) |
| **Nuclei** | MIT | GREEN | container_cli / local | integrate-isolated (template checks) — **shipped** |
| Wapiti | GPL-2.0 | RED | container_cli | avoid/replace (ZAP+Nuclei cover it) |
| w3af | GPL-2.0 | RED | — | avoid (largely unmaintained; GPL) |
| Arachni | custom/non-commercial-ish | RED | — | avoid (licensing + maintenance) |
| Nikto | GPL | RED | container_cli | optional-isolated (server checks only) |

**WHY ZAP + Nuclei:** ZAP gives broad, actively-maintained active/passive
scanning under Apache-2.0 (embeddable-friendly, arms-length isolated here).
Nuclei gives fast, community-curated template checks under MIT. Together they
cover the active-scan surface without any GPL engine. **NOT:** neither replaces
Vantage's validation/correlation layer. **Alternatives to GPL scanners:** ZAP
(Apache) + Nuclei (MIT) — chosen precisely to avoid GPL entanglement.

## C. Web crawling / URL discovery

| Project | License | Class | Integration | Recommendation |
|---|---|---|---|---|
| **katana** | MIT | GREEN | container_cli / local | integrate-isolated — **adapter shipped** |
| hakrawler | MIT | GREEN | container_cli | optional-isolated |
| gau (getallurls) | MIT | GREEN | container_cli | optional-isolated |
| Colly / Scrapy | Apache-2.0 / BSD | GREEN | library | reference-only |
| Vantage native crawler | first-party | GREEN | native | build-own — **shipped** |

**WHY:** Vantage ships a native crawler (HTTP + JS endpoint extraction) for the
default path and integrates katana for JS-heavy/headless crawling. **NOT:**
native crawler is intentionally conservative; katana adds headless depth.

## D. Browser automation

| Project | License | Class | Recommendation |
|---|---|---|---|
| **Playwright** | Apache-2.0 | GREEN | integrate-embed (SPA discovery, auth) |
| Chromium | BSD-3-Clause + bundled | GREEN* | integrate-isolated (via Playwright) |
| Selenium | Apache-2.0 | GREEN | reference-only |

*Chromium bundles many components under compatible licenses; ship the browser as
a separate artifact and reproduce its own NOTICE. **WHY:** Playwright is the
modern, well-maintained driver for SPA crawling and authenticated sessions.

## E. JavaScript / static analysis assist

| Project | License | Class | Recommendation |
|---|---|---|---|
| tree-sitter (+ grammars) | MIT | GREEN | integrate-embed |
| @babel/parser, Acorn, Esprima | MIT | GREEN | integrate-embed |
| source-map (Mozilla) | BSD-3-Clause | GREEN | integrate-embed |
| **Semgrep CE** | LGPL-2.1-or-later | YELLOW | optional-isolated (engine); rules licensed separately |
| CodeQL | proprietary terms | RED | avoid for product use (license terms) |
| Joern | Apache-2.0 | GREEN | reference-only |

**WHY:** tree-sitter/Babel/Acorn (MIT) power native JS endpoint/source-map
analysis. Semgrep is LGPL → isolated + review; its **rules registry is licensed
separately**, so bundling rules needs its own review. CodeQL's terms make it
unsuitable to embed in a commercial product.

## F. API security

| Project | License | Class | Recommendation |
|---|---|---|---|
| **Schemathesis** | MIT | GREEN | integrate-isolated (OpenAPI property testing) |
| Dredd | MIT | GREEN | optional-isolated (contract testing) |
| Stoplight Prism | Apache-2.0 | GREEN | optional-isolated (OpenAPI validate/mock) |
| openapi-core / openapi-spec-validator / prance | BSD/Apache | GREEN | integrate-embed |
| RESTler | MIT | GREEN | reference-only (stateful REST fuzzing) |
| zeep (SOAP/WSDL) | MIT | GREEN | integrate-embed |
| graphql-core / graphql-js | MIT | GREEN | integrate-embed |

**WHY:** Schemathesis + OpenAPI libraries give strong, permissive API coverage.
All GREEN.

## G. Fuzzing / content discovery

| Project | License | Class | Recommendation |
|---|---|---|---|
| **ffuf** | MIT | GREEN | integrate-isolated — **shipped** |
| **feroxbuster** | MIT | GREEN | integrate-isolated — **adapter shipped** |
| gobuster | Apache-2.0 (verify) | GREEN | optional-isolated |
| wfuzz | GPL-2.0 | RED | replace with ffuf |
| dirsearch | GPL-2.0 | RED | replace with ffuf/feroxbuster |
| boofuzz | GPL-2.0 | RED | reference-only (protocol fuzzing, not web DAST) |
| AFL++, libFuzzer | Apache-2.0 | GREEN | reference-only (binary fuzzing — out of DAST scope) |
| Radamsa | MIT | GREEN | reference-only |

**WHY:** ffuf and feroxbuster (both MIT) cover web content discovery, replacing
the GPL wfuzz/dirsearch. Binary fuzzers are deliberately **not** forced into the
web workflow.

## H. Template-based testing

**Nuclei** (MIT) + **nuclei-templates** (MIT, content). Vantage adds a Template
Registry (validation, metadata, versioning, execution, normalization) and never
executes arbitrary templates — the scan policy denylists intrusive tags.

## I. Network / TLS / DNS

| Project | License | Class | Recommendation |
|---|---|---|---|
| **cryptography (pyca)** | Apache-2.0 OR BSD-3 | GREEN | integrate-embed (native TLS analyzer) — **shipped** |
| tlsx | MIT | GREEN | optional-isolated |
| dnspython / dnsx | MIT | GREEN | integrate-embed / optional-isolated |
| testssl.sh | GPL-2.0 | RED | replace with native TLS |
| sslyze | AGPL-3.0 | RED | replace with native TLS |

**WHY:** Native TLS analysis via pyca/cryptography (GREEN) avoids the AGPL
(sslyze) / GPL (testssl.sh) trap entirely.

## J. Technology fingerprinting

| Project | License | Class | Recommendation |
|---|---|---|---|
| Vantage native fingerprint | first-party | GREEN | build-own — **shipped** |
| wappalyzergo | MIT | GREEN | optional-isolated |
| httpx (PD) tech-detect | MIT | GREEN | integrate-isolated — **adapter shipped** |
| WhatWeb | GPL-2.0 | RED | replace (native + wappalyzergo) |
| Wappalyzer (original) | post-2023 non-OSS | RED | avoid (license change) |

**WHY:** The original Wappalyzer went non-OSS; WhatWeb is GPL. Vantage uses a
native passive signature set plus MIT wappalyzergo/httpx.

## K. Content / URL discovery tools

See G (ffuf, feroxbuster). Plus **httpx**, **katana** (both MIT, shipped
adapters). The Scan Planner selects the right tool per target — it does **not**
run all of them.

## L. GraphQL

graphql-core / graphql-js (MIT) for schema/introspection parsing; a dedicated
GraphQL adapter. graphql-cop / clairvoyance are references. All permissive.

## M. WebSockets

Python `websockets` (BSD-3), aiohttp (Apache-2.0), gorilla/websocket (BSD-3) —
all GREEN — back a native WebSocket discovery/session/test/evidence module.

## N. OOB / callback

**interactsh** (MIT) is the self-hostable OOB server — ideal for air-gapped.
Fallback: a first-party lightweight DNS/HTTP callback collector. Recommendation:
optional-isolated (interactsh) + build-own (fallback).

## O. Secret detection

| Project | License | Class | Recommendation |
|---|---|---|---|
| **Gitleaks** | MIT | GREEN | integrate-isolated (preferred) |
| detect-secrets (Yelp) | Apache-2.0 | GREEN | optional-isolated |
| Vantage native secret scan | first-party | GREEN | build-own — **shipped** (response/JS scanning) |
| TruffleHog | AGPL-3.0 | RED | replace with gitleaks |

**WHY:** Gitleaks (MIT) is preferred over AGPL TruffleHog. Native regex scanning
covers response/JS bodies inline.

## P. SAST assist

tree-sitter / Semgrep (see E). Keep SAST/DAST boundaries explicit; Semgrep stays
isolated + reviewed.

## Q. URL / DNS / HTTP intelligence (ProjectDiscovery)

httpx, dnsx, subfinder, naabu (note: **naabu needs libpcap**), uncover — all
MIT. Include only those with a legitimate role in *authorized application
attack-surface inventory*; gate behind the DEEP profile.

---

## Proposed final engine stack

**First-party (native, GREEN):** scope-enforcing proxy, crawler + JS extraction,
security-header/cookie/CORS analyzer, secret scanner, TLS analyzer
(cryptography), technology fingerprint, validation engine, correlation, risk.

**Isolated open-source (GREEN, arms-length):** ZAP (Apache-2.0), Nuclei (MIT),
ffuf (MIT), feroxbuster (MIT), katana (MIT), httpx (MIT), plus optional
subfinder/dnsx/tlsx/gitleaks/schemathesis/prism/interactsh (all permissive).

**Isolated, review-gated:** Semgrep (LGPL).

**External bring-your-own-license:** Burp Suite (commercial) via its REST API to
a customer-hosted instance — Vantage ships only the API client.

**Avoided / replaced (RED):** wfuzz, dirsearch, whatweb, testssl.sh, sslyze,
trufflehog, wapiti, w3af, Arachni, CodeQL — each with a permissive/native
replacement named above.

See `third-party-license-matrix.md` for the full license table and
`../architecture/engine-architecture.md` for how these plug into the platform.
