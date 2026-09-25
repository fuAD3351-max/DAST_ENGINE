# Third-Party License Matrix

License determinations for every component Vantage integrates, isolates, or
avoids. Verified against upstream `LICENSE` files / package metadata on
**2026-09-25**. The machine-readable source of truth is
`third_party/inventory/third_party_inventory.yaml` (bundled components) and
`engines/manifests/` + `engines/engine-lock.yaml` (engines); `vantage license
check` enforces the policy in CI.

**Policy classes:** GREEN = embed/redistribute after notice review; YELLOW =
weak copyleft, isolate + recorded review; RED = strong/network copyleft or
commercial, never embed — isolate as unmodified separate program after legal
review, or replace.

## Bundled control-plane dependencies (shipped, in-process)

| Component | Version | License (SPDX) | Class | Notes |
|---|---|---|---|---|
| pydantic | ≥2.7 | MIT | GREEN | domain model |
| SQLAlchemy | ≥2.0 | MIT | GREEN | persistence |
| alembic | ≥1.13 | MIT | GREEN | migrations |
| fastapi | ≥0.115 | MIT | GREEN | control-plane API |
| starlette | ≥0.37 | BSD-3-Clause | GREEN | ASGI toolkit |
| uvicorn | ≥0.30 | BSD-3-Clause | GREEN | ASGI server |
| typer | ≥0.12 | MIT | GREEN | CLI |
| PyYAML | ≥6 | MIT | GREEN | config/policy parsing |
| httpx | ≥0.27 | BSD-3-Clause | GREEN | native probing/validation |
| cryptography | ≥42 | Apache-2.0 OR BSD-3-Clause | GREEN | native TLS analysis |

Build/dev only (not redistributed): pytest, ruff, mypy — all MIT.

## Security engines

| Engine | Version | License (SPDX) | Class | Integration | Status |
|---|---|---|---|---|---|
| Nuclei | v3.4.10 | MIT | GREEN | container_cli / local | **shipped** |
| ffuf | v2.1.0 | MIT | GREEN | container_cli / local | **shipped** |
| katana | v1.2.2 | MIT | GREEN | container_cli / local | adapter shipped |
| httpx (PD) | v1.6.9 | MIT | GREEN | container_cli / local | adapter shipped |
| feroxbuster | v2.11.0 | MIT | GREEN | container_cli / local | adapter shipped |
| OWASP ZAP | 2.16.1 | Apache-2.0 | GREEN | container_cli | **adapter shipped** |
| gau | v2.2.4 | MIT | GREEN | container_cli | declared |
| subfinder | v2.6.8 | MIT | GREEN | container_cli | **adapter shipped** |
| dnsx | v1.2.1 | MIT | GREEN | container_cli | **adapter shipped** |
| tlsx | v1.1.9 | MIT | GREEN | container_cli | **adapter shipped** |
| gitleaks | v8.21.2 | MIT | GREEN | container_cli | **adapter shipped** |
| wappalyzergo | v0.2.0 | MIT | GREEN | container_cli | declared |
| schemathesis | 4.28.0 | MIT | GREEN | container_cli | declared |
| Stoplight Prism | 5.16.0 | Apache-2.0 | GREEN | container_cli | declared |
| interactsh | v1.2.4 | MIT | GREEN | container_api | declared |
| Semgrep CE | 1.178.0 | **LGPL-2.1-or-later** | YELLOW | container_cli | review-gated, disabled |
| TruffleHog | 3.82.13 | **AGPL-3.0-only** | RED | container_cli | blocked → use gitleaks |
| SSLyze | 6.3.1 | **AGPL-3.0-only** | RED | container_cli | blocked → native TLS |
| wfuzz | 3.1.0 | **GPL-2.0-only** | RED | container_cli | blocked → ffuf |
| dirsearch | 0.4.3 | **GPL-2.0-only** | RED | container_cli | blocked → ffuf/feroxbuster |
| WhatWeb | 0.5.5 | **GPL-2.0-only** | RED | container_cli | blocked → native + wappalyzergo |
| testssl.sh | 3.2 | **GPL-2.0-only** | RED | container_cli | blocked → native TLS |
| Wapiti | 3.3.2 | **GPL-2.0-only** | RED | container_cli | blocked → ZAP + Nuclei |
| Burp Suite | (customer) | **Commercial (PortSwigger)** | RED | external_service | BYOL; client only |

## Distribution rules enforced by `vantage license check`

1. A GREEN component may be embedded or isolated and redistributed (with NOTICE).
2. A YELLOW component must have a recorded approval before it ships; it is run
   isolated (arms-length container), never linked into Vantage.
3. A RED component **cannot be embedded or redistributed**. It may be used only
   as an unmodified, isolated, separately-obtained program after a recorded
   legal review (`approval_status: approved` + `approval_reference`), or it is
   replaced by the permissive/native alternative named above.
4. Any license not in the policy table is treated as UNKNOWN and **blocks the
   build**.
5. First-party (`native`) engines are Vantage's own code and are exempt from the
   third-party policy (still version-pinned for reproducibility).

## RED-engine handling summary

Every RED engine that ships in Kali is **declared** in the registry (so it is
tracked and governed) but **disabled and unusable** until a recorded review
approves it, and each has a GREEN/native replacement already implemented:

| Blocked (RED) | Replacement (GREEN/native) |
|---|---|
| trufflehog (AGPL) | gitleaks (MIT) + native secret scan |
| sslyze (AGPL), testssl.sh (GPL) | native TLS analyzer (cryptography) |
| wfuzz, dirsearch (GPL) | ffuf, feroxbuster (MIT) |
| whatweb (GPL) | native fingerprint + wappalyzergo (MIT) |
| wapiti, w3af (GPL) | OWASP ZAP (Apache-2.0) + Nuclei (MIT) |

## Actions before first commercial release

- [ ] Resolve every engine image tag to a pinned digest (`engines/engine-lock.yaml`).
- [ ] Populate `third_party/licenses/` with each component's full upstream text.
- [ ] Legal review of any YELLOW/RED engine an operator chooses to enable.
- [ ] Regenerate and archive the SBOM (`third_party/sbom/`).
