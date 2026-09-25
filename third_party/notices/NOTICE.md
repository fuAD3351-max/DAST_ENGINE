# Third-Party Notices — Sentinel DAST

Sentinel DAST incorporates and/or integrates the third-party components listed
in `third_party/inventory/third_party_inventory.yaml`. This NOTICE aggregates
the attribution required by their licenses. Full license texts belong in
`third_party/licenses/` (populated by the release process from each component's
upstream LICENSE file).

## Control-plane runtime (bundled, permissive)

| Component | License | Copyright |
|-----------|---------|-----------|
| pydantic | MIT | Pydantic Services Inc. and contributors |
| SQLAlchemy | MIT | SQLAlchemy authors and contributors |
| alembic | MIT | Mike Bayer and contributors |
| FastAPI | MIT | Sebastián Ramírez |
| Starlette | BSD-3-Clause | Encode OSS Ltd. |
| Uvicorn | BSD-3-Clause | Encode OSS Ltd. |
| Typer | MIT | Sebastián Ramírez |
| PyYAML | MIT | Ingy döt Net, Kirill Simonov |
| httpx | BSD-3-Clause | Encode OSS Ltd. |
| cryptography | Apache-2.0 OR BSD-3-Clause | PyCA contributors |

## Isolated security engines (not linked; run unmodified in a sandbox)

| Engine | License | Vendor | Integration |
|--------|---------|--------|-------------|
| Nuclei | MIT | ProjectDiscovery | container/local, arms-length |
| ffuf | MIT | Joona Hoikkala | container/local, arms-length |
| katana | MIT | ProjectDiscovery | container/local, arms-length |
| httpx (PD) | MIT | ProjectDiscovery | container/local, arms-length |
| feroxbuster | MIT | epi052 | container/local, arms-length |

Engines declared in `engines/manifests/` but under GPL/AGPL (e.g. trufflehog,
wfuzz, dirsearch, whatweb, testssl.sh, wapiti, sslyze) or LGPL (semgrep) are NOT
bundled or redistributed with Sentinel. They may be run only as unmodified,
isolated programs after a recorded legal review, or replaced by the permissive
alternatives Sentinel ships natively. Burp Suite (PortSwigger, commercial) is
integrated only as an external, customer-hosted, separately-licensed service;
Sentinel distributes only the API client.

A machine-readable SBOM is generated at `third_party/sbom/sbom.cyclonedx.json`.
