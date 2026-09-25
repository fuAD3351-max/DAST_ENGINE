# Vantage DAST

**Vantage** is a unified, license-governed **Dynamic Application Security
Testing** platform for *authorized* security testing. It orchestrates,
normalizes, validates, correlates and reports across a carefully selected set of
open-source security engines and a proprietary intelligence layer — so users see
**one product and one finding per issue**, not a pile of scanner outputs.

> ⚖️ **Authorized use only.** Vantage is a defensive product. Only test systems
> you own or are explicitly authorized to assess. Targets require an
> authorization record; the CLI refuses to scan without `--authorize`.

> 🏷️ Open-source during development; intended to move to a closed, commercial
> license later. The architecture and license-governance layer assume a
> commercial distribution model from day one.

## What makes it one product

The proprietary layer owns the intelligence; open-source engines are pluggable
detection behind a uniform adapter boundary:

- **Scan Orchestrator** — a strict scan state machine with per-engine failure isolation.
- **Scope Engine** — the authorized-target gate (includes/excludes, private-IP guard).
- **Scan Planner** — picks *which tool to use per target* by capability + app kind (no "run every scanner").
- **Validation Engine** — baseline/differential re-verification; confidence, not noise.
- **Correlation Engine** — merges multi-engine observations into one unified finding.
- **Risk Engine** — deterministic, explainable 0–100 scoring.
- **License Governance** — a build gate that blocks GPL/AGPL/commercial code from being embedded.
- **On-prem AI layer** — a local LLM (Qwen2.5/Qwen3 Apache-2.0 via llama.cpp or Ollama) *above* the engines that prioritizes, explains and triages findings; annotates only, never invents evidence; off by default.

Engines are selected by **capability**, so any engine can be swapped without
touching planning, correlation, risk or reporting.

## Engines

| Tier | Engines |
|---|---|
| Native (first-party) | crawler+JS, security headers/cookies/CORS, secret scan, TLS (cryptography), tech fingerprint, validation, correlation, risk |
| Isolated GREEN (arms-length) | **Nuclei, ffuf, katana, httpx, feroxbuster, ZAP, gitleaks, subfinder, dnsx, tlsx** (shipped adapters); schemathesis, prism, interactsh (declared) |
| Review-gated (YELLOW) | Semgrep (LGPL) — disabled until reviewed |
| External (bring-your-own-license) | **Burp Suite** via the customer's own licensed instance (API client only) |
| Blocked (RED) → replaced | trufflehog→gitleaks, sslyze/testssl→native TLS, wfuzz/dirsearch→ffuf/feroxbuster, whatweb→native+wappalyzergo, wapiti/w3af→ZAP+Nuclei |

See `docs/assessment/` for the full ecosystem assessment and license matrix.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

vantage version
vantage license check           # license governance build gate
vantage engine list             # all engines, license class, usability
vantage engine detect           # which engine binaries are installed (Kali/host)

# Scan a target you are authorized to test (native engines only shown here):
vantage scan https://target.you.own/ --authorize --profile standard \
    --sandbox local --format markdown
```

`--sandbox`: `auto` (docker if present, else local) · `docker` (hardened
containers) · `local` (native Kali/host binaries) · `fake` (offline).

## Run on Kali / Linux (native tools)

Kali ships the engines as apt packages; Vantage runs them natively and
auto-detects what's installed:

```bash
sudo ./deploy/install-kali.sh --with-green-engines
vantage scan https://target.you.own/ --authorize --sandbox local
```

Or all-in-one container: `docker build -f deploy/Dockerfile.kali -t vantage:kali . && docker run -p 8080:8080 vantage:kali`.

## Control plane (API)

```bash
uvicorn vantage.api.app:app --host 0.0.0.0 --port 8080
# POST /targets {name, base_urls, authorized:true} → id
# POST /scans   {target_id, profile}               → scan_id + summary
# GET  /scans/{id}/report?fmt=json|sarif|markdown
# GET  /engines                                     → license-governed catalog
```

Environment: `VANTAGE_SANDBOX`, `VANTAGE_AUTODETECT`, `VANTAGE_DATABASE_URL`.

## Deployment

- **On-prem / private cloud:** `deploy/docker-compose.yml` (control plane +
  Postgres + Redis, docker sandbox).
- **Kali / Linux host:** `deploy/Dockerfile.kali`, `deploy/install-kali.sh`,
  `deploy/vantage.service` (systemd) — native engines.
- **Air-gapped:** local engine registry + self-hosted interactsh (design in
  `docs/architecture/product-roadmap.md`).

## Development

```bash
ruff check src tests && ruff format --check src tests
mypy                 # strict
pytest -q            # offline; fakes all network/sandbox
```

CI (`.github/workflows/ci.yml`) runs lint, format, strict types, tests, the
**license gate**, engine verification, and SBOM generation.

## Layout

Vantage is **polyglot** (see `docs/architecture/language-strategy.md`): a Python
control plane, a Go egress proxy, and engines in Go/Java/Rust/Python — all
speaking the language-agnostic JSON-Schema contracts in `contracts/`.

```
contracts/      language-agnostic JSON-Schema (generated from the models)
components/
  egress-proxy/ Go scope-enforcing forward proxy (stdlib only) + tests
src/vantage/
  domain/       shared contracts (targets, scans, engines, findings)
  scope/        authorized-target scope engine
  governance/   license policy + inventory + build gate
  engines/      registry, adapter interface, sandbox runners, detection
  adapters/     native/ (first-party) · oss/ (isolated) · external/ (BYOL)
  planner/      capability-based scan planner
  scan/         orchestrator (state machine) + validation engine
  findings/     taxonomy, correlation, risk, reporting
  knowledge/    request knowledge base (dedup)
  persistence/  SQLAlchemy models + repositories
  api/          FastAPI control plane
  cli/          Typer CLI
  ai/           on-prem LLM providers + analyst (above the engines)
  config.py     persisted AI model/provider selection
engines/manifests/  one YAML per engine   engines/engine-lock.yaml  pinned versions/digests
third_party/        policy, inventory, licenses, notices, SBOM
deploy/             Dockerfiles, compose, Kali installer, systemd
docs/               assessment + architecture + roadmap
```

## License & attribution

Vantage's own code is proprietary (`LicenseRef-Vantage-Proprietary`).
Third-party components and their licenses are tracked in
`third_party/inventory/third_party_inventory.yaml` and attributed in
`third_party/notices/NOTICE.md`. Respect every third-party license; the build
gate enforces the policy.
