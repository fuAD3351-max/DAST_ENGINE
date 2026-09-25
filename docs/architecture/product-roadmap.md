# Vantage DAST — Product Roadmap

Phased delivery. Status reflects this repository. The proprietary
orchestration/validation/correlation/governance layer is the product; engines
are pluggable behind it.

## Phase 0 — Research ✅ (done)
Open-source ecosystem assessment, license verification, capability map.
Deliverables: `docs/assessment/opensource-dast-matrix.md`,
`third-party-license-matrix.md`, this roadmap, and the architecture docs.

## Phase 1 — Core platform ✅ (done)
Domain contracts; scope engine; scan state machine; persistence (SQLAlchemy;
SQLite embedded / Postgres); engine registry from manifests + `engine-lock`;
adapter framework; **license governance engine + build gate**; sandbox runners
(docker / local / fake).

## Phase 2 — Discovery ◑ (native done; OSS partial)
Native crawler + JS endpoint extraction ✅; technology fingerprint ✅; katana &
httpx adapters ✅. Remaining: browser (Playwright) SPA crawl; richer JS/source-map
analysis; API-spec ingestion (OpenAPI/GraphQL/WSDL) into the application model.

## Phase 3 — Security engines ◑
Nuclei ✅, ffuf ✅, feroxbuster ✅ (isolated). Remaining: ZAP daemon adapter
(primary active scanner); schemathesis/prism API testing; gitleaks isolated
secret scan; Semgrep (review-gated).

## Phase 4 — Validation ◑
Baseline/differential validation engine with config-reverify and reflection-
consistency strategies ✅. Remaining: active controlled-confirmation strategies
(opt-in), per-class validators, OOB-backed confirmation via interactsh.

## Phase 5 — Correlation ✅ (core done)
Endpoint normalization, fingerprint de-duplication, multi-engine merge, evidence
de-dup, cross-scan `first_seen` carry-over ✅. Next: full attack-surface graph
and relationship modelling.

## Phase 6 — Authentication ☐
Authentication profiles, browser login, token/session management, multi-role
authorization testing. (Domain hooks exist: `EngineRunRequest.auth_context`.)

## Phase 7 — Advanced API ☐
First-class OpenAPI, GraphQL (introspection + authz), WebSocket, SOAP adapters
and dedicated audit flows.

## Phase 8 — Enterprise ◑
RBAC, multi-tenancy (tenant scoping present in the model + audit log ✅),
reporting (JSON/SARIF/Markdown ✅), CI/CD (SARIF + exit codes ✅), SSO, deployment
automation (Docker/Kali/compose/systemd ✅). Remaining: RBAC/SSO, worker queue,
object storage for artifacts, air-gapped update channel.

## Phase 9 — AI ◑ (on-prem layer delivered)
Local-LLM layer **above** deterministic engines: finding prioritization,
explanation, grouping and likely-false-positive triage — all fully on-prem
(llama.cpp in-process or self-hosted Ollama), off by default. Hard rule enforced
in code: AI annotates deterministic findings only, drops hallucinated ids, and
never invents findings or evidence. Default model Qwen2.5-7B-Instruct
(Apache-2.0); see `ai-layer.md`. Remaining: endpoint classification pre-scan,
retrieval over past scans, GPU (vLLM) serving backend.

## Deployment targets (available now)
- **On-prem / private cloud:** `deploy/docker-compose.yml` (control plane +
  Postgres + Redis; docker sandbox).
- **Kali / Linux host:** `deploy/Dockerfile.kali` and `deploy/install-kali.sh`
  (native engines via `LocalSubprocessRunner`, auto-detected); systemd unit.
- **Air-gapped:** local engine registry + self-hosted interactsh + offline
  template bundle (design in place; packaging pending).

## Commercialization note
The project is open-source during development and intended to move to a closed,
commercially-licensed distribution later. The license-governance layer already
assumes a commercial distribution model, so the boundary between (a) Vantage's
proprietary code, (b) bundled permissive dependencies, and (c) isolated/external
engines is tracked from day one — making the future transition clean.
