# Engine Integration Plan

How each selected engine is wired into Vantage, in dependency order. Every
integration follows the same adapter lifecycle and the same rules: license
governed, version pinned, output treated as untrusted, no direct DB access,
scope + rate limits enforced by the platform.

## Integration tiers

1. **Native (first-party, in-process).** Vantage code. Fetches only through the
   scope-enforcing `HttpClient`. Examples: crawler, headers, TLS, fingerprint,
   secret scan, validation. Status: **implemented**.
2. **Isolated GREEN (arms-length).** Unmodified upstream engine run in a sandbox
   (`docker` or `local`). Adapter builds a `ContainerSpec` (image + `binary` for
   host mode) and parses upstream output. Examples: Nuclei, ffuf (shipped);
   katana, httpx, feroxbuster (adapters shipped); ZAP, gitleaks, schemathesis,
   subfinder/dnsx/tlsx/prism/interactsh (declared).
3. **Review-gated (YELLOW).** As tier 2, but disabled until a recorded legal
   review approves it. Example: Semgrep (LGPL).
4. **External BYOL.** Customer hosts and licenses the engine; Vantage ships only
   an API client. Example: Burp Suite. Disabled until configured.
5. **Blocked (RED) / replaced.** Declared for tracking, unusable; a native/GREEN
   replacement is implemented.

## Per-engine plan (selected)

### Nuclei (MIT) — template checks — **implemented**
Container/local via CLI, JSONL output. Template selection controlled by the
Template Registry + policy tag denylist (never arbitrary templates). Egress
forced through the scope proxy via `-proxy`. Output → Observations, CWE mapped
from template classification.

### ffuf / feroxbuster (MIT) — content discovery — **implemented**
Curated wordlist mounted read-only. JSON output; interesting statuses only. Rate
bounded by target limits. Replaces GPL wfuzz/dirsearch.

### katana / httpx (MIT) — crawl / recon+fingerprint — **implemented**
JSONL output → discovered endpoints / detected technologies feeding the
attack-surface graph and correlation technology context.

### OWASP ZAP (Apache-2.0) — active/passive scanning — **planned**
`container_api`: run the ZAP daemon in a sandbox, drive via its API, ingest
alerts, normalize to Observations. Primary active-scan engine.

### Semgrep (LGPL) — JS static assist — **review-gated**
Isolated container; rules registry licensed separately (own review). Disabled by
default.

### Burp Suite (commercial) — external — **implemented (client)**
`external_service`: REST API to a customer-hosted Burp; launch scan, poll,
ingest issues, map to Observations (Burp "certain" → FIRM, never CONFIRMED).
Disabled until `base_url`/`api_key` configured.

## Cross-engine feedback loop
Crawler/discovery output feeds the `RequestKnowledgeBase`; the planner and later
engines consult it to avoid re-testing the same (endpoint, method, parameter,
class). API/authz discovery raises authorization candidates. Validation combines
endpoint + role + object + response before confirming.

## Deterministic orchestration (no "run everything")
`Target → fingerprint → classify → select capabilities (profile ∩ app-kind) →
one engine per capability → execute (staged) → validate → correlate → risk →
report`. Redundant multi-engine coverage is opt-in (`PlannerConfig.redundant_engines`).

## Adding a new engine
1. Verify license; add SPDX to policy if new.
2. Write `engines/manifests/<id>.yaml` (capabilities, integration, image/binary).
3. Pin version + digest in `engine-lock.yaml`.
4. Implement an `EngineAdapter` (container or native) that normalizes output.
5. Bind it in `vantage.app` (or auto-detect on host).
6. Add tests with a fake sandbox/HTTP client.
7. `vantage license check` + `vantage engine verify` must pass.
No planning/correlation/risk/report changes are required — that is the point of
the capability + adapter design.
