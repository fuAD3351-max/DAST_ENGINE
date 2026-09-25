# Vantage DAST — Engine & Platform Architecture

Vantage is **one product**, not a bundle of scanners. Users see *Vantage
findings*; the engines behind them are implementation detail. The proprietary
layer owns orchestration, scope, application modelling, validation, evidence,
correlation, risk, reporting and enterprise management. Open-source engines
supply specialized detection behind a uniform adapter boundary.

```
                          Vantage DAST
                               │
                        Control Plane (API / CLI)
                               │
                       Scan Orchestrator  ── state machine
                               │
      ┌────────────────────────┼─────────────────────────┐
   Scan Planner            Engine Registry           Scope Engine
 (capability select)     (license-governed)      (authorized targets)
      │                        │                          │
      └──────────► Engine Adapters ◄──── Sandbox (docker | local | none)
                        │
   Native (first-party) │ Isolated OSS (arms-length) │ External BYOL
      │                        │                          │
      └────────────► Observations (normalized) ──────────┘
                               │
                        Validation Engine   (baseline / differential)
                               │
                     Correlation & De-duplication  (unified findings)
                               │
                          Risk Engine
                               │
                     Unified Findings store
                               │
                  Reports (JSON · SARIF · Markdown)
```

## Layers

### Domain contracts (`vantage.domain`)
Pydantic models shared by every subsystem: `Target` + `ScopeRule` +
`AuthorizationRecord`; `Scan`/`ScanPolicy`/`ScanPlan`/`ScanState`; engine
metadata (`Capability`, `EngineMetadata`, `EngineRunRequest/Result`,
`IntegrationType`, `ResourceLimits`); and the finding model (`Evidence`,
`Observation`, `UnifiedFinding`). Engines are selected by **capability**, never
by name, which is what lets an engine be swapped without redesigning the product.

### Governance (`vantage.governance`)
`LicensePolicy` classifies SPDX ids into GREEN/YELLOW/RED; `check_inventory`
applies the policy to the third-party inventory. `vantage license check` fails
CI on any RED/UNKNOWN/unreviewed component. This is a **hard release gate**.

### Engine registry (`vantage.engines.registry`)
Loads YAML manifests + `engine-lock.yaml` (exact versions, image digests),
cross-checks each engine against the license policy, and computes usability:

- `native` first-party engines → approved (own code).
- `container_cli/api` engines → GREEN approved; YELLOW/RED pending review.
- `external_service` (BYOL) → approved to *distribute the client*, disabled
  until configured, carries a bring-your-own-license note.

Only engines that are policy-usable **and have a bound adapter** are visible to
the planner.

### Adapter boundary (`vantage.engines.adapter`, `vantage.adapters.*`)
Uniform lifecycle: `metadata → health_check → capabilities → prepare_target →
execute_scan → collect_results → normalize_results → cleanup`. Adapters are the
**trust boundary**: engine output is untrusted input, validated before parsing.
Adapters never touch the database — they return `Observation`s; the orchestrator
persists.

- **Native adapters** run in-process and fetch only through a scope-enforcing,
  rate-limited `HttpClient`.
- **Container adapters** build a `ContainerSpec` and hand it to a
  `SandboxRunner`; they parse the engine's own output format.
- **External adapters** (Burp) speak a customer-hosted service's API.

### Sandbox (`vantage.engines.sandbox`)
Three runners, chosen by the operator (`SANDBOX=auto|docker|local|fake`):

- `DockerSandboxRunner` — read-only rootfs, all caps dropped,
  `no-new-privileges`, non-root, CPU/mem/pid limits, size-capped tmpfs, network
  = none or scoped-egress. Use for hardened/multi-tenant deployments.
- `LocalSubprocessRunner` — runs the pinned binary from `PATH` with a private
  temp workspace and POSIX rlimits. Use on **Kali/Linux hosts** where the tools
  are installed natively.
- `FakeSandboxRunner` — tests / embedded demo.

### Scope engine (`vantage.scope`)
The authoritative gate on whether any URL may be touched: authorization
required; excludes beat includes; nothing outside the include set; private/
loopback literals refused unless explicitly opted in. Pure and synchronous, so
it is reused inside the egress proxy and exhaustively unit-tested.

### Orchestrator (`vantage.scan.orchestrator`)
The only component that mutates scan state and writes findings. Legal state
machine (`created→queued→planning→running→correlating→validating→reporting→
completed`, with cancel/fail paths). Per-engine failure isolation: one engine
crashing degrades coverage but never aborts the scan or corrupts results.

### Intelligence (proprietary differentiators)
- **Planner** — capability selection specialized by application kind + profile,
  one engine per capability by default (no "run 30 scanners"), with explainable
  reasons and recorded skips. A `RequestKnowledgeBase` prevents duplicate work.
- **Validation** — baseline/differential re-verification; only raises confidence
  to CONFIRMED or lowers to FALSE_POSITIVE, never invents evidence.
- **Correlation** — normalizes endpoints (`/users/1`→`/users/{id}`) and merges
  multi-engine observations of the same weakness into one finding with all
  evidence; confidence rises with independent corroboration.
- **Risk** — deterministic, explainable 0–100 score (impact × certainty ×
  exposure) with per-finding factor breakdown.

### Surfaces
FastAPI control plane, Typer CLI, and JSON/SARIF/Markdown reporting — all over
the same subsystems. Both surfaces refuse to scan an unauthorized target.

## Security posture
- Authorization required before any active traffic.
- Every engine treated as untrusted; output validated at the adapter boundary.
- No engine writes to the primary database.
- Traffic bounded by per-target rate limits; scope enforced centrally.
- Reproducible engines via pinned versions + image digests.

## Replaceability
Because selection is capability-based and normalization is centralized, any
engine can be replaced (e.g. swap ffuf for feroxbuster, or drop a RED engine for
its native replacement) by editing a manifest and binding a different adapter —
no change to planning, correlation, risk, or reporting.
