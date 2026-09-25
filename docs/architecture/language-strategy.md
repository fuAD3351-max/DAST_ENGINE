# Language Strategy — why Vantage is polyglot

Vantage is intentionally **multi-language**, with a **language-agnostic contract**
at the seams so components interoperate regardless of implementation language.
A single-language product would be the wrong call for a DAST platform, because
the ecosystem it orchestrates is already polyglot.

## The contract boundary

`contracts/` holds JSON-Schema (Draft 2020-12) definitions generated from the
domain models by `scripts/gen_contracts.py`: `ScopeRule`, `Target`,
`EngineRunRequest`, `Evidence`, `Observation`, `UnifiedFinding`. Every component —
in any language — produces/consumes these shapes. CI fails if the committed
contracts drift from the models, so the boundary stays authoritative. This is
what makes the system genuinely multi-language rather than one runtime with
glue: a Go proxy, a TypeScript UI, or a third-party integration all speak the
same versioned schema.

## Language per layer (fit-for-purpose)

| Layer | Language | Why |
|---|---|---|
| Control plane: orchestration, planner, validation, correlation, risk, governance, API/CLI | **Python** | Fastest path to a correct, exhaustively-tested intelligence layer; natural host for the AI glue; rich security/parsing libraries. |
| Hot-path network components (scope-enforcing egress proxy; future high-throughput probers) | **Go** | Static binary, low overhead, first-class concurrency; matches the engine ecosystem, so one toolchain covers proxy + most engines. |
| Web UI / browser SDK (roadmap) | **TypeScript/React** | The right tool for an enterprise console; consumes the same contracts. |
| Detection engines (integrated, not written by us) | **Go** (nuclei, ffuf, katana, httpx, feroxbuster*), **Java** (OWASP ZAP), **Rust** (feroxbuster), **Python** (schemathesis) | Best-of-breed engines are chosen on merit and license, not language. The adapter boundary makes their language irrelevant to the platform. |

\* feroxbuster is Rust; the ProjectDiscovery suite and ffuf are Go.

## Shipped multi-language components

- **`components/egress-proxy/`** — a Go, standard-library-only, scope-enforcing
  HTTP/HTTPS forward proxy. Engines run with `HTTP(S)_PROXY` pointed at it; it
  re-checks every request (and every TLS `CONNECT` target) against the shared
  scope-rule contract and refuses out-of-scope traffic with 403. Its scope
  semantics mirror the Python `ScopeEngine` and are covered by Go tests that
  parallel the Python scope tests — the contract keeps them in lockstep.
- **`src/vantage/`** — the Python control plane (this repository's core).

## How they interoperate at runtime

```
orchestrator (Python)
   │  writes scope rules  →  contracts/scope-rule (JSON)
   ▼
egress proxy (Go)  ── enforces scope ──►  isolated engines (Go/Java/Rust/Python)
   │
   └─ engine output (contracts/observation) → normalizer (Python) → findings
```

The orchestrator emits scope rules as the shared contract; the Go proxy loads
them (`-rules`) and enforces the identical policy on the wire. Engines never see
out-of-scope destinations regardless of what language they are written in.

## Adding a component in a new language

1. Consume the relevant schema from `contracts/` (generate types with your
   language's JSON-Schema tooling).
2. Communicate via those shapes (files, stdout, or HTTP) — never via Python
   internals.
3. Add build+test to CI (see the `go-components` job as the template).
4. Track any third-party libraries in `third_party/inventory` so the license
   gate covers them too.
