# Vantage DAST — Commercial Differentiators

Anyone can download Nuclei or ZAP. Vantage is not "we run open-source tools" —
it is the proprietary layer that turns raw scanner output into **authentic,
proof-carrying, low-false-positive results** with enterprise governance. This is
what makes it sellable.

## The core claim: proof, not alerts

Open-source scanners emit *alerts* — unvalidated, per-tool, un-correlated, and
noisy. Vantage emits **confirmed findings, each with a Proof-of-Vulnerability
bundle**:

- **Verdict**, earned not asserted: `confirmed` (Vantage's validation engine
  reproduced the behaviour against a baseline), `corroborated` (multiple
  independent engines agree), `reported` (single indicator, needs review), or
  `disputed` (validation classified it a false positive).
- **Baseline-vs-observed differential** that establishes the behaviour.
- **A reproduction recipe** the customer can run themselves — the result does
  not require trusting the scanner.
- **A tamper-evident integrity digest** (SHA-256), and an **HMAC signature**
  when an evidence-signing key is configured, so results are auditable and
  court/compliance-grade.
- `--confirmed-only` produces the stakeholder view: **only findings that carry a
  confirmed/corroborated proof** — the "we don't drown you in false positives"
  deliverable.

No single open-source tool produces this, because it requires cross-engine
correlation + independent validation + evidence bundling — the proprietary layer.

## What each proprietary layer adds over the raw tools

| Layer | Raw OSS tools | Vantage |
|---|---|---|
| **Validation** | Report indicators as-is | Re-tests against a baseline; only `confirmed` when reproduced; demotes false positives |
| **Correlation** | N tools → N overlapping alerts | One unified finding per weakness, with all contributing engines and evidence merged |
| **Proof** | A log line | A reproducible, tamper-evident evidence bundle per finding |
| **Risk** | CVSS or nothing | Deterministic, explainable 0–100 score (impact × certainty × exposure) with factor breakdown |
| **Planning** | You run each tool by hand | Capability-based, application-aware planning: the right tools per target, no duplicate traffic |
| **Governance** | Your legal problem | A build gate that provably keeps GPL/AGPL/commercial code out of the shipped product |
| **AI** | — | On-prem LLM that prioritizes/explains/triages, annotating findings only — never inventing evidence |
| **Deployment** | DIY | On-prem, Kali-native, air-gapped, signed evidence, CI/CD (SARIF), multi-language components |

## Why the false-positive story is defensible

The industry's #1 DAST complaint is false positives. Vantage's validation +
correlation + proof pipeline is purpose-built to attack exactly that:

1. An engine reports an indicator.
2. The validation engine reproduces it against a baseline (or demotes it).
3. Correlation merges corroborating engines and raises confidence only on
   independent agreement.
4. Only findings that survive get a `confirmed`/`corroborated` proof; the rest
   are visible but clearly separated.

You can sell a **confirmed-only report** whose every line ships with reproducible
proof — something a bare scanner cannot offer.

## Bundled on-prem AI (installs with the product)

The most mature commercially-licensable local model — **Qwen2.5-7B-Instruct
(Apache-2.0)** — is pinned in `ai/model-lock.yaml` and installed with the
solution via `vantage ai install` (called by the installers). It runs entirely
on-prem (Ollama or in-process llama.cpp), so the AI assistance is part of the
product, not a cloud dependency, and works air-gapped.

## Enterprise moat (beyond detection)

Multi-tenancy and audit logging in the data model, license governance as a CI
gate, reproducible pinned engines, signed evidence, SARIF/CI integration,
on-prem/air-gapped deployment, and a replaceable-engine architecture (swap or
drop any engine without touching planning/correlation/risk/reporting). These are
the things a security *program* buys — not a scanner.

## One-line positioning

> **Vantage turns a fleet of best-of-breed scanners into one product that
> delivers confirmed, reproducible, signed findings — with the false positives
> removed and the licensing handled — deployable on-prem and air-gapped.**
