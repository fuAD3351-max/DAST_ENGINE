# Vantage DAST — On-Premise AI Layer

The AI layer helps *manage* DAST activity — prioritizing, explaining, grouping
and false-positive triage of findings — while running **entirely on the
customer's hardware**. Nothing about a scan leaves the deployment, so it works
in private-cloud and air-gapped installs.

## Position in the architecture (AI sits ABOVE deterministic engines)

```
open-source + native engines → Observations → validation → correlation → risk
                                                                              │
                                                             Unified Findings (deterministic)
                                                                              │
                                                       ┌──────────────────────┘
                                                 SecurityAnalyst (local LLM)
                                                       │  annotate only
                                             AiAssessment (advisory metadata)
```

The deterministic pipeline is complete and authoritative on its own. The AI
layer **annotates** it; disabling AI changes nothing about what is detected.

## Hard contract (enforced in code, not just the prompt)

- AI **annotates existing findings**; it never creates findings or evidence.
- Every AI statement must reference a finding by its exact `id`. Any id the model
  returns that is not in the input set is **dropped** (`test_ai.py` covers this).
- AI output is advisory `AiAnnotation` metadata attached alongside the finding.
  It never overwrites `severity`, `confidence`, `evidence` or the deterministic
  `risk_score`. Prioritized ordering is presentation-only, with deterministic
  risk as the tiebreak.
- If the provider is unavailable or returns unparseable output, the analyst is a
  **no-op** and deterministic results stand.

## Recommended model: which AI to use on-prem

Run a permissively-licensed local model. `vantage ai models` lists the catalog,
license-classed by the same policy that governs every other component.

| Model | Params | License | Class | Notes |
|---|---|---|---|---|
| **Qwen2.5-7B-Instruct** (default) | 7B | Apache-2.0 | GREEN | Commercial use, no user cap at 7B; strong JSON/instruction following |
| Qwen2.5-14B-Instruct | 14B | Apache-2.0 | GREEN | Higher quality; dedicated analyst box |
| Qwen3-8B | 8B | Apache-2.0 | GREEN | Newer generation, no added terms |
| Mistral-7B-Instruct | 7B | Apache-2.0 | GREEN | Solid Apache-2.0 alternative |
| Phi-4-mini | 3.8B | MIT | GREEN | Small footprint for constrained/edge nodes |
| Qwen2.5-3B / Llama 3.1 / Gemma 2 | — | Qwen/Llama/Gemma | **YELLOW** | Usage restrictions — recorded review before commercial use |

Pick GREEN (Apache-2.0 / MIT) for a commercial product. The license gate tracks
the chosen model as a third-party component (`third_party/inventory`).

## Runtimes (all local, permissive)

- **llama.cpp via `llama-cpp-python`** (MIT) — in-process, loads a local GGUF
  file. The most self-contained/air-gapped option. Optional `ai` extra.
- **Ollama** (MIT) — self-hosted daemon on localhost; better ops/model
  management. No code dependency.
- (vLLM, Apache-2.0, is a supported future backend for GPU serving.)

## Choosing a model

The solution asks which model to use: run `vantage ai select` for an interactive
picker over the commercially-licensed catalog (YELLOW models require
`--accept-yellow`). The choice is persisted to the Vantage config and used by
future scans; `VANTAGE_AI_*` env vars override it. `vantage ai models` lists the
catalog; `vantage ai info` shows the active choice and availability.

## Install / enable

**Ollama (simplest, on-prem):**
```bash
# on the host: install Ollama, then
ollama pull qwen2.5:7b-instruct
export VANTAGE_AI_PROVIDER=ollama VANTAGE_AI_MODEL=qwen2.5:7b-instruct
vantage ai info          # shows provider/model/license/availability
vantage scan https://target.you.own/ --authorize --ai
```

**llama.cpp (fully in-process, air-gapped):**
```bash
pip install 'vantage-dast[ai]'
# obtain a GGUF (e.g. Qwen2.5-7B-Instruct Q4_K_M) onto the host, then
export VANTAGE_AI_PROVIDER=llama_cpp \
       VANTAGE_AI_MODEL=qwen2.5:7b-instruct \
       VANTAGE_AI_MODEL_PATH=/models/qwen2.5-7b-instruct-q4_k_m.gguf
vantage scan https://target.you.own/ --authorize --ai
```

Environment: `VANTAGE_AI_PROVIDER` (`none`|`ollama`|`llama_cpp`),
`VANTAGE_AI_MODEL`, `VANTAGE_AI_MODEL_PATH`, `VANTAGE_AI_OLLAMA_URL`.

## What the analyst produces

`AiAssessment` with, per finding: an advisory `priority_rank`, a
`likely_false_positive` flag (for human review), a short `explanation` and
`remediation`, and an optional `group_id` clustering related findings. Reports
(JSON and Markdown) surface these clearly labelled as **AI-assisted / advisory**.

## Air-gapped notes

Both runtimes work with no internet at inference time; only the initial model
download needs connectivity (do it once, then ship the GGUF/Ollama blob into the
air-gapped environment). No telemetry, no external API calls.
