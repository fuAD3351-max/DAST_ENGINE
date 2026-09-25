"""Catalog of recommended on-premise LLMs for the Vantage AI layer.

Every model is a third-party component and is license-classed like everything
else Vantage governs. Only GREEN (permissive, commercially-usable) models are
recommended as defaults; YELLOW models carry usage restrictions and need a
recorded review before shipping/enabling in a commercial deployment.

Licenses verified against model cards on 2026-09-25; re-verify before pinning a
specific revision. Sizes/quant are guidance for GGUF (llama.cpp) deployments.
"""

from __future__ import annotations

from dataclasses import dataclass

from vantage.domain.common import LicenseClass


@dataclass(frozen=True)
class ModelInfo:
    id: str  # ollama-style tag / logical id
    family: str
    params: str
    license_spdx: str
    license_class: LicenseClass
    context: int
    gguf_hint: str  # e.g. recommended quant + approx size
    notes: str


# Recommended for managing DAST activity on-prem (reasoning + tool-style JSON
# output, permissive licenses). Default is Qwen2.5-7B-Instruct (Apache-2.0).
CATALOG: tuple[ModelInfo, ...] = (
    ModelInfo(
        "qwen2.5:7b-instruct",
        "Qwen2.5",
        "7B",
        "Apache-2.0",
        LicenseClass.GREEN,
        32768,
        "Q4_K_M ≈ 4.7GB (8GB+ RAM)",
        "DEFAULT. Strong instruction-following + JSON; Apache-2.0, no usage caps at 7B.",
    ),
    ModelInfo(
        "qwen2.5:14b-instruct",
        "Qwen2.5",
        "14B",
        "Apache-2.0",
        LicenseClass.GREEN,
        32768,
        "Q4_K_M ≈ 9GB (16GB+ RAM)",
        "Higher quality; Apache-2.0. Good for a dedicated on-prem analyst box.",
    ),
    ModelInfo(
        "qwen3:8b",
        "Qwen3",
        "8B",
        "Apache-2.0",
        LicenseClass.GREEN,
        32768,
        "Q4_K_M ≈ 5GB",
        "Newer generation, Apache-2.0 with no added terms.",
    ),
    ModelInfo(
        "mistral:7b-instruct",
        "Mistral",
        "7B",
        "Apache-2.0",
        LicenseClass.GREEN,
        32768,
        "Q4_K_M ≈ 4.4GB",
        "Apache-2.0 alternative; solid general reasoning.",
    ),
    ModelInfo(
        "phi4-mini",
        "Phi-4",
        "3.8B",
        "MIT",
        LicenseClass.GREEN,
        16384,
        "Q4_K_M ≈ 2.5GB (constrained hosts)",
        "MIT; small footprint for edge/constrained on-prem nodes.",
    ),
    ModelInfo(
        "qwen2.5:3b-instruct",
        "Qwen2.5",
        "3B",
        "LicenseRef-Qwen",
        LicenseClass.YELLOW,
        32768,
        "Q4_K_M ≈ 2GB",
        "3B ships under the Qwen (not Apache) license — review before commercial use.",
    ),
    ModelInfo(
        "llama3.1:8b-instruct",
        "Llama 3.1",
        "8B",
        "LicenseRef-Llama-3.1-Community",
        LicenseClass.YELLOW,
        131072,
        "Q4_K_M ≈ 4.9GB",
        "Llama Community License (not OSI; MAU clause) — review before commercial use.",
    ),
    ModelInfo(
        "gemma2:9b-instruct",
        "Gemma 2",
        "9B",
        "LicenseRef-Gemma",
        LicenseClass.YELLOW,
        8192,
        "Q4_K_M ≈ 5.8GB",
        "Gemma Terms of Use (use restrictions) — review before commercial use.",
    ),
)

BY_ID: dict[str, ModelInfo] = {m.id: m for m in CATALOG}
DEFAULT_MODEL_ID = "qwen2.5:7b-instruct"


def recommended(license_class: LicenseClass | None = LicenseClass.GREEN) -> list[ModelInfo]:
    if license_class is None:
        return list(CATALOG)
    return [m for m in CATALOG if m.license_class is license_class]


def get(model_id: str) -> ModelInfo | None:
    return BY_ID.get(model_id)
