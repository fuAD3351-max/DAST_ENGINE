"""Persisted Vantage configuration (currently the AI provider/model choice).

Resolution order for AI settings, most specific first:
1. explicit environment variables (VANTAGE_AI_*),
2. the persisted config file written by ``vantage ai select``,
3. built-in defaults (AI disabled).

The config file is JSON at ``$VANTAGE_CONFIG`` or, failing that,
``$XDG_CONFIG_HOME/vantage/config.json`` (``~/.config/vantage/config.json``).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def config_path() -> Path:
    explicit = os.environ.get("VANTAGE_CONFIG")
    if explicit:
        return Path(explicit)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "vantage" / "config.json"


@dataclass
class AIConfig:
    provider: str = "none"  # none | ollama | llama_cpp
    model: str = "qwen2.5:7b-instruct"
    model_path: str = ""  # GGUF for llama_cpp
    ollama_url: str = "http://127.0.0.1:11434"


@dataclass
class VantageConfig:
    ai: AIConfig = field(default_factory=AIConfig)

    @classmethod
    def load(cls) -> VantageConfig:
        path = config_path()
        if not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return cls()
        ai = data.get("ai", {}) if isinstance(data, dict) else {}
        return cls(
            ai=AIConfig(
                provider=str(ai.get("provider", "none")),
                model=str(ai.get("model", "qwen2.5:7b-instruct")),
                model_path=str(ai.get("model_path", "")),
                ollama_url=str(ai.get("ollama_url", "http://127.0.0.1:11434")),
            )
        )

    def save(self) -> Path:
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {"ai": asdict(self.ai)}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return path


def resolve_ai_settings() -> AIConfig:
    """Merge persisted config with environment overrides (env wins)."""
    cfg = VantageConfig.load().ai
    return AIConfig(
        provider=os.environ.get("VANTAGE_AI_PROVIDER", cfg.provider),
        model=os.environ.get("VANTAGE_AI_MODEL", cfg.model),
        model_path=os.environ.get("VANTAGE_AI_MODEL_PATH", cfg.model_path),
        ollama_url=os.environ.get("VANTAGE_AI_OLLAMA_URL", cfg.ollama_url),
    )
