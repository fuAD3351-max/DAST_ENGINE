"""AI config persistence and resolution tests."""

from __future__ import annotations

import json

from vantage.config import AIConfig, VantageConfig, config_path, resolve_ai_settings


def test_default_config_is_ai_off(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VANTAGE_CONFIG", str(tmp_path / "config.json"))
    for var in ("VANTAGE_AI_PROVIDER", "VANTAGE_AI_MODEL", "VANTAGE_AI_MODEL_PATH"):
        monkeypatch.delenv(var, raising=False)
    assert resolve_ai_settings().provider == "none"


def test_save_and_load_roundtrip(monkeypatch, tmp_path) -> None:
    cfgfile = tmp_path / "config.json"
    monkeypatch.setenv("VANTAGE_CONFIG", str(cfgfile))
    cfg = VantageConfig(ai=AIConfig(provider="ollama", model="qwen3:8b"))
    path = cfg.save()
    assert path == config_path()
    loaded = VantageConfig.load()
    assert loaded.ai.provider == "ollama"
    assert loaded.ai.model == "qwen3:8b"
    # File is valid JSON with the expected shape.
    data = json.loads(cfgfile.read_text())
    assert data["ai"]["model"] == "qwen3:8b"


def test_env_overrides_config(monkeypatch, tmp_path) -> None:
    cfgfile = tmp_path / "config.json"
    monkeypatch.setenv("VANTAGE_CONFIG", str(cfgfile))
    VantageConfig(ai=AIConfig(provider="ollama", model="qwen3:8b")).save()
    monkeypatch.setenv("VANTAGE_AI_PROVIDER", "llama_cpp")
    monkeypatch.setenv("VANTAGE_AI_MODEL", "phi4-mini")
    settings = resolve_ai_settings()
    assert settings.provider == "llama_cpp"  # env wins
    assert settings.model == "phi4-mini"


def test_missing_config_file_is_safe(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VANTAGE_CONFIG", str(tmp_path / "does-not-exist.json"))
    assert VantageConfig.load().ai.provider == "none"
