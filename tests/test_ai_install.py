"""Tests for the bundled-model installer resolver."""

from __future__ import annotations

import pytest

from vantage.ai.install import install_model, load_locked_model

pytestmark = pytest.mark.asyncio


def test_load_locked_default_model() -> None:
    m = load_locked_model("ai/model-lock.yaml")
    assert m.key == "qwen2.5-7b-instruct"
    assert m.license == "Apache-2.0"
    assert m.ollama_tag == "qwen2.5:7b-instruct"


def test_unknown_model_raises() -> None:
    with pytest.raises(KeyError):
        load_locked_model("ai/model-lock.yaml", key="does-not-exist")


async def test_install_llama_cpp_missing_gguf_reports_steps(tmp_path) -> None:
    result = await install_model(
        lock_path="ai/model-lock.yaml",
        backend="llama_cpp",
        gguf_dest_dir=str(tmp_path),
    )
    assert result.ok is False
    assert result.backend == "llama_cpp"
    assert any("Obtain" in s for s in result.steps)


async def test_install_llama_cpp_from_staged_gguf(tmp_path) -> None:
    # Air-gapped path: a pre-staged GGUF is accepted (digest unpinned in lock).
    staged = tmp_path / "model.gguf"
    staged.write_bytes(b"fake-gguf-content")
    result = await install_model(
        lock_path="ai/model-lock.yaml",
        backend="llama_cpp",
        gguf_from=str(staged),
        gguf_dest_dir=str(tmp_path / "dest"),
    )
    assert result.ok is True
    assert result.model.endswith(".gguf")


async def test_install_llama_cpp_missing_staged_file(tmp_path) -> None:
    result = await install_model(
        lock_path="ai/model-lock.yaml",
        backend="llama_cpp",
        gguf_from=str(tmp_path / "nope.gguf"),
        gguf_dest_dir=str(tmp_path / "dest"),
    )
    assert result.ok is False
    assert "not found" in result.detail
