"""Local-LLM provider abstraction for the on-premise AI layer.

Providers run entirely on the customer's hardware — no data leaves the
deployment, so the AI layer works air-gapped. The default is
:class:`NullProvider` (AI off); enabling AI is an explicit choice. Providers are
license-governed like engines: the model a provider loads is a third-party
component tracked in the inventory.

Concrete providers:
* :class:`LlamaCppProvider` — embeds llama.cpp via ``llama-cpp-python`` (MIT) and
  loads a local GGUF model. Truly in-process, no server, ideal for air-gapped.
* :class:`OllamaProvider` — talks to a self-hosted Ollama daemon (MIT) over
  localhost. Better ops story; still fully on-prem.
* :class:`FakeProvider` — deterministic, offline; used in tests.
"""

from __future__ import annotations

import abc
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class LLMResponse:
    text: str
    model: str
    provider: str
    usage: dict[str, int] = field(default_factory=dict)

    def json(self) -> Any:
        """Parse the response as JSON, tolerating code fences and prose.

        Returns None if no JSON object/array can be extracted — callers must
        handle that (the AI layer never trusts the model blindly).
        """
        text = self.text.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1] if "```" in text[3:] else text
            text = text.removeprefix("json").strip("`\n ")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Best-effort: grab the outermost {...} or [...].
            for opener, closer in (("{", "}"), ("[", "]")):
                i, j = text.find(opener), text.rfind(closer)
                if 0 <= i < j:
                    try:
                        return json.loads(text[i : j + 1])
                    except json.JSONDecodeError:
                        continue
            return None


class LLMProvider(abc.ABC):
    name: str = "abstract"
    model_id: str = "unknown"
    model_license: str = "unknown"

    @abc.abstractmethod
    async def available(self) -> bool: ...

    @abc.abstractmethod
    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse: ...


class NullProvider(LLMProvider):
    """AI disabled. Every call reports unavailable; the analyst becomes a no-op."""

    name = "null"
    model_id = "none"
    model_license = "n/a"

    async def available(self) -> bool:
        return False

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        return LLMResponse(text="", model="none", provider="null")


class LlamaCppProvider(LLMProvider):
    """In-process local inference via llama-cpp-python (MIT) + a GGUF model.

    Fully local and air-gapped: the model file is on disk and inference runs in
    this process. Requires the optional ``ai`` extra:
    ``pip install 'vantage-dast[ai]'`` and a GGUF model at ``model_path``.
    """

    name = "llama_cpp"

    def __init__(
        self,
        model_path: str,
        *,
        model_id: str = "local-gguf",
        model_license: str = "unknown",
        n_ctx: int = 8192,
        n_threads: int | None = None,
        n_gpu_layers: int = 0,
    ) -> None:
        self.model_id = model_id
        self.model_license = model_license
        self._model_path = model_path
        self._n_ctx = n_ctx
        self._n_threads = n_threads
        self._n_gpu_layers = n_gpu_layers
        self._llm: Any = None

    def _load(self) -> Any:
        if self._llm is None:
            from llama_cpp import Llama  # type: ignore[import-not-found]  # optional dep

            self._llm = Llama(
                model_path=self._model_path,
                n_ctx=self._n_ctx,
                n_threads=self._n_threads,
                n_gpu_layers=self._n_gpu_layers,
                verbose=False,
            )
        return self._llm

    async def available(self) -> bool:
        import importlib.util
        import os

        return importlib.util.find_spec("llama_cpp") is not None and os.path.exists(
            self._model_path
        )

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        import asyncio

        def _run() -> LLMResponse:
            llm = self._load()
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})
            out = llm.create_chat_completion(
                messages=messages, max_tokens=max_tokens, temperature=temperature
            )
            text = out["choices"][0]["message"]["content"]
            usage = out.get("usage", {})
            return LLMResponse(text=text, model=self.model_id, provider=self.name, usage=usage)

        return await asyncio.to_thread(_run)


class OllamaProvider(LLMProvider):
    """Local Ollama daemon (MIT) over localhost — on-prem, no external calls."""

    name = "ollama"

    def __init__(
        self,
        model_id: str = "qwen2.5:7b-instruct",
        *,
        base_url: str = "http://127.0.0.1:11434",
        model_license: str = "unknown",
    ) -> None:
        self.model_id = model_id
        self.model_license = model_license
        self._base_url = base_url.rstrip("/")

    async def available(self) -> bool:
        import httpx

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self._base_url}/api/tags")
                return r.status_code == 200
        except Exception:
            return False

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        import httpx

        payload: dict[str, Any] = {
            "model": self.model_id,
            "prompt": prompt,
            "system": system or "",
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        async with httpx.AsyncClient(timeout=120.0) as client:
            r = await client.post(f"{self._base_url}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
        return LLMResponse(
            text=str(data.get("response", "")),
            model=self.model_id,
            provider=self.name,
            usage={
                "prompt_tokens": int(data.get("prompt_eval_count", 0)),
                "completion_tokens": int(data.get("eval_count", 0)),
            },
        )


@dataclass
class FakeProvider(LLMProvider):
    """Deterministic provider for tests: returns a scripted reply per call."""

    reply: str = "{}"
    name: str = "fake"
    model_id: str = "fake-model"
    model_license: str = "MIT"
    calls: list[str] = field(default_factory=list)

    async def available(self) -> bool:
        return True

    async def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        max_tokens: int = 1024,
        temperature: float = 0.0,
    ) -> LLMResponse:
        self.calls.append(prompt)
        return LLMResponse(text=self.reply, model=self.model_id, provider=self.name)
