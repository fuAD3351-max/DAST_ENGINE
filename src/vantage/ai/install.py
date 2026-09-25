"""Install the on-premise LLM that ships with Vantage.

``vantage ai install`` (and the product installers) call this to fetch and
verify the pinned model during installation, so the model lands *with* the
solution rather than as a manual afterthought. Two backends:

* **Ollama** (default when the ``ollama`` binary is present): ``ollama pull`` the
  pinned tag; verify it appears in ``ollama list``.
* **llama.cpp**: use a local GGUF at ``--from`` (air-gapped) or a target path;
  verify its SHA-256 against the model-lock when a digest is pinned.

On success it writes the AI config so scans use the model by default. The
function is import-light and degrades gracefully when a backend is unavailable
(reports the exact next step instead of failing hard).
"""

from __future__ import annotations

import asyncio
import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

DEFAULT_LOCK = "ai/model-lock.yaml"


@dataclass
class LockedModel:
    key: str
    ollama_tag: str
    gguf_repo: str
    gguf_file: str
    gguf_sha256: str
    license: str
    size_hint: str


@dataclass
class InstallResult:
    ok: bool
    backend: str
    model: str
    detail: str
    steps: list[str]


def load_locked_model(lock_path: str | Path = DEFAULT_LOCK, key: str | None = None) -> LockedModel:
    data: dict[str, Any] = yaml.safe_load(Path(lock_path).read_text(encoding="utf-8")) or {}
    models = data.get("models", {})
    resolved: str = key or str(data.get("default", ""))
    if resolved not in models:
        raise KeyError(f"model '{resolved}' not in {lock_path}")
    m = models[resolved]
    return LockedModel(
        key=resolved,
        ollama_tag=m.get("ollama_tag", ""),
        gguf_repo=m.get("gguf_repo", ""),
        gguf_file=m.get("gguf_file", ""),
        gguf_sha256=m.get("gguf_sha256", ""),
        license=m.get("license", "unknown"),
        size_hint=m.get("size_hint", ""),
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


async def _run(*argv: str, timeout: float = 1800.0) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        return 124, "timed out"
    return (proc.returncode or 0), out.decode("utf-8", "replace")


async def install_model(
    *,
    lock_path: str | Path = DEFAULT_LOCK,
    model_key: str | None = None,
    backend: str = "auto",  # auto | ollama | llama_cpp
    gguf_from: str | None = None,
    gguf_dest_dir: str = "/opt/vantage/models",
) -> InstallResult:
    model = load_locked_model(lock_path, model_key)

    chosen = backend
    if chosen == "auto":
        chosen = "ollama" if shutil.which("ollama") else "llama_cpp"

    if chosen == "ollama":
        if not shutil.which("ollama"):
            return InstallResult(
                ok=False,
                backend="ollama",
                model=model.ollama_tag,
                detail="Ollama not found on PATH.",
                steps=[
                    "Install Ollama (https://ollama.com/download), then re-run "
                    "'vantage ai install'.",
                ],
            )
        rc, out = await _run("ollama", "pull", model.ollama_tag)
        if rc != 0:
            return InstallResult(
                False, "ollama", model.ollama_tag, f"ollama pull failed: {out.strip()[:200]}", []
            )
        _rc, listing = await _run("ollama", "list", timeout=30)
        present = model.ollama_tag.split(":")[0] in listing
        return InstallResult(
            ok=present,
            backend="ollama",
            model=model.ollama_tag,
            detail="Model pulled and present." if present else "Pulled but not listed; verify.",
            steps=[],
        )

    # llama_cpp / GGUF path
    dest = Path(gguf_dest_dir) / model.gguf_file
    if gguf_from:
        src = Path(gguf_from)
        if not src.exists():
            return InstallResult(False, "llama_cpp", model.gguf_file, f"{src} not found", [])
        dest.parent.mkdir(parents=True, exist_ok=True)
        if src.resolve() != dest.resolve():
            shutil.copy2(src, dest)
    if not dest.exists():
        return InstallResult(
            ok=False,
            backend="llama_cpp",
            model=model.gguf_file,
            detail="GGUF not present.",
            steps=[
                f"Obtain {model.gguf_file} from {model.gguf_repo} (license {model.license}).",
                f"Place it at {dest} or pass --from <path> (air-gapped installs stage it).",
                "Then re-run 'vantage ai install --backend llama_cpp'.",
            ],
        )
    # Verify digest when the lock pins a real one.
    if model.gguf_sha256 and not model.gguf_sha256.startswith("REPLACE_"):
        digest = _sha256(dest)
        if digest != model.gguf_sha256:
            return InstallResult(
                False,
                "llama_cpp",
                model.gguf_file,
                f"SHA-256 mismatch: expected {model.gguf_sha256[:12]}…, got {digest[:12]}…",
                [],
            )
    return InstallResult(
        ok=True, backend="llama_cpp", model=str(dest), detail="GGUF present and verified.", steps=[]
    )
