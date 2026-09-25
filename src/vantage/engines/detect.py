"""Detect engine binaries installed on the host (Kali / Linux).

On a Kali deployment the security tools are installed via apt and available on
``PATH``. This module reports which engines the registry knows about are actually
installed and at what version, so the operator (or ``vantage engine detect``)
can enable installed engines and run them with :class:`LocalSubprocessRunner`.

Detection never runs a scan - it only asks each tool for its version.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass

# engine_id -> (binary, version_args, version_regex)
_VERSION_PROBES: dict[str, tuple[str, list[str], str]] = {
    "nuclei": ("nuclei", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "ffuf": ("ffuf", ["-V"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "feroxbuster": ("feroxbuster", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "gobuster": ("gobuster", ["version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "katana": ("katana", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "httpx": ("httpx", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "subfinder": ("subfinder", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "dnsx": ("dnsx", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "naabu": ("naabu", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "tlsx": ("tlsx", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "gitleaks": ("gitleaks", ["version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "gau": ("gau", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "schemathesis": ("schemathesis", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "zap": ("zap.sh", ["-version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    # RED-licensed tools may exist on Kali; detection reports them but the
    # registry keeps them blocked until a recorded review approves them.
    "whatweb": ("whatweb", ["--version"], r"([0-9]+\.[0-9]+)"),
    "wfuzz": ("wfuzz", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "dirsearch": ("dirsearch", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "sslyze": ("sslyze", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
    "testssl": ("testssl.sh", ["--version"], r"([0-9]+\.[0-9]+)"),
    "wapiti": ("wapiti", ["--version"], r"([0-9]+\.[0-9]+\.[0-9]+)"),
}


@dataclass
class Detection:
    engine_id: str
    binary: str
    installed: bool
    path: str | None
    version: str | None
    version_matches_lock: bool | None = None


async def _probe(
    engine_id: str, binary: str, args: list[str], regex: str
) -> tuple[str | None, str | None]:
    path = shutil.which(binary)
    if path is None:
        return None, None
    try:
        proc = await asyncio.create_subprocess_exec(
            path, *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
    except (TimeoutError, OSError):
        return path, None
    m = re.search(regex, out.decode("utf-8", "replace"))
    return path, (m.group(1) if m else None)


async def detect_engines(
    engine_ids: list[str] | None = None,
    locked_versions: dict[str, str] | None = None,
) -> list[Detection]:
    ids = engine_ids or list(_VERSION_PROBES)
    results: list[Detection] = []
    for eid in ids:
        probe = _VERSION_PROBES.get(eid)
        if probe is None:
            continue
        binary, args, regex = probe
        path, version = await _probe(eid, binary, args, regex)
        matches: bool | None = None
        if locked_versions and version and eid in locked_versions:
            locked = locked_versions[eid].lstrip("v")
            matches = version == locked
        results.append(
            Detection(
                engine_id=eid,
                binary=binary,
                installed=path is not None,
                path=path,
                version=version,
                version_matches_lock=matches,
            )
        )
    return results
