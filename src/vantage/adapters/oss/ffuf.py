"""Adapter for ffuf, run as an isolated container for content discovery.

ffuf is MIT-licensed and executed unmodified over its CLI. Vantage supplies a
curated wordlist (mounted read-only) and consumes ffuf's JSON output. Discovered
resources are reported as INFO observations feeding the attack-surface inventory;
ffuf's rate is bounded by the target's rate limits.
"""

from __future__ import annotations

import json
from typing import ClassVar

from vantage.adapters.oss.base import ContainerEngineAdapter
from vantage.domain import (
    Capability,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from vantage.engines.adapter import ExecutionOutcome, PreparedRun, RawResults
from vantage.findings import taxonomy

# Interesting statuses for content discovery (found / redirect / auth-required).
_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405}


class FfufAdapter(ContainerEngineAdapter):
    engine_id = "ffuf"
    engine_name = "ffuf"
    vendor = "joohoi"
    homepage = "https://github.com/ffuf/ffuf"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.DISCOVERY_CONTENT]
    image = "ghcr.io/ffuf/ffuf"
    binary = "ffuf"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        wordlist = str(request.options.get("wordlist", "/wordlists/common.txt"))
        seed = request.seed_urls[0].rstrip("/")
        args = [
            "-u",
            f"{seed}/FUZZ",
            "-w",
            wordlist,
            "-of",
            "json",
            "-o",
            "/out/ffuf.json",
            "-rate",
            str(int(request.max_requests_per_second)),
            "-t",
            str(request.max_concurrency),
            "-mc",
            ",".join(str(s) for s in sorted(_INTERESTING)),
        ]
        if request.proxy_url:
            args += ["-x", request.proxy_url]
        spec = self._base_spec(args)
        return PreparedRun(request=request, spec=spec)

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        records: list[dict[str, object]] = []
        rejected = 0
        # ffuf writes JSON to /out/ffuf.json; the sandbox returns output files.
        blob = b""
        if outcome.sandbox is not None:
            blob = outcome.sandbox.output_files.get("ffuf.json", b"") or outcome.sandbox.stdout
        if blob:
            try:
                doc = json.loads(blob.decode("utf-8", "replace"))
                results = doc.get("results", []) if isinstance(doc, dict) else []
                for r in results:
                    if isinstance(r, dict):
                        records.append(r)
                    else:
                        rejected += 1
            except json.JSONDecodeError:
                rejected += 1
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="ffuf.json",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        for rec in raw.records:
            url = str(rec.get("url", ""))
            status = int(rec.get("status", 0) or 0)
            if not url or status not in _INTERESTING:
                continue
            loc = _location(url)
            severity = Severity.LOW if status in (401, 403) else Severity.INFO
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id=f"content:{status}",
                    title=f"Discovered resource ({status}): {loc.path}",
                    vuln_class=vc.key,
                    severity=severity,
                    location=loc,
                    description=f"ffuf discovered {url} with status {status}.",
                    remediation="Review whether this resource should be publicly reachable.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HTTP_EXCHANGE,
                            engine_id=self.engine_id,
                            summary=f"{status} {url}",
                            matched=[url],
                            data={"status": status, "length": rec.get("length")},
                        )
                    ],
                )
            )
        return out


def _location(url: str) -> Location:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "unknown").lower(),
        port=port,
        path=parts.path or "/",
        method="GET",
    )
