"""Adapter for httpx (ProjectDiscovery) - HTTP probing + tech fingerprinting.

httpx is MIT-licensed, run unmodified via CLI. With ``-json -tech-detect`` it
emits one JSON record per live host with detected technologies, status, title
and TLS info. We normalize technologies into INFO fingerprint observations.

Note: this is the ProjectDiscovery *binary* ``httpx``, unrelated to the Python
``httpx`` HTTP client library used elsewhere in Sentinel; the module is named
``httpx_engine`` to avoid the import clash.
"""

from __future__ import annotations

import json
from typing import ClassVar
from urllib.parse import urlsplit

from sentinel.adapters.oss.base import ContainerEngineAdapter
from sentinel.domain import (
    Capability,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from sentinel.engines.adapter import ExecutionOutcome, PreparedRun, RawResults
from sentinel.findings import taxonomy


class HttpxAdapter(ContainerEngineAdapter):
    engine_id = "httpx"
    engine_name = "httpx"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/httpx"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.RECON_HTTP,
        Capability.FINGERPRINT_TECH,
    ]
    image = "ghcr.io/projectdiscovery/httpx"
    binary = "httpx"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-json", "-silent", "-no-color", "-tech-detect", "-title", "-status-code"]
        args += ["-rate-limit", str(int(request.max_requests_per_second))]
        args += ["-threads", str(request.max_concurrency)]
        for url in request.seed_urls:
            args += ["-u", url]
        return PreparedRun(request=request, spec=self._base_spec(args))

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        text = self._guard_output(outcome.sandbox)
        records: list[dict[str, object]] = []
        rejected = 0
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    records.append(obj)
                else:
                    rejected += 1
            except json.JSONDecodeError:
                rejected += 1
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="httpx.jsonl",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        for rec in raw.records:
            url = str(rec.get("url") or rec.get("input") or "")
            if not url:
                continue
            loc = _location(url)
            techs = rec.get("tech") or rec.get("technologies") or []
            tech_list = [str(t) for t in techs] if isinstance(techs, list) else []
            for tech in tech_list:
                out.append(
                    Observation(
                        scan_id=request.scan_id,
                        run_id=request.run_id,
                        engine_id=self.engine_id,
                        engine_version=self._version,
                        detector_id=f"tech:{tech}",
                        title=f"Technology detected: {tech}",
                        vuln_class=vc.key,
                        severity=Severity.INFO,
                        cwe=[200],
                        location=loc,
                        description=f"httpx fingerprinted {tech} at {url}.",
                        remediation="Informational technology inventory.",
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.RESPONSE_MATCH,
                                engine_id=self.engine_id,
                                summary=f"{tech} at {url}",
                                matched=[tech],
                                data={"technology": tech, "status": rec.get("status_code")},
                            )
                        ],
                    )
                )
        return out


def _location(url: str) -> Location:
    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "").lower(),
        port=port,
        path=parts.path or "/",
        method="GET",
    )
