"""Adapter for Katana (ProjectDiscovery) - crawling / endpoint discovery.

Katana is MIT-licensed, run unmodified via CLI (container or local binary). It
emits JSONL, one record per crawled endpoint, which we normalize into INFO
"endpoint discovered" observations feeding the attack-surface inventory.
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


class KatanaAdapter(ContainerEngineAdapter):
    engine_id = "katana"
    engine_name = "Katana"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/katana"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.CRAWL_HTTP,
        Capability.CRAWL_BROWSER,
        Capability.DISCOVERY_JS,
    ]
    image = "ghcr.io/projectdiscovery/katana"
    binary = "katana"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-jsonl", "-silent", "-no-color"]
        args += ["-rate-limit", str(int(request.max_requests_per_second))]
        args += ["-concurrency", str(request.max_concurrency)]
        depth = int(request.options.get("max_depth", 3))
        args += ["-depth", str(depth)]
        if request.options.get("headless"):
            args += ["-headless", "-no-sandbox"]
        for url in request.seed_urls:
            args += ["-u", url]
        if request.proxy_url:
            args += ["-proxy", request.proxy_url]
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
            format="katana.jsonl",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        seen: set[str] = set()
        for rec in raw.records:
            req = rec.get("request", {}) if isinstance(rec.get("request"), dict) else {}
            endpoint = str(req.get("endpoint") or rec.get("endpoint") or "")
            method = str(req.get("method", "GET"))
            if not endpoint or endpoint in seen:
                continue
            seen.add(endpoint)
            loc = _location(endpoint, method)
            if not loc.host:
                continue
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id="endpoint-discovered",
                    title=f"Endpoint discovered: {loc.path}",
                    vuln_class=vc.key,
                    severity=Severity.INFO,
                    location=loc,
                    description=f"Katana crawled {endpoint}.",
                    remediation="Informational; feeds attack-surface inventory.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.NOTE,
                            engine_id=self.engine_id,
                            summary=f"crawled {method} {endpoint}",
                            data={"url": endpoint, "method": method},
                        )
                    ],
                )
            )
        return out


def _location(url: str, method: str) -> Location:
    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "").lower(),
        port=port,
        path=parts.path or "/",
        method=method.upper(),
    )
