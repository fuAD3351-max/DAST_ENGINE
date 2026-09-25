"""Adapter for feroxbuster - recursive content discovery.

feroxbuster is MIT-licensed, run unmodified via CLI. With ``--json`` it emits
JSONL response records; we keep interesting statuses and report them as INFO/LOW
"discovered resource" observations.
"""

from __future__ import annotations

import json
from typing import ClassVar
from urllib.parse import urlsplit

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

_INTERESTING = {200, 201, 204, 301, 302, 307, 401, 403, 405}


class FeroxbusterAdapter(ContainerEngineAdapter):
    engine_id = "feroxbuster"
    engine_name = "feroxbuster"
    vendor = "epi052"
    homepage = "https://github.com/epi052/feroxbuster"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.DISCOVERY_CONTENT]
    image = "ghcr.io/epi052/feroxbuster"
    binary = "feroxbuster"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        wordlist = str(request.options.get("wordlist", "/wordlists/common.txt"))
        args = [
            "--silent",
            "--json",
            "--wordlist",
            wordlist,
            "--rate-limit",
            str(int(request.max_requests_per_second)),
            "--threads",
            str(request.max_concurrency),
            "--url",
            request.seed_urls[0],
        ]
        if request.proxy_url:
            args += ["--proxy", request.proxy_url]
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
                # feroxbuster emits mixed record types; keep response rows.
                if isinstance(obj, dict) and obj.get("type") in (None, "response"):
                    records.append(obj)
            except json.JSONDecodeError:
                rejected += 1
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="feroxbuster.jsonl",
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
                    description=f"feroxbuster discovered {url} with status {status}.",
                    remediation="Review whether this resource should be publicly reachable.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HTTP_EXCHANGE,
                            engine_id=self.engine_id,
                            summary=f"{status} {url}",
                            matched=[url],
                            data={"status": status, "length": rec.get("content_length")},
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
