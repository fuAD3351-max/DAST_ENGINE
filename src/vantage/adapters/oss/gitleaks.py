"""Adapter for Gitleaks - secret detection (MIT; preferred over AGPL TruffleHog).

Gitleaks is MIT, run unmodified in a sandbox over collected artifacts (response
bodies, JS) that Vantage stages into the engine's input directory. It emits a
JSON array of findings which we normalize into HIGH-severity secret-exposure
Observations, with the secret value redacted in evidence.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

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


class GitleaksAdapter(ContainerEngineAdapter):
    engine_id = "gitleaks"
    engine_name = "Gitleaks"
    vendor = "gitleaks"
    homepage = "https://github.com/gitleaks/gitleaks"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.ANALYSIS_SECRETS]
    image = "ghcr.io/gitleaks/gitleaks"
    binary = "gitleaks"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        # Scan the staged artifacts directory (mounted at /work) in no-git mode.
        args = [
            "dir",
            "/work",
            "--report-format",
            "json",
            "--report-path",
            "/out/gitleaks.json",
            "--no-banner",
        ]
        return PreparedRun(request=request, spec=self._base_spec(args))

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        records: list[dict[str, Any]] = []
        rejected = 0
        blob = b""
        if outcome.sandbox is not None:
            blob = outcome.sandbox.output_files.get("gitleaks.json", b"") or outcome.sandbox.stdout
        if blob:
            try:
                doc = json.loads(blob.decode("utf-8", "replace"))
                if isinstance(doc, list):
                    records = [r for r in doc if isinstance(r, dict)]
                elif isinstance(doc, dict):
                    records = [doc]
            except json.JSONDecodeError:
                rejected += 1
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="gitleaks.json",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["secret_exposure"]
        host = _host(request)
        out: list[Observation] = []
        for rec in raw.records:
            rule = str(rec.get("RuleID") or rec.get("Description") or "secret")
            secret = str(rec.get("Secret", ""))
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id=f"gitleaks:{rule}",
                    title=f"Potential exposed secret: {rule}",
                    vuln_class=vc.key,
                    severity=Severity.HIGH,
                    cwe=[540, 312],
                    location=Location(scheme="https", host=host, port=443, path="/", method="GET"),
                    description=f"Gitleaks matched rule '{rule}' in a served artifact.",
                    remediation="Remove secrets from client-served content and rotate them.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.RESPONSE_MATCH,
                            engine_id=self.engine_id,
                            summary=f"{rule} matched (value redacted)",
                            matched=[_redact(secret)],
                            data={"file": rec.get("File"), "rule": rule},
                        )
                    ],
                )
            )
        return out


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _host(request: EngineRunRequest) -> str:
    from urllib.parse import urlsplit

    for u in request.seed_urls:
        h = urlsplit(u).hostname
        if h:
            return h.lower()
    return "unknown"
