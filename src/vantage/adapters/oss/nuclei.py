"""Adapter for Nuclei (ProjectDiscovery), run as an isolated container.

Nuclei is MIT-licensed and executed as an unmodified upstream image over its
CLI. Vantage controls which templates run through its Template Registry and the
scan policy's tag denylist - it never executes arbitrary user-supplied
templates. Output is consumed as JSONL and normalized into Observations.
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
    HttpMessage,
    Location,
    Observation,
    Severity,
)
from vantage.engines.adapter import ExecutionOutcome, PreparedRun, RawResults
from vantage.findings import taxonomy

_SEVERITY_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "unknown": Severity.INFO,
}


class NucleiAdapter(ContainerEngineAdapter):
    engine_id = "nuclei"
    engine_name = "Nuclei"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/nuclei"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.AUDIT_TEMPLATES,
        Capability.FINGERPRINT_TECH,
    ]
    image = "ghcr.io/projectdiscovery/nuclei"
    binary = "nuclei"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-jsonl", "-silent", "-no-color", "-duc"]
        # Respect the scan's rate/concurrency envelope.
        args += ["-rate-limit", str(int(request.max_requests_per_second))]
        args += ["-c", str(request.max_concurrency)]
        # Template selection is controlled by Vantage (Template Registry), never
        # arbitrary user input. Tags come pre-validated in options.
        tags = request.options.get("template_tags")
        if isinstance(tags, list) and tags:
            args += ["-tags", ",".join(str(t) for t in tags)]
        exclude = request.options.get("exclude_tags")
        if isinstance(exclude, list) and exclude:
            args += ["-exclude-tags", ",".join(str(t) for t in exclude)]
        for url in request.seed_urls:
            args += ["-u", url]
        # Force egress through Vantage's scope-enforcing proxy when provided.
        env: dict[str, str] = {}
        if request.proxy_url:
            args += ["-proxy", request.proxy_url]
        spec = self._base_spec(args, env)
        return PreparedRun(request=request, spec=spec)

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
            format="nuclei.jsonl",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        out: list[Observation] = []
        for rec in raw.records:
            info = rec.get("info", {}) if isinstance(rec.get("info"), dict) else {}
            severity = _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            classification = info.get("classification", {}) if isinstance(info, dict) else {}
            cwes = _extract_cwes(classification)
            template_id = str(rec.get("template-id") or rec.get("templateID") or "unknown")
            matched = str(rec.get("matched-at") or rec.get("host") or "")
            loc = _location(matched, str(rec.get("type", "http")))
            vc = taxonomy.classify(cwes, _guess_class(template_id, str(info.get("name", ""))))
            request_str = rec.get("request")
            response_str = rec.get("response")
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id=template_id,
                    title=str(info.get("name") or template_id),
                    vuln_class=vc.key,
                    severity=severity,
                    cwe=cwes,
                    location=loc,
                    description=str(info.get("description", "")),
                    remediation=str(info.get("remediation", "")),
                    references=_as_str_list(info.get("reference")),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HTTP_EXCHANGE,
                            engine_id=self.engine_id,
                            summary=f"nuclei template {template_id} matched at {matched}",
                            matched=[matched] if matched else [],
                            request=HttpMessage(body=request_str)
                            if isinstance(request_str, str)
                            else None,
                            response=HttpMessage(body=response_str)
                            if isinstance(response_str, str)
                            else None,
                            data={"template_id": template_id},
                        )
                    ],
                    raw_ref=template_id,
                )
            )
        return out


def _extract_cwes(classification: object) -> list[int]:
    if not isinstance(classification, dict):
        return []
    raw = classification.get("cwe-id") or classification.get("cwe")
    items = raw if isinstance(raw, list) else [raw]
    out: list[int] = []
    for item in items:
        if item is None:
            continue
        s = str(item).lower().replace("cwe-", "")
        if s.isdigit():
            out.append(int(s))
    return out


def _as_str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def _guess_class(template_id: str, name: str) -> str:
    text = f"{template_id} {name}".lower()
    hints = {
        "xss": "xss",
        "sqli": "sql_injection",
        "sql-injection": "sql_injection",
        "ssrf": "ssrf",
        "lfi": "path_traversal",
        "rce": "command_injection",
        "traversal": "path_traversal",
        "xxe": "xxe",
        "open-redirect": "open_redirect",
        "cors": "cors_misconfiguration",
        "exposure": "information_disclosure",
        "default-login": "authentication",
        "takeover": "security_misconfiguration",
    }
    for needle, key in hints.items():
        if needle in text:
            return key
    return "other"


def _location(matched: str, kind: str) -> Location:
    from urllib.parse import urlsplit

    if "://" not in matched:
        matched = f"https://{matched}" if matched else "https://unknown/"
    parts = urlsplit(matched)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "unknown").lower(),
        port=port,
        path=parts.path or "/",
        method="GET",
    )
