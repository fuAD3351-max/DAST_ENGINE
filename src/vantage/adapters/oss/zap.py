"""Adapter for OWASP ZAP - primary active/passive web scanner.

ZAP is Apache-2.0, run unmodified in a sandbox. This adapter drives ZAP's
baseline automation, which crawls and passively (optionally actively) scans a
target and writes a JSON report; we parse that report's alerts into
Observations. ZAP is the main active-scan engine in the GREEN stack, chosen over
GPL scanners (w3af/wapiti) precisely for its permissive license.

The report is written to ``/out/zap.json`` inside the sandbox and returned as an
output file. Alert risk/confidence map onto Vantage severity/confidence (ZAP
"Confirmed"/High confidence maps to FIRM, never CONFIRMED - that verdict is
reserved for Vantage's own validation engine).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar
from urllib.parse import urlsplit

from vantage.adapters.oss.base import ContainerEngineAdapter
from vantage.domain import (
    Capability,
    Confidence,
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

_RISK_MAP = {
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
}
# ZAP confidence: 0 FalsePositive, 1 Low, 2 Medium, 3 High, 4 Confirmed.
_CONF_MAP = {
    "0": Confidence.FALSE_POSITIVE,
    "1": Confidence.TENTATIVE,
    "2": Confidence.TENTATIVE,
    "3": Confidence.FIRM,
    "4": Confidence.FIRM,
}


class ZapAdapter(ContainerEngineAdapter):
    engine_id = "zap"
    engine_name = "OWASP ZAP"
    vendor = "OWASP"
    homepage = "https://www.zaproxy.org"
    license_spdx = "Apache-2.0"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.AUDIT_ACTIVE,
        Capability.AUDIT_PASSIVE,
        Capability.CRAWL_HTTP,
    ]
    image = "ghcr.io/zaproxy/zaproxy"
    binary = "zap-baseline.py"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        # zap-baseline.py -t <url> -J <report> [-a active] runs a passive
        # baseline (optionally active) and writes a JSON report.
        target = request.seed_urls[0]
        args = ["-t", target, "-J", "/out/zap.json", "-I", "-m", "2"]
        if request.options.get("active"):
            args.append("-a")
        return PreparedRun(request=request, spec=self._base_spec(args))

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        records: list[dict[str, Any]] = []
        rejected = 0
        blob = b""
        if outcome.sandbox is not None:
            blob = outcome.sandbox.output_files.get("zap.json", b"") or outcome.sandbox.stdout
        if blob:
            try:
                doc = json.loads(blob.decode("utf-8", "replace"))
                for site in doc.get("site", []) if isinstance(doc, dict) else []:
                    if not isinstance(site, dict):
                        continue
                    host = site.get("@name", "")
                    for alert in site.get("alerts", []):
                        if isinstance(alert, dict):
                            alert["_host"] = host
                            records.append(alert)
                        else:
                            rejected += 1
            except json.JSONDecodeError:
                rejected += 1
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="zap.json",
            records=records,
            rejected_records=rejected,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        out: list[Observation] = []
        for alert in raw.records:
            severity = _RISK_MAP.get(
                str(alert.get("riskcode", alert.get("risk", "0"))).lower(), Severity.INFO
            )
            confidence = _CONF_MAP.get(str(alert.get("confidence", "1")), Confidence.TENTATIVE)
            cwes = _cwe(alert)
            name = str(alert.get("name") or alert.get("alert") or "ZAP alert")
            instances = alert.get("instances", [])
            first = instances[0] if instances and isinstance(instances[0], dict) else {}
            url = str(first.get("uri") or alert.get("_host") or "")
            loc = _location(url, str(first.get("method", "GET")), first.get("param"))
            vc = taxonomy.classify(cwes, _guess_class(name))
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id=str(alert.get("pluginid") or alert.get("alertRef") or name),
                    title=name,
                    vuln_class=vc.key,
                    severity=severity,
                    confidence=confidence,
                    cwe=cwes,
                    location=loc,
                    description=_strip_html(str(alert.get("desc", ""))),
                    remediation=_strip_html(str(alert.get("solution", ""))),
                    references=_refs(alert),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HTTP_EXCHANGE,
                            engine_id=self.engine_id,
                            summary=f"ZAP alert '{name}' ({severity.value}/{confidence.value})",
                            matched=[str(first.get("evidence"))] if first.get("evidence") else [],
                            request=HttpMessage(method=str(first.get("method", "GET")), url=url),
                            data={"pluginid": alert.get("pluginid"), "count": len(instances)},
                        )
                    ],
                )
            )
        return out


def _cwe(alert: dict[str, Any]) -> list[int]:
    raw = alert.get("cweid")
    s = str(raw)
    return [int(s)] if s.isdigit() and int(s) > 0 else []


def _refs(alert: dict[str, Any]) -> list[str]:
    ref = alert.get("reference", "")
    if isinstance(ref, str) and ref:
        return [r.strip() for r in _strip_html(ref).splitlines() if r.strip()][:5]
    return []


def _guess_class(name: str) -> str:
    text = name.lower()
    hints = {
        "cross site scripting": "xss",
        "sql injection": "sql_injection",
        "remote os command": "command_injection",
        "path traversal": "path_traversal",
        "remote file inclusion": "ssrf",
        "external redirect": "open_redirect",
        "content security policy": "missing_security_header",
        "x-frame-options": "clickjacking",
        "cookie": "insecure_cookie",
        "cors": "cors_misconfiguration",
        "information disclosure": "information_disclosure",
    }
    for needle, key in hints.items():
        if needle in text:
            return key
    return "other"


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", text).strip()


def _location(url: str, method: str, param: object) -> Location:
    if "://" not in url:
        url = f"https://{url}" if url else "https://unknown/"
    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "unknown").lower(),
        port=port,
        path=parts.path or "/",
        method=method.upper(),
        parameter=str(param) if param else None,
    )
