"""Adapter for Burp Suite (PortSwigger), integrated as an external service.

IMPORTANT LICENSING NOTE
------------------------
Burp Suite is proprietary, commercial software. Sentinel does **not** bundle,
embed, containerize or redistribute Burp in any form. This adapter is
first-party Sentinel code that speaks Burp's documented REST API to a Burp
instance the **customer** hosts and licenses themselves (Burp Suite Professional
or Enterprise / DAST). This "bring-your-own-license" model is the only
license-compatible way to offer Burp coverage in a commercially distributed
product, and it is why the engine is modelled as ``IntegrationType.EXTERNAL_SERVICE``
and ships **disabled by default**.

The adapter:

* requires an operator-provided base URL + API key (never defaults to a live
  host); without configuration it reports ``UNAVAILABLE`` and produces nothing;
* launches a scan constrained to Sentinel's scope, polls to completion within a
  bounded budget, and maps Burp's issue model onto Sentinel Observations;
* treats Burp's output as untrusted input, like every other engine;
* maps Burp confidence onto Sentinel confidence conservatively - Burp's own
  "certain" becomes FIRM, never CONFIRMED, because CONFIRMED is reserved for
  Sentinel's own validation engine.

The transport is injected (:class:`BurpTransport`), so the adapter is fully
unit-testable offline with :class:`FakeBurpTransport`.
"""

from __future__ import annotations

import abc
import asyncio
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import urlsplit

from sentinel.domain import (
    ApprovalStatus,
    Capability,
    Confidence,
    EngineMetadata,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    HealthState,
    HealthStatus,
    HttpMessage,
    IntegrationType,
    LicenseClass,
    Location,
    Observation,
    Severity,
)
from sentinel.engines.adapter import (
    EngineAdapter,
    ExecutionOutcome,
    PreparedRun,
    RawResults,
)
from sentinel.findings import taxonomy

BURP_LICENSE = "LicenseRef-PortSwigger-Commercial"

_SEVERITY_MAP = {
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "information": Severity.INFO,
}
# Burp confidence -> Sentinel confidence. Never CONFIRMED (reserved for our
# validation engine).
_CONFIDENCE_MAP = {
    "certain": Confidence.FIRM,
    "firm": Confidence.FIRM,
    "tentative": Confidence.TENTATIVE,
}


@dataclass
class BurpConfig:
    base_url: str = ""
    api_key: str = ""
    api_prefix: str = "/v0.1"
    poll_interval_seconds: float = 5.0
    verify_tls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.base_url)


@dataclass
class BurpResponse:
    status: int
    json: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class BurpTransport(abc.ABC):
    """Minimal HTTP transport to a customer-hosted Burp REST API."""

    @abc.abstractmethod
    async def post(self, path: str, body: dict[str, Any]) -> BurpResponse: ...

    @abc.abstractmethod
    async def get(self, path: str) -> BurpResponse: ...


class HttpxBurpTransport(BurpTransport):
    def __init__(self, config: BurpConfig) -> None:
        self._config = config
        self._client: Any = None

    async def _ensure(self) -> Any:
        if self._client is None:
            import httpx

            headers = {}
            if self._config.api_key:
                headers["Authorization"] = self._config.api_key
            self._client = httpx.AsyncClient(
                base_url=self._config.base_url.rstrip("/") + self._config.api_prefix,
                headers=headers,
                timeout=30.0,
                verify=self._config.verify_tls,
            )
        return self._client

    async def post(self, path: str, body: dict[str, Any]) -> BurpResponse:
        client = await self._ensure()
        try:
            resp = await client.post(path, json=body)
            data = resp.json() if resp.content else {}
            return BurpResponse(resp.status_code, data if isinstance(data, dict) else {})
        except Exception as exc:
            return BurpResponse(0, {}, error=str(exc))

    async def get(self, path: str) -> BurpResponse:
        client = await self._ensure()
        try:
            resp = await client.get(path)
            data = resp.json() if resp.content else {}
            return BurpResponse(resp.status_code, data if isinstance(data, dict) else {})
        except Exception as exc:
            return BurpResponse(0, {}, error=str(exc))

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class BurpAdapter(EngineAdapter):
    engine_id = "burp"
    engine_name = "Burp Suite (external)"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.AUDIT_ACTIVE,
        Capability.AUDIT_PASSIVE,
        Capability.CRAWL_HTTP,
    ]

    def __init__(
        self,
        config: BurpConfig,
        version: str = "external",
        *,
        transport: BurpTransport | None = None,
        max_poll_seconds: int = 3600,
    ) -> None:
        self._config = config
        self._version = version
        self._transport = transport or HttpxBurpTransport(config)
        self._max_poll_seconds = max_poll_seconds

    def metadata(self) -> EngineMetadata:
        return EngineMetadata(
            id=self.engine_id,
            name=self.engine_name,
            version=self._version,
            vendor="PortSwigger",
            license_spdx=BURP_LICENSE,
            license_class=LicenseClass.RED,
            # Approved for Sentinel to DISTRIBUTE (we ship only the API client);
            # the customer must separately license and host Burp.
            approval_status=ApprovalStatus.APPROVED,
            integration=IntegrationType.EXTERNAL_SERVICE,
            capabilities=list(self.engine_capabilities),
            homepage="https://portswigger.net/burp",
        )

    async def health_check(self) -> HealthStatus:
        if not self._config.configured:
            return HealthStatus(
                state=HealthState.UNAVAILABLE,
                detail="Burp integration not configured (no base_url/api_key). "
                "Provide a customer-hosted Burp Suite instance to enable it.",
            )
        resp = await self._transport.get("/knowledge_base/issue_definitions")
        if resp.error or resp.status >= 500:
            return HealthStatus(
                state=HealthState.UNAVAILABLE, detail=resp.error or f"HTTP {resp.status}"
            )
        if resp.status in (401, 403):
            return HealthStatus(state=HealthState.DEGRADED, detail="authentication rejected")
        return HealthStatus(state=HealthState.HEALTHY, detail="Burp reachable")

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        scan_body: dict[str, Any] = {
            "urls": list(request.seed_urls),
            "scope": {
                "include": [{"rule": u} for u in request.seed_urls],
            },
            "application_logins": [],
        }
        return PreparedRun(request=request, state={"scan_body": scan_body})

    async def execute_scan(self, prepared: PreparedRun) -> ExecutionOutcome:
        if not self._config.configured:
            return ExecutionOutcome(prepared=prepared, sandbox=None, native_output=[])
        start = await self._transport.post("/scan", prepared.state["scan_body"])
        if start.error or start.status not in (200, 201):
            return ExecutionOutcome(prepared=prepared, sandbox=None, native_output=[])
        scan_id = str(start.json.get("scan_id") or start.json.get("id") or "")
        if not scan_id:
            # Some deployments return the id in a Location header; without a
            # transport-level header we cannot proceed - fail soft.
            return ExecutionOutcome(prepared=prepared, sandbox=None, native_output=[])

        issues = await self._poll(scan_id)
        return ExecutionOutcome(prepared=prepared, sandbox=None, native_output=issues)

    async def _poll(self, scan_id: str) -> list[dict[str, Any]]:
        waited = 0.0
        interval = max(self._config.poll_interval_seconds, 1.0)
        while waited < self._max_poll_seconds:
            resp = await self._transport.get(f"/scan/{scan_id}")
            if resp.error:
                return []
            status = str(resp.json.get("scan_status") or resp.json.get("status") or "").lower()
            if status in ("succeeded", "finished", "completed", "paused", "failed"):
                issues = resp.json.get("issue_events") or resp.json.get("issues") or []
                return [self._issue_of(i) for i in issues if isinstance(i, dict)]
            await asyncio.sleep(interval)
            waited += interval
        return []

    @staticmethod
    def _issue_of(event: dict[str, Any]) -> dict[str, Any]:
        # Enterprise wraps issues in issue_events; Professional returns issues.
        return event.get("issue", event) if "issue" in event else event

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        issues: list[dict[str, Any]] = outcome.native_output or []
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format="burp.issues",
            records=issues,
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        out: list[Observation] = []
        for issue in raw.records:
            severity = _SEVERITY_MAP.get(str(issue.get("severity", "info")).lower(), Severity.INFO)
            confidence = _CONFIDENCE_MAP.get(
                str(issue.get("confidence", "tentative")).lower(), Confidence.TENTATIVE
            )
            cwes = _extract_cwes(issue)
            name = str(issue.get("name") or issue.get("issue_type", {}).get("name") or "Burp issue")
            origin = str(issue.get("origin", ""))
            path = str(issue.get("path", "/"))
            url = origin + path if origin else path
            loc = _location(url)
            vc = taxonomy.classify(cwes, _guess_class(name))
            evidence_items = _evidence(issue)
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id=str(issue.get("type_index") or issue.get("serial_number") or name),
                    title=name,
                    vuln_class=vc.key,
                    severity=severity,
                    confidence=confidence,
                    cwe=cwes,
                    location=loc,
                    description=_strip_html(str(issue.get("description", ""))),
                    remediation=_strip_html(str(issue.get("remediation", ""))),
                    references=[],
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HTTP_EXCHANGE,
                            engine_id=self.engine_id,
                            summary=f"Burp reported '{name}' ({severity.value}/{confidence.value})",
                            matched=[url] if url else [],
                            request=evidence_items[0] if evidence_items else None,
                            response=evidence_items[1] if len(evidence_items) > 1 else None,
                            data={"burp_confidence": str(issue.get("confidence", ""))},
                        )
                    ],
                )
            )
        return out

    async def cleanup(self, prepared: PreparedRun) -> None:
        transport = self._transport
        if isinstance(transport, HttpxBurpTransport):
            await transport.aclose()


def _extract_cwes(issue: dict[str, Any]) -> list[int]:
    raw = issue.get("vulnerability_classifications") or issue.get("cwe") or ""
    import re

    return [int(m) for m in re.findall(r"CWE-(\d+)", str(raw))]


def _evidence(issue: dict[str, Any]) -> list[HttpMessage]:
    ev = issue.get("evidence")
    messages: list[HttpMessage] = []
    if isinstance(ev, list):
        for item in ev[:2]:
            if isinstance(item, dict):
                req = item.get("request_response", {})
                if isinstance(req, dict):
                    messages.append(HttpMessage(body=str(req.get("request", "") or "")))
    return messages


def _guess_class(name: str) -> str:
    text = name.lower()
    hints = {
        "cross-site scripting": "xss",
        "sql injection": "sql_injection",
        "os command": "command_injection",
        "path traversal": "path_traversal",
        "file path": "path_traversal",
        "server-side request forgery": "ssrf",
        "xml external": "xxe",
        "open redirect": "open_redirect",
        "cross-site request forgery": "csrf",
        "cleartext": "tls_weakness",
        "certificate": "tls_weakness",
        "cookie": "insecure_cookie",
        "cors": "cors_misconfiguration",
        "information disclosure": "information_disclosure",
        "deserialization": "insecure_deserialization",
    }
    for needle, key in hints.items():
        if needle in text:
            return key
    return "other"


def _strip_html(text: str) -> str:
    import re

    return re.sub(r"<[^>]+>", "", text).strip()


def _location(url: str) -> Location:
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
        method="GET",
    )


class FakeBurpTransport(BurpTransport):
    """Deterministic transport for tests: scripted responses by path."""

    def __init__(
        self,
        *,
        start_scan_id: str = "1",
        issues: list[dict[str, Any]] | None = None,
        final_status: str = "succeeded",
        healthy: bool = True,
    ) -> None:
        self._scan_id = start_scan_id
        self._issues = issues or []
        self._final_status = final_status
        self._healthy = healthy
        self.calls: list[tuple[str, str]] = []

    async def post(self, path: str, body: dict[str, Any]) -> BurpResponse:
        self.calls.append(("POST", path))
        if path == "/scan":
            return BurpResponse(201, {"scan_id": self._scan_id})
        return BurpResponse(404, {})

    async def get(self, path: str) -> BurpResponse:
        self.calls.append(("GET", path))
        if path.startswith("/knowledge_base"):
            return BurpResponse(200 if self._healthy else 500, {})
        if path.startswith("/scan/"):
            return BurpResponse(
                200, {"scan_status": self._final_status, "issue_events": self._issues}
            )
        return BurpResponse(404, {})
