"""Evidence, engine observations and the unified finding.

Flow: an adapter turns raw engine output into :class:`Observation` objects
(one per engine-reported issue). The correlation engine groups observations
that describe the same weakness into one :class:`UnifiedFinding`, keeping every
observation and its evidence. Raw engine output stays available by reference
for debugging but is never shown to users as the finding itself.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from vantage.domain.common import Confidence, Identifier, Severity, VantageModel, new_id, utcnow

MAX_EVIDENCE_BODY = 64 * 1024  # bytes kept inline; the rest lives in the artifact store


class EvidenceKind(StrEnum):
    HTTP_EXCHANGE = "http_exchange"
    RESPONSE_MATCH = "response_match"
    DOM_OBSERVATION = "dom_observation"
    OOB_INTERACTION = "oob_interaction"
    TLS_OBSERVATION = "tls_observation"
    HEADER_OBSERVATION = "header_observation"
    VALIDATION_RESULT = "validation_result"
    NOTE = "note"


class HttpMessage(VantageModel):
    method: str | None = None
    url: str | None = None
    status: int | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_truncated: bool = False

    @field_validator("body")
    @classmethod
    def _cap_body(cls, v: str | None) -> str | None:
        if v is not None and len(v.encode("utf-8", "replace")) > MAX_EVIDENCE_BODY:
            return v.encode("utf-8", "replace")[:MAX_EVIDENCE_BODY].decode("utf-8", "ignore")
        return v


class Evidence(VantageModel):
    id: str = Field(default_factory=new_id)
    kind: EvidenceKind
    engine_id: Identifier
    summary: str = Field(max_length=2000)
    request: HttpMessage | None = None
    response: HttpMessage | None = None
    matched: list[str] = Field(default_factory=list, description="Matched strings/markers")
    artifact_refs: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    captured_at: datetime = Field(default_factory=utcnow)

    def digest(self) -> str:
        """Stable content hash used for evidence de-duplication."""
        h = hashlib.sha256()
        h.update(self.kind.value.encode())
        h.update(self.summary.encode())
        for m in sorted(self.matched):
            h.update(m.encode())
        if self.request is not None:
            h.update(f"{self.request.method} {self.request.url}".encode())
        if self.response is not None and self.response.status is not None:
            h.update(str(self.response.status).encode())
        return h.hexdigest()


class Location(VantageModel):
    scheme: str
    host: str
    port: int
    path: str = "/"
    method: str | None = None
    parameter: str | None = None
    parameter_location: str | None = Field(
        default=None, description="query | body | header | cookie | path | json | graphql | ws"
    )

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return v.lower().rstrip(".")

    @field_validator("method")
    @classmethod
    def _method(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class Observation(VantageModel):
    """One issue as reported by one engine, already normalized."""

    id: str = Field(default_factory=new_id)
    scan_id: str
    run_id: str
    engine_id: Identifier
    engine_version: str
    detector_id: str = Field(
        description="Engine-specific rule id, e.g. ZAP plugin id or template id"
    )
    title: str
    vuln_class: str = Field(description="Vantage canonical class, see findings.taxonomy")
    severity: Severity
    confidence: Confidence = Confidence.TENTATIVE
    cwe: list[int] = Field(default_factory=list)
    location: Location
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    raw_ref: str | None = Field(default=None, description="Pointer into the raw engine artifact")
    observed_at: datetime = Field(default_factory=utcnow)


class FindingStatus(StrEnum):
    OPEN = "open"
    TRIAGED = "triaged"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"


class UnifiedFinding(VantageModel):
    """The single user-facing finding produced by correlation."""

    id: str = Field(default_factory=new_id)
    tenant_id: str
    scan_id: str
    target_id: str
    fingerprint: str = Field(description="Correlation key; stable across scans")
    title: str
    category: str = Field(description="Vantage canonical vulnerability class")
    severity: Severity
    confidence: Confidence
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    cwe: list[int] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    host: str
    port: int
    endpoint: str = Field(description="Normalized path template, e.g. /api/users/{id}")
    method: str | None = None
    parameter: str | None = None
    affected_urls: list[str] = Field(
        default_factory=list, description="Concrete URLs behind a templated/site-wide finding"
    )
    description: str = ""
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list, description="Contributing engine ids")
    detectors: list[str] = Field(default_factory=list)
    observation_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
