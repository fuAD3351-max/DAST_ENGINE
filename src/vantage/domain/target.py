"""Targets, scope rules and authorization records.

A target cannot receive active traffic until it carries a valid
:class:`AuthorizationRecord`. This is a product-level safety control: Vantage
is for testing systems the customer owns or is explicitly authorized to test.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field, HttpUrl, field_validator

from vantage.domain.common import VantageModel, new_id, utcnow


class ApplicationKind(StrEnum):
    UNKNOWN = "unknown"
    TRADITIONAL_WEB = "traditional_web"
    SPA = "spa"
    REST_API = "rest_api"
    GRAPHQL_API = "graphql_api"
    SOAP_API = "soap_api"
    WEBSOCKET = "websocket"


class AuthorizationMethod(StrEnum):
    """How the tenant proved it may test the target."""

    DNS_TXT = "dns_txt"  # TXT record with a Vantage verification token
    HTTP_FILE = "http_file"  # /.well-known/vantage-verification.txt
    SIGNED_ATTESTATION = "signed_attestation"  # written authorization, recorded by an admin
    INTERNAL_ASSET = "internal_asset"  # asset inventory marks it as owned (on-prem)


class AuthorizationRecord(VantageModel):
    method: AuthorizationMethod
    verified_at: datetime
    verified_by: str = Field(min_length=1)
    expires_at: datetime | None = None
    reference: str | None = Field(default=None, description="Ticket / contract / token id")

    def is_valid(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        return self.expires_at is None or self.expires_at > now


class ScopeRuleKind(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class ScopeRule(VantageModel):
    """One include/exclude rule. Excludes always win over includes.

    ``host`` accepts an exact hostname, a ``*.example.com`` wildcard (subdomains
    only, not the apex), an IP address, or a CIDR block.
    """

    kind: ScopeRuleKind = ScopeRuleKind.INCLUDE
    host: str = Field(min_length=1, max_length=253)
    schemes: list[str] = Field(default_factory=lambda: ["https", "http"])
    ports: list[int] | None = None  # None = default port for the scheme only
    path_prefix: str = "/"
    path_regex: str | None = None
    methods: list[str] | None = None  # None = any method permitted by the scan policy

    @field_validator("host")
    @classmethod
    def _lower_host(cls, v: str) -> str:
        return v.strip().lower().rstrip(".")

    @field_validator("schemes")
    @classmethod
    def _schemes(cls, v: list[str]) -> list[str]:
        out = [s.lower() for s in v]
        bad = [s for s in out if s not in {"http", "https", "ws", "wss"}]
        if bad:
            raise ValueError(f"unsupported scheme(s): {bad}")
        return out

    @field_validator("path_prefix")
    @classmethod
    def _path_prefix(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path_prefix must start with '/'")
        return v

    @field_validator("methods")
    @classmethod
    def _methods(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else [m.upper() for m in v]


class RateLimits(VantageModel):
    """Traffic ceilings enforced by the orchestrator for every engine."""

    max_requests_per_second: float = Field(default=10.0, gt=0, le=1000)
    max_concurrency: int = Field(default=4, ge=1, le=256)
    max_total_requests: int | None = Field(default=None, ge=1)


class Target(VantageModel):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    name: str = Field(min_length=1, max_length=200)
    base_urls: list[HttpUrl] = Field(min_length=1)
    kind: ApplicationKind = ApplicationKind.UNKNOWN
    scope_rules: list[ScopeRule] = Field(default_factory=list)
    rate_limits: RateLimits = Field(default_factory=RateLimits)
    authorization: AuthorizationRecord | None = None
    api_definitions: list[str] = Field(
        default_factory=list, description="OpenAPI/GraphQL/WSDL locations (URL or artifact ref)"
    )
    tags: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)

    def is_authorized(self, now: datetime | None = None) -> bool:
        return self.authorization is not None and self.authorization.is_valid(now)
