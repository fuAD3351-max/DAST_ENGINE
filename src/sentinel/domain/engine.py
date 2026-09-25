"""Engine metadata and the data exchanged across the adapter boundary."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from sentinel.domain.common import (
    ApprovalStatus,
    Identifier,
    LicenseClass,
    SentinelModel,
    new_id,
    utcnow,
)


class Capability(StrEnum):
    """Product-level capabilities. The planner selects engines by capability,
    never by engine name, so engines stay replaceable."""

    CRAWL_HTTP = "crawl.http"
    CRAWL_BROWSER = "crawl.browser"
    DISCOVERY_CONTENT = "discovery.content"
    DISCOVERY_JS = "discovery.js"
    DISCOVERY_API_SPEC = "discovery.api_spec"
    DISCOVERY_SUBDOMAIN = "discovery.subdomain"
    RECON_HTTP = "recon.http"  # live-host probing / HTTP intelligence over the attack surface
    FINGERPRINT_TECH = "fingerprint.tech"
    ANALYSIS_TLS = "analysis.tls"
    ANALYSIS_DNS = "analysis.dns"
    ANALYSIS_HEADERS = "analysis.headers"
    ANALYSIS_SECRETS = "analysis.secrets"
    AUDIT_PASSIVE = "audit.passive"
    AUDIT_ACTIVE = "audit.active"
    AUDIT_TEMPLATES = "audit.templates"
    AUDIT_API_REST = "audit.api.rest"
    AUDIT_API_GRAPHQL = "audit.api.graphql"
    AUDIT_API_SOAP = "audit.api.soap"
    AUDIT_WEBSOCKET = "audit.websocket"
    AUDIT_AUTHZ = "audit.authz"
    OOB_CALLBACK = "oob.callback"
    VALIDATION = "validation"


class IntegrationType(StrEnum):
    NATIVE = "native"  # proprietary Sentinel code, in-process
    LIBRARY = "library"  # permissively licensed library, in-process
    CONTAINER_CLI = "container_cli"  # unmodified external program in an isolated container
    CONTAINER_API = "container_api"  # external daemon in a container, driven over its API
    EXTERNAL_SERVICE = "external_service"  # third-party service the CUSTOMER hosts and licenses;
    # Sentinel ships only an API client, never the third-party software (bring-your-own-license)


class NetworkMode(StrEnum):
    NONE = "none"  # no network at all (parsers, analyzers of stored artifacts)
    SCOPED_EGRESS = "scoped_egress"  # egress only via the Sentinel scope-enforcing proxy


class ResourceLimits(SentinelModel):
    cpus: float = Field(default=1.0, gt=0, le=64)
    memory_mb: int = Field(default=1024, ge=64, le=262144)
    pids: int = Field(default=512, ge=16, le=65536)
    timeout_seconds: int = Field(default=3600, ge=10, le=86400)
    max_output_bytes: int = Field(default=256 * 1024 * 1024, ge=1024)
    tmpfs_mb: int = Field(default=512, ge=16, le=65536)


class EngineMetadata(SentinelModel):
    id: Identifier
    name: str
    version: str
    vendor: str
    license_spdx: str
    license_class: LicenseClass
    approval_status: ApprovalStatus
    integration: IntegrationType
    capabilities: list[Capability]
    image: str | None = Field(default=None, description="Container image pinned by digest")
    homepage: str | None = None


class HealthState(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class HealthStatus(SentinelModel):
    state: HealthState
    detail: str = ""
    checked_at: datetime = Field(default_factory=utcnow)


class EngineRunRequest(SentinelModel):
    """Everything an adapter needs to run one engine against one scope slice.

    Adapters never receive database handles or credentials beyond what is in
    ``auth_context``; the orchestrator owns persistence.
    """

    run_id: str = Field(default_factory=new_id)
    scan_id: str
    tenant_id: str
    engine_id: Identifier
    capabilities: list[Capability] = Field(min_length=1)
    seed_urls: list[str] = Field(min_length=1)
    scope_rules: list[dict[str, Any]] = Field(default_factory=list)
    max_requests_per_second: float = Field(default=10.0, gt=0)
    max_concurrency: int = Field(default=4, ge=1)
    options: dict[str, Any] = Field(default_factory=dict)
    auth_context: dict[str, Any] | None = Field(
        default=None, description="Session material produced by the Authentication Manager"
    )
    proxy_url: str | None = Field(
        default=None, description="Scope-enforcing egress proxy the engine must use"
    )


class RunStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    REJECTED_OUTPUT = "rejected_output"  # engine output failed validation


class EngineRunResult(SentinelModel):
    run_id: str
    engine_id: Identifier
    engine_version: str
    status: RunStatus
    started_at: datetime
    finished_at: datetime
    exit_code: int | None = None
    raw_artifacts: list[str] = Field(
        default_factory=list, description="Content-addressed refs to raw engine output"
    )
    observations_count: int = 0
    error: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
