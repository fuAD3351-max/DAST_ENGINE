"""Scan policy, scan plan and scan lifecycle records."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field

from sentinel.domain.common import SentinelModel, new_id, utcnow
from sentinel.domain.engine import Capability


class ScanProfile(StrEnum):
    """Pre-defined policies. PASSIVE never sends crafted test input."""

    PASSIVE = "passive"
    STANDARD = "standard"
    DEEP = "deep"


class ScanPolicy(SentinelModel):
    profile: ScanProfile = ScanProfile.STANDARD
    capabilities: list[Capability] | None = Field(
        default=None, description="Explicit capability allowlist; None = profile default"
    )
    disabled_engines: list[str] = Field(default_factory=list)
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "HEAD", "OPTIONS", "POST"],
        description="State-changing methods (PUT/PATCH/DELETE) must be opted into explicitly",
    )
    max_duration_minutes: int = Field(default=240, ge=1, le=10080)
    max_total_requests: int | None = Field(default=None, ge=1)
    template_tags_denylist: list[str] = Field(
        default_factory=lambda: ["dos", "fuzz", "intrusive", "brute-force"],
    )


class ScanState(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    PLANNING = "planning"
    RUNNING = "running"
    PAUSED = "paused"
    CORRELATING = "correlating"
    VALIDATING = "validating"
    REPORTING = "reporting"
    COMPLETED = "completed"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    FAILED = "failed"


TERMINAL_STATES = frozenset({ScanState.COMPLETED, ScanState.CANCELLED, ScanState.FAILED})


class StageKind(StrEnum):
    FINGERPRINT = "fingerprint"
    DISCOVERY = "discovery"
    AUDIT = "audit"
    VALIDATION = "validation"


class PlannedTask(SentinelModel):
    id: str = Field(default_factory=new_id)
    engine_id: str
    capability: Capability
    seed_urls: list[str]
    options: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(description="Why the planner chose this engine (explainability)")


class PlanStage(SentinelModel):
    kind: StageKind
    tasks: list[PlannedTask] = Field(default_factory=list)


class ScanPlan(SentinelModel):
    scan_id: str
    stages: list[PlanStage] = Field(default_factory=list)
    skipped: list[str] = Field(
        default_factory=list, description="Capabilities not covered, with the reason"
    )
    created_at: datetime = Field(default_factory=utcnow)


class Scan(SentinelModel):
    id: str = Field(default_factory=new_id)
    tenant_id: str
    target_id: str
    policy: ScanPolicy = Field(default_factory=ScanPolicy)
    state: ScanState = ScanState.CREATED
    state_reason: str | None = None
    created_by: str
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
