"""Shared primitives used across the Sentinel domain model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    """Timezone-aware UTC now. All persisted timestamps are UTC."""
    return datetime.now(UTC)


def new_id() -> str:
    return uuid.uuid4().hex


Identifier = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")]


class SentinelModel(BaseModel):
    """Base model: immutable-by-convention, strict about unknown fields."""

    model_config = ConfigDict(extra="forbid", frozen=False, validate_assignment=True)


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def max(cls, *values: Severity) -> Severity:
        return max(values, key=lambda s: s.rank)


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(StrEnum):
    """How sure Sentinel is that a finding is real.

    TENTATIVE: a single engine reported an indicator.
    FIRM: corroborated by several independent engines or strong evidence.
    CONFIRMED: Sentinel's validation engine reproduced the behaviour.
    FALSE_POSITIVE: validation disproved it (kept for audit, hidden by default).
    """

    TENTATIVE = "tentative"
    FIRM = "firm"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK = {
    Confidence.FALSE_POSITIVE: -1,
    Confidence.TENTATIVE: 0,
    Confidence.FIRM: 1,
    Confidence.CONFIRMED: 2,
}


class LicenseClass(StrEnum):
    """License policy classes (see third_party/policy/license-policy.yaml)."""

    GREEN = "GREEN"
    YELLOW = "YELLOW"
    RED = "RED"
    UNKNOWN = "UNKNOWN"


class ApprovalStatus(StrEnum):
    APPROVED = "approved"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"
