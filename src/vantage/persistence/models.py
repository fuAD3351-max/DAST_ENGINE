"""SQLAlchemy ORM models.

The rich pydantic domain objects are stored as JSON in a ``payload`` column,
with the fields needed for filtering/joins promoted to real columns. This keeps
the schema stable as the domain evolves while still allowing indexed queries by
tenant, scan, state, severity and correlation fingerprint.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Index, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TenantRow(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)


class TargetRow(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(40))
    authorized: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    state: Mapped[str] = mapped_column(String(40), index=True)
    created_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict[str, object]] = mapped_column(JSON)

    __table_args__ = (Index("ix_scans_tenant_state", "tenant_id", "state"),)


class ObservationRow(Base):
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    engine_id: Mapped[str] = mapped_column(String(64), index=True)
    vuln_class: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16))
    host: Mapped[str] = mapped_column(String(253))
    payload: Mapped[dict[str, object]] = mapped_column(JSON)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    scan_id: Mapped[str] = mapped_column(String(64), ForeignKey("scans.id"), index=True)
    target_id: Mapped[str] = mapped_column(String(64), index=True)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[str] = mapped_column(String(20), index=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String(20), default="open")
    payload: Mapped[dict[str, object]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_findings_scan_fp", "scan_id", "fingerprint", unique=True),
        Index("ix_findings_tenant_sev", "tenant_id", "severity"),
    )


class KnowledgeRow(Base):
    """RequestKnowledgeBase entries: which (endpoint, method, param, test-class)
    tuples an engine has already covered, so the planner avoids redundant work."""

    __tablename__ = "request_knowledge"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    key: Mapped[str] = mapped_column(String(512), index=True)
    engine_id: Mapped[str] = mapped_column(String(64))
    test_class: Mapped[str] = mapped_column(String(64))
    result: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_knowledge_scan_key", "scan_id", "key"),)


class AuditRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource: Mapped[str] = mapped_column(String(200))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    detail: Mapped[str] = mapped_column(Text, default="")
    payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)


class ArtifactRow(Base):
    """Content-addressed raw engine output and large evidence bodies."""

    __tablename__ = "artifacts"

    digest: Mapped[str] = mapped_column(String(128), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    media_type: Mapped[str] = mapped_column(String(120))
    size: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # In production this points to object storage; for the embedded build the
    # bytes live inline.
    inline: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    location: Mapped[str | None] = mapped_column(String(512), nullable=True)
