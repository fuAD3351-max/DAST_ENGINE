"""Repositories over the ORM, plus a SQLite/Postgres session factory.

Domain objects are pydantic models; rows store them as JSON. Repositories are
the only place that translates between the two, so the rest of the platform
never imports SQLAlchemy.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime

from sqlalchemy import create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from vantage.domain import Observation, Scan, ScanState, Severity, Target, UnifiedFinding, utcnow
from vantage.persistence.models import (
    AuditRow,
    Base,
    FindingRow,
    KnowledgeRow,
    ObservationRow,
    ScanRow,
    TargetRow,
)


def make_engine(url: str = "sqlite+pysqlite:///:memory:", echo: bool = False) -> Engine:
    connect_args: dict[str, object] = {}
    kwargs: dict[str, object] = {"echo": echo, "future": True}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if ":memory:" in url or url in ("sqlite://", "sqlite+pysqlite://"):
            # A single shared connection so every thread/session sees the same
            # in-memory database (used by the API TestClient and embedded mode).
            from sqlalchemy.pool import StaticPool

            kwargs["poolclass"] = StaticPool
    return create_engine(url, connect_args=connect_args, **kwargs)


def create_all(engine: Engine) -> None:
    Base.metadata.create_all(engine)


class Database:
    def __init__(self, url: str = "sqlite+pysqlite:///:memory:", echo: bool = False) -> None:
        self.engine = make_engine(url, echo=echo)
        create_all(self.engine)
        self._session_factory = sessionmaker(bind=self.engine, future=True, expire_on_commit=False)

    @contextmanager
    def unit_of_work(self) -> Iterator[UnitOfWork]:
        session = self._session_factory()
        uow = UnitOfWork(session)
        try:
            yield uow
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()


class TargetRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def upsert(self, target: Target) -> None:
        row = self._s.get(TargetRow, target.id)
        payload = target.model_dump(mode="json")
        if row is None:
            row = TargetRow(
                id=target.id,
                tenant_id=target.tenant_id,
                name=target.name,
                kind=target.kind.value,
                authorized=target.is_authorized(),
                created_at=target.created_at,
                payload=payload,
            )
            self._s.add(row)
        else:
            row.tenant_id = target.tenant_id
            row.name = target.name
            row.kind = target.kind.value
            row.authorized = target.is_authorized()
            row.payload = payload

    def get(self, target_id: str) -> Target | None:
        row = self._s.get(TargetRow, target_id)
        return Target.model_validate(row.payload) if row else None

    def list(self, tenant_id: str) -> list[Target]:
        rows = self._s.scalars(select(TargetRow).where(TargetRow.tenant_id == tenant_id)).all()
        return [Target.model_validate(r.payload) for r in rows]


class ScanRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def upsert(self, scan: Scan) -> None:
        row = self._s.get(ScanRow, scan.id)
        payload = scan.model_dump(mode="json")
        if row is None:
            self._s.add(
                ScanRow(
                    id=scan.id,
                    tenant_id=scan.tenant_id,
                    target_id=scan.target_id,
                    state=scan.state.value,
                    created_by=scan.created_by,
                    created_at=scan.created_at,
                    started_at=scan.started_at,
                    finished_at=scan.finished_at,
                    payload=payload,
                )
            )
        else:
            row.state = scan.state.value
            row.started_at = scan.started_at
            row.finished_at = scan.finished_at
            row.payload = payload

    def get(self, scan_id: str) -> Scan | None:
        row = self._s.get(ScanRow, scan_id)
        return Scan.model_validate(row.payload) if row else None

    def list(self, tenant_id: str, state: ScanState | None = None) -> list[Scan]:
        stmt = select(ScanRow).where(ScanRow.tenant_id == tenant_id)
        if state is not None:
            stmt = stmt.where(ScanRow.state == state.value)
        stmt = stmt.order_by(ScanRow.created_at.desc())
        return [Scan.model_validate(r.payload) for r in self._s.scalars(stmt).all()]


class ObservationRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def add_many(self, observations: Sequence[Observation]) -> None:
        for obs in observations:
            self._s.add(
                ObservationRow(
                    id=obs.id,
                    scan_id=obs.scan_id,
                    run_id=obs.run_id,
                    engine_id=obs.engine_id,
                    vuln_class=obs.vuln_class,
                    severity=obs.severity.value,
                    host=obs.location.host,
                    payload=obs.model_dump(mode="json"),
                )
            )

    def for_scan(self, scan_id: str) -> list[Observation]:
        rows = self._s.scalars(
            select(ObservationRow).where(ObservationRow.scan_id == scan_id)
        ).all()
        return [Observation.model_validate(r.payload) for r in rows]


class FindingRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def upsert(self, finding: UnifiedFinding) -> None:
        existing = self._s.execute(
            select(FindingRow).where(
                FindingRow.scan_id == finding.scan_id,
                FindingRow.fingerprint == finding.fingerprint,
            )
        ).scalar_one_or_none()
        payload = finding.model_dump(mode="json")
        if existing is None:
            self._s.add(
                FindingRow(
                    id=finding.id,
                    tenant_id=finding.tenant_id,
                    scan_id=finding.scan_id,
                    target_id=finding.target_id,
                    fingerprint=finding.fingerprint,
                    category=finding.category,
                    severity=finding.severity.value,
                    confidence=finding.confidence.value,
                    risk_score=finding.risk_score,
                    status=finding.status.value,
                    payload=payload,
                )
            )
        else:
            existing.severity = finding.severity.value
            existing.confidence = finding.confidence.value
            existing.risk_score = finding.risk_score
            existing.status = finding.status.value
            existing.payload = payload

    def for_scan(self, scan_id: str, min_severity: Severity | None = None) -> list[UnifiedFinding]:
        rows = self._s.scalars(
            select(FindingRow)
            .where(FindingRow.scan_id == scan_id)
            .order_by(FindingRow.risk_score.desc())
        ).all()
        findings = [UnifiedFinding.model_validate(r.payload) for r in rows]
        if min_severity is not None:
            findings = [f for f in findings if f.severity.rank >= min_severity.rank]
        return findings


class KnowledgeRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def record(self, scan_id: str, key: str, engine_id: str, test_class: str, result: str) -> None:
        self._s.add(
            KnowledgeRow(
                scan_id=scan_id,
                key=key,
                engine_id=engine_id,
                test_class=test_class,
                result=result,
                created_at=utcnow(),
            )
        )

    def seen(self, scan_id: str, key: str, test_class: str) -> bool:
        row = self._s.execute(
            select(KnowledgeRow.id).where(
                KnowledgeRow.scan_id == scan_id,
                KnowledgeRow.key == key,
                KnowledgeRow.test_class == test_class,
            )
        ).first()
        return row is not None


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self._s = session

    def record(
        self,
        tenant_id: str,
        actor: str,
        action: str,
        resource: str,
        detail: str = "",
        at: datetime | None = None,
    ) -> None:
        self._s.add(
            AuditRow(
                tenant_id=tenant_id,
                actor=actor,
                action=action,
                resource=resource,
                at=at or utcnow(),
                detail=detail,
            )
        )

    def recent(self, tenant_id: str, limit: int = 100) -> list[AuditRow]:
        return list(
            self._s.scalars(
                select(AuditRow)
                .where(AuditRow.tenant_id == tenant_id)
                .order_by(AuditRow.at.desc())
                .limit(limit)
            ).all()
        )


class UnitOfWork:
    def __init__(self, session: Session) -> None:
        self.session = session
        self.targets = TargetRepository(session)
        self.scans = ScanRepository(session)
        self.observations = ObservationRepository(session)
        self.findings = FindingRepository(session)
        self.knowledge = KnowledgeRepository(session)
        self.audit = AuditRepository(session)
