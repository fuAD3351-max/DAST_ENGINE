"""Scan Orchestrator - the proprietary control loop.

Drives one scan through its lifecycle, coordinating every other subsystem:

    plan (planner) -> execute engines (adapters + sandbox, scope-enforced)
      -> persist observations -> validate (validation engine)
      -> correlate + de-duplicate -> risk score -> persist unified findings

The orchestrator is the *only* component that mutates scan state and writes
findings. Adapters return data; the orchestrator decides what is trustworthy and
what is stored. Engine failures are isolated: one engine crashing or timing out
degrades coverage but never aborts the scan or corrupts results.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from vantage.ai.analyst import AiAssessment, SecurityAnalyst
from vantage.domain import (
    Capability,
    EngineRunRequest,
    Observation,
    Scan,
    ScanState,
    Target,
    UnifiedFinding,
    utcnow,
)
from vantage.engines.adapter import EngineAdapter
from vantage.engines.registry import EngineRegistry
from vantage.findings.correlation import CorrelationEngine, merge_across_scans
from vantage.findings.risk import RiskEngine
from vantage.knowledge.base import RequestKnowledgeBase, coverage_key
from vantage.persistence.repositories import Database
from vantage.planner.planner import PlannerConfig, ScanPlanner
from vantage.scan.validation import Prober, ValidationEngine

logger = logging.getLogger("vantage.orchestrator")

# Legal scan-state transitions. Guards against illegal jumps and double-runs.
_TRANSITIONS: dict[ScanState, set[ScanState]] = {
    ScanState.CREATED: {ScanState.QUEUED, ScanState.CANCELLED},
    ScanState.QUEUED: {ScanState.PLANNING, ScanState.CANCELLING, ScanState.CANCELLED},
    ScanState.PLANNING: {ScanState.RUNNING, ScanState.FAILED, ScanState.CANCELLING},
    ScanState.RUNNING: {
        ScanState.CORRELATING,
        ScanState.PAUSED,
        ScanState.FAILED,
        ScanState.CANCELLING,
    },
    ScanState.PAUSED: {ScanState.RUNNING, ScanState.CANCELLING, ScanState.CANCELLED},
    ScanState.CORRELATING: {ScanState.VALIDATING, ScanState.FAILED, ScanState.CANCELLING},
    ScanState.VALIDATING: {ScanState.REPORTING, ScanState.FAILED, ScanState.CANCELLING},
    ScanState.REPORTING: {ScanState.COMPLETED, ScanState.FAILED},
    ScanState.CANCELLING: {ScanState.CANCELLED},
}


class IllegalTransition(RuntimeError):
    pass


def can_transition(src: ScanState, dst: ScanState) -> bool:
    return dst in _TRANSITIONS.get(src, set())


ProberFactory = Callable[[Target], Prober]


@dataclass
class ScanReport:
    scan: Scan
    findings: list[UnifiedFinding]
    observations: int
    engines_run: list[str]
    engines_failed: list[str]
    skipped_capabilities: list[str]
    stats: dict[str, object] = field(default_factory=dict)
    ai: AiAssessment | None = None


class Orchestrator:
    def __init__(
        self,
        db: Database,
        registry: EngineRegistry,
        *,
        validation_engine: ValidationEngine | None = None,
        risk_engine: RiskEngine | None = None,
        prober_factory: ProberFactory | None = None,
        planner_config: PlannerConfig | None = None,
        validate_findings: bool = True,
        analyst: SecurityAnalyst | None = None,
    ) -> None:
        self._db = db
        self._registry = registry
        self._planner = ScanPlanner(registry, planner_config)
        self._validation = validation_engine or ValidationEngine()
        self._risk = risk_engine or RiskEngine()
        self._prober_factory = prober_factory
        self._validate = validate_findings
        # AI layer sits ABOVE deterministic results; default is a no-op analyst.
        self._analyst = analyst or SecurityAnalyst()

    def _set_state(self, scan: Scan, dst: ScanState, reason: str | None = None) -> Scan:
        if scan.state is dst:
            return scan
        if not can_transition(scan.state, dst):
            raise IllegalTransition(f"{scan.state} -> {dst}")
        updates: dict[str, object] = {"state": dst, "state_reason": reason}
        if dst is ScanState.RUNNING and scan.started_at is None:
            updates["started_at"] = utcnow()
        if dst in (ScanState.COMPLETED, ScanState.FAILED, ScanState.CANCELLED):
            updates["finished_at"] = utcnow()
        scan = scan.model_copy(update=updates)
        with self._db.unit_of_work() as uow:
            uow.scans.upsert(scan)
            uow.audit.record(
                scan.tenant_id,
                scan.created_by,
                "scan.state",
                scan.id,
                f"{dst.value}:{reason or ''}",
            )
        return scan

    async def run(self, scan: Scan, target: Target) -> ScanReport:
        if not target.is_authorized():
            scan = self._set_state(
                self._set_state(scan, ScanState.QUEUED),
                ScanState.PLANNING,
            )
            scan = self._set_state(scan, ScanState.FAILED, "target not authorized")
            return ScanReport(scan, [], 0, [], [], ["all: target not authorized"])

        scan = self._set_state(scan, ScanState.QUEUED)
        scan = self._set_state(scan, ScanState.PLANNING)

        seeds = [str(u) for u in target.base_urls]
        plan = self._planner.plan(target, scan.policy, seeds)
        plan = plan.model_copy(update={"scan_id": scan.id})

        scan = self._set_state(scan, ScanState.RUNNING)
        kb = RequestKnowledgeBase()
        all_obs: list[Observation] = []
        engines_run: list[str] = []
        engines_failed: list[str] = []

        for stage in plan.stages:
            for task in stage.tasks:
                adapter = self._registry.adapter_for(task.engine_id)
                if adapter is None:
                    engines_failed.append(task.engine_id)
                    logger.warning("no bound adapter for engine %s", task.engine_id)
                    continue
                obs = await self._run_engine(
                    scan, target, adapter, task.capabilities, task.seed_urls, kb
                )
                engines_run.append(task.engine_id)
                all_obs.extend(obs)

        if all_obs:
            with self._db.unit_of_work() as uow:
                uow.observations.add_many(all_obs)

        # Validation (raises/lowers confidence before correlation).
        scan = self._set_state(scan, ScanState.CORRELATING)
        if self._validate and self._prober_factory is not None:
            prober = self._prober_factory(target)
            validated: list[Observation] = []
            for observation in all_obs:
                try:
                    validated.append(await self._validation.validate(observation, prober))
                except Exception:
                    logger.exception("validation failed for observation %s", observation.id)
                    validated.append(observation)
            all_obs = validated

        # Correlation + de-duplication.
        correlator = CorrelationEngine(scan.tenant_id, scan.id, target.id)
        findings = correlator.correlate(all_obs)

        # Carry first_seen across the target's previous scan.
        findings = self._merge_history(scan, target, findings)

        # Validation stage marker (state machine) + risk scoring.
        scan = self._set_state(scan, ScanState.VALIDATING)
        for f in findings:
            self._risk.apply(f)

        scan = self._set_state(scan, ScanState.REPORTING)
        with self._db.unit_of_work() as uow:
            for f in findings:
                uow.findings.upsert(f)

        # AI layer (optional, on-prem): annotates deterministic findings only.
        ai = await self._analyst.assess(findings)
        if ai.enabled:
            findings = self._analyst.prioritized_order(findings, ai)

        scan = self._set_state(scan, ScanState.COMPLETED, f"{len(findings)} findings")

        return ScanReport(
            scan=scan,
            findings=findings,
            observations=len(all_obs),
            engines_run=engines_run,
            engines_failed=engines_failed,
            skipped_capabilities=plan.skipped,
            stats={"coverage_entries": len(kb)},
            ai=ai,
        )

    async def _run_engine(
        self,
        scan: Scan,
        target: Target,
        adapter: EngineAdapter,
        capabilities: Sequence[Capability],
        seed_urls: list[str],
        kb: RequestKnowledgeBase,
    ) -> list[Observation]:
        meta = adapter.metadata()
        request = EngineRunRequest(
            scan_id=scan.id,
            tenant_id=scan.tenant_id,
            engine_id=meta.id,
            capabilities=list(capabilities),
            seed_urls=seed_urls,
            scope_rules=[r.model_dump(mode="json") for r in target.scope_rules],
            max_requests_per_second=target.rate_limits.max_requests_per_second,
            max_concurrency=target.rate_limits.max_concurrency,
        )
        try:
            health = await adapter.health_check()
            if health.state.value == "unavailable":
                logger.warning("engine %s unavailable: %s", meta.id, health.detail)
                return []
            prepared = await adapter.prepare_target(request)
            outcome = await adapter.execute_scan(prepared)
            raw = await adapter.collect_results(outcome)
            observations = adapter.normalize_results(raw, request)
            await adapter.cleanup(prepared)
        except Exception:
            logger.exception("engine %s failed", meta.id)
            return []

        # Record coverage so later engines avoid duplicate work.
        for obs in observations:
            key = coverage_key(
                obs.location.host,
                obs.location.port,
                obs.location.path,
                obs.location.method or "GET",
                obs.location.parameter,
            )
            kb.mark(key, obs.vuln_class)
        return observations

    def _merge_history(
        self, scan: Scan, target: Target, findings: list[UnifiedFinding]
    ) -> list[UnifiedFinding]:
        with self._db.unit_of_work() as uow:
            prev_scans = [
                s
                for s in uow.scans.list(scan.tenant_id, ScanState.COMPLETED)
                if s.target_id == target.id and s.id != scan.id
            ]
            if not prev_scans:
                return findings
            last = prev_scans[0]
            previous = uow.findings.for_scan(last.id)
        return merge_across_scans(previous, findings)
