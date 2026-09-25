"""Scan Intelligence Orchestrator - the scan planner.

The planner turns a target + policy into a staged :class:`ScanPlan`. It selects
engines by *capability*, not by name, and shapes the plan to the application
kind so Sentinel does not "run every tool against every target":

    fingerprint -> classify application -> pick capabilities for the profile
                -> choose one engine per capability -> order into stages

Stages run in order (fingerprint, discovery, audit, validation); tasks within a
stage may run concurrently. The plan records *why* each engine was chosen and
which capabilities were skipped, for explainability.
"""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.domain import (
    ApplicationKind,
    Capability,
    PlannedTask,
    PlanStage,
    ScanPlan,
    ScanPolicy,
    ScanProfile,
    StageKind,
    Target,
)
from sentinel.engines.catalog import EngineCatalog

# Capabilities enabled by each profile. PASSIVE never sends crafted test input.
_PROFILE_CAPS: dict[ScanProfile, list[Capability]] = {
    ScanProfile.PASSIVE: [
        Capability.FINGERPRINT_TECH,
        Capability.CRAWL_HTTP,
        Capability.ANALYSIS_TLS,
        Capability.ANALYSIS_HEADERS,
        Capability.ANALYSIS_SECRETS,
        Capability.AUDIT_PASSIVE,
    ],
    ScanProfile.STANDARD: [
        Capability.FINGERPRINT_TECH,
        Capability.CRAWL_HTTP,
        Capability.DISCOVERY_JS,
        Capability.DISCOVERY_CONTENT,
        Capability.ANALYSIS_TLS,
        Capability.ANALYSIS_HEADERS,
        Capability.ANALYSIS_SECRETS,
        Capability.AUDIT_PASSIVE,
        Capability.AUDIT_TEMPLATES,
        Capability.AUDIT_ACTIVE,
        Capability.VALIDATION,
    ],
    ScanProfile.DEEP: list(Capability),
}

# Application-kind specialization: which capabilities matter for each kind. A
# capability not listed for the detected kind is dropped even if the profile
# would allow it (keeps API scans from running browser crawls, etc.).
_KIND_CAPS: dict[ApplicationKind, set[Capability]] = {
    ApplicationKind.TRADITIONAL_WEB: {
        Capability.CRAWL_HTTP,
        Capability.DISCOVERY_CONTENT,
        Capability.AUDIT_ACTIVE,
        Capability.AUDIT_TEMPLATES,
    },
    ApplicationKind.SPA: {
        Capability.CRAWL_BROWSER,
        Capability.DISCOVERY_JS,
        Capability.DISCOVERY_API_SPEC,
        Capability.AUDIT_ACTIVE,
        Capability.AUDIT_TEMPLATES,
    },
    ApplicationKind.REST_API: {
        Capability.DISCOVERY_API_SPEC,
        Capability.AUDIT_API_REST,
        Capability.AUDIT_AUTHZ,
        Capability.AUDIT_TEMPLATES,
    },
    ApplicationKind.GRAPHQL_API: {
        Capability.DISCOVERY_API_SPEC,
        Capability.AUDIT_API_GRAPHQL,
        Capability.AUDIT_AUTHZ,
    },
    ApplicationKind.SOAP_API: {
        Capability.DISCOVERY_API_SPEC,
        Capability.AUDIT_API_REST,
    },
    ApplicationKind.WEBSOCKET: {
        Capability.AUDIT_WEBSOCKET,
    },
}

# Capabilities that are always relevant regardless of application kind.
_UNIVERSAL_CAPS = {
    Capability.FINGERPRINT_TECH,
    Capability.ANALYSIS_TLS,
    Capability.ANALYSIS_HEADERS,
    Capability.ANALYSIS_SECRETS,
    Capability.AUDIT_PASSIVE,
    Capability.VALIDATION,
    Capability.OOB_CALLBACK,
}

_CAP_STAGE: dict[Capability, StageKind] = {
    Capability.FINGERPRINT_TECH: StageKind.FINGERPRINT,
    Capability.CRAWL_HTTP: StageKind.DISCOVERY,
    Capability.CRAWL_BROWSER: StageKind.DISCOVERY,
    Capability.DISCOVERY_CONTENT: StageKind.DISCOVERY,
    Capability.DISCOVERY_JS: StageKind.DISCOVERY,
    Capability.DISCOVERY_API_SPEC: StageKind.DISCOVERY,
    Capability.ANALYSIS_TLS: StageKind.AUDIT,
    Capability.ANALYSIS_HEADERS: StageKind.AUDIT,
    Capability.ANALYSIS_SECRETS: StageKind.AUDIT,
    Capability.AUDIT_PASSIVE: StageKind.AUDIT,
    Capability.AUDIT_ACTIVE: StageKind.AUDIT,
    Capability.AUDIT_TEMPLATES: StageKind.AUDIT,
    Capability.AUDIT_API_REST: StageKind.AUDIT,
    Capability.AUDIT_API_GRAPHQL: StageKind.AUDIT,
    Capability.AUDIT_WEBSOCKET: StageKind.AUDIT,
    Capability.AUDIT_AUTHZ: StageKind.AUDIT,
    Capability.OOB_CALLBACK: StageKind.AUDIT,
    Capability.VALIDATION: StageKind.VALIDATION,
}

_STAGE_ORDER = [StageKind.FINGERPRINT, StageKind.DISCOVERY, StageKind.AUDIT, StageKind.VALIDATION]


@dataclass
class PlannerConfig:
    # If True, allow several engines per capability (more coverage, more
    # traffic). Default False: one engine per capability, chosen by catalog
    # preference order, keeping traffic and duplication down.
    redundant_engines: bool = False


class ScanPlanner:
    def __init__(self, catalog: EngineCatalog, config: PlannerConfig | None = None) -> None:
        self._catalog = catalog
        self._config = config or PlannerConfig()

    def _wanted_capabilities(self, target: Target, policy: ScanPolicy) -> list[Capability]:
        profile_caps = list(policy.capabilities or _PROFILE_CAPS[policy.profile])
        if target.kind is ApplicationKind.UNKNOWN:
            # Nothing to specialize on yet: keep all profile capabilities.
            allowed = set(profile_caps)
        else:
            allowed = _UNIVERSAL_CAPS | _KIND_CAPS.get(target.kind, set())
        # Preserve profile order for determinism.
        return [c for c in profile_caps if c in allowed]

    def plan(self, target: Target, policy: ScanPolicy, seed_urls: list[str]) -> ScanPlan:
        wanted = self._wanted_capabilities(target, policy)
        stages: dict[StageKind, list[PlannedTask]] = {s: [] for s in _STAGE_ORDER}
        skipped: list[str] = []

        for cap in wanted:
            engines = [
                m for m in self._catalog.engines_for(cap) if m.id not in policy.disabled_engines
            ]
            if not engines:
                skipped.append(f"{cap.value}: no enabled engine provides this capability")
                continue
            chosen = engines if self._config.redundant_engines else engines[:1]
            stage = _CAP_STAGE[cap]
            for meta in chosen:
                reason = (
                    f"selected {meta.id} for {cap.value} "
                    f"(profile={policy.profile.value}, app={target.kind.value})"
                )
                # Merge into an existing task for the same engine+stage so one
                # engine that covers several capabilities runs once.
                existing = next((t for t in stages[stage] if t.engine_id == meta.id), None)
                if existing is not None:
                    existing.capabilities.append(cap)
                    existing.reason += f"; +{cap.value}"
                else:
                    stages[stage].append(
                        PlannedTask(
                            engine_id=meta.id,
                            capabilities=[cap],
                            seed_urls=list(seed_urls),
                            reason=reason,
                        )
                    )

        plan_stages = [PlanStage(kind=s, tasks=stages[s]) for s in _STAGE_ORDER if stages[s]]
        return ScanPlan(scan_id="", stages=plan_stages, skipped=skipped)
