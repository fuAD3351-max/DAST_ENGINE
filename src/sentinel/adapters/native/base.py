"""Base class for native (first-party, in-process) engine adapters.

Native adapters run Sentinel's own detectors. They fetch only through an
:class:`HttpClient`, which the orchestrator supplies via a factory so the client
is scoped and rate-limited to the specific target. The heavy lifting of each
adapter lives in ``_analyze``; the lifecycle methods are thin wrappers.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from typing import Any, ClassVar

from sentinel.adapters.http import HttpClient, ScopedHttpClient
from sentinel.domain import (
    ApprovalStatus,
    Capability,
    EngineMetadata,
    EngineRunRequest,
    HealthState,
    HealthStatus,
    IntegrationType,
    LicenseClass,
    Observation,
)
from sentinel.domain.target import ScopeRule
from sentinel.engines.adapter import (
    EngineAdapter,
    ExecutionOutcome,
    PreparedRun,
    RawResults,
)
from sentinel.scope.engine import ScopeEngine

ClientFactory = Callable[[EngineRunRequest], HttpClient]

FIRST_PARTY_LICENSE = "LicenseRef-Sentinel-Proprietary"


def default_client_factory(request: EngineRunRequest) -> HttpClient:
    """Build a scope-enforcing client from the request's own scope rules."""
    rules = [ScopeRule.model_validate(r) for r in request.scope_rules]
    scope = ScopeEngine.from_rules(rules, authorized=True)
    return ScopedHttpClient(
        scope,
        rate_per_sec=request.max_requests_per_second,
        concurrency=request.max_concurrency,
    )


class NativeAdapter(EngineAdapter):
    engine_id: str
    engine_name: str
    version: str = "0.1.0"
    engine_capabilities: ClassVar[list[Capability]] = []

    def __init__(self, client_factory: ClientFactory | None = None) -> None:
        self._client_factory = client_factory or default_client_factory

    def metadata(self) -> EngineMetadata:
        return EngineMetadata(
            id=self.engine_id,
            name=self.engine_name,
            version=self.version,
            vendor="Sentinel DAST",
            license_spdx=FIRST_PARTY_LICENSE,
            license_class=LicenseClass.GREEN,
            approval_status=ApprovalStatus.APPROVED,
            integration=IntegrationType.NATIVE,
            capabilities=list(self.engine_capabilities),
        )

    async def health_check(self) -> HealthStatus:
        return HealthStatus(state=HealthState.HEALTHY, detail="native engine")

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        client = self._client_factory(request)
        return PreparedRun(request=request, state={"client": client})

    async def execute_scan(self, prepared: PreparedRun) -> ExecutionOutcome:
        client: HttpClient = prepared.state["client"]
        observations = await self._analyze(prepared.request, client)
        return ExecutionOutcome(prepared=prepared, sandbox=None, native_output=observations)

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        observations: list[Observation] = outcome.native_output or []
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self.version,
            format="sentinel.observations",
            records=[o.model_dump(mode="json") for o in observations],
        )

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        # Native engines already emit Observations; re-validate for safety.
        return [Observation.model_validate(r) for r in raw.records]

    async def cleanup(self, prepared: PreparedRun) -> None:
        client = prepared.state.get("client")
        if client is not None:
            await client.aclose()

    @abc.abstractmethod
    async def _analyze(
        self, request: EngineRunRequest, client: HttpClient
    ) -> list[Observation]: ...

    # Convenience for subclasses.
    def _new_observation(self, request: EngineRunRequest, **kwargs: Any) -> Observation:
        return Observation(
            scan_id=request.scan_id,
            run_id=request.run_id,
            engine_id=self.engine_id,
            engine_version=self.version,
            **kwargs,
        )
