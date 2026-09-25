"""Base for adapters that wrap an unmodified open-source engine in a container.

These adapters never link the engine into our process. They build a
:class:`ContainerSpec`, hand it to a :class:`SandboxRunner`, then parse the
engine's own output format into :class:`Observation` objects. This is the
arms-length boundary that keeps third-party engines (and their licenses) isolated
from Vantage's code, and treats their output as untrusted input.
"""

from __future__ import annotations

import abc
from typing import ClassVar

from vantage.domain import (
    ApprovalStatus,
    Capability,
    EngineMetadata,
    EngineRunRequest,
    HealthState,
    HealthStatus,
    IntegrationType,
    LicenseClass,
    NetworkMode,
    Observation,
    ResourceLimits,
)
from vantage.engines.adapter import (
    ContainerSpec,
    EngineAdapter,
    ExecutionOutcome,
    PreparedRun,
    RawResults,
    SandboxResult,
    SandboxRunner,
)


class ContainerEngineAdapter(EngineAdapter):
    engine_id: str
    engine_name: str
    vendor: str
    homepage: str = ""
    license_spdx: str
    engine_capabilities: ClassVar[list[Capability]] = []
    image: str = ""
    binary: str = ""  # local executable name for LocalSubprocessRunner (Kali/host)

    def __init__(
        self,
        runner: SandboxRunner,
        version: str,
        *,
        limits: ResourceLimits | None = None,
        approved: bool = False,
    ) -> None:
        self._runner = runner
        self._version = version
        self._limits = limits or ResourceLimits()
        # Third-party engines default to PENDING_REVIEW; the registry/operator
        # records legal approval explicitly for isolated RED/YELLOW engines.
        self._approval = ApprovalStatus.APPROVED if approved else ApprovalStatus.PENDING_REVIEW

    def metadata(self) -> EngineMetadata:
        return EngineMetadata(
            id=self.engine_id,
            name=self.engine_name,
            version=self._version,
            vendor=self.vendor,
            license_spdx=self.license_spdx,
            license_class=LicenseClass.GREEN,  # overridden by registry policy check
            approval_status=self._approval,
            integration=IntegrationType.CONTAINER_CLI,
            capabilities=list(self.engine_capabilities),
            image=self.image,
            homepage=self.homepage or None,
        )

    async def health_check(self) -> HealthStatus:
        if await self._runner.available():
            return HealthStatus(state=HealthState.HEALTHY, detail="sandbox available")
        return HealthStatus(state=HealthState.UNAVAILABLE, detail="sandbox runner unavailable")

    async def execute_scan(self, prepared: PreparedRun) -> ExecutionOutcome:
        assert prepared.spec is not None
        result = await self._runner.run(prepared.spec)
        return ExecutionOutcome(prepared=prepared, sandbox=result)

    def _network_mode(self) -> NetworkMode:
        return NetworkMode.SCOPED_EGRESS

    def _base_spec(self, args: list[str], env: dict[str, str] | None = None) -> ContainerSpec:
        return ContainerSpec(
            image=self.image,
            args=args,
            network=self._network_mode(),
            limits=self._limits,
            env=env or {},
            binary=self.binary or None,
        )

    def _guard_output(self, result: SandboxResult | None) -> str:
        """Validate the sandbox result before parsing (untrusted-input guard)."""
        if result is None:
            return ""
        if result.timed_out:
            return ""
        if result.output_truncated:
            # Truncated output is parsed best-effort but flagged by the adapter.
            pass
        return result.stdout.decode("utf-8", "replace")

    @abc.abstractmethod
    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun: ...

    @abc.abstractmethod
    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults: ...

    @abc.abstractmethod
    def normalize_results(
        self, raw: RawResults, request: EngineRunRequest
    ) -> list[Observation]: ...
