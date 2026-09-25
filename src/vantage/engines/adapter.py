"""The EngineAdapter contract.

Every engine, open-source or proprietary, is reached only through an adapter.
The orchestrator drives the lifecycle::

    metadata() -> health_check() -> capabilities()
      -> prepare_target() -> execute_scan() -> collect_results()
      -> normalize_results() -> cleanup()

Adapters are the trust boundary: engine output is untrusted input. Adapters
never write to the database; they return :class:`Observation` objects and the
orchestrator persists them after validation.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vantage.domain import (
    Capability,
    EngineMetadata,
    EngineRunRequest,
    HealthStatus,
    NetworkMode,
    Observation,
    ResourceLimits,
)


@dataclass(frozen=True)
class ContainerSpec:
    """Description of one isolated engine execution.

    The sandbox runner turns this into a container with: read-only root fs,
    all capabilities dropped, no-new-privileges, non-root user, CPU/memory/pid
    limits, a size-limited tmpfs work dir and the requested network mode.
    """

    image: str
    args: list[str]
    network: NetworkMode
    limits: ResourceLimits
    env: dict[str, str] = field(default_factory=dict)
    input_files: dict[str, bytes] = field(default_factory=dict)  # name -> content, mounted ro
    output_dir: str = "/out"
    workdir: str = "/work"
    user: str = "65532:65532"
    binary: str | None = None
    # Local-execution name of the tool (e.g. "nuclei"). Used by the
    # LocalSubprocessRunner on hosts (Kali) where the engine is installed as a
    # native binary. ``args`` may reference the tokens ``/out`` and ``/work``,
    # which the local runner rewrites to real temp directories.


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes
    output_files: dict[str, bytes]
    duration_seconds: float
    output_truncated: bool = False


class SandboxRunner(abc.ABC):
    """Executes a :class:`ContainerSpec`. Implementations: Docker, Kubernetes, fake."""

    @abc.abstractmethod
    async def run(self, spec: ContainerSpec) -> SandboxResult: ...

    @abc.abstractmethod
    async def available(self) -> bool: ...


@dataclass
class PreparedRun:
    request: EngineRunRequest
    spec: ContainerSpec | None = None
    workspace: Path | None = None
    state: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionOutcome:
    prepared: PreparedRun
    sandbox: SandboxResult | None
    native_output: Any = None


@dataclass
class RawResults:
    """Engine output after structural validation, before normalization."""

    engine_id: str
    engine_version: str
    format: str
    records: list[dict[str, Any]]
    rejected_records: int = 0
    artifact: bytes | None = None
    notes: list[str] = field(default_factory=list)


class EngineAdapter(abc.ABC):
    """Base class for all engine adapters."""

    @abc.abstractmethod
    def metadata(self) -> EngineMetadata: ...

    @abc.abstractmethod
    async def health_check(self) -> HealthStatus: ...

    def capabilities(self) -> set[Capability]:
        return set(self.metadata().capabilities)

    @abc.abstractmethod
    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun: ...

    @abc.abstractmethod
    async def execute_scan(self, prepared: PreparedRun) -> ExecutionOutcome: ...

    @abc.abstractmethod
    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults: ...

    @abc.abstractmethod
    def normalize_results(
        self, raw: RawResults, request: EngineRunRequest
    ) -> list[Observation]: ...

    async def cleanup(self, prepared: PreparedRun) -> None:  # noqa: B027 - optional hook
        """Release resources. Must be idempotent and must not raise."""
