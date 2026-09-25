"""Read-only view of available engines, used by the planner.

The planner depends on this protocol rather than on the concrete registry so
that planning logic can be tested without manifests, containers or adapters.
"""

from __future__ import annotations

from typing import Protocol

from sentinel.domain import Capability, EngineMetadata


class EngineCatalog(Protocol):
    def enabled_engines(self) -> list[EngineMetadata]:
        """Engines that are enabled, license-approved and pinned."""
        ...

    def engines_for(self, capability: Capability) -> list[EngineMetadata]:
        """Enabled engines advertising ``capability``, in preference order."""
        ...


class StaticCatalog:
    """Simple in-memory catalog (tests, embedded use)."""

    def __init__(self, engines: list[EngineMetadata]) -> None:
        self._engines = list(engines)

    def enabled_engines(self) -> list[EngineMetadata]:
        return list(self._engines)

    def engines_for(self, capability: Capability) -> list[EngineMetadata]:
        return [e for e in self._engines if capability in e.capabilities]
