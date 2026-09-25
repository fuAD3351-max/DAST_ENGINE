"""Validator engine adapter.

The validation *logic* lives in :mod:`sentinel.scan.validation` and is driven by
the orchestrator between the discovery/audit stages and correlation, because
validation needs the full observation set. This adapter exists so the engine
appears in the registry and the planner's VALIDATION stage; it produces no
observations of its own.
"""

from __future__ import annotations

from typing import ClassVar

from sentinel.adapters.http import HttpClient
from sentinel.adapters.native.base import NativeAdapter
from sentinel.domain import Capability, EngineRunRequest, Observation


class ValidatorAdapter(NativeAdapter):
    engine_id = "sentinel-validator"
    engine_name = "Sentinel Validation Engine"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.VALIDATION]

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        return []
