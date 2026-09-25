"""Validator engine adapter.

The validation *logic* lives in :mod:`vantage.scan.validation` and is driven by
the orchestrator between the discovery/audit stages and correlation, because
validation needs the full observation set. This adapter exists so the engine
appears in the registry and the planner's VALIDATION stage; it produces no
observations of its own.
"""

from __future__ import annotations

from typing import ClassVar

from vantage.adapters.http import HttpClient
from vantage.adapters.native.base import NativeAdapter
from vantage.domain import Capability, EngineRunRequest, Observation


class ValidatorAdapter(NativeAdapter):
    engine_id = "vantage-validator"
    engine_name = "Vantage Validation Engine"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.VALIDATION]

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        return []
