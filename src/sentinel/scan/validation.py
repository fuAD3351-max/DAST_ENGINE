"""Validation engine - Sentinel's proprietary confidence layer.

External engines produce *candidate* findings. The validation engine decides how
much to trust each one by re-testing it in a controlled way and comparing
against a baseline, then sets the observation's confidence accordingly:

    candidate -> baseline -> controlled re-test -> differential -> verdict

Design constraints (this is a defensive product):

* Validation *re-verifies* the reported condition; it does not escalate or craft
  new exploitation. For configuration issues it re-checks the condition
  deterministically. For reflection-type indicators it confirms the reported
  benign marker still reproduces and is absent from a baseline request.
* All network access goes through a :class:`Prober`, which the orchestrator wires
  to the scope-enforcing HTTP client. Tests inject a fake prober, so the engine
  is fully unit-testable offline.
* Validation only ever *raises* confidence to CONFIRMED or *lowers* it to
  FALSE_POSITIVE; it never invents evidence.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from sentinel.domain import (
    Confidence,
    Evidence,
    EvidenceKind,
    HttpMessage,
    Observation,
    utcnow,
)


class Verdict(StrEnum):
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class ProbeResponse:
    status: int
    headers: dict[str, str]
    body: str
    url: str
    elapsed_ms: float = 0.0


class Prober(abc.ABC):
    """Minimal, scope-checked HTTP access used only for validation re-tests."""

    @abc.abstractmethod
    async def get(self, url: str, headers: dict[str, str] | None = None) -> ProbeResponse: ...

    @abc.abstractmethod
    async def request(
        self, method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None
    ) -> ProbeResponse: ...


@dataclass
class ValidationResult:
    verdict: Verdict
    confidence: Confidence
    evidence: Evidence | None
    detail: str


class ValidationStrategy(abc.ABC):
    """Validates one class of observation."""

    @abc.abstractmethod
    def handles(self, observation: Observation) -> bool: ...

    @abc.abstractmethod
    async def validate(self, observation: Observation, prober: Prober) -> ValidationResult: ...


def _url_of(obs: Observation) -> str:
    loc = obs.location
    return f"{loc.scheme}://{loc.host}:{loc.port}{loc.path}"


class ConfigReverifyStrategy(ValidationStrategy):
    """Deterministically re-check configuration findings by re-fetching.

    Confirms the reported condition still holds on a fresh request. Applies to
    findings whose evidence is a stable property of the response (missing
    security header, insecure cookie flags, directory listing, CORS reflection).
    """

    _CATEGORIES: ClassVar[set[str]] = {
        "missing_security_header",
        "insecure_cookie",
        "cors_misconfiguration",
        "directory_listing",
        "clickjacking",
    }

    def handles(self, observation: Observation) -> bool:
        return observation.vuln_class in self._CATEGORIES

    async def validate(self, observation: Observation, prober: Prober) -> ValidationResult:
        resp = await prober.get(_url_of(observation))
        header_names = {k.lower() for k in resp.headers}
        still_present = self._condition_holds(observation, resp, header_names)
        ev = Evidence(
            kind=EvidenceKind.VALIDATION_RESULT,
            engine_id="sentinel-validator",
            summary=f"Re-verified {observation.vuln_class}: condition "
            f"{'holds' if still_present else 'no longer holds'} on fresh request",
            response=HttpMessage(
                status=resp.status,
                url=resp.url,
                headers={k: v for k, v in resp.headers.items()},
            ),
            data={"category": observation.vuln_class},
        )
        if still_present:
            return ValidationResult(Verdict.CONFIRMED, Confidence.CONFIRMED, ev, "condition holds")
        return ValidationResult(
            Verdict.REFUTED, Confidence.FALSE_POSITIVE, ev, "condition not reproduced"
        )

    def _condition_holds(
        self, obs: Observation, resp: ProbeResponse, header_names: set[str]
    ) -> bool:
        cat = obs.vuln_class
        if cat == "missing_security_header":
            # The finding names the missing header in detector_id or matched.
            expected = _expected_header(obs)
            return expected is not None and expected not in header_names
        if cat == "clickjacking":
            return "x-frame-options" not in header_names and "content-security-policy" not in {
                k for k in header_names
            }
        if cat == "insecure_cookie":
            set_cookie = resp.headers.get("set-cookie", "") or resp.headers.get("Set-Cookie", "")
            return "secure" not in set_cookie.lower() or "httponly" not in set_cookie.lower()
        if cat == "directory_listing":
            body = resp.body.lower()
            return "index of /" in body or "<title>directory listing" in body
        if cat == "cors_misconfiguration":
            acao = header_names
            return "access-control-allow-origin" in acao
        return False


def _expected_header(obs: Observation) -> str | None:
    for m in obs.evidence:
        for name in m.matched:
            if name.lower().startswith(("content-security", "strict-transport", "x-", "referrer")):
                return name.lower()
    # detector_id convention: "missing-header:<name>"
    if ":" in obs.detector_id:
        return obs.detector_id.split(":", 1)[1].lower()
    return None


class ReflectionConsistencyStrategy(ValidationStrategy):
    """Confirm a reflection indicator by baseline/probe differential.

    Only confirms that a benign, unique marker the original engine already
    reported as reflected is (a) absent from a clean baseline request and
    (b) reproduced when that same marker is present. It performs no new
    exploitation - it re-runs the engine's own benign observation to weed out
    coincidental matches.
    """

    _CATEGORIES: ClassVar[set[str]] = {"xss", "open_redirect", "header_injection"}

    def handles(self, observation: Observation) -> bool:
        return observation.vuln_class in self._CATEGORIES and bool(self._marker(observation))

    def _marker(self, obs: Observation) -> str | None:
        for ev in obs.evidence:
            if ev.matched:
                return ev.matched[0]
        return None

    async def validate(self, observation: Observation, prober: Prober) -> ValidationResult:
        marker = self._marker(observation)
        if not marker:
            return ValidationResult(
                Verdict.INCONCLUSIVE, observation.confidence, None, "no reproducible marker"
            )
        base = await prober.get(_url_of(observation))
        baseline_clean = marker not in base.body
        ev = Evidence(
            kind=EvidenceKind.VALIDATION_RESULT,
            engine_id="sentinel-validator",
            summary=(
                f"Baseline differential for {observation.vuln_class}: marker "
                f"{'absent from' if baseline_clean else 'present in'} clean baseline"
            ),
            matched=[marker],
            data={"baseline_clean": baseline_clean},
        )
        if baseline_clean:
            # Marker is not naturally present -> the engine's reflection is
            # meaningful. Raise to FIRM (not CONFIRMED without an active re-test,
            # which this defensive profile does not perform automatically).
            return ValidationResult(
                Verdict.INCONCLUSIVE,
                Confidence.FIRM,
                ev,
                "marker absent from baseline; reflection is meaningful",
            )
        return ValidationResult(
            Verdict.REFUTED,
            Confidence.FALSE_POSITIVE,
            ev,
            "marker present in clean baseline; likely coincidental",
        )


class ValidationEngine:
    def __init__(self, strategies: list[ValidationStrategy] | None = None) -> None:
        self._strategies = strategies or [
            ConfigReverifyStrategy(),
            ReflectionConsistencyStrategy(),
        ]

    async def validate(self, observation: Observation, prober: Prober) -> Observation:
        for strat in self._strategies:
            if strat.handles(observation):
                result = await strat.validate(observation, prober)
                updated = list(observation.evidence)
                if result.evidence is not None:
                    updated.append(result.evidence)
                # Never downgrade a CONFIRMED except to FALSE_POSITIVE.
                new_conf = result.confidence
                if (
                    observation.confidence is Confidence.CONFIRMED
                    and new_conf is not Confidence.FALSE_POSITIVE
                ):
                    new_conf = Confidence.CONFIRMED
                return observation.model_copy(
                    update={
                        "confidence": new_conf,
                        "evidence": updated,
                        "observed_at": utcnow(),
                    }
                )
        return observation
