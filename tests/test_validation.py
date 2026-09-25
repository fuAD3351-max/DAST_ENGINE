"""Validation engine tests."""

from __future__ import annotations

import pytest

from sentinel.domain import (
    Confidence,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from sentinel.scan.validation import Prober, ProbeResponse, ValidationEngine

pytestmark = pytest.mark.asyncio


class DictProber(Prober):
    def __init__(self, resp: ProbeResponse) -> None:
        self._resp = resp

    async def get(self, url, headers=None):
        return self._resp

    async def request(self, method, url, headers=None, body=None):
        return self._resp


def _header_obs() -> Observation:
    return Observation(
        scan_id="s",
        run_id="r",
        engine_id="sentinel-headers",
        engine_version="1",
        detector_id="missing-header:content-security-policy",
        title="Missing CSP",
        vuln_class="missing_security_header",
        severity=Severity.MEDIUM,
        location=Location(scheme="https", host="h.example.com", port=443, path="/", method="GET"),
        evidence=[
            Evidence(
                kind=EvidenceKind.HEADER_OBSERVATION,
                engine_id="sentinel-headers",
                summary="csp absent",
                matched=["content-security-policy"],
            )
        ],
    )


async def test_config_reverify_confirms_when_condition_holds() -> None:
    # Fresh response still missing CSP -> confirmed.
    prober = DictProber(
        ProbeResponse(200, {"content-type": "text/html"}, "", "https://h.example.com/")
    )
    out = await ValidationEngine().validate(_header_obs(), prober)
    assert out.confidence is Confidence.CONFIRMED


async def test_config_reverify_refutes_when_header_now_present() -> None:
    prober = DictProber(
        ProbeResponse(
            200,
            {"content-security-policy": "default-src 'self'", "content-type": "text/html"},
            "",
            "https://h.example.com/",
        )
    )
    out = await ValidationEngine().validate(_header_obs(), prober)
    assert out.confidence is Confidence.FALSE_POSITIVE


async def test_reflection_marker_absent_from_baseline_raises_to_firm() -> None:
    obs = Observation(
        scan_id="s",
        run_id="r",
        engine_id="zap",
        engine_version="1",
        detector_id="xss",
        title="XSS",
        vuln_class="xss",
        severity=Severity.MEDIUM,
        confidence=Confidence.TENTATIVE,
        location=Location(scheme="https", host="h.example.com", port=443, path="/s", method="GET"),
        evidence=[
            Evidence(
                kind=EvidenceKind.RESPONSE_MATCH,
                engine_id="zap",
                summary="reflected",
                matched=["sentinel-unique-marker-xyz"],
            )
        ],
    )
    prober = DictProber(ProbeResponse(200, {}, "clean baseline body", "https://h.example.com/s"))
    out = await ValidationEngine().validate(obs, prober)
    assert out.confidence is Confidence.FIRM


async def test_validation_never_downgrades_confirmed_except_to_fp() -> None:
    obs = _header_obs().model_copy(update={"confidence": Confidence.CONFIRMED})
    # condition still holds -> stays confirmed
    prober = DictProber(ProbeResponse(200, {}, "", "https://h.example.com/"))
    out = await ValidationEngine().validate(obs, prober)
    assert out.confidence is Confidence.CONFIRMED
