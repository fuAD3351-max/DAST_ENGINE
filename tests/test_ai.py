"""On-premise AI layer tests.

The critical contract: the AI annotates deterministic findings, drops any
hallucinated finding ids, never creates findings/evidence, and is a no-op when
the provider is unavailable.
"""

from __future__ import annotations

import json

import pytest

from vantage.ai.analyst import SecurityAnalyst
from vantage.ai.provider import FakeProvider, NullProvider
from vantage.domain import Confidence, Severity, UnifiedFinding

pytestmark = pytest.mark.asyncio


def _finding(fid: str, risk: float, sev: Severity = Severity.MEDIUM) -> UnifiedFinding:
    return UnifiedFinding(
        id=fid,
        tenant_id="t",
        scan_id="s",
        target_id="tg",
        fingerprint=fid,
        title=f"Finding {fid}",
        category="xss",
        severity=sev,
        confidence=Confidence.FIRM,
        risk_score=risk,
        host="h.example.com",
        port=443,
        endpoint="/x",
    )


async def test_null_provider_is_noop() -> None:
    findings = [_finding("a", 50.0)]
    assessment = await SecurityAnalyst(NullProvider()).assess(findings)
    assert assessment.enabled is False
    assert assessment.annotations == {}


async def test_empty_findings_short_circuits() -> None:
    assessment = await SecurityAnalyst(FakeProvider(reply="{}")).assess([])
    assert assessment.enabled is False


async def test_annotations_attach_to_known_findings() -> None:
    findings = [_finding("a", 40.0), _finding("b", 60.0)]
    reply = json.dumps(
        {
            "findings": [
                {"id": "a", "priority_rank": 1, "explanation": "reachable", "group_id": "g1"},
                {"id": "b", "priority_rank": 2, "likely_false_positive": True, "group_id": "g1"},
            ]
        }
    )
    assessment = await SecurityAnalyst(FakeProvider(reply=reply)).assess(findings)
    assert assessment.enabled
    assert set(assessment.annotations) == {"a", "b"}
    assert assessment.annotations["a"].priority_rank == 1
    assert assessment.annotations["b"].likely_false_positive is True
    assert assessment.groups == {"g1": ["a", "b"]}


async def test_hallucinated_ids_are_dropped() -> None:
    findings = [_finding("a", 40.0)]
    reply = json.dumps(
        {
            "findings": [
                {"id": "a", "priority_rank": 1},
                {"id": "does-not-exist", "priority_rank": 1, "explanation": "invented"},
            ]
        }
    )
    assessment = await SecurityAnalyst(FakeProvider(reply=reply)).assess(findings)
    assert set(assessment.annotations) == {"a"}  # invented id dropped
    assert any("Dropped" in n for n in assessment.notes)


async def test_ai_cannot_add_findings() -> None:
    findings = [_finding("a", 40.0)]
    # Model tries to return extra findings; analyst only ever annotates inputs.
    reply = json.dumps({"findings": [{"id": "a"}, {"id": "b"}, {"id": "c"}]})
    assessment = await SecurityAnalyst(FakeProvider(reply=reply)).assess(findings)
    assert list(assessment.annotations) == ["a"]


async def test_garbage_output_disables_ai_gracefully() -> None:
    findings = [_finding("a", 40.0)]
    assessment = await SecurityAnalyst(FakeProvider(reply="not json at all")).assess(findings)
    assert assessment.enabled is False


async def test_prioritized_order_uses_ai_then_risk() -> None:
    analyst = SecurityAnalyst(FakeProvider())
    a = _finding("a", 90.0)  # high risk
    b = _finding("b", 10.0)  # low risk but AI says act first
    reply = json.dumps(
        {"findings": [{"id": "b", "priority_rank": 1}, {"id": "a", "priority_rank": 2}]}
    )
    assessment = await SecurityAnalyst(FakeProvider(reply=reply)).assess([a, b])
    ordered = analyst.prioritized_order([a, b], assessment)
    assert [f.id for f in ordered] == ["b", "a"]  # AI rank wins


async def test_prioritized_order_falls_back_to_risk_when_disabled() -> None:
    analyst = SecurityAnalyst(NullProvider())
    a = _finding("a", 90.0)
    b = _finding("b", 10.0)
    assessment = await analyst.assess([a, b])
    ordered = analyst.prioritized_order([a, b], assessment)
    assert [f.id for f in ordered] == ["a", "b"]  # risk order


async def test_deterministic_fields_never_mutated_by_ai() -> None:
    findings = [_finding("a", 40.0, Severity.MEDIUM)]
    reply = json.dumps(
        {"findings": [{"id": "a", "priority_rank": 1, "likely_false_positive": True}]}
    )
    assessment = await SecurityAnalyst(FakeProvider(reply=reply)).assess(findings)
    analyst = SecurityAnalyst(FakeProvider())
    ordered = analyst.prioritized_order(findings, assessment)
    # AI flagged FP, but deterministic severity/confidence/risk are untouched.
    assert ordered[0].severity is Severity.MEDIUM
    assert ordered[0].confidence is Confidence.FIRM
    assert ordered[0].risk_score == 40.0
