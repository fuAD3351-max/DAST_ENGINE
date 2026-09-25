"""End-to-end orchestration test with a fully faked network.

Exercises: plan -> native engines (via injected fake HTTP client) -> validation
-> correlation -> risk -> persistence -> report, entirely offline.
"""

from __future__ import annotations

import pytest

from sentinel.adapters.http import FakeHttpClient, FetchResult
from sentinel.adapters.native.crawler import CrawlerAdapter
from sentinel.adapters.native.fingerprint import FingerprintAdapter
from sentinel.adapters.native.headers import HeadersAdapter
from sentinel.adapters.native.validator import ValidatorAdapter
from sentinel.domain import (
    AuthorizationMethod,
    AuthorizationRecord,
    Scan,
    ScanPolicy,
    ScanProfile,
    ScanState,
    Target,
    utcnow,
)
from sentinel.engines.registry import EngineRegistry
from sentinel.findings import reporting
from sentinel.governance.policy import LicensePolicy
from sentinel.persistence.repositories import Database
from sentinel.scan.orchestrator import Orchestrator
from sentinel.scan.validation import Prober, ProbeResponse
from sentinel.scope.engine import default_scope_rules_for

pytestmark = pytest.mark.asyncio

URL = "https://demo.example.com/"
RESP = FetchResult(
    url=URL,
    status=200,
    headers={"content-type": "text/html", "server": "nginx/1.25.0", "set-cookie": "sid=1"},
    body="<html><a href='/about'>about</a></html>",
    elapsed_ms=1.0,
)


def _fake_client_factory(_request):
    return FakeHttpClient(responses={URL: RESP, "https://demo.example.com/about": RESP})


class _FakeProber(Prober):
    async def get(self, url, headers=None):
        return ProbeResponse(200, dict(RESP.headers), RESP.body, url)

    async def request(self, method, url, headers=None, body=None):
        return ProbeResponse(200, dict(RESP.headers), RESP.body, url)


def _target() -> Target:
    t = Target(
        tenant_id="t1",
        name="demo",
        base_urls=[URL],
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION, verified_at=utcnow(), verified_by="test"
        ),
    )
    return t.model_copy(update={"scope_rules": default_scope_rules_for(t)})


def _registry() -> EngineRegistry:
    reg = EngineRegistry.load(
        "engines/manifests",
        "engines/engine-lock.yaml",
        LicensePolicy.load("third_party/policy/license-policy.yaml"),
    )
    for a in (
        HeadersAdapter(client_factory=_fake_client_factory),
        FingerprintAdapter(client_factory=_fake_client_factory),
        CrawlerAdapter(client_factory=_fake_client_factory),
        ValidatorAdapter(client_factory=_fake_client_factory),
    ):
        reg.bind_adapter(a.metadata().id, a)
    return reg


async def test_full_scan_produces_validated_correlated_findings() -> None:
    db = Database()
    orch = Orchestrator(
        db, _registry(), prober_factory=lambda _t: _FakeProber(), validate_findings=True
    )
    target = _target()
    with db.unit_of_work() as uow:
        uow.targets.upsert(target)
    scan = Scan(
        tenant_id="t1",
        target_id=target.id,
        policy=ScanPolicy(profile=ScanProfile.STANDARD),
        created_by="test",
    )

    report = await orch.run(scan, target)

    assert report.scan.state is ScanState.COMPLETED
    assert report.observations > 0
    assert report.findings
    # Missing security headers should be found and validated to CONFIRMED.
    header_findings = [f for f in report.findings if f.category == "missing_security_header"]
    assert header_findings
    assert any(f.confidence.value == "confirmed" for f in header_findings)
    # Every finding carries a risk score.
    assert all(f.risk_score >= 0 for f in report.findings)

    # Findings were persisted.
    with db.unit_of_work() as uow:
        stored = uow.findings.for_scan(scan.id)
    assert len(stored) == len(report.findings)

    # Reports render in all formats.
    assert "Sentinel DAST report" in reporting.to_markdown(report)
    assert '"version": "2.1.0"' in reporting.to_sarif(report)
    assert reporting.to_json(report)


async def test_unauthorized_target_fails_closed() -> None:
    db = Database()
    orch = Orchestrator(db, _registry(), prober_factory=lambda _t: _FakeProber())
    target = _target().model_copy(update={"authorization": None})
    scan = Scan(tenant_id="t1", target_id=target.id, created_by="test")
    report = await orch.run(scan, target)
    assert report.scan.state is ScanState.FAILED
    assert not report.findings
