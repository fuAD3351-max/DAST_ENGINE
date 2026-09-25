"""End-to-end integration test: scan the bundled vulnerable app over real HTTP.

This exercises the whole native pipeline (crawl -> discovery feedback -> header/
secret/TLS analysis -> validation -> correlation -> risk -> proof) against a live
localhost server, entirely offline. It is the strongest capability proof in the
suite.
"""

from __future__ import annotations

import importlib.util
import socket
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from vantage.app import VantageApp
from vantage.domain import (
    ApplicationKind,
    AuthorizationMethod,
    AuthorizationRecord,
    Scan,
    ScanPolicy,
    ScanProfile,
    Target,
    utcnow,
)
from vantage.scope.engine import default_scope_rules_for

pytestmark = pytest.mark.asyncio


def _load_handler():
    spec = importlib.util.spec_from_file_location(
        "vuln_app", Path(__file__).parent.parent / "examples" / "vulnerable-app" / "app.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Handler


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def vulnerable_server():
    port = _free_port()
    srv = ThreadingHTTPServer(("127.0.0.1", port), _load_handler())
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/"
    finally:
        srv.shutdown()
        srv.server_close()


def _target(url: str) -> Target:
    t = Target(
        tenant_id="it",
        name="vuln",
        base_urls=[url],
        kind=ApplicationKind.TRADITIONAL_WEB,
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION, verified_at=utcnow(), verified_by="it"
        ),
    )
    return t.model_copy(update={"scope_rules": default_scope_rules_for(t)})


async def test_scan_detects_planted_weaknesses(vulnerable_server: str) -> None:
    app = VantageApp.build(bind_oss=False)
    target = _target(vulnerable_server)
    scan = Scan(
        tenant_id="it",
        target_id=target.id,
        policy=ScanPolicy(profile=ScanProfile.STANDARD),
        created_by="it",
    )
    report = await app.orchestrator.run(scan, target)

    categories = {f.category for f in report.findings}
    # The core planted weaknesses must be detected.
    assert "missing_security_header" in categories
    assert "insecure_cookie" in categories
    assert "cors_misconfiguration" in categories
    # The secret in the crawled JS is found via the discovery->audit feedback loop.
    assert "secret_exposure" in categories

    # Config findings are validated to CONFIRMED.
    header = next(f for f in report.findings if f.category == "missing_security_header")
    assert header.confidence.value == "confirmed"

    # The secret value is redacted in evidence (never leaked in the report).
    secret = next(f for f in report.findings if f.category == "secret_exposure")
    assert secret.severity.value == "high"
    assert all("*" in m for e in secret.evidence for m in e.matched)

    # Every finding carries a Proof-of-Vulnerability bundle with an integrity hash.
    assert report.proofs is not None
    assert len(report.proofs.proofs) == len(report.findings)
    assert all(p.integrity_sha256 for p in report.proofs.proofs)
    assert report.proofs.confirmed  # at least one confirmed/corroborated


async def test_scan_stays_in_scope(vulnerable_server: str) -> None:
    # A finding must never reference a host outside the target.
    app = VantageApp.build(bind_oss=False)
    target = _target(vulnerable_server)
    scan = Scan(tenant_id="it", target_id=target.id, created_by="it")
    report = await app.orchestrator.run(scan, target)
    assert all(f.host == "127.0.0.1" for f in report.findings)
