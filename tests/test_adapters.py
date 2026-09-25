"""Native and OSS adapter tests using fake HTTP/transport/sandbox."""

from __future__ import annotations

import json

import pytest

from sentinel.adapters.external.burp import BurpAdapter, BurpConfig, FakeBurpTransport
from sentinel.adapters.http import FakeHttpClient, FetchResult
from sentinel.adapters.native.fingerprint import FingerprintAdapter
from sentinel.adapters.native.headers import HeadersAdapter
from sentinel.adapters.oss.ffuf import FfufAdapter
from sentinel.adapters.oss.nuclei import NucleiAdapter
from sentinel.domain import Capability, EngineRunRequest, Severity
from sentinel.engines.adapter import SandboxResult
from sentinel.engines.sandbox import FakeSandboxRunner


def _request(engine_id: str, caps: list[Capability], url: str) -> EngineRunRequest:
    return EngineRunRequest(
        scan_id="s",
        tenant_id="t",
        engine_id=engine_id,
        capabilities=caps,
        seed_urls=[url],
        scope_rules=[{"kind": "include", "host": "h.example.com", "schemes": ["https"]}],
    )


async def _run_native(adapter, request, client):
    p = await adapter.prepare_target(request)
    p.state["client"] = client  # inject fake client
    outcome = await adapter.execute_scan(p)
    raw = await adapter.collect_results(outcome)
    return adapter.normalize_results(raw, request)


async def test_headers_adapter_flags_missing_headers() -> None:
    url = "https://h.example.com/"
    client = FakeHttpClient(
        responses={
            url: FetchResult(
                url=url,
                status=200,
                headers={"content-type": "text/html", "set-cookie": "sid=abc"},
                body="<html>ok</html>",
                elapsed_ms=1.0,
            )
        }
    )
    obs = await _run_native(
        HeadersAdapter(),
        _request("sentinel-headers", [Capability.ANALYSIS_HEADERS], url),
        client,
    )
    classes = {o.vuln_class for o in obs}
    assert "missing_security_header" in classes
    assert "insecure_cookie" in classes  # cookie missing Secure/HttpOnly/SameSite


async def test_headers_adapter_detects_secret() -> None:
    url = "https://h.example.com/"
    body = "var key='AKIA" + "A" * 16 + "';"
    client = FakeHttpClient(
        responses={url: FetchResult(url, 200, {"content-type": "text/html"}, body, 1.0)}
    )
    obs = await _run_native(
        HeadersAdapter(), _request("sentinel-headers", [Capability.ANALYSIS_SECRETS], url), client
    )
    secrets = [o for o in obs if o.vuln_class == "secret_exposure"]
    assert secrets
    assert secrets[0].severity is Severity.HIGH
    # value must be redacted in evidence
    assert all("*" in m for e in secrets[0].evidence for m in e.matched)


async def test_fingerprint_adapter_identifies_tech() -> None:
    url = "https://h.example.com/"
    client = FakeHttpClient(
        responses={
            url: FetchResult(
                url, 200, {"server": "nginx/1.25.0", "content-type": "text/html"}, "", 1.0
            )
        }
    )
    obs = await _run_native(
        FingerprintAdapter(),
        _request("sentinel-fingerprint", [Capability.FINGERPRINT_TECH], url),
        client,
    )
    techs = {e.data.get("technology") for o in obs for e in o.evidence}
    assert "nginx" in techs


async def test_nuclei_adapter_parses_jsonl() -> None:
    records = [
        json.dumps(
            {
                "template-id": "xss-reflected",
                "info": {
                    "name": "Reflected XSS",
                    "severity": "high",
                    "classification": {"cwe-id": ["CWE-79"]},
                },
                "matched-at": "https://h.example.com/search",
                "type": "http",
            }
        ),
        "not-json-line",
    ]
    runner = FakeSandboxRunner(lambda spec: _sandbox_stdout("\n".join(records)))
    adapter = NucleiAdapter(runner, "v3.4.10")
    req = _request("nuclei", [Capability.AUDIT_TEMPLATES], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    assert raw.rejected_records == 1  # the bad line
    obs = adapter.normalize_results(raw, req)
    assert len(obs) == 1
    assert obs[0].vuln_class == "xss"
    assert obs[0].severity is Severity.HIGH
    assert 79 in obs[0].cwe


async def test_ffuf_adapter_parses_json_output() -> None:
    doc = {"results": [{"url": "https://h.example.com/admin", "status": 403, "length": 12}]}
    runner = FakeSandboxRunner(lambda spec: _sandbox_files({"ffuf.json": json.dumps(doc).encode()}))
    adapter = FfufAdapter(runner, "v2.1.0")
    req = _request("ffuf", [Capability.DISCOVERY_CONTENT], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    obs = adapter.normalize_results(raw, req)
    assert len(obs) == 1
    assert obs[0].location.path == "/admin"
    assert obs[0].severity is Severity.LOW  # 403 is interesting


async def test_burp_unconfigured_is_unavailable() -> None:
    adapter = BurpAdapter(BurpConfig())  # no base_url
    health = await adapter.health_check()
    assert health.state.value == "unavailable"


async def test_burp_maps_issues_via_fake_transport() -> None:
    issues = [
        {
            "issue": {
                "name": "Cross-site scripting (reflected)",
                "severity": "high",
                "confidence": "certain",
                "origin": "https://h.example.com",
                "path": "/q",
                "description": "<p>desc</p>",
            }
        }
    ]
    transport = FakeBurpTransport(issues=issues)
    adapter = BurpAdapter(BurpConfig(base_url="https://burp.internal"), transport=transport)
    health = await adapter.health_check()
    assert health.state.value == "healthy"
    req = _request("burp", [Capability.AUDIT_ACTIVE], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    obs = adapter.normalize_results(raw, req)
    assert len(obs) == 1
    assert obs[0].vuln_class == "xss"
    assert obs[0].severity is Severity.HIGH
    # Burp "certain" maps to FIRM, never CONFIRMED.
    assert obs[0].confidence.value == "firm"


def _sandbox_stdout(text: str) -> SandboxResult:
    return SandboxResult(0, False, text.encode(), b"", {}, 0.1)


def _sandbox_files(files: dict[str, bytes]) -> SandboxResult:
    return SandboxResult(0, False, b"", b"", files, 0.1)


pytestmark = pytest.mark.asyncio


async def test_local_subprocess_runner_runs_binary() -> None:
    from sentinel.domain import NetworkMode, ResourceLimits
    from sentinel.engines.adapter import ContainerSpec
    from sentinel.engines.sandbox import LocalSubprocessRunner

    runner = LocalSubprocessRunner()
    assert await runner.available()
    spec = ContainerSpec(
        image="",
        args=["sentinel-local-test"],
        network=NetworkMode.NONE,
        limits=ResourceLimits(timeout_seconds=10),
        binary="echo",
    )
    result = await runner.run(spec)
    assert result.exit_code == 0
    assert b"sentinel-local-test" in result.stdout


async def test_local_subprocess_runner_missing_binary() -> None:
    from sentinel.domain import NetworkMode, ResourceLimits
    from sentinel.engines.adapter import ContainerSpec
    from sentinel.engines.sandbox import LocalSubprocessRunner

    spec = ContainerSpec(
        image="",
        args=[],
        network=NetworkMode.NONE,
        limits=ResourceLimits(),
        binary="sentinel-nonexistent-binary-xyz",
    )
    result = await LocalSubprocessRunner().run(spec)
    assert result.exit_code == 127
    assert b"not found" in result.stderr


async def test_detect_engines_reports_known_set() -> None:
    from sentinel.engines.detect import detect_engines

    dets = await detect_engines(["nuclei", "ffuf"])
    ids = {d.engine_id for d in dets}
    assert ids == {"nuclei", "ffuf"}
    # In this container the tools are absent; detection must not raise.
    assert all(d.installed in (True, False) for d in dets)


async def test_katana_adapter_parses_endpoints() -> None:
    from sentinel.adapters.oss.katana import KatanaAdapter

    rec = json.dumps({"request": {"endpoint": "https://h.example.com/api/x", "method": "GET"}})
    runner = FakeSandboxRunner(lambda spec: _sandbox_stdout(rec))
    adapter = KatanaAdapter(runner, "v1.2.2")
    req = _request("katana", [Capability.CRAWL_HTTP], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    obs = adapter.normalize_results(raw, req)
    assert len(obs) == 1
    assert obs[0].location.path == "/api/x"


async def test_httpx_adapter_parses_tech() -> None:
    from sentinel.adapters.oss.httpx_engine import HttpxAdapter

    rec = json.dumps({"url": "https://h.example.com/", "tech": ["nginx", "PHP"]})
    runner = FakeSandboxRunner(lambda spec: _sandbox_stdout(rec))
    adapter = HttpxAdapter(runner, "v1.6.9")
    req = _request("httpx", [Capability.FINGERPRINT_TECH], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    obs = adapter.normalize_results(raw, req)
    techs = {e.data.get("technology") for o in obs for e in o.evidence}
    assert techs == {"nginx", "PHP"}


async def test_feroxbuster_adapter_parses_responses() -> None:
    from sentinel.adapters.oss.feroxbuster import FeroxbusterAdapter

    rec = json.dumps({"type": "response", "url": "https://h.example.com/secret", "status": 403})
    runner = FakeSandboxRunner(lambda spec: _sandbox_stdout(rec))
    adapter = FeroxbusterAdapter(runner, "v2.11.0")
    req = _request("feroxbuster", [Capability.DISCOVERY_CONTENT], "https://h.example.com/")
    prepared = await adapter.prepare_target(req)
    outcome = await adapter.execute_scan(prepared)
    raw = await adapter.collect_results(outcome)
    obs = adapter.normalize_results(raw, req)
    assert len(obs) == 1
    assert obs[0].location.path == "/secret"
    assert obs[0].severity is Severity.LOW
