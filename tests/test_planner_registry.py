"""Planner and registry tests."""

from __future__ import annotations

from sentinel.domain import ApplicationKind, Capability, ScanPolicy, ScanProfile
from sentinel.engines.registry import EngineRegistry
from sentinel.governance.policy import LicensePolicy
from sentinel.planner.planner import PlannerConfig, ScanPlanner

POLICY = "third_party/policy/license-policy.yaml"
MANIFESTS = "engines/manifests"
LOCK = "engines/engine-lock.yaml"


def registry() -> EngineRegistry:
    return EngineRegistry.load(MANIFESTS, LOCK, LicensePolicy.load(POLICY))


def test_registry_blocks_gpl_engines() -> None:
    reg = registry()
    for eid in ("trufflehog", "wfuzz", "whatweb", "testssl", "sslyze", "dirsearch", "wapiti"):
        eng = reg.get(eid)
        assert eng is not None
        assert not eng.usable, f"{eid} should be blocked"


def test_registry_native_engines_approved() -> None:
    reg = registry()
    for eid in ("sentinel-headers", "sentinel-tls", "sentinel-crawler"):
        eng = reg.get(eid)
        assert eng is not None
        assert eng.usable


def test_registry_burp_is_external_service_disabled() -> None:
    eng = registry().get("burp")
    assert eng is not None
    assert eng.metadata.integration.value == "external_service"
    assert not eng.manifest.enabled
    assert any("bring-your-own-license" in n for n in eng.notes)


def test_planner_needs_bound_adapter(monkeypatch) -> None:
    # Without adapters bound, engines_for returns nothing -> everything skipped.
    reg = registry()
    plan = ScanPlanner(reg).plan(_target(ApplicationKind.UNKNOWN), ScanPolicy(), ["https://x/"])
    assert all(len(s.tasks) == 0 for s in plan.stages)
    assert plan.skipped


def test_planner_specializes_by_kind() -> None:
    reg = registry()
    _bind_fakes(reg)
    api_plan = ScanPlanner(reg).plan(
        _target(ApplicationKind.REST_API), ScanPolicy(profile=ScanProfile.STANDARD), ["https://x/"]
    )
    caps = {c for s in api_plan.stages for t in s.tasks for c in t.capabilities}
    # A REST API scan should not include browser crawling.
    assert Capability.CRAWL_BROWSER not in caps


def test_planner_passive_profile_has_no_active_audit() -> None:
    reg = registry()
    _bind_fakes(reg)
    plan = ScanPlanner(reg).plan(
        _target(ApplicationKind.TRADITIONAL_WEB),
        ScanPolicy(profile=ScanProfile.PASSIVE),
        ["https://x/"],
    )
    caps = {c for s in plan.stages for t in s.tasks for c in t.capabilities}
    assert Capability.AUDIT_ACTIVE not in caps
    assert Capability.AUDIT_TEMPLATES not in caps


def test_planner_merges_multi_capability_engine_into_one_task() -> None:
    reg = registry()
    _bind_fakes(reg)
    plan = ScanPlanner(reg, PlannerConfig()).plan(
        _target(ApplicationKind.UNKNOWN), ScanPolicy(profile=ScanProfile.STANDARD), ["https://x/"]
    )
    # sentinel-headers covers headers+secrets+passive; it should appear once.
    header_tasks = [t for s in plan.stages for t in s.tasks if t.engine_id == "sentinel-headers"]
    assert len(header_tasks) == 1
    assert len(header_tasks[0].capabilities) >= 2


# --- helpers ---------------------------------------------------------------


def _target(kind: ApplicationKind):
    from sentinel.domain import AuthorizationMethod, AuthorizationRecord, Target, utcnow

    return Target(
        tenant_id="t",
        name="x",
        base_urls=["https://x.example.com/"],
        kind=kind,
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION, verified_at=utcnow(), verified_by="t"
        ),
    )


def _bind_fakes(reg: EngineRegistry) -> None:
    from sentinel.adapters.native.crawler import CrawlerAdapter
    from sentinel.adapters.native.fingerprint import FingerprintAdapter
    from sentinel.adapters.native.headers import HeadersAdapter
    from sentinel.adapters.native.tls import TlsAdapter
    from sentinel.adapters.native.validator import ValidatorAdapter

    for a in (
        HeadersAdapter(),
        FingerprintAdapter(),
        TlsAdapter(),
        CrawlerAdapter(),
        ValidatorAdapter(),
    ):
        if reg.get(a.metadata().id):
            reg.bind_adapter(a.metadata().id, a)
