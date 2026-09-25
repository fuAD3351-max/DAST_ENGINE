"""Scope engine tests - the safety-critical gate."""

from __future__ import annotations

from sentinel.domain import (
    AuthorizationMethod,
    AuthorizationRecord,
    ScopeRule,
    ScopeRuleKind,
    Target,
    utcnow,
)
from sentinel.scope.engine import ScopeEngine, default_scope_rules_for


def _target(rules: list[ScopeRule], authorized: bool = True) -> Target:
    return Target(
        tenant_id="t",
        name="x",
        base_urls=["https://app.example.com/"],
        scope_rules=rules,
        authorization=(
            AuthorizationRecord(
                method=AuthorizationMethod.SIGNED_ATTESTATION,
                verified_at=utcnow(),
                verified_by="t",
            )
            if authorized
            else None
        ),
    )


def test_unauthorized_target_denies_everything() -> None:
    t = _target([ScopeRule(host="app.example.com")], authorized=False)
    assert not ScopeEngine(t).allows("https://app.example.com/")


def test_include_and_exclude() -> None:
    rules = [
        ScopeRule(host="app.example.com", path_prefix="/"),
        ScopeRule(kind=ScopeRuleKind.EXCLUDE, host="app.example.com", path_prefix="/admin"),
    ]
    se = ScopeEngine(_target(rules))
    assert se.allows("https://app.example.com/x")
    assert not se.allows("https://app.example.com/admin/panel")


def test_exclude_beats_include_order_independent() -> None:
    rules = [
        ScopeRule(kind=ScopeRuleKind.EXCLUDE, host="app.example.com", path_prefix="/admin"),
        ScopeRule(host="app.example.com", path_prefix="/"),
    ]
    assert not ScopeEngine(_target(rules)).allows("https://app.example.com/admin")


def test_out_of_scope_host_denied() -> None:
    se = ScopeEngine(_target([ScopeRule(host="app.example.com")]))
    assert not se.allows("https://evil.example.com/")


def test_wildcard_subdomain() -> None:
    se = ScopeEngine(_target([ScopeRule(host="*.example.com")]))
    assert se.allows("https://api.example.com/")
    assert not se.allows("https://example.com/")  # apex not matched by *.


def test_private_address_blocked_without_optin() -> None:
    se = ScopeEngine(_target([ScopeRule(host="app.example.com")]))
    assert not se.allows("https://127.0.0.1/")
    assert not se.allows("https://10.0.0.5/")


def test_private_address_allowed_with_explicit_cidr() -> None:
    rules = [ScopeRule(host="10.0.0.0/8", schemes=["https"])]
    se = ScopeEngine(_target(rules))
    assert se.allows("https://10.0.0.5/")


def test_scheme_and_port_enforced() -> None:
    se = ScopeEngine(_target([ScopeRule(host="app.example.com", schemes=["https"])]))
    assert not se.allows("http://app.example.com/")  # scheme not allowed


def test_default_rules_scope_to_directory() -> None:
    t = Target(
        tenant_id="t",
        name="x",
        base_urls=["https://app.example.com/portal/"],
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION,
            verified_at=utcnow(),
            verified_by="t",
        ),
    )
    t = t.model_copy(update={"scope_rules": default_scope_rules_for(t)})
    se = ScopeEngine(t)
    assert se.allows("https://app.example.com/portal/page")
    assert not se.allows("https://app.example.com/other")


def test_from_rules_constructor() -> None:
    se = ScopeEngine.from_rules([ScopeRule(host="app.example.com")], authorized=True)
    assert se.allows("https://app.example.com/")
    se2 = ScopeEngine.from_rules([ScopeRule(host="app.example.com")], authorized=False)
    assert not se2.allows("https://app.example.com/")
