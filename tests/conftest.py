"""Shared test fixtures."""

from __future__ import annotations

import pytest

from sentinel.domain import (
    AuthorizationMethod,
    AuthorizationRecord,
    Target,
    utcnow,
)
from sentinel.scope.engine import default_scope_rules_for


@pytest.fixture
def authorized_target() -> Target:
    target = Target(
        tenant_id="t1",
        name="demo",
        base_urls=["https://demo.example.com/app/"],
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION,
            verified_at=utcnow(),
            verified_by="test",
        ),
    )
    return target.model_copy(update={"scope_rules": default_scope_rules_for(target)})
