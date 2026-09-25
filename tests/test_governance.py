"""License policy and inventory governance tests."""

from __future__ import annotations

from sentinel.domain.common import ApprovalStatus, LicenseClass
from sentinel.governance.inventory import Component, IntegrationType, Inventory, check_inventory
from sentinel.governance.policy import LicensePolicy

POLICY = "third_party/policy/license-policy.yaml"


def policy() -> LicensePolicy:
    return LicensePolicy.load(POLICY)


def test_permissive_licenses_are_green() -> None:
    p = policy()
    for spdx in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC"):
        assert p.classify(spdx).license_class is LicenseClass.GREEN


def test_copyleft_licenses_are_red() -> None:
    p = policy()
    for spdx in ("GPL-3.0-only", "AGPL-3.0-or-later", "GPL-2.0-only"):
        assert p.classify(spdx).license_class is LicenseClass.RED


def test_weak_copyleft_is_yellow() -> None:
    assert policy().classify("MPL-2.0").license_class is LicenseClass.YELLOW
    assert policy().classify("LGPL-2.1-or-later").license_class is LicenseClass.YELLOW


def test_unknown_license_blocks() -> None:
    d = policy().classify("Weird-Custom-1.0")
    assert d.license_class is LicenseClass.UNKNOWN
    assert d.action == "block"


def test_or_expression_takes_most_permissive() -> None:
    d = policy().classify("GPL-3.0-only OR MIT")
    assert d.license_class is LicenseClass.GREEN


def test_and_expression_takes_most_restrictive() -> None:
    d = policy().classify("MIT AND GPL-3.0-only")
    assert d.license_class is LicenseClass.RED


def test_shipped_inventory_passes() -> None:
    inv = Inventory.load("third_party/inventory/third_party_inventory.yaml")
    report = check_inventory(inv, policy())
    assert report.ok, [v.__dict__ for v in report.errors]


def test_red_component_embedded_is_error() -> None:
    inv = Inventory(
        components=[
            Component(
                name="badlib",
                version="1.0",
                license="GPL-3.0-only",
                integration_type=IntegrationType.LIBRARY_STATIC,
            )
        ]
    )
    report = check_inventory(inv, policy())
    assert not report.ok
    assert any(v.code == "license.red.blocked" for v in report.errors)


def test_red_component_isolated_and_approved_is_warning_not_error() -> None:
    inv = Inventory(
        components=[
            Component(
                name="isolated-engine",
                version="1.0",
                license="GPL-3.0-only",
                integration_type=IntegrationType.CONTAINER_CLI,
                approval_status=ApprovalStatus.APPROVED,
                approval_reference="LEGAL-123",
            )
        ]
    )
    report = check_inventory(inv, policy())
    assert report.ok  # no errors
    assert any(v.code == "license.red.arms_length_approved" for v in report.warnings)


def test_yellow_without_approval_is_error() -> None:
    inv = Inventory(
        components=[
            Component(
                name="weaklib",
                version="1.0",
                license="MPL-2.0",
                integration_type=IntegrationType.LIBRARY_DYNAMIC,
                approval_status=ApprovalStatus.PENDING_REVIEW,
            )
        ]
    )
    report = check_inventory(inv, policy())
    assert not report.ok
    assert any(v.code == "license.yellow.needs_review" for v in report.errors)
