"""Third-party inventory model and the license-check gate.

The inventory (``third_party/inventory/third_party_inventory.yaml``) is the
authoritative list of every third-party component Sentinel ships or depends on.
``check_inventory`` applies the license policy and returns violations; the CLI
turns a non-empty result into a non-zero exit so CI blocks the release.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from sentinel.domain.common import ApprovalStatus, LicenseClass
from sentinel.governance.policy import LicensePolicy


class IntegrationType(StrEnum):
    LIBRARY_STATIC = "library_static"
    LIBRARY_DYNAMIC = "library_dynamic"
    CONTAINER_CLI = "container_cli"
    CONTAINER_API = "container_api"
    CONTENT = "content"  # data such as rule/template sets
    BUILD_ONLY = "build_only"  # dev/test/build tooling, not redistributed


class Component(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str
    repository: str = ""
    license: str = Field(description="SPDX id or expression")
    copyright: str = ""
    integration_type: IntegrationType
    source_distribution_required: bool = False
    modification_required: bool = False
    network_service: bool = False
    static_linking: bool = False
    dynamic_linking: bool = False
    containerized: bool = False
    redistribution_allowed: bool = True
    commercial_risk: str = "unknown"  # low | medium | high | unknown
    approval_status: ApprovalStatus = ApprovalStatus.PENDING_REVIEW
    approval_reference: str = ""
    notes: str = ""


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int = 1
    components: list[Component] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> Inventory:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls.model_validate(data)


@dataclass
class Violation:
    component: str
    version: str
    severity: str  # error | warning
    code: str
    message: str


@dataclass
class CheckReport:
    violations: list[Violation] = field(default_factory=list)
    checked: int = 0

    @property
    def errors(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "error"]

    @property
    def warnings(self) -> list[Violation]:
        return [v for v in self.violations if v.severity == "warning"]

    @property
    def ok(self) -> bool:
        return not self.errors


def check_inventory(inventory: Inventory, policy: LicensePolicy) -> CheckReport:
    report = CheckReport(checked=len(inventory.components))
    arms_length = policy.arms_length_integration_types

    for comp in inventory.components:
        decision = policy.classify(comp.license)
        is_arms_length = comp.integration_type.value in arms_length

        if decision.license_class == LicenseClass.UNKNOWN:
            report.violations.append(
                Violation(
                    comp.name,
                    comp.version,
                    "error",
                    "license.unknown",
                    f"License '{comp.license}' is not classified by policy ({decision.reason}); "
                    "add it to the policy table and record a review.",
                )
            )
            continue

        if decision.license_class == LicenseClass.RED:
            if is_arms_length and comp.approval_status == ApprovalStatus.APPROVED:
                report.violations.append(
                    Violation(
                        comp.name,
                        comp.version,
                        "warning",
                        "license.red.arms_length_approved",
                        f"RED license '{comp.license}' shipped as isolated {comp.integration_type} "
                        f"under recorded approval {comp.approval_reference or '(missing ref)'}.",
                    )
                )
                if not comp.approval_reference:
                    report.violations.append(
                        Violation(
                            comp.name,
                            comp.version,
                            "error",
                            "license.approval.no_reference",
                            "Approved component is missing approval_reference.",
                        )
                    )
            else:
                report.violations.append(
                    Violation(
                        comp.name,
                        comp.version,
                        "error",
                        "license.red.blocked",
                        f"RED license '{comp.license}' cannot ship as {comp.integration_type} "
                        f"(approval={comp.approval_status}). Isolate as an unmodified container "
                        "engine and record legal approval, or replace the component.",
                    )
                )
            continue

        if decision.license_class == LicenseClass.YELLOW:
            if comp.approval_status != ApprovalStatus.APPROVED:
                report.violations.append(
                    Violation(
                        comp.name,
                        comp.version,
                        "error",
                        "license.yellow.needs_review",
                        f"YELLOW license '{comp.license}' requires recorded approval before "
                        f"distribution (current: {comp.approval_status}).",
                    )
                )
            continue

        # GREEN
        if comp.approval_status == ApprovalStatus.REJECTED:
            report.violations.append(
                Violation(
                    comp.name,
                    comp.version,
                    "error",
                    "component.rejected",
                    "Component is marked rejected but still present in the inventory.",
                )
            )

    return report
