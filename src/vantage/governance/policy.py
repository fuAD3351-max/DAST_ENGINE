"""License policy engine.

Loads ``third_party/policy/license-policy.yaml`` and classifies SPDX license
identifiers. This is deliberately mechanical: it never concludes that a license
is legally acceptable, only which policy bucket (allow / review / block) applies
so that the build gate and inventory tooling behave consistently.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import yaml

from vantage.domain.common import LicenseClass


@dataclass(frozen=True)
class PolicyDecision:
    license_id: str
    license_class: LicenseClass
    action: str  # allow | review | block
    reason: str


class LicensePolicy:
    def __init__(
        self,
        class_to_spdx: dict[LicenseClass, frozenset[str]],
        unknown_action: str,
        arms_length_integration_types: frozenset[str],
    ) -> None:
        self._class_to_spdx = class_to_spdx
        self._unknown_action = unknown_action
        self.arms_length_integration_types = arms_length_integration_types
        self._spdx_to_class: dict[str, LicenseClass] = {}
        for cls, ids in class_to_spdx.items():
            for spdx in ids:
                self._spdx_to_class[spdx.lower()] = cls

    @classmethod
    def load(cls, path: str | Path) -> LicensePolicy:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        classes: dict[LicenseClass, frozenset[str]] = {}
        for name, body in data.get("classes", {}).items():
            classes[LicenseClass(name)] = frozenset(body.get("spdx", []))
        return cls(
            class_to_spdx=classes,
            unknown_action=data.get("unknown_action", "block"),
            arms_length_integration_types=frozenset(data.get("arms_length_integration_types", [])),
        )

    _ACTION_BY_CLASS: ClassVar[dict[LicenseClass, str]] = {
        LicenseClass.GREEN: "allow",
        LicenseClass.YELLOW: "review",
        LicenseClass.RED: "block",
    }

    def classify(self, license_id: str) -> PolicyDecision:
        """Classify a single SPDX id.

        Compound expressions are handled conservatively: for ``A OR B`` the most
        permissive operand wins (the distributor may pick it); for ``A AND B``
        the most restrictive operand wins (both obligations apply).
        """
        raw = (license_id or "").strip()
        if not raw:
            return PolicyDecision(license_id, LicenseClass.UNKNOWN, self._unknown_action, "empty")

        upper = raw.upper()
        if " OR " in upper:
            parts = [self.classify(p) for p in _split(raw, " OR ")]
            best = min(parts, key=lambda d: _severity(d.license_class))
            return PolicyDecision(
                raw, best.license_class, best.action, f"OR -> most permissive: {best.license_id}"
            )
        if " AND " in upper:
            parts = [self.classify(p) for p in _split(raw, " AND ")]
            worst = max(parts, key=lambda d: _severity(d.license_class))
            return PolicyDecision(
                raw,
                worst.license_class,
                worst.action,
                f"AND -> most restrictive: {worst.license_id}",
            )

        cls = self._spdx_to_class.get(raw.lower())
        if cls is None:
            return PolicyDecision(
                raw, LicenseClass.UNKNOWN, self._unknown_action, "not in policy table"
            )
        return PolicyDecision(raw, cls, self._ACTION_BY_CLASS[cls], "policy table")


def _split(expr: str, sep: str) -> list[str]:
    # Case-insensitive split on the separator, tolerating surrounding parens.
    import re

    parts = re.split(re.escape(sep), expr, flags=re.IGNORECASE)
    return [p.strip().strip("()").strip() for p in parts if p.strip()]


_SEVERITY = {
    LicenseClass.GREEN: 0,
    LicenseClass.YELLOW: 1,
    LicenseClass.UNKNOWN: 2,
    LicenseClass.RED: 3,
}


def _severity(cls: LicenseClass) -> int:
    return _SEVERITY[cls]
