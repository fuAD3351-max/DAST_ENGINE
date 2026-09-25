"""Risk engine: turns a unified finding into a 0-100 risk score.

The score blends impact (severity), certainty (confidence and corroboration)
and exposure (a small set of context signals). It is deterministic and
explainable - every score comes with the factors that produced it - so the
enterprise UI can show *why* one finding outranks another. This is intentionally
not a CVSS re-implementation; it is a prioritization signal layered on top of
CWE/severity, and CVSS vectors can be attached later without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vantage.domain import Confidence, Severity, UnifiedFinding

_SEVERITY_BASE = {
    Severity.INFO: 5.0,
    Severity.LOW: 25.0,
    Severity.MEDIUM: 50.0,
    Severity.HIGH: 75.0,
    Severity.CRITICAL: 95.0,
}

_CONFIDENCE_FACTOR = {
    Confidence.FALSE_POSITIVE: 0.0,
    Confidence.TENTATIVE: 0.6,
    Confidence.FIRM: 0.85,
    Confidence.CONFIRMED: 1.0,
}

# Categories whose exploitation is typically unauthenticated and high-impact get
# a small exposure bump; purely informational categories get a small discount.
_EXPOSURE_BUMP = {
    "sql_injection": 1.10,
    "command_injection": 1.10,
    "code_injection": 1.10,
    "insecure_deserialization": 1.10,
    "ssrf": 1.08,
    "xxe": 1.06,
    "broken_object_authz": 1.06,
    "broken_access_control": 1.06,
    "secret_exposure": 1.05,
    "xss": 1.03,
}
_EXPOSURE_DISCOUNT = {
    "missing_security_header": 0.9,
    "information_disclosure": 0.92,
    "directory_listing": 0.92,
    "clickjacking": 0.9,
}


@dataclass
class RiskBreakdown:
    score: float
    factors: dict[str, float] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class RiskEngine:
    def score(self, finding: UnifiedFinding) -> RiskBreakdown:
        base = _SEVERITY_BASE[finding.severity]
        conf = _CONFIDENCE_FACTOR[finding.confidence]

        corroboration = 1.0
        n_engines = len(finding.engines)
        if n_engines >= 3:
            corroboration = 1.08
        elif n_engines == 2:
            corroboration = 1.04

        exposure = _EXPOSURE_BUMP.get(finding.category, 1.0)
        exposure *= _EXPOSURE_DISCOUNT.get(finding.category, 1.0)

        raw = base * conf * corroboration * exposure
        score = max(0.0, min(100.0, round(raw, 1)))

        notes: list[str] = []
        if finding.confidence is Confidence.CONFIRMED:
            notes.append("validated by Vantage validation engine")
        if n_engines >= 2:
            notes.append(f"corroborated by {n_engines} engines")
        if finding.confidence is Confidence.FALSE_POSITIVE:
            notes.append("classified false positive; scored 0")

        return RiskBreakdown(
            score=score,
            factors={
                "severity_base": base,
                "confidence_factor": conf,
                "corroboration": corroboration,
                "exposure": round(exposure, 3),
            },
            notes=notes,
        )

    def apply(self, finding: UnifiedFinding) -> UnifiedFinding:
        finding.risk_score = self.score(finding).score
        return finding
