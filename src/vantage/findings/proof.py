"""Proof-of-Vulnerability (PoV) engine — Vantage's authentic-results differentiator.

Open-source scanners emit *alerts*. Vantage emits **proof**: for each finding it
assembles a self-contained, reproducible, tamper-evident evidence bundle so a
customer (or an auditor) can independently confirm the result without trusting
the scanner. This is the commercial value that raw engines do not provide.

A :class:`ProofOfVulnerability` carries:

* the verdict (CONFIRMED only when Vantage's validation engine reproduced it),
* the corroboration set (which independent engines agreed),
* the baseline-vs-observed differential that establishes the behaviour,
* a **reproduction recipe** — safe, high-level steps + a benign replay descriptor
  the customer can run themselves,
* an **integrity digest** (SHA-256 over canonical content), and an optional
  HMAC **signature** when an evidence-signing key is configured, making the
  bundle tamper-evident and auditable.

Nothing here weaponizes a finding: reproduction re-observes the benign marker or
re-checks a configuration condition; it never emits new exploitation payloads.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field

from vantage.domain import Confidence, Evidence, EvidenceKind, UnifiedFinding


class ProofVerdict:
    CONFIRMED = "confirmed"  # Vantage validation reproduced the behaviour
    CORROBORATED = "corroborated"  # multiple independent engines agree, not yet actively confirmed
    REPORTED = "reported"  # single-engine indicator, needs review
    DISPUTED = "disputed"  # validation classified it a false positive


@dataclass
class ReplayStep:
    order: int
    action: str  # human-readable, safe step
    detail: str = ""


@dataclass
class ProofOfVulnerability:
    finding_id: str
    fingerprint: str
    category: str
    verdict: str
    severity: str
    confidence: str
    corroborating_engines: list[str]
    endpoint: str
    baseline: dict[str, object] | None
    observed: dict[str, object] | None
    differential: str
    markers: list[str]
    reproduction: list[ReplayStep]
    references: list[str]
    integrity_sha256: str = ""
    signature_hmac_sha256: str | None = None
    signed: bool = False

    def to_dict(self) -> dict[str, object]:
        d = asdict(self)
        return d


def _verdict_for(finding: UnifiedFinding) -> str:
    if finding.confidence is Confidence.FALSE_POSITIVE:
        return ProofVerdict.DISPUTED
    if finding.confidence is Confidence.CONFIRMED:
        return ProofVerdict.CONFIRMED
    if len(finding.engines) >= 2 or finding.confidence is Confidence.FIRM:
        return ProofVerdict.CORROBORATED
    return ProofVerdict.REPORTED


def _pick(evidence: list[Evidence], kind: EvidenceKind) -> Evidence | None:
    for ev in evidence:
        if ev.kind is kind:
            return ev
    return None


def _msg(ev: Evidence | None, which: str) -> dict[str, object] | None:
    if ev is None:
        return None
    msg = getattr(ev, which, None)
    if msg is None:
        return None
    result: dict[str, object] = msg.model_dump(mode="json")
    return result


def _reproduction(finding: UnifiedFinding, markers: list[str]) -> list[ReplayStep]:
    """Safe, defensive reproduction steps — re-observe, never weaponize."""
    url = f"{finding.host}:{finding.port}{finding.endpoint}"
    method = finding.method or "GET"
    steps = [
        ReplayStep(1, f"Send an authorized {method} request to {url}", "Within the agreed scope."),
    ]
    cat = finding.category
    if cat in (
        "missing_security_header",
        "insecure_cookie",
        "cors_misconfiguration",
        "clickjacking",
    ):
        steps.append(
            ReplayStep(
                2, "Inspect the response headers", "Confirm the reported header/attribute state."
            )
        )
    elif cat == "tls_weakness":
        steps.append(
            ReplayStep(
                2,
                "Inspect the negotiated TLS protocol and certificate",
                "Confirm the reported weakness.",
            )
        )
    elif cat in ("xss", "open_redirect", "header_injection"):
        steps.append(
            ReplayStep(
                2,
                "Confirm the benign marker reflected by the application",
                f"Marker(s): {', '.join(markers) if markers else '(see evidence)'}. "
                "The marker is inert; no active payload is required to observe reflection.",
            )
        )
    else:
        steps.append(ReplayStep(2, "Compare the observed response against the baseline", ""))
    steps.append(
        ReplayStep(
            3,
            "Compare against the recorded baseline",
            "The differential in this proof establishes the behaviour.",
        )
    )
    return steps


def _canonical(proof: ProofOfVulnerability) -> bytes:
    payload = proof.to_dict()
    payload.pop("integrity_sha256", None)
    payload.pop("signature_hmac_sha256", None)
    payload.pop("signed", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


class ProofEngine:
    """Builds proof bundles. An optional signing key makes bundles tamper-evident.

    The key is read from ``VANTAGE_EVIDENCE_KEY`` (or passed explicitly). Without
    a key, bundles still carry an integrity SHA-256 (detects accidental change);
    with a key they also carry an HMAC signature (detects tampering).
    """

    def __init__(self, signing_key: str | None = None) -> None:
        self._key = (
            signing_key if signing_key is not None else os.environ.get("VANTAGE_EVIDENCE_KEY")
        )

    def build(self, finding: UnifiedFinding) -> ProofOfVulnerability:
        markers = sorted({m for ev in finding.evidence for m in ev.matched})
        http = _pick(finding.evidence, EvidenceKind.HTTP_EXCHANGE)
        validation = _pick(finding.evidence, EvidenceKind.VALIDATION_RESULT)
        baseline = _msg(validation, "response") or _msg(http, "request")
        observed = _msg(http, "response") or _msg(
            _pick(finding.evidence, EvidenceKind.RESPONSE_MATCH), "response"
        )

        differential = _describe_differential(finding, validation)
        proof = ProofOfVulnerability(
            finding_id=finding.id,
            fingerprint=finding.fingerprint,
            category=finding.category,
            verdict=_verdict_for(finding),
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            corroborating_engines=list(finding.engines),
            endpoint=f"{finding.method or 'ANY'} {finding.host}:{finding.port}{finding.endpoint}",
            baseline=baseline,
            observed=observed,
            differential=differential,
            markers=markers,
            reproduction=_reproduction(finding, markers),
            references=list(finding.references),
        )
        proof.integrity_sha256 = hashlib.sha256(_canonical(proof)).hexdigest()
        if self._key:
            proof.signature_hmac_sha256 = hmac.new(
                self._key.encode(), _canonical(proof), hashlib.sha256
            ).hexdigest()
            proof.signed = True
        return proof

    def verify(self, proof: ProofOfVulnerability) -> bool:
        """Independently verify a bundle's integrity (and signature if signed)."""
        if hashlib.sha256(_canonical(proof)).hexdigest() != proof.integrity_sha256:
            return False
        if proof.signed:
            if not self._key or proof.signature_hmac_sha256 is None:
                return False
            expected = hmac.new(self._key.encode(), _canonical(proof), hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, proof.signature_hmac_sha256)
        return True


CONFIRMED_VERDICTS = frozenset({ProofVerdict.CONFIRMED, ProofVerdict.CORROBORATED})


@dataclass
class ProofReport:
    proofs: list[ProofOfVulnerability] = field(default_factory=list)
    signed: bool = False

    @property
    def confirmed(self) -> list[ProofOfVulnerability]:
        return [p for p in self.proofs if p.verdict in CONFIRMED_VERDICTS]


def build_proofs(findings: list[UnifiedFinding], signing_key: str | None = None) -> ProofReport:
    engine = ProofEngine(signing_key)
    proofs = [engine.build(f) for f in findings]
    return ProofReport(proofs=proofs, signed=any(p.signed for p in proofs))


def _describe_differential(finding: UnifiedFinding, validation: Evidence | None) -> str:
    if validation is not None and validation.summary:
        return validation.summary
    if finding.confidence is Confidence.CONFIRMED:
        return "Validation reproduced the reported behaviour against a clean baseline."
    if len(finding.engines) >= 2:
        engines = ", ".join(finding.engines)
        return f"Independently reported by {len(finding.engines)} engines: {engines}."
    return "Single-engine indicator; baseline differential recorded in evidence."
