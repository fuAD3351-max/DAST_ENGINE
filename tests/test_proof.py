"""Proof-of-Vulnerability engine tests (the authentic-results differentiator)."""

from __future__ import annotations

from vantage.domain import (
    Confidence,
    Evidence,
    EvidenceKind,
    HttpMessage,
    Severity,
    UnifiedFinding,
)
from vantage.findings.proof import ProofEngine, ProofVerdict, build_proofs


def _finding(
    fid: str,
    confidence: Confidence,
    engines: list[str],
    evidence: list[Evidence] | None = None,
) -> UnifiedFinding:
    return UnifiedFinding(
        id=fid,
        tenant_id="t",
        scan_id="s",
        target_id="tg",
        fingerprint=fid,
        title="XSS",
        category="xss",
        severity=Severity.HIGH,
        confidence=confidence,
        engines=engines,
        host="h.example.com",
        port=443,
        endpoint="/q",
        method="GET",
        evidence=evidence or [],
    )


def test_verdict_confirmed_when_validated() -> None:
    f = _finding("a", Confidence.CONFIRMED, ["zap"])
    proof = ProofEngine().build(f)
    assert proof.verdict == ProofVerdict.CONFIRMED


def test_verdict_corroborated_for_multi_engine() -> None:
    f = _finding("a", Confidence.FIRM, ["zap", "nuclei"])
    assert ProofEngine().build(f).verdict == ProofVerdict.CORROBORATED


def test_verdict_reported_for_single_tentative() -> None:
    f = _finding("a", Confidence.TENTATIVE, ["nuclei"])
    assert ProofEngine().build(f).verdict == ProofVerdict.REPORTED


def test_verdict_disputed_for_false_positive() -> None:
    f = _finding("a", Confidence.FALSE_POSITIVE, ["zap"])
    assert ProofEngine().build(f).verdict == ProofVerdict.DISPUTED


def test_proof_has_integrity_digest_and_verifies() -> None:
    f = _finding("a", Confidence.CONFIRMED, ["zap"])
    engine = ProofEngine()  # no key
    proof = engine.build(f)
    assert proof.integrity_sha256
    assert proof.signed is False
    assert engine.verify(proof) is True


def test_tampering_breaks_integrity() -> None:
    engine = ProofEngine()
    proof = engine.build(_finding("a", Confidence.CONFIRMED, ["zap"]))
    proof.differential = "tampered"
    assert engine.verify(proof) is False


def test_signed_proof_is_tamper_evident() -> None:
    engine = ProofEngine(signing_key="secret-key")
    proof = engine.build(_finding("a", Confidence.CONFIRMED, ["zap"]))
    assert proof.signed is True
    assert proof.signature_hmac_sha256
    assert engine.verify(proof) is True
    proof.severity = "low"  # tamper
    assert engine.verify(proof) is False


def test_signature_requires_the_key() -> None:
    signed = ProofEngine(signing_key="k1").build(_finding("a", Confidence.CONFIRMED, ["zap"]))
    # A verifier without the key (or wrong key) cannot validate a signed bundle.
    assert ProofEngine().verify(signed) is False
    assert ProofEngine(signing_key="wrong").verify(signed) is False


def test_reproduction_included_and_safe() -> None:
    ev = [
        Evidence(
            kind=EvidenceKind.RESPONSE_MATCH,
            engine_id="zap",
            summary="reflected",
            matched=["benign-marker-123"],
        ),
        Evidence(
            kind=EvidenceKind.HTTP_EXCHANGE,
            engine_id="zap",
            summary="exchange",
            response=HttpMessage(status=200, url="https://h.example.com/q"),
        ),
    ]
    proof = ProofEngine().build(_finding("a", Confidence.FIRM, ["zap", "nuclei"], ev))
    assert proof.reproduction  # steps present
    assert proof.markers == ["benign-marker-123"]
    assert proof.observed is not None  # response captured


def test_build_proofs_report_confirmed_filter() -> None:
    findings = [
        _finding("a", Confidence.CONFIRMED, ["zap"]),
        _finding("b", Confidence.TENTATIVE, ["nuclei"]),
        _finding("c", Confidence.FALSE_POSITIVE, ["zap"]),
    ]
    report = build_proofs(findings)
    assert len(report.proofs) == 3
    confirmed_ids = {p.finding_id for p in report.confirmed}
    assert confirmed_ids == {"a"}  # only the validated one
