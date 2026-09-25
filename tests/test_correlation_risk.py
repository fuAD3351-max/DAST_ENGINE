"""Correlation, taxonomy and risk-engine tests."""

from __future__ import annotations

from vantage.domain import (
    Confidence,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from vantage.findings import taxonomy
from vantage.findings.correlation import CorrelationEngine, normalize_endpoint
from vantage.findings.risk import RiskEngine


def _obs(engine: str, cwe: list[int], path: str, sev: Severity, marker: str = "m") -> Observation:
    return Observation(
        scan_id="s",
        run_id="r",
        engine_id=engine,
        engine_version="1",
        detector_id=f"{engine}-det",
        title="XSS",
        vuln_class="xss",
        severity=sev,
        cwe=cwe,
        location=Location(scheme="https", host="h.example.com", port=443, path=path, method="GET"),
        evidence=[
            Evidence(
                kind=EvidenceKind.RESPONSE_MATCH, engine_id=engine, summary="x", matched=[marker]
            )
        ],
    )


def test_normalize_endpoint_collapses_ids() -> None:
    assert normalize_endpoint("/users/123/posts/456") == "/users/{id}/posts/{id}"
    assert normalize_endpoint("/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{uuid}"


def test_taxonomy_maps_cwe() -> None:
    assert taxonomy.classify([79]).key == "xss"
    assert taxonomy.classify([89]).key == "sql_injection"
    assert taxonomy.classify([99999], "ssrf").key == "ssrf"
    assert taxonomy.classify([]).key == "other"


def test_correlation_merges_same_issue_from_two_engines() -> None:
    obs = [
        _obs("zap", [79], "/search", Severity.MEDIUM),
        _obs("nuclei", [79], "/search", Severity.HIGH),
    ]
    findings = CorrelationEngine("t", "s", "tg").correlate(obs)
    assert len(findings) == 1
    f = findings[0]
    assert set(f.engines) == {"zap", "nuclei"}
    assert f.severity is Severity.HIGH  # max
    assert f.confidence is Confidence.FIRM  # two engines agree
    assert len(f.observation_ids) == 2


def test_correlation_collapses_per_id_endpoints() -> None:
    obs = [
        _obs("zap", [79], "/item/1", Severity.LOW),
        _obs("zap", [79], "/item/2", Severity.LOW),
    ]
    findings = CorrelationEngine("t", "s", "tg").correlate(obs)
    assert len(findings) == 1
    assert findings[0].endpoint == "/item/{id}"
    assert len(findings[0].affected_urls) == 2


def test_correlation_keeps_distinct_classes_apart() -> None:
    xss = _obs("zap", [79], "/a", Severity.MEDIUM)
    sqli = _obs("zap", [89], "/a", Severity.HIGH)
    sqli = sqli.model_copy(update={"vuln_class": "sql_injection"})
    findings = CorrelationEngine("t", "s", "tg").correlate([xss, sqli])
    assert len(findings) == 2


def test_evidence_deduplicated_across_engines() -> None:
    obs = [
        _obs("zap", [79], "/search", Severity.MEDIUM, marker="same"),
        _obs("nuclei", [79], "/search", Severity.MEDIUM, marker="same"),
    ]
    f = CorrelationEngine("t", "s", "tg").correlate(obs)[0]
    # identical evidence content dedupes to a single item
    assert len(f.evidence) == 1


def test_risk_scoring_orders_by_impact_and_certainty() -> None:
    risk = RiskEngine()
    crit = _obs("e", [89], "/a", Severity.CRITICAL).model_copy(
        update={"vuln_class": "sql_injection", "confidence": Confidence.CONFIRMED}
    )
    low = _obs("e", [693], "/b", Severity.LOW).model_copy(
        update={"vuln_class": "missing_security_header"}
    )
    f_crit = CorrelationEngine("t", "s", "tg").correlate([crit])[0]
    f_low = CorrelationEngine("t", "s", "tg").correlate([low])[0]
    risk.apply(f_crit)
    risk.apply(f_low)
    assert f_crit.risk_score > f_low.risk_score
    assert f_crit.risk_score > 90


def test_false_positive_scores_zero() -> None:
    obs = _obs("e", [79], "/a", Severity.HIGH).model_copy(
        update={"confidence": Confidence.FALSE_POSITIVE}
    )
    f = CorrelationEngine("t", "s", "tg").correlate([obs])[0]
    assert f.confidence is Confidence.FALSE_POSITIVE
    assert RiskEngine().score(f).score == 0.0
