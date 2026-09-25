"""Report generation from unified findings.

Produces three formats from the same finding set:

* ``json``     - the full structured result (machine-readable, lossless);
* ``sarif``    - SARIF 2.1.0 for CI / code-scanning ingestion;
* ``markdown`` - a human-readable summary for reviews and tickets.

Reports present *unified* findings only - the customer sees one issue per
weakness with the contributing engines listed, never one row per engine.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from vantage.domain import Severity, UnifiedFinding
from vantage.scan.orchestrator import ScanReport

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def summarize(findings: list[UnifiedFinding]) -> dict[str, int]:
    counts = Counter(f.severity.value for f in findings)
    return {sev.value: counts.get(sev.value, 0) for sev in Severity}


def to_json(report: ScanReport) -> str:
    payload: dict[str, Any] = {
        "scan": report.scan.model_dump(mode="json"),
        "summary": {
            "findings": len(report.findings),
            "by_severity": summarize(report.findings),
            "observations": report.observations,
            "engines_run": report.engines_run,
            "engines_failed": report.engines_failed,
            "skipped_capabilities": report.skipped_capabilities,
        },
        "findings": [f.model_dump(mode="json") for f in report.findings],
    }
    return json.dumps(payload, indent=2, default=str)


def to_sarif(report: ScanReport, tool_version: str = "0.1.0") -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in report.findings:
        rule_id = f.category
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.category},
                "properties": {
                    "cwe": [f"CWE-{c}" for c in f.cwe],
                    "owasp": f.owasp,
                },
            }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title} ({', '.join(f.engines)})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"{f.host}:{f.port}{f.endpoint}"}
                        }
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "risk_score": f.risk_score,
                    "engines": f.engines,
                    "fingerprint": f.fingerprint,
                },
                "partialFingerprints": {"vantage/v1": f.fingerprint},
            }
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Vantage DAST",
                        "version": tool_version,
                        "informationUri": "https://vantage.example/dast",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def to_markdown(report: ScanReport) -> str:
    counts = summarize(report.findings)
    lines: list[str] = []
    lines.append(f"# Vantage DAST report - scan `{report.scan.id}`")
    lines.append("")
    lines.append(f"- Target: `{report.scan.target_id}`")
    lines.append(f"- State: **{report.scan.state.value}**")
    lines.append(
        f"- Findings: **{len(report.findings)}** across {report.observations} observations"
    )
    lines.append(
        "- Severity: " + ", ".join(f"{sev.upper()}={counts[sev]}" for sev in reversed(list(counts)))
    )
    lines.append(f"- Engines run: {', '.join(report.engines_run) or '(none)'}")
    if report.engines_failed:
        lines.append(f"- Engines failed: {', '.join(report.engines_failed)}")
    if report.skipped_capabilities:
        lines.append(f"- Skipped capabilities: {len(report.skipped_capabilities)}")
    lines.append("")

    if not report.findings:
        lines.append("_No findings._")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")
    lines.append("| Risk | Severity | Confidence | Category | Endpoint | Engines |")
    lines.append("|------|----------|------------|----------|----------|---------|")
    for f in report.findings:
        engines = ", ".join(f.engines)
        endpoint = f"{f.method or 'ANY'} {f.endpoint}"
        lines.append(
            f"| {f.risk_score:.0f} | {f.severity.value} | {f.confidence.value} | "
            f"{f.category} | `{endpoint}` | {engines} |"
        )
    lines.append("")

    # Detail the top findings.
    lines.append("## Details (top 20 by risk)")
    for f in report.findings[:20]:
        lines.append("")
        lines.append(f"### [{f.severity.value.upper()}] {f.title}")
        lines.append(f"- **Risk:** {f.risk_score:.0f}  **Confidence:** {f.confidence.value}")
        lines.append(f"- **Location:** `{f.host}:{f.port}{f.endpoint}`")
        if f.parameter:
            lines.append(f"- **Parameter:** `{f.parameter}`")
        if f.cwe:
            lines.append(f"- **CWE:** {', '.join(f'CWE-{c}' for c in f.cwe)}")
        if f.owasp:
            lines.append(f"- **OWASP:** {', '.join(f.owasp)}")
        lines.append(f"- **Detected by:** {', '.join(f.detectors)}")
        if f.description:
            lines.append(f"- **Description:** {f.description}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
    return "\n".join(lines)


def render(report: ScanReport, fmt: str) -> str:
    fmt = fmt.lower()
    if fmt == "json":
        return to_json(report)
    if fmt == "sarif":
        return to_sarif(report)
    if fmt in ("md", "markdown"):
        return to_markdown(report)
    raise ValueError(f"unknown report format: {fmt}")
