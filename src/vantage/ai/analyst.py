"""SecurityAnalyst — the AI layer that sits ABOVE the deterministic engines.

Hard contract (enforced in code, not just prompt):

* AI **annotates** existing findings; it never creates findings or evidence.
* Every AI statement references a finding by its id. Any id the model returns
  that is not in the input set is **dropped** (anti-hallucination).
* AI output is advisory metadata (:class:`AiAnnotation`) attached alongside the
  deterministic finding — it never overwrites severity, confidence, evidence or
  the deterministic risk score.
* If the provider is unavailable or returns unparseable output, the analyst is a
  no-op and the deterministic results stand unchanged.

The analyst can: prioritize (advisory ordering), explain (plain-language
summary + remediation), group related findings, and flag likely false positives
for human review. All fully on-prem via a local :class:`LLMProvider`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field

from vantage.ai.provider import LLMProvider, NullProvider
from vantage.domain import UnifiedFinding

logger = logging.getLogger("vantage.ai")

_SYSTEM = (
    "You are a defensive application-security analyst assisting a DAST platform. "
    "You are given already-detected, evidence-backed findings. Your job is to "
    "explain, prioritize and group them for a human reviewer. "
    "STRICT RULES: Only reference findings by the exact 'id' values provided. "
    "Never invent findings, evidence, endpoints, CVEs or CWEs. Never claim a "
    "vulnerability that is not in the input. If unsure, say so. Respond with "
    "JSON only, no prose."
)


@dataclass
class AiAnnotation:
    finding_id: str
    priority_rank: int | None = None  # 1 = act first (advisory)
    likely_false_positive: bool = False
    explanation: str = ""
    remediation: str = ""
    group_id: str | None = None
    rationale: str = ""


@dataclass
class AiAssessment:
    provider: str
    model: str
    model_license: str
    annotations: dict[str, AiAnnotation] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    enabled: bool = True
    notes: list[str] = field(default_factory=list)

    @classmethod
    def disabled(cls) -> AiAssessment:
        return cls(provider="null", model="none", model_license="n/a", enabled=False)


class SecurityAnalyst:
    def __init__(self, provider: LLMProvider | None = None) -> None:
        self._provider = provider or NullProvider()

    @property
    def provider(self) -> LLMProvider:
        return self._provider

    async def assess(self, findings: list[UnifiedFinding]) -> AiAssessment:
        if not findings or not await self._provider.available():
            return AiAssessment.disabled()

        valid_ids = {f.id for f in findings}
        prompt = _build_prompt(findings)
        try:
            resp = await self._provider.complete(prompt, system=_SYSTEM, max_tokens=2048)
        except Exception:
            logger.exception("AI provider failed; continuing without AI assessment")
            return AiAssessment.disabled()

        data = resp.json()
        assessment = AiAssessment(
            provider=self._provider.name,
            model=self._provider.model_id,
            model_license=self._provider.model_license,
        )
        if not isinstance(data, dict):
            assessment.notes.append("AI output was not valid JSON; ignored.")
            assessment.enabled = False
            return assessment

        dropped = 0
        for item in data.get("findings", []) if isinstance(data.get("findings"), list) else []:
            if not isinstance(item, dict):
                continue
            fid = str(item.get("id", ""))
            if fid not in valid_ids:  # anti-hallucination: drop unknown ids
                dropped += 1
                continue
            assessment.annotations[fid] = AiAnnotation(
                finding_id=fid,
                priority_rank=_int_or_none(item.get("priority_rank")),
                likely_false_positive=bool(item.get("likely_false_positive", False)),
                explanation=str(item.get("explanation", ""))[:2000],
                remediation=str(item.get("remediation", ""))[:2000],
                group_id=str(item["group_id"]) if item.get("group_id") else None,
                rationale=str(item.get("rationale", ""))[:1000],
            )
        # Build groups from validated annotations only.
        for fid, ann in assessment.annotations.items():
            if ann.group_id:
                assessment.groups.setdefault(ann.group_id, []).append(fid)
        if dropped:
            assessment.notes.append(f"Dropped {dropped} AI reference(s) to unknown finding ids.")
        return assessment

    def prioritized_order(
        self, findings: list[UnifiedFinding], assessment: AiAssessment
    ) -> list[UnifiedFinding]:
        """Advisory ordering: AI priority first, deterministic risk as tiebreak.

        Deterministic risk_score is never modified; this only reorders for
        presentation, and findings without an AI rank keep risk ordering.
        """
        if not assessment.enabled:
            return sorted(findings, key=lambda f: f.risk_score, reverse=True)

        def key(f: UnifiedFinding) -> tuple[int, float]:
            ann = assessment.annotations.get(f.id)
            rank = ann.priority_rank if ann and ann.priority_rank else 10_000
            return (rank, -f.risk_score)

        return sorted(findings, key=key)


def _build_prompt(findings: list[UnifiedFinding]) -> str:
    compact = [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "risk_score": f.risk_score,
            "endpoint": f"{f.method or 'ANY'} {f.host}:{f.port}{f.endpoint}",
            "engines": f.engines,
            "cwe": f.cwe,
        }
        for f in findings
    ]
    return (
        "Findings (JSON):\n" + json.dumps(compact, indent=2) + "\n\nReturn JSON of the form:\n"
        '{"findings": [{"id": "<one of the ids above>", "priority_rank": <int, 1=first>, '
        '"likely_false_positive": <bool>, "group_id": "<optional cluster label>", '
        '"explanation": "<short>", "remediation": "<short>", "rationale": "<short>"}]}\n'
        "Only use ids from the input. Do not add findings."
    )


def _int_or_none(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None
