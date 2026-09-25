"""Finding correlation and de-duplication engine.

Different engines report the same weakness in different words. Correlation
groups :class:`Observation` objects that describe the same underlying issue into
one :class:`UnifiedFinding`, keeping every observation and its evidence.

The correlation key ("fingerprint") is deliberately coarse enough to merge
genuine duplicates and fine enough not to merge distinct issues. It is built
from: canonical vulnerability class + normalized endpoint template + HTTP method
+ affected parameter. Endpoints are normalized so that ``/users/1`` and
``/users/2`` collapse to ``/users/{id}`` - a common source of duplicate findings.

Severity/confidence of the merged finding follow evidence, not the loudest
engine: severity is the max reported; confidence rises when several independent
engines agree, and is only CONFIRMED once the validation engine says so.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from sentinel.domain import (
    Confidence,
    Evidence,
    Location,
    Observation,
    Severity,
    UnifiedFinding,
    utcnow,
)
from sentinel.findings import taxonomy

# Path segments that look like identifiers, collapsed to a placeholder so that
# per-instance URLs do not create per-instance findings.
_NUMERIC = re.compile(r"^\d+$")
_HEXLIKE = re.compile(r"^[0-9a-fA-F]{8,}$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def normalize_endpoint(path: str) -> str:
    """Collapse identifier-like path segments to ``{id}``."""
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if _UUID.match(seg):
            out.append("{uuid}")
        elif _NUMERIC.match(seg):
            out.append("{id}")
        elif _HEXLIKE.match(seg):
            out.append("{hash}")
        else:
            out.append(seg)
    norm = "/".join(out)
    return norm or "/"


def fingerprint(category: str, loc: Location) -> str:
    endpoint = normalize_endpoint(loc.path)
    parts = [
        category,
        loc.host,
        str(loc.port),
        endpoint,
        loc.method or "*",
        loc.parameter or "*",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def _confidence_from_engines(engines: set[str], any_confirmed: bool) -> Confidence:
    if any_confirmed:
        return Confidence.CONFIRMED
    if len(engines) >= 2:
        return Confidence.FIRM
    return Confidence.TENTATIVE


class CorrelationEngine:
    def __init__(self, tenant_id: str, scan_id: str, target_id: str) -> None:
        self._tenant_id = tenant_id
        self._scan_id = scan_id
        self._target_id = target_id

    def correlate(self, observations: list[Observation]) -> list[UnifiedFinding]:
        groups: dict[str, list[Observation]] = defaultdict(list)
        for obs in observations:
            vc = taxonomy.classify(obs.cwe, obs.vuln_class)
            fp = fingerprint(vc.key, obs.location)
            groups[fp].append(obs)

        findings: list[UnifiedFinding] = []
        for fp, group in groups.items():
            findings.append(self._merge(fp, group))
        findings.sort(key=lambda f: (f.severity.rank, f.confidence.rank), reverse=True)
        return findings

    def _merge(self, fp: str, group: list[Observation]) -> UnifiedFinding:
        primary = max(group, key=lambda o: (o.severity.rank, o.confidence.rank))
        vc = taxonomy.classify(primary.cwe, primary.vuln_class)

        engines = {o.engine_id for o in group}
        detectors = sorted({f"{o.engine_id}:{o.detector_id}" for o in group})
        severity = Severity.max(*(o.severity for o in group))
        any_confirmed = any(o.confidence is Confidence.CONFIRMED for o in group)
        any_fp = all(o.confidence is Confidence.FALSE_POSITIVE for o in group)
        confidence = (
            Confidence.FALSE_POSITIVE
            if any_fp
            else _confidence_from_engines(engines, any_confirmed)
        )

        # De-duplicate evidence across engines by content digest.
        seen: set[str] = set()
        evidence: list[Evidence] = []
        for obs in group:
            for ev in obs.evidence:
                d = ev.digest()
                if d not in seen:
                    seen.add(d)
                    evidence.append(ev)

        cwes = sorted({c for o in group for c in o.cwe} | set(vc.cwes))
        references = sorted({r for o in group for r in o.references})
        affected = sorted(
            {
                f"{o.location.scheme}://{o.location.host}:{o.location.port}{o.location.path}"
                for o in group
            }
        )

        first_seen = min(o.observed_at for o in group)
        last_seen = max(o.observed_at for o in group)

        return UnifiedFinding(
            tenant_id=self._tenant_id,
            scan_id=self._scan_id,
            target_id=self._target_id,
            fingerprint=fp,
            title=primary.title or vc.title,
            category=vc.key,
            severity=severity,
            confidence=confidence,
            cwe=cwes,
            owasp=list(vc.owasp_2021),
            host=primary.location.host,
            port=primary.location.port,
            endpoint=normalize_endpoint(primary.location.path),
            method=primary.location.method,
            parameter=primary.location.parameter,
            affected_urls=affected,
            description=primary.description,
            remediation=primary.remediation,
            references=references,
            engines=sorted(engines),
            detectors=detectors,
            observation_ids=[o.id for o in group],
            evidence=evidence,
            first_seen=first_seen,
            last_seen=last_seen,
        )


def merge_across_scans(
    previous: list[UnifiedFinding], current: list[UnifiedFinding]
) -> list[UnifiedFinding]:
    """Carry ``first_seen`` forward for findings that persist across scans,
    matched by fingerprint. Returns the current findings, updated in place."""
    prev_by_fp = {f.fingerprint: f for f in previous}
    for f in current:
        old = prev_by_fp.get(f.fingerprint)
        if old is not None:
            f.first_seen = old.first_seen
            f.last_seen = utcnow()
    return current
