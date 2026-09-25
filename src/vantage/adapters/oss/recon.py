"""Adapters for the ProjectDiscovery recon trio (all MIT), run in a sandbox.

* subfinder - passive subdomain enumeration (attack-surface inventory).
* dnsx      - DNS record resolution/analysis.
* tlsx      - TLS grabber (alternative to the native TLS analyzer).

Each emits JSONL; we normalize into INFO observations (subfinder/dnsx feed the
attack-surface inventory; tlsx yields TLS observations that can escalate on
expired/self-signed certificates). These populate the DEEP profile's
attack-surface stage and are gated by scope.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from vantage.adapters.oss.base import ContainerEngineAdapter
from vantage.domain import (
    Capability,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from vantage.engines.adapter import ExecutionOutcome, PreparedRun, RawResults
from vantage.findings import taxonomy


def _parse_jsonl(text: str) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    rejected = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                records.append(obj)
            else:
                rejected += 1
        except json.JSONDecodeError:
            rejected += 1
    return records, rejected


def _base_host(request: EngineRunRequest) -> str:
    from urllib.parse import urlsplit

    for u in request.seed_urls:
        h = urlsplit(u).hostname
        if h:
            return h.lower()
    return "unknown"


class _JsonlContainerAdapter(ContainerEngineAdapter):
    """Shared collect_results for the JSONL recon tools."""

    output_format = "jsonl"

    async def collect_results(self, outcome: ExecutionOutcome) -> RawResults:
        text = self._guard_output(outcome.sandbox)
        records, rejected = _parse_jsonl(text)
        return RawResults(
            engine_id=self.engine_id,
            engine_version=self._version,
            format=self.output_format,
            records=records,
            rejected_records=rejected,
        )


class SubfinderAdapter(_JsonlContainerAdapter):
    engine_id = "subfinder"
    engine_name = "subfinder"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/subfinder"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.DISCOVERY_SUBDOMAIN]
    image = "ghcr.io/projectdiscovery/subfinder"
    binary = "subfinder"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-oJ", "-silent", "-d", _base_host(request)]
        return PreparedRun(request=request, spec=self._base_spec(args))

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        for rec in raw.records:
            host = str(rec.get("host") or rec.get("input") or "")
            if not host:
                continue
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id="subdomain",
                    title=f"Subdomain discovered: {host}",
                    vuln_class=vc.key,
                    severity=Severity.INFO,
                    location=Location(scheme="https", host=host, port=443, path="/"),
                    description=f"Passive enumeration found subdomain {host}.",
                    remediation="Informational; confirm ownership and scope before testing.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.NOTE,
                            engine_id=self.engine_id,
                            summary=f"subdomain {host}",
                            data={"host": host, "source": rec.get("source")},
                        )
                    ],
                )
            )
        return out


class DnsxAdapter(_JsonlContainerAdapter):
    engine_id = "dnsx"
    engine_name = "dnsx"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/dnsx"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.ANALYSIS_DNS]
    image = "ghcr.io/projectdiscovery/dnsx"
    binary = "dnsx"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-json", "-silent", "-a", "-aaaa", "-cname", "-d", _base_host(request)]
        return PreparedRun(request=request, spec=self._base_spec(args))

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        for rec in raw.records:
            host = str(rec.get("host", ""))
            if not host:
                continue
            records_summary = {k: rec.get(k) for k in ("a", "aaaa", "cname") if rec.get(k)}
            out.append(
                Observation(
                    scan_id=request.scan_id,
                    run_id=request.run_id,
                    engine_id=self.engine_id,
                    engine_version=self._version,
                    detector_id="dns-record",
                    title=f"DNS records for {host}",
                    vuln_class=vc.key,
                    severity=Severity.INFO,
                    location=Location(scheme="https", host=host, port=443, path="/"),
                    description=f"Resolved DNS records for {host}.",
                    remediation="Informational; feeds attack-surface inventory.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.NOTE,
                            engine_id=self.engine_id,
                            summary=f"DNS {host}",
                            data=records_summary,
                        )
                    ],
                )
            )
        return out


class TlsxAdapter(_JsonlContainerAdapter):
    engine_id = "tlsx"
    engine_name = "tlsx"
    vendor = "ProjectDiscovery"
    homepage = "https://github.com/projectdiscovery/tlsx"
    license_spdx = "MIT"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.ANALYSIS_TLS]
    image = "ghcr.io/projectdiscovery/tlsx"
    binary = "tlsx"

    async def prepare_target(self, request: EngineRunRequest) -> PreparedRun:
        args = ["-json", "-silent", "-expired", "-self-signed", "-u", _base_host(request)]
        return PreparedRun(request=request, spec=self._base_spec(args))

    def normalize_results(self, raw: RawResults, request: EngineRunRequest) -> list[Observation]:
        out: list[Observation] = []
        for rec in raw.records:
            host = str(rec.get("host", ""))
            port = int(rec.get("port", 443) or 443)
            loc = Location(scheme="https", host=host or "unknown", port=port, path="/")
            if rec.get("expired"):
                out.append(
                    self._tls_obs(
                        request,
                        loc,
                        "cert-expired",
                        "TLS certificate expired",
                        Severity.HIGH,
                        "The certificate is expired.",
                        rec,
                    )
                )
            if rec.get("self_signed"):
                out.append(
                    self._tls_obs(
                        request,
                        loc,
                        "cert-self-signed",
                        "Self-signed TLS certificate",
                        Severity.MEDIUM,
                        "The certificate is self-signed.",
                        rec,
                    )
                )
            version = str(rec.get("tls_version", "")).upper()
            if version in ("SSL30", "TLS10", "TLS11", "SSLV3", "TLSV1", "TLSV1.1"):
                out.append(
                    self._tls_obs(
                        request,
                        loc,
                        f"weak-protocol:{version}",
                        f"Obsolete TLS protocol: {version}",
                        Severity.MEDIUM,
                        f"Server negotiated {version}.",
                        rec,
                    )
                )
        return out

    def _tls_obs(
        self,
        request: EngineRunRequest,
        loc: Location,
        det: str,
        title: str,
        sev: Severity,
        desc: str,
        rec: dict[str, Any],
    ) -> Observation:
        return Observation(
            scan_id=request.scan_id,
            run_id=request.run_id,
            engine_id=self.engine_id,
            engine_version=self._version,
            detector_id=det,
            title=title,
            vuln_class="tls_weakness",
            severity=sev,
            cwe=[295, 326],
            location=loc,
            description=desc,
            remediation="Use a valid CA-issued certificate and disable obsolete protocols.",
            evidence=[
                Evidence(
                    kind=EvidenceKind.TLS_OBSERVATION,
                    engine_id=self.engine_id,
                    summary=title,
                    data={"tls_version": rec.get("tls_version"), "cipher": rec.get("cipher")},
                )
            ],
        )
