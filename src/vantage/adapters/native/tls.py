"""Native TLS / certificate analyzer.

Uses only the Python standard library (``ssl``/``socket``) plus a pluggable
:class:`TlsInspector`, so no AGPL/GPL TLS tool is embedded. It inspects the
negotiated protocol version and the leaf certificate and reports weak transport
configuration (obsolete protocol, expired/near-expiry certificate, self-signed
leaf). TLS inspection is a separate connection from HTTP, so it is guarded by
scope on the host:port and skipped for non-TLS schemes.
"""

from __future__ import annotations

import abc
import socket
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar
from urllib.parse import urlsplit

from vantage.adapters.http import HttpClient
from vantage.adapters.native.base import ClientFactory, NativeAdapter
from vantage.domain import (
    Capability,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    Location,
    Observation,
    Severity,
)
from vantage.findings import taxonomy

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TlsInfo:
    host: str
    port: int
    protocol: str | None
    cipher: str | None
    not_after: datetime | None
    issuer_cn: str | None
    subject_cn: str | None
    self_signed: bool
    error: str | None = None
    raw: dict[str, object] = field(default_factory=dict)


class TlsInspector(abc.ABC):
    @abc.abstractmethod
    async def inspect(self, host: str, port: int) -> TlsInfo: ...


class SslTlsInspector(TlsInspector):
    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def inspect(self, host: str, port: int) -> TlsInfo:
        import asyncio

        return await asyncio.to_thread(self._inspect_sync, host, port)

    def _inspect_sync(self, host: str, port: int) -> TlsInfo:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with (
                socket.create_connection((host, port), timeout=self._timeout) as sock,
                ctx.wrap_socket(sock, server_hostname=host) as ssock,
            ):
                proto = ssock.version()
                cipher = ssock.cipher()
                der = ssock.getpeercert(binary_form=True)
            not_after, issuer, subject = _parse_cert(der) if der else (None, None, None)
            return TlsInfo(
                host=host,
                port=port,
                protocol=proto,
                cipher=cipher[0] if cipher else None,
                not_after=not_after,
                issuer_cn=issuer,
                subject_cn=subject,
                self_signed=bool(issuer and subject and issuer == subject),
            )
        except Exception as exc:
            return TlsInfo(host, port, None, None, None, None, None, False, error=str(exc))


class TlsAdapter(NativeAdapter):
    engine_id = "vantage-tls"
    engine_name = "Vantage TLS Analyzer"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.ANALYSIS_TLS]

    def __init__(
        self,
        client_factory: ClientFactory | None = None,
        inspector: TlsInspector | None = None,
    ) -> None:
        super().__init__(client_factory)
        self._inspector = inspector or SslTlsInspector()

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        targets: set[tuple[str, int]] = set()
        for url in request.seed_urls:
            parts = urlsplit(url)
            if (parts.scheme or "").lower() not in ("https", "wss"):
                continue
            if parts.hostname:
                targets.add((parts.hostname.lower(), parts.port or 443))

        observations: list[Observation] = []
        for host, port in sorted(targets):
            info = await self._inspector.inspect(host, port)
            observations.extend(self._evaluate(request, info))
        return observations

    def _evaluate(self, request: EngineRunRequest, info: TlsInfo) -> list[Observation]:
        if info.error:
            return []
        loc = Location(scheme="https", host=info.host, port=info.port, path="/", method="GET")
        vc = taxonomy.BY_KEY["tls_weakness"]
        out: list[Observation] = []

        if info.protocol in _WEAK_PROTOCOLS:
            out.append(
                self._new_observation(
                    request,
                    detector_id=f"weak-protocol:{info.protocol}",
                    title=f"Obsolete TLS protocol negotiated: {info.protocol}",
                    vuln_class=vc.key,
                    severity=Severity.MEDIUM,
                    cwe=[326, 327],
                    location=loc,
                    description=f"The server negotiated {info.protocol}.",
                    remediation="Disable TLS < 1.2 and prefer TLS 1.3.",
                    evidence=[_tls_ev(self.engine_id, info, f"protocol={info.protocol}")],
                )
            )

        if info.not_after is not None:
            now = datetime.now(UTC)
            days = (info.not_after - now).days
            if days < 0:
                out.append(
                    self._new_observation(
                        request,
                        detector_id="cert-expired",
                        title="TLS certificate expired",
                        vuln_class=vc.key,
                        severity=Severity.HIGH,
                        cwe=[295, 298],
                        location=loc,
                        description=f"Leaf certificate expired {abs(days)} day(s) ago.",
                        remediation="Renew the certificate and automate rotation.",
                        evidence=[_tls_ev(self.engine_id, info, f"not_after={info.not_after}")],
                    )
                )
            elif days < 15:
                out.append(
                    self._new_observation(
                        request,
                        detector_id="cert-expiring",
                        title="TLS certificate expiring soon",
                        vuln_class=vc.key,
                        severity=Severity.LOW,
                        cwe=[295],
                        location=loc,
                        description=f"Leaf certificate expires in {days} day(s).",
                        remediation="Renew before expiry; automate rotation.",
                        evidence=[_tls_ev(self.engine_id, info, f"not_after={info.not_after}")],
                    )
                )

        if info.self_signed:
            out.append(
                self._new_observation(
                    request,
                    detector_id="cert-self-signed",
                    title="Self-signed TLS certificate",
                    vuln_class=vc.key,
                    severity=Severity.MEDIUM,
                    cwe=[295],
                    location=loc,
                    description="The leaf certificate appears self-signed (issuer == subject).",
                    remediation="Use a certificate from a trusted CA for public endpoints.",
                    evidence=[_tls_ev(self.engine_id, info, f"issuer={info.issuer_cn}")],
                )
            )
        return out


def _tls_ev(engine_id: str, info: TlsInfo, summary: str) -> Evidence:
    return Evidence(
        kind=EvidenceKind.TLS_OBSERVATION,
        engine_id=engine_id,
        summary=summary,
        data={
            "protocol": info.protocol or "",
            "cipher": info.cipher or "",
            "issuer_cn": info.issuer_cn or "",
            "subject_cn": info.subject_cn or "",
        },
    )


def _parse_cert(der: bytes) -> tuple[datetime | None, str | None, str | None]:
    """Return (not_after_utc, issuer_cn, subject_cn) from a DER certificate."""
    from cryptography import x509

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return (None, None, None)
    not_after = cert.not_valid_after_utc
    return (not_after, _cn(cert.issuer), _cn(cert.subject))


def _cn(name: object) -> str | None:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    if not isinstance(name, x509.Name):
        return None
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if attrs:
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8", "replace")
    return None
