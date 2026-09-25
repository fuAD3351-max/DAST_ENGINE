"""Native security-header, cookie and sensitive-data analyzer (passive).

Fetches each seed URL once and evaluates response metadata only - it sends no
crafted input, so it is safe in the PASSIVE profile. Detects:

* missing/weak security headers (HSTS, CSP, X-Content-Type-Options, ...),
* insecure cookie attributes (missing Secure/HttpOnly/SameSite),
* permissive CORS reflection,
* high-confidence secret patterns in response bodies and headers,
* server/version banners (information disclosure).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar

from vantage.adapters.http import FetchResult, HttpClient
from vantage.adapters.native.base import NativeAdapter
from vantage.domain import (
    Capability,
    EngineRunRequest,
    Evidence,
    EvidenceKind,
    HttpMessage,
    Location,
    Observation,
    Severity,
)
from vantage.findings import taxonomy


@dataclass(frozen=True)
class HeaderSpec:
    header: str
    severity: Severity
    remediation: str


_REQUIRED_HEADERS = [
    HeaderSpec(
        "strict-transport-security",
        Severity.MEDIUM,
        "Send Strict-Transport-Security with a max-age of at least 31536000.",
    ),
    HeaderSpec(
        "content-security-policy",
        Severity.MEDIUM,
        "Define a restrictive Content-Security-Policy to mitigate injection classes.",
    ),
    HeaderSpec(
        "x-content-type-options",
        Severity.LOW,
        "Set X-Content-Type-Options: nosniff.",
    ),
    HeaderSpec(
        "referrer-policy",
        Severity.LOW,
        "Set a privacy-preserving Referrer-Policy such as strict-origin-when-cross-origin.",
    ),
]

# High-confidence, low-false-positive secret indicators only.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"ghp_[0-9A-Za-z]{36}")),
]

_VERSION_BANNER = re.compile(r"[0-9]+\.[0-9]+(\.[0-9]+)?")


class HeadersAdapter(NativeAdapter):
    engine_id = "vantage-headers"
    engine_name = "Vantage Security Headers Analyzer"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.ANALYSIS_HEADERS,
        Capability.ANALYSIS_SECRETS,
        Capability.AUDIT_PASSIVE,
    ]

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        observations: list[Observation] = []
        for url in request.seed_urls:
            res = await client.get(url)
            if not res.ok:
                continue
            loc = _location(res.url)
            observations.extend(self._header_findings(request, loc, res))
            observations.extend(self._cookie_findings(request, loc, res))
            observations.extend(self._cors_findings(request, loc, res))
            observations.extend(self._banner_findings(request, loc, res))
            observations.extend(self._secret_findings(request, loc, res))
        return observations

    def _header_findings(
        self, request: EngineRunRequest, loc: Location, res: FetchResult
    ) -> list[Observation]:
        present = {k.lower() for k in res.headers}
        out: list[Observation] = []
        is_https = res.url.lower().startswith("https://")
        for spec in _REQUIRED_HEADERS:
            if spec.header == "strict-transport-security" and not is_https:
                continue
            if spec.header not in present:
                vc = taxonomy.BY_KEY["missing_security_header"]
                out.append(
                    self._new_observation(
                        request,
                        detector_id=f"missing-header:{spec.header}",
                        title=f"Missing security header: {spec.header}",
                        vuln_class=vc.key,
                        severity=spec.severity,
                        cwe=[693],
                        location=loc,
                        description=f"The response does not set the {spec.header} header.",
                        remediation=spec.remediation,
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.HEADER_OBSERVATION,
                                engine_id=self.engine_id,
                                summary=f"{spec.header} absent",
                                matched=[spec.header],
                                response=HttpMessage(
                                    status=res.status, url=res.url, headers=dict(res.headers)
                                ),
                            )
                        ],
                    )
                )
        return out

    def _cookie_findings(
        self, request: EngineRunRequest, loc: Location, res: FetchResult
    ) -> list[Observation]:
        raw = res.headers.get("set-cookie") or res.headers.get("Set-Cookie")
        if not raw:
            return []
        lowered = raw.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if not missing:
            return []
        vc = taxonomy.BY_KEY["insecure_cookie"]
        return [
            self._new_observation(
                request,
                detector_id="cookie-flags",
                title=f"Insecure cookie attributes: missing {', '.join(missing)}",
                vuln_class=vc.key,
                severity=Severity.LOW,
                cwe=[614, 1004],
                location=loc,
                description="A Set-Cookie response is missing hardening attributes.",
                remediation="Set Secure, HttpOnly and SameSite on session cookies.",
                evidence=[
                    Evidence(
                        kind=EvidenceKind.HEADER_OBSERVATION,
                        engine_id=self.engine_id,
                        summary=f"Set-Cookie missing {missing}",
                        matched=missing,
                    )
                ],
            )
        ]

    def _cors_findings(
        self, request: EngineRunRequest, loc: Location, res: FetchResult
    ) -> list[Observation]:
        acao = res.headers.get("access-control-allow-origin") or res.headers.get(
            "Access-Control-Allow-Origin"
        )
        acac = (
            res.headers.get("access-control-allow-credentials")
            or res.headers.get("Access-Control-Allow-Credentials")
            or ""
        )
        if acao == "*" and acac.lower() == "true":
            vc = taxonomy.BY_KEY["cors_misconfiguration"]
            return [
                self._new_observation(
                    request,
                    detector_id="cors-wildcard-credentials",
                    title="CORS allows any origin with credentials",
                    vuln_class=vc.key,
                    severity=Severity.MEDIUM,
                    cwe=[942],
                    location=loc,
                    description="Access-Control-Allow-Origin: * combined with credentials.",
                    remediation=(
                        "Reflect only allow-listed origins; never combine * with credentials."
                    ),
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.HEADER_OBSERVATION,
                            engine_id=self.engine_id,
                            summary="ACAO=* with credentials=true",
                            matched=["access-control-allow-origin"],
                        )
                    ],
                )
            ]
        return []

    def _banner_findings(
        self, request: EngineRunRequest, loc: Location, res: FetchResult
    ) -> list[Observation]:
        out: list[Observation] = []
        for hdr in ("server", "x-powered-by", "x-aspnet-version"):
            val = res.headers.get(hdr) or res.headers.get(hdr.title())
            if val and _VERSION_BANNER.search(val):
                vc = taxonomy.BY_KEY["information_disclosure"]
                out.append(
                    self._new_observation(
                        request,
                        detector_id=f"version-banner:{hdr}",
                        title=f"Version banner disclosed via {hdr}",
                        vuln_class=vc.key,
                        severity=Severity.INFO,
                        cwe=[200],
                        location=loc,
                        description=f"The {hdr} header discloses software version '{val}'.",
                        remediation="Suppress or genericize version banners.",
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.HEADER_OBSERVATION,
                                engine_id=self.engine_id,
                                summary=f"{hdr}: {val}",
                                matched=[val],
                            )
                        ],
                    )
                )
        return out

    def _secret_findings(
        self, request: EngineRunRequest, loc: Location, res: FetchResult
    ) -> list[Observation]:
        haystack = res.body + "\n" + "\n".join(f"{k}: {v}" for k, v in res.headers.items())
        out: list[Observation] = []
        vc = taxonomy.BY_KEY["secret_exposure"]
        for name, pattern in _SECRET_PATTERNS:
            m = pattern.search(haystack)
            if m:
                redacted = _redact(m.group(0))
                out.append(
                    self._new_observation(
                        request,
                        detector_id=f"secret:{name}",
                        title=f"Potential exposed secret: {name}",
                        vuln_class=vc.key,
                        severity=Severity.HIGH,
                        cwe=[540, 312],
                        location=loc,
                        description=f"A value matching {name} was found in the response.",
                        remediation="Remove secrets from client-served responses and rotate them.",
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.RESPONSE_MATCH,
                                engine_id=self.engine_id,
                                summary=f"{name} pattern matched (value redacted)",
                                matched=[redacted],
                            )
                        ],
                    )
                )
        return out


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _location(url: str) -> Location:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return Location(
        scheme=scheme,
        host=(parts.hostname or "").lower(),
        port=port,
        path=parts.path or "/",
        method="GET",
    )
