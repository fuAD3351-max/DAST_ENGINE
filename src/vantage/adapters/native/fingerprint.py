"""Native passive technology fingerprinting.

Infers server-side and client-side technologies from response headers, cookies
and body markers using a small, curated passive signature set. Fingerprints are
low severity on their own (INFO) but feed the planner's application
classification and the correlation engine's technology context.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar
from urllib.parse import urlsplit

from vantage.adapters.http import FetchResult, HttpClient
from vantage.adapters.native.base import NativeAdapter
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


@dataclass(frozen=True)
class Signature:
    technology: str
    category: str  # server | language | framework | cms | cdn | analytics
    header: str | None = None
    header_regex: str | None = None
    body_regex: str | None = None
    cookie: str | None = None


# Curated, independently authored passive signatures (no third-party fingerprint
# database is bundled, so no external data license applies).
_SIGNATURES: list[Signature] = [
    Signature("nginx", "server", header="server", header_regex=r"nginx"),
    Signature("Apache httpd", "server", header="server", header_regex=r"Apache"),
    Signature("Microsoft IIS", "server", header="server", header_regex=r"IIS"),
    Signature("PHP", "language", header="x-powered-by", header_regex=r"PHP"),
    Signature("ASP.NET", "framework", header="x-powered-by", header_regex=r"ASP\.NET"),
    Signature("Express", "framework", header="x-powered-by", header_regex=r"Express"),
    Signature("Django", "framework", cookie="csrftoken"),
    Signature("Laravel", "framework", cookie="laravel_session"),
    Signature(
        "WordPress", "cms", body_regex=r"/wp-content/|<meta name=\"generator\" content=\"WordPress"
    ),
    Signature("Drupal", "cms", header="x-generator", header_regex=r"Drupal"),
    Signature("Cloudflare", "cdn", header="server", header_regex=r"cloudflare"),
    Signature("React", "framework", body_regex=r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    Signature("Vue.js", "framework", body_regex=r"data-v-[0-9a-f]{8}|__VUE__"),
    Signature("Angular", "framework", body_regex=r"ng-version=\""),
    Signature("Next.js", "framework", body_regex=r"/_next/static/|__NEXT_DATA__"),
]


class FingerprintAdapter(NativeAdapter):
    engine_id = "vantage-fingerprint"
    engine_name = "Vantage Technology Fingerprint"
    engine_capabilities: ClassVar[list[Capability]] = [Capability.FINGERPRINT_TECH]

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        observations: list[Observation] = []
        for url in request.seed_urls:
            res = await client.get(url)
            if not res.ok:
                continue
            observations.extend(self._match(request, res))
        return observations

    def _match(self, request: EngineRunRequest, res: FetchResult) -> list[Observation]:
        loc = _location(res.url)
        lowered = {k.lower(): v for k, v in res.headers.items()}
        set_cookie = (lowered.get("set-cookie") or "").lower()
        found: list[Observation] = []
        vc = taxonomy.BY_KEY["information_disclosure"]
        for sig in _SIGNATURES:
            matched_value: str | None = None
            if sig.header and sig.header_regex:
                val = lowered.get(sig.header)
                if val and re.search(sig.header_regex, val, re.I):
                    matched_value = f"{sig.header}: {val}"
            if matched_value is None and sig.cookie and sig.cookie.lower() in set_cookie:
                matched_value = f"cookie:{sig.cookie}"
            if (
                matched_value is None
                and sig.body_regex
                and re.search(sig.body_regex, res.body, re.I)
            ):
                matched_value = "body-marker"
            if matched_value is not None:
                found.append(
                    self._new_observation(
                        request,
                        detector_id=f"tech:{sig.technology}",
                        title=f"Technology detected: {sig.technology}",
                        vuln_class=vc.key,
                        severity=Severity.INFO,
                        cwe=[200],
                        location=loc,
                        description=f"Passive fingerprint identified {sig.technology} "
                        f"({sig.category}).",
                        remediation="No action required; informational technology inventory.",
                        evidence=[
                            Evidence(
                                kind=EvidenceKind.RESPONSE_MATCH,
                                engine_id=self.engine_id,
                                summary=f"{sig.technology} via {matched_value}",
                                matched=[matched_value],
                                data={"technology": sig.technology, "category": sig.category},
                            )
                        ],
                    )
                )
        return found


def _location(url: str) -> Location:
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
