"""Native HTTP crawler with lightweight JS endpoint extraction.

Breadth-first crawl within scope, honouring the shared HttpClient's rate limits.
Extracts links from HTML (href/src/action) and candidate endpoints from inline
and referenced JavaScript via conservative URL/path regexes. It reports
discovered endpoints as INFO observations so the attack-surface graph and the
knowledge base can consume them; it does not itself audit for vulnerabilities.
"""

from __future__ import annotations

import re
from collections import deque
from typing import ClassVar
from urllib.parse import urljoin, urlsplit

from vantage.adapters.http import HttpClient
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

_HREF = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>]+)["']""", re.I)
_JS_PATH = re.compile(r"""["'](/[A-Za-z0-9_\-./]{2,}(?:\?[^"']*)?)["']""")
_JS_URL = re.compile(r"""["'](https?://[A-Za-z0-9_\-./:%?=&]+)["']""")
_SCRIPT_SRC = re.compile(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", re.I)

DEFAULT_MAX_PAGES = 60
DEFAULT_MAX_DEPTH = 3


class CrawlerAdapter(NativeAdapter):
    engine_id = "vantage-crawler"
    engine_name = "Vantage HTTP Crawler"
    engine_capabilities: ClassVar[list[Capability]] = [
        Capability.CRAWL_HTTP,
        Capability.DISCOVERY_JS,
    ]

    async def _analyze(self, request: EngineRunRequest, client: HttpClient) -> list[Observation]:
        max_pages = int(request.options.get("max_pages", DEFAULT_MAX_PAGES))
        max_depth = int(request.options.get("max_depth", DEFAULT_MAX_DEPTH))
        seen: set[str] = set()
        discovered: dict[str, str] = {}  # url -> how found
        queue: deque[tuple[str, int]] = deque((u, 0) for u in request.seed_urls)

        while queue and len(seen) < max_pages:
            url, depth = queue.popleft()
            norm = _strip_fragment(url)
            if norm in seen:
                continue
            seen.add(norm)
            res = await client.get(norm)
            if not res.ok or "html" not in res.headers.get("content-type", "").lower():
                # Still record JS files for endpoint extraction.
                if res.ok and _looks_like_js(norm, res.headers):
                    for ep in _extract_js_endpoints(norm, res.body):
                        discovered.setdefault(ep, f"js:{norm}")
                continue

            for link in _extract_links(norm, res.body):
                if link not in discovered:
                    discovered[link] = f"html:{norm}"
                if depth < max_depth and _same_host(link, request.seed_urls):
                    queue.append((link, depth + 1))

            for src in _extract_script_srcs(norm, res.body):
                js = await client.get(src)
                if js.ok:
                    for ep in _extract_js_endpoints(src, js.body):
                        discovered.setdefault(ep, f"js:{src}")

        return self._to_observations(request, discovered)

    def _to_observations(
        self, request: EngineRunRequest, discovered: dict[str, str]
    ) -> list[Observation]:
        vc = taxonomy.BY_KEY["information_disclosure"]
        out: list[Observation] = []
        for url, how in sorted(discovered.items()):
            loc = _location(url)
            if not loc.host:
                continue
            out.append(
                self._new_observation(
                    request,
                    detector_id="endpoint-discovered",
                    title=f"Endpoint discovered: {loc.path}",
                    vuln_class=vc.key,
                    severity=Severity.INFO,
                    cwe=[],
                    location=loc,
                    description=f"Discovered endpoint {url} ({how}).",
                    remediation="Informational; feeds attack-surface inventory.",
                    evidence=[
                        Evidence(
                            kind=EvidenceKind.NOTE,
                            engine_id=self.engine_id,
                            summary=f"discovered via {how}",
                            data={"url": url, "source": how},
                        )
                    ],
                )
            )
        return out


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def _extract_links(base: str, html: str) -> list[str]:
    out: list[str] = []
    for m in _HREF.finditer(html):
        raw = m.group(1).strip()
        if raw.lower().startswith(("mailto:", "tel:", "javascript:", "data:")):
            continue
        out.append(_strip_fragment(urljoin(base, raw)))
    return out


def _extract_script_srcs(base: str, html: str) -> list[str]:
    return [urljoin(base, m.group(1)) for m in _SCRIPT_SRC.finditer(html)]


def _extract_js_endpoints(base: str, js: str) -> list[str]:
    out: set[str] = set()
    for m in _JS_URL.finditer(js):
        out.add(_strip_fragment(m.group(1)))
    for m in _JS_PATH.finditer(js):
        path = m.group(1)
        if path.startswith("//"):
            continue
        out.add(_strip_fragment(urljoin(base, path)))
    return sorted(out)


def _looks_like_js(url: str, headers: dict[str, str]) -> bool:
    if url.split("?", 1)[0].endswith(".js"):
        return True
    ct = headers.get("content-type", "").lower()
    return "javascript" in ct or "ecmascript" in ct


def _same_host(url: str, seeds: list[str]) -> bool:
    host = urlsplit(url).hostname
    seed_hosts = {urlsplit(s).hostname for s in seeds}
    return host in seed_hosts


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
