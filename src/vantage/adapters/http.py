"""Scope-enforcing, rate-limited HTTP client for native engines.

Every native engine makes requests only through this client. It:

* refuses any URL the :class:`ScopeEngine` does not allow (defence in depth -
  the planner already restricts seeds, but engines discover new URLs);
* enforces a token-bucket request rate and a concurrency ceiling from the
  target's rate limits;
* caps response body size and follows redirects only within scope.

The concrete implementation uses httpx; tests inject :class:`FakeHttpClient`.
"""

from __future__ import annotations

import abc
import asyncio
import time
from dataclasses import dataclass, field

from vantage.scope.engine import ScopeEngine

DEFAULT_MAX_BODY = 4 * 1024 * 1024
DEFAULT_UA = "VantageDAST/0.1 (+authorized-security-testing)"


@dataclass
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str | None = None
    out_of_scope: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.out_of_scope


class HttpClient(abc.ABC):
    @abc.abstractmethod
    async def fetch(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> FetchResult: ...

    async def get(self, url: str, headers: dict[str, str] | None = None) -> FetchResult:
        return await self.fetch("GET", url, headers)

    async def aclose(self) -> None:
        return None


class _TokenBucket:
    def __init__(self, rate_per_sec: float) -> None:
        self._rate = max(rate_per_sec, 0.1)
        self._tokens = self._rate
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self._rate, self._tokens + (now - self._updated) * self._rate)
            self._updated = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0


class ScopedHttpClient(HttpClient):
    def __init__(
        self,
        scope: ScopeEngine,
        *,
        rate_per_sec: float = 10.0,
        concurrency: int = 4,
        max_body: int = DEFAULT_MAX_BODY,
        timeout: float = 20.0,
        user_agent: str = DEFAULT_UA,
    ) -> None:
        self._scope = scope
        self._bucket = _TokenBucket(rate_per_sec)
        self._sem = asyncio.Semaphore(concurrency)
        self._max_body = max_body
        self._timeout = timeout
        self._ua = user_agent
        self._client: object | None = None

    async def _ensure_client(self) -> object:
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(
                follow_redirects=False,
                timeout=self._timeout,
                headers={"User-Agent": self._ua},
                verify=True,
            )
        return self._client

    async def fetch(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> FetchResult:
        decision = self._scope.check(url, method)
        if not decision.allowed:
            return FetchResult(url, 0, {}, "", 0.0, out_of_scope=True, error=decision.reason)

        client = await self._ensure_client()
        await self._bucket.take()
        async with self._sem:
            start = time.monotonic()
            try:
                import httpx

                assert isinstance(client, httpx.AsyncClient)
                resp = await client.request(method, url, headers=headers, content=body)
                raw = resp.content[: self._max_body]
                text = raw.decode(resp.encoding or "utf-8", "replace")
                return FetchResult(
                    url=str(resp.url),
                    status=resp.status_code,
                    headers={k: v for k, v in resp.headers.items()},
                    body=text,
                    elapsed_ms=(time.monotonic() - start) * 1000,
                )
            except Exception as exc:
                return FetchResult(
                    url, 0, {}, "", (time.monotonic() - start) * 1000, error=str(exc)
                )

    async def aclose(self) -> None:
        if self._client is not None:
            import httpx

            assert isinstance(self._client, httpx.AsyncClient)
            await self._client.aclose()
            self._client = None


@dataclass
class FakeHttpClient(HttpClient):
    """Deterministic client for tests: maps URL -> FetchResult."""

    responses: dict[str, FetchResult] = field(default_factory=dict)
    scope: ScopeEngine | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)

    async def fetch(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> FetchResult:
        self.calls.append((method, url))
        if self.scope is not None and not self.scope.allows(url, method):
            return FetchResult(url, 0, {}, "", 0.0, out_of_scope=True, error="out of scope")
        r = self.responses.get(url)
        if r is None:
            return FetchResult(url, 404, {}, "", 0.0)
        return r
