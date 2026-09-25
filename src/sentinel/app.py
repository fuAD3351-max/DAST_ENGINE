"""Application composition root.

Wires the concrete pieces together into a ready-to-use :class:`SentinelApp`:
database, license policy, engine registry (with native adapters bound), and an
orchestrator with a validation prober. This is the single place that decides
which adapters are active, so tests and deployments can swap pieces cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sentinel.adapters.http import ScopedHttpClient
from sentinel.adapters.native.crawler import CrawlerAdapter
from sentinel.adapters.native.fingerprint import FingerprintAdapter
from sentinel.adapters.native.headers import HeadersAdapter
from sentinel.adapters.native.tls import TlsAdapter
from sentinel.adapters.native.validator import ValidatorAdapter
from sentinel.adapters.oss.ffuf import FfufAdapter
from sentinel.adapters.oss.nuclei import NucleiAdapter
from sentinel.domain import Target
from sentinel.engines.adapter import SandboxRunner
from sentinel.engines.registry import EngineRegistry
from sentinel.engines.sandbox import select_runner
from sentinel.governance.policy import LicensePolicy
from sentinel.scan.orchestrator import Orchestrator
from sentinel.scan.validation import Prober, ProbeResponse
from sentinel.scope.engine import ScopeEngine

DEFAULT_POLICY = "third_party/policy/license-policy.yaml"
DEFAULT_MANIFESTS = "engines/manifests"
DEFAULT_LOCK = "engines/engine-lock.yaml"


class HttpProber(Prober):
    """Validation prober backed by a scope-enforcing HTTP client."""

    def __init__(self, target: Target) -> None:
        scope = ScopeEngine(target)
        self._client = ScopedHttpClient(
            scope,
            rate_per_sec=target.rate_limits.max_requests_per_second,
            concurrency=target.rate_limits.max_concurrency,
        )

    async def get(self, url: str, headers: dict[str, str] | None = None) -> ProbeResponse:
        return await self.request("GET", url, headers)

    async def request(
        self, method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None
    ) -> ProbeResponse:
        res = await self._client.fetch(method, url, headers, body)
        return ProbeResponse(
            status=res.status,
            headers=res.headers,
            body=res.body,
            url=res.url,
            elapsed_ms=res.elapsed_ms,
        )


@dataclass
class SentinelApp:
    registry: EngineRegistry
    orchestrator: Orchestrator
    policy: LicensePolicy

    @classmethod
    def build(
        cls,
        *,
        database_url: str = "sqlite+pysqlite:///:memory:",
        policy_path: str | Path = DEFAULT_POLICY,
        manifests_dir: str | Path = DEFAULT_MANIFESTS,
        lock_path: str | Path = DEFAULT_LOCK,
        sandbox: SandboxRunner | None = None,
        sandbox_mode: str = "auto",
        bind_oss: bool = True,
        validate_findings: bool = True,
    ) -> SentinelApp:
        from sentinel.persistence.repositories import Database

        policy = LicensePolicy.load(policy_path)
        registry = EngineRegistry.load(manifests_dir, lock_path, policy)
        runner = sandbox or select_runner(sandbox_mode)

        # Bind native (first-party) adapters.
        native = [
            HeadersAdapter(),
            FingerprintAdapter(),
            TlsAdapter(),
            CrawlerAdapter(),
            ValidatorAdapter(),
        ]
        for adapter in native:
            eng = registry.get(adapter.metadata().id)
            if eng is not None:
                registry.bind_adapter(adapter.metadata().id, adapter)

        # Bind isolated OSS adapters when their engine is usable.
        if bind_oss:
            for eid, factory in (
                ("nuclei", lambda: NucleiAdapter(runner, _ver(registry, "nuclei"))),
                ("ffuf", lambda: FfufAdapter(runner, _ver(registry, "ffuf"))),
            ):
                eng = registry.get(eid)
                if eng is not None and eng.usable:
                    registry.bind_adapter(eid, factory())

        db = Database(database_url)
        orchestrator = Orchestrator(
            db,
            registry,
            prober_factory=HttpProber,
            validate_findings=validate_findings,
        )
        return cls(registry=registry, orchestrator=orchestrator, policy=policy)


def _ver(registry: EngineRegistry, engine_id: str) -> str:
    eng = registry.get(engine_id)
    return eng.metadata.version if eng else "unknown"
