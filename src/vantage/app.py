"""Application composition root.

Wires the concrete pieces together into a ready-to-use :class:`VantageApp`:
database, license policy, engine registry (with native adapters bound), and an
orchestrator with a validation prober. This is the single place that decides
which adapters are active, so tests and deployments can swap pieces cleanly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from vantage.adapters.http import ScopedHttpClient
from vantage.adapters.native.crawler import CrawlerAdapter
from vantage.adapters.native.fingerprint import FingerprintAdapter
from vantage.adapters.native.headers import HeadersAdapter
from vantage.adapters.native.tls import TlsAdapter
from vantage.adapters.native.validator import ValidatorAdapter
from vantage.domain import Target
from vantage.engines.adapter import EngineAdapter, SandboxRunner
from vantage.engines.registry import EngineRegistry
from vantage.engines.sandbox import select_runner
from vantage.governance.policy import LicensePolicy
from vantage.scan.orchestrator import Orchestrator
from vantage.scan.validation import Prober, ProbeResponse
from vantage.scope.engine import ScopeEngine

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
class VantageApp:
    registry: EngineRegistry
    orchestrator: Orchestrator
    policy: LicensePolicy

    @classmethod
    def from_env(cls) -> VantageApp:
        """Build from environment variables (used by the container entrypoints).

        VANTAGE_DATABASE_URL, VANTAGE_SANDBOX (auto|docker|local|fake),
        VANTAGE_AUTODETECT (1/0). Defaults match an on-host/Kali deployment.
        """
        import os

        return cls.build(
            database_url=os.environ.get("VANTAGE_DATABASE_URL", "sqlite+pysqlite:///:memory:"),
            sandbox_mode=os.environ.get("VANTAGE_SANDBOX", "auto"),
            auto_detect=os.environ.get("VANTAGE_AUTODETECT", "0") in ("1", "true", "yes"),
        )

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
        auto_detect: bool = False,
        validate_findings: bool = True,
    ) -> VantageApp:
        from vantage.persistence.repositories import Database

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

        # Isolated OSS adapters, keyed by engine id. Only GREEN, permissively
        # licensed engines have a bundled adapter; RED/YELLOW engines require a
        # recorded approval before they become usable regardless.
        oss_adapters = _oss_adapter_factories(runner, registry)

        # On a host/Kali deployment, detect which of these tools are actually
        # installed and enable them so the planner can choose among them.
        detected: set[str] = set()
        if auto_detect:
            detected = _detect_installed(list(oss_adapters))
            for eid in detected:
                registry.enable(eid, True)

        if bind_oss:
            for eid, factory in oss_adapters.items():
                eng = registry.get(eid)
                if eng is None or not eng.usable:
                    continue
                # If auto-detecting, only bind engines actually present on host.
                if auto_detect and eid not in detected:
                    continue
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


def _oss_adapter_factories(
    runner: SandboxRunner, registry: EngineRegistry
) -> dict[str, Callable[[], EngineAdapter]]:
    """Map engine id -> factory for every GREEN engine with a bundled adapter."""
    from vantage.adapters.oss.base import ContainerEngineAdapter
    from vantage.adapters.oss.feroxbuster import FeroxbusterAdapter
    from vantage.adapters.oss.ffuf import FfufAdapter
    from vantage.adapters.oss.gitleaks import GitleaksAdapter
    from vantage.adapters.oss.httpx_engine import HttpxAdapter
    from vantage.adapters.oss.katana import KatanaAdapter
    from vantage.adapters.oss.nuclei import NucleiAdapter
    from vantage.adapters.oss.recon import DnsxAdapter, SubfinderAdapter, TlsxAdapter
    from vantage.adapters.oss.zap import ZapAdapter

    def mk(cls: type[ContainerEngineAdapter], eid: str) -> Callable[[], EngineAdapter]:
        return lambda: cls(runner, _ver(registry, eid))

    return {
        "nuclei": mk(NucleiAdapter, "nuclei"),
        "ffuf": mk(FfufAdapter, "ffuf"),
        "katana": mk(KatanaAdapter, "katana"),
        "httpx": mk(HttpxAdapter, "httpx"),
        "feroxbuster": mk(FeroxbusterAdapter, "feroxbuster"),
        "zap": mk(ZapAdapter, "zap"),
        "gitleaks": mk(GitleaksAdapter, "gitleaks"),
        "subfinder": mk(SubfinderAdapter, "subfinder"),
        "dnsx": mk(DnsxAdapter, "dnsx"),
        "tlsx": mk(TlsxAdapter, "tlsx"),
    }


def _detect_installed(engine_ids: list[str]) -> set[str]:
    import asyncio

    from vantage.engines.detect import detect_engines

    detections = asyncio.run(detect_engines(engine_ids))
    return {d.engine_id for d in detections if d.installed}
