"""Sandbox runners for containerized engines.

External engines are treated as untrusted. Each runs in a locked-down
container: read-only root filesystem, all Linux capabilities dropped,
``no-new-privileges``, a non-root user, CPU/memory/PID limits, a size-capped
tmpfs work area, and a network mode chosen by the adapter (none, or egress only
through the Sentinel scope-enforcing proxy). Output size is capped and the
runner enforces a hard timeout.

Two implementations are provided:

* :class:`FakeSandboxRunner` - deterministic, no Docker; used in tests and the
  embedded demo.
* :class:`DockerSandboxRunner` - shells out to the Docker CLI with the hardening
  flags. It is only used when Docker is available.
"""

from __future__ import annotations

import asyncio
import inspect
import shutil
from collections.abc import Awaitable, Callable

from sentinel.domain import NetworkMode
from sentinel.engines.adapter import ContainerSpec, SandboxResult, SandboxRunner


class FakeSandboxRunner(SandboxRunner):
    """Runs a Python callable instead of a container. For tests/embedded mode."""

    def __init__(
        self,
        handler: Callable[[ContainerSpec], Awaitable[SandboxResult] | SandboxResult] | None = None,
    ) -> None:
        self._handler = handler

    async def available(self) -> bool:
        return True

    async def run(self, spec: ContainerSpec) -> SandboxResult:
        if self._handler is not None:
            result = self._handler(spec)
            if inspect.isawaitable(result):
                return await result
            return result
        return SandboxResult(
            exit_code=0,
            timed_out=False,
            stdout=b"",
            stderr=b"",
            output_files={},
            duration_seconds=0.0,
        )


class DockerSandboxRunner(SandboxRunner):
    def __init__(self, docker_bin: str = "docker") -> None:
        self._docker = docker_bin

    async def available(self) -> bool:
        if shutil.which(self._docker) is None:
            return False
        proc = await asyncio.create_subprocess_exec(
            self._docker,
            "info",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await proc.wait() == 0

    def _build_argv(self, spec: ContainerSpec) -> list[str]:
        argv = [
            self._docker,
            "run",
            "--rm",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            spec.user,
            "--pids-limit",
            str(spec.limits.pids),
            "--cpus",
            str(spec.limits.cpus),
            "--memory",
            f"{spec.limits.memory_mb}m",
            "--memory-swap",
            f"{spec.limits.memory_mb}m",
            "--workdir",
            spec.workdir,
            "--tmpfs",
            f"{spec.workdir}:rw,size={spec.limits.tmpfs_mb}m,mode=1777",
            "--tmpfs",
            f"{spec.output_dir}:rw,size={spec.limits.tmpfs_mb}m,mode=1777",
        ]
        if spec.network is NetworkMode.NONE:
            argv += ["--network", "none"]
        else:
            # Scoped egress: attach to the dedicated proxy network and force all
            # traffic through the scope-enforcing proxy via env vars. The proxy
            # itself re-checks every request against the ScopeEngine.
            argv += ["--network", "sentinel-egress"]
        for k, v in spec.env.items():
            argv += ["--env", f"{k}={v}"]
        argv.append(spec.image)
        argv += spec.args
        return argv

    async def run(self, spec: ContainerSpec) -> SandboxResult:
        argv = self._build_argv(spec)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=spec.limits.timeout_seconds
            )
        except TimeoutError:
            timed_out = True
            proc.kill()
            stdout, stderr = await proc.communicate()

        cap = spec.limits.max_output_bytes
        truncated = len(stdout) > cap
        stdout = stdout[:cap]

        # Output files are collected by the adapter reading a bind-mounted dir in
        # real deployments; the CLI-capture path returns stdout only.
        return SandboxResult(
            exit_code=None if timed_out else proc.returncode,
            timed_out=timed_out,
            stdout=stdout,
            stderr=stderr[:cap],
            output_files={},
            duration_seconds=float(spec.limits.timeout_seconds if timed_out else 0.0),
            output_truncated=truncated,
        )


def select_runner(prefer_docker: bool = True) -> SandboxRunner:
    """Best-effort runner selection for the embedded build."""
    if prefer_docker and shutil.which("docker") is not None:
        return DockerSandboxRunner()
    return FakeSandboxRunner()
