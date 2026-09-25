"""Sandbox runners for containerized engines.

External engines are treated as untrusted. Each runs in a locked-down
container: read-only root filesystem, all Linux capabilities dropped,
``no-new-privileges``, a non-root user, CPU/memory/PID limits, a size-capped
tmpfs work area, and a network mode chosen by the adapter (none, or egress only
through the Vantage scope-enforcing proxy). Output size is capped and the
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

from vantage.domain import NetworkMode, ResourceLimits
from vantage.engines.adapter import ContainerSpec, SandboxResult, SandboxRunner


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
            argv += ["--network", "vantage-egress"]
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


class LocalSubprocessRunner(SandboxRunner):
    """Run an engine as a native binary on the host (Kali / Linux deployment).

    On a Kali box the security tools are installed via apt and live on ``PATH``,
    so containerization is unnecessary. This runner executes the pinned binary
    directly with best-effort isolation available without containers:

    * a private temporary work/output directory per run (tokens ``/work`` and
      ``/out`` in the engine args are rewritten to it),
    * a hard wall-clock timeout,
    * POSIX resource limits (address space and CPU time) applied in the child
      via ``preexec_fn`` on Linux,
    * output size caps.

    It is not a security boundary as strong as a container; on multi-tenant or
    untrusted deployments prefer :class:`DockerSandboxRunner`. The choice is made
    by the operator via configuration.
    """

    def __init__(self, *, allow_missing: bool = True) -> None:
        self._allow_missing = allow_missing

    async def available(self) -> bool:
        return True

    def _resolve(self, spec: ContainerSpec) -> str | None:
        binary = spec.binary or (
            spec.image.rsplit("/", 1)[-1].split(":", 1)[0] if spec.image else ""
        )
        if not binary:
            return None
        return shutil.which(binary)

    async def run(self, spec: ContainerSpec) -> SandboxResult:
        import os
        import tempfile

        path = self._resolve(spec)
        if path is None:
            return SandboxResult(
                exit_code=127,
                timed_out=False,
                stdout=b"",
                stderr=f"engine binary not found on PATH: {spec.binary or spec.image}".encode(),
                output_files={},
                duration_seconds=0.0,
            )

        with tempfile.TemporaryDirectory(prefix="vantage-eng-") as tmp:
            workdir = os.path.join(tmp, "work")
            outdir = os.path.join(tmp, "out")
            os.makedirs(workdir, exist_ok=True)
            os.makedirs(outdir, exist_ok=True)
            args = [self._rewrite(a, spec, workdir, outdir) for a in spec.args]

            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": workdir}
            env.update(spec.env)

            proc = await asyncio.create_subprocess_exec(
                path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=workdir,
                env=env,
                preexec_fn=_rlimit_preexec(spec.limits),
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
            output_files: dict[str, bytes] = {}
            for name in os.listdir(outdir):
                fp = os.path.join(outdir, name)
                if os.path.isfile(fp):
                    with open(fp, "rb") as fh:
                        output_files[name] = fh.read(cap)

            return SandboxResult(
                exit_code=None if timed_out else proc.returncode,
                timed_out=timed_out,
                stdout=stdout[:cap],
                stderr=stderr[:cap],
                output_files=output_files,
                duration_seconds=0.0,
                output_truncated=len(stdout) > cap,
            )

    @staticmethod
    def _rewrite(arg: str, spec: ContainerSpec, workdir: str, outdir: str) -> str:
        return arg.replace(spec.output_dir, outdir).replace(spec.workdir, workdir)


def _rlimit_preexec(limits: ResourceLimits) -> Callable[[], None] | None:
    """Return a preexec_fn applying POSIX resource limits, or None if unavailable."""
    try:
        import resource
    except ImportError:  # pragma: no cover - non-POSIX
        return None

    import contextlib

    def _apply() -> None:  # pragma: no cover - runs in the child process
        mem = limits.memory_mb * 1024 * 1024
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        with contextlib.suppress(ValueError, OSError):
            cpu = limits.timeout_seconds
            resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))

    return _apply


def select_runner(mode: str = "auto", *, prefer_docker: bool = True) -> SandboxRunner:
    """Select a sandbox runner.

    ``mode``: "auto" (docker if available, else local subprocess), "docker",
    "local", or "fake". Kali/host deployments typically use "local"; hardened or
    multi-tenant deployments use "docker".
    """
    mode = mode.lower()
    if mode == "docker":
        return DockerSandboxRunner()
    if mode == "local":
        return LocalSubprocessRunner()
    if mode == "fake":
        return FakeSandboxRunner()
    # auto
    if prefer_docker and shutil.which("docker") is not None:
        return DockerSandboxRunner()
    return LocalSubprocessRunner()
