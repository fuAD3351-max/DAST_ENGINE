"""Vantage command-line interface.

Commands:

    vantage license check      validate the third-party inventory (CI gate)
    vantage engine list        list engines with license/approval/usability
    vantage engine verify      check version/digest pinning
    vantage scan run           run a scan against an authorized target
    vantage version            print version

The CLI is a thin layer over the same subsystems the API uses.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from vantage import __version__

app = typer.Typer(
    name="vantage",
    help="Vantage DAST - unified dynamic application security testing platform.",
    no_args_is_help=True,
    add_completion=False,
)
engine_app = typer.Typer(help="Engine registry operations.", no_args_is_help=True)
license_app = typer.Typer(help="License governance operations.", no_args_is_help=True)
app.add_typer(engine_app, name="engine")
app.add_typer(license_app, name="license")

DEFAULT_POLICY = "third_party/policy/license-policy.yaml"
DEFAULT_INVENTORY = "third_party/inventory/third_party_inventory.yaml"
DEFAULT_MANIFESTS = "engines/manifests"
DEFAULT_LOCK = "engines/engine-lock.yaml"


@app.command()
def version() -> None:
    """Print the Vantage version."""
    typer.echo(f"Vantage DAST {__version__}")


@license_app.command("check")
def license_check(
    inventory: Annotated[str, typer.Option(help="Inventory YAML")] = DEFAULT_INVENTORY,
    policy: Annotated[str, typer.Option(help="Policy YAML")] = DEFAULT_POLICY,
    json_out: Annotated[bool, typer.Option("--json", help="JSON output")] = False,
) -> None:
    """Validate the third-party inventory against the license policy.

    Exits non-zero on any error, so CI blocks a release with a non-compliant
    dependency.
    """
    from vantage.governance.inventory import Inventory, check_inventory
    from vantage.governance.policy import LicensePolicy

    pol = LicensePolicy.load(policy)
    inv = Inventory.load(inventory)
    report = check_inventory(inv, pol)

    if json_out:
        typer.echo(
            json.dumps(
                {
                    "ok": report.ok,
                    "checked": report.checked,
                    "violations": [v.__dict__ for v in report.violations],
                },
                indent=2,
            )
        )
    else:
        typer.echo(f"Checked {report.checked} components.")
        for v in report.violations:
            colour = typer.colors.RED if v.severity == "error" else typer.colors.YELLOW
            typer.secho(
                f"  [{v.severity}] {v.component} {v.version}: {v.code} - {v.message}", fg=colour
            )
        if report.ok:
            typer.secho("License policy: PASS", fg=typer.colors.GREEN)
        else:
            typer.secho(
                f"License policy: FAIL ({len(report.errors)} error(s))", fg=typer.colors.RED
            )

    raise typer.Exit(code=0 if report.ok else 1)


@engine_app.command("list")
def engine_list(
    policy: Annotated[str, typer.Option()] = DEFAULT_POLICY,
    manifests: Annotated[str, typer.Option()] = DEFAULT_MANIFESTS,
    lock: Annotated[str, typer.Option()] = DEFAULT_LOCK,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List all registered engines with license class, approval and usability."""
    from vantage.engines.registry import EngineRegistry
    from vantage.governance.policy import LicensePolicy

    pol = LicensePolicy.load(policy)
    reg = EngineRegistry.load(manifests, lock, pol)
    engines = sorted(reg.all(), key=lambda e: (e.metadata.license_class.value, e.metadata.id))

    if json_out:
        typer.echo(
            json.dumps(
                [
                    {
                        "id": e.metadata.id,
                        "version": e.metadata.version,
                        "license": e.metadata.license_spdx,
                        "license_class": e.metadata.license_class.value,
                        "approval": e.metadata.approval_status.value,
                        "integration": e.metadata.integration.value,
                        "enabled": e.manifest.enabled,
                        "usable": e.usable,
                        "capabilities": [c.value for c in e.metadata.capabilities],
                        "problems": e.problems,
                        "notes": e.notes,
                    }
                    for e in engines
                ],
                indent=2,
            )
        )
        return

    typer.echo(f"{'ENGINE':20} {'CLASS':7} {'APPROVAL':14} {'ENABLED':7} {'USABLE':6} INTEGRATION")
    for e in engines:
        colour = {
            "GREEN": typer.colors.GREEN,
            "YELLOW": typer.colors.YELLOW,
            "RED": typer.colors.RED,
        }.get(e.metadata.license_class.value, typer.colors.WHITE)
        typer.secho(
            f"{e.metadata.id:20} {e.metadata.license_class.value:7} "
            f"{e.metadata.approval_status.value:14} {e.manifest.enabled!s:7} "
            f"{e.usable!s:6} {e.metadata.integration.value}",
            fg=colour,
        )
    typer.echo(f"\n{len(engines)} engines; {len(reg.enabled_engines())} usable.")


@engine_app.command("detect")
def engine_detect(
    lock: Annotated[str, typer.Option()] = DEFAULT_LOCK,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Detect engine binaries installed on this host (Kali/Linux).

    Reports which engines are installed on PATH and their versions, and whether
    the version matches the pinned engine-lock.
    """
    import yaml

    from vantage.engines.detect import detect_engines

    locked: dict[str, str] = {}
    lock_path = Path(lock)
    if lock_path.exists():
        data = yaml.safe_load(lock_path.read_text()) or {}
        locked = {k: v.get("version", "") for k, v in data.get("engines", {}).items()}

    detections = asyncio.run(detect_engines(locked_versions=locked))
    installed = [d for d in detections if d.installed]

    if json_out:
        typer.echo(
            json.dumps(
                [
                    {
                        "engine": d.engine_id,
                        "binary": d.binary,
                        "installed": d.installed,
                        "path": d.path,
                        "version": d.version,
                        "matches_lock": d.version_matches_lock,
                    }
                    for d in detections
                ],
                indent=2,
            )
        )
        return

    typer.echo(f"{'ENGINE':16} {'INSTALLED':10} {'VERSION':12} {'MATCHES LOCK':12} PATH")
    for d in detections:
        colour = typer.colors.GREEN if d.installed else typer.colors.WHITE
        match = "" if d.version_matches_lock is None else str(d.version_matches_lock)
        ver = d.version or "-"
        typer.secho(
            f"{d.engine_id:16} {d.installed!s:10} {ver:12} {match:12} {d.path or ''}",
            fg=colour,
        )
    typer.echo(f"\n{len(installed)}/{len(detections)} known engines installed on this host.")


@engine_app.command("verify")
def engine_verify(
    policy: Annotated[str, typer.Option()] = DEFAULT_POLICY,
    manifests: Annotated[str, typer.Option()] = DEFAULT_MANIFESTS,
    lock: Annotated[str, typer.Option()] = DEFAULT_LOCK,
) -> None:
    """Verify engines are version/digest pinned and report any problems."""
    from vantage.engines.registry import EngineRegistry
    from vantage.governance.policy import LicensePolicy

    pol = LicensePolicy.load(policy)
    reg = EngineRegistry.load(manifests, lock, pol)
    problems = 0
    for e in reg.all():
        for p in e.problems:
            problems += 1
            typer.secho(f"  [{e.metadata.id}] {p}", fg=typer.colors.YELLOW)
    if problems == 0:
        typer.secho("All engines pinned and policy-clean.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"{problems} engine problem(s) require attention.", fg=typer.colors.YELLOW)


@app.command("scan")
def scan_run(
    url: Annotated[list[str], typer.Argument(help="Base URL(s) to scan")],
    profile: Annotated[str, typer.Option(help="passive|standard|deep")] = "standard",
    kind: Annotated[str, typer.Option(help="Application kind hint")] = "unknown",
    authorize: Annotated[
        bool,
        typer.Option(
            "--authorize",
            help="Assert you are authorized to test these targets (required).",
        ),
    ] = False,
    fmt: Annotated[str, typer.Option("--format", help="json|sarif|markdown")] = "markdown",
    out: Annotated[str | None, typer.Option(help="Write report to file")] = None,
    no_oss: Annotated[bool, typer.Option("--no-oss", help="Native engines only")] = False,
    sandbox: Annotated[
        str,
        typer.Option(help="Engine execution: auto|docker|local|fake (local = Kali/host binaries)"),
    ] = "auto",
) -> None:
    """Run a scan against target(s) you are authorized to test."""
    if not authorize:
        typer.secho(
            "Refusing to scan without --authorize. Only test systems you own or are "
            "explicitly authorized to assess.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)

    from vantage.app import VantageApp
    from vantage.domain import (
        ApplicationKind,
        AuthorizationMethod,
        AuthorizationRecord,
        Scan,
        ScanPolicy,
        ScanProfile,
        Target,
        utcnow,
    )
    from vantage.findings import reporting
    from vantage.scope.engine import default_scope_rules_for

    try:
        app_profile = ScanProfile(profile.lower())
    except ValueError:
        typer.secho(f"Unknown profile: {profile}", fg=typer.colors.RED)
        raise typer.Exit(code=2) from None

    # In local (Kali/host) mode, auto-detect installed tools so the planner can
    # decide which of the natively-installed engines to use per target.
    sapp = VantageApp.build(
        bind_oss=not no_oss,
        sandbox_mode=sandbox,
        auto_detect=(sandbox.lower() == "local"),
    )
    target = Target(
        tenant_id="cli",
        name=url[0],
        base_urls=url,
        kind=ApplicationKind(kind.lower()) if kind else ApplicationKind.UNKNOWN,
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION,
            verified_at=utcnow(),
            verified_by="cli --authorize",
        ),
    )
    target = target.model_copy(update={"scope_rules": default_scope_rules_for(target)})
    scan = Scan(
        tenant_id="cli",
        target_id=target.id,
        policy=ScanPolicy(profile=app_profile),
        created_by="cli",
    )

    report = asyncio.run(sapp.orchestrator.run(scan, target))
    rendered = reporting.render(report, fmt)
    if out:
        Path(out).write_text(rendered, encoding="utf-8")
        typer.secho(f"Wrote {fmt} report to {out}", fg=typer.colors.GREEN)
    else:
        typer.echo(rendered)

    counts = reporting.summarize(report.findings)
    if counts["critical"] or counts["high"]:
        raise typer.Exit(code=1)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())  # pragma: no cover
