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
ai_app = typer.Typer(help="On-premise AI layer operations.", no_args_is_help=True)
app.add_typer(engine_app, name="engine")
app.add_typer(license_app, name="license")
app.add_typer(ai_app, name="ai")

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
    usable = sum(1 for e in engines if e.usable)
    typer.echo(
        f"\n{len(engines)} engines; {usable} policy-usable "
        "(bind an adapter / install the binary to run them)."
    )


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


@ai_app.command("models")
def ai_models(
    all_classes: Annotated[bool, typer.Option("--all", help="Include review-gated models")] = False,
    json_out: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List recommended on-premise LLMs for managing DAST activity, license-classed.

    All run fully local (llama.cpp in-process, or a self-hosted Ollama daemon) —
    nothing leaves the deployment. GREEN = commercially usable; YELLOW = review.
    """
    from vantage.ai import models as m
    from vantage.domain.common import LicenseClass

    catalog = m.recommended(None) if all_classes else m.recommended(LicenseClass.GREEN)
    if json_out:
        typer.echo(
            json.dumps(
                [
                    {
                        "id": x.id,
                        "family": x.family,
                        "params": x.params,
                        "license": x.license_spdx,
                        "license_class": x.license_class.value,
                        "context": x.context,
                        "gguf": x.gguf_hint,
                        "default": x.id == m.DEFAULT_MODEL_ID,
                        "notes": x.notes,
                    }
                    for x in catalog
                ],
                indent=2,
            )
        )
        return
    typer.echo(f"{'MODEL':26} {'PARAMS':7} {'LICENSE':14} {'CLASS':7} GGUF")
    for x in catalog:
        colour = {"GREEN": typer.colors.GREEN, "YELLOW": typer.colors.YELLOW}.get(
            x.license_class.value, typer.colors.WHITE
        )
        tag = "  (default)" if x.id == m.DEFAULT_MODEL_ID else ""
        row = f"{x.id:26} {x.params:7} {x.license_spdx:14} {x.license_class.value:7} {x.gguf_hint}"
        typer.secho(row + tag, fg=colour)
    typer.echo(
        "\nEnable on-prem AI, e.g.:\n"
        "  Ollama:    VANTAGE_AI_PROVIDER=ollama VANTAGE_AI_MODEL=qwen2.5:7b-instruct\n"
        "  llama.cpp: pip install 'vantage-dast[ai]'; VANTAGE_AI_PROVIDER=llama_cpp "
        "VANTAGE_AI_MODEL_PATH=/models/qwen2.5-7b-instruct-q4_k_m.gguf"
    )


@ai_app.command("select")
def ai_select(
    model: Annotated[str | None, typer.Option(help="Model id (see 'vantage ai models')")] = None,
    provider: Annotated[
        str | None, typer.Option(help="Provider: ollama | llama_cpp | none")
    ] = None,
    model_path: Annotated[str | None, typer.Option(help="GGUF path (llama_cpp)")] = None,
    ollama_url: Annotated[str | None, typer.Option(help="Ollama base URL")] = None,
    accept_yellow: Annotated[
        bool, typer.Option("--accept-yellow", help="Allow a review-gated (YELLOW) model")
    ] = False,
) -> None:
    """Choose the on-premise AI model and provider, and persist the choice.

    With no --model, it lists the recommended commercially-licensed models and
    asks you to pick one interactively. The choice is saved to the Vantage config
    and used by future scans (env vars still override it).
    """
    from vantage.ai import models as m
    from vantage.config import VantageConfig
    from vantage.domain.common import LicenseClass

    green = m.recommended(LicenseClass.GREEN)

    if model is None:
        typer.echo("Recommended on-premise models (commercially-licensed, run locally):\n")
        for i, x in enumerate(green, 1):
            default = "  (default)" if x.id == m.DEFAULT_MODEL_ID else ""
            typer.echo(f"  {i}. {x.id:24} {x.params:5} {x.license_spdx}{default}")
        typer.echo("")
        choice = typer.prompt("Select a model by number (or type a model id)", default="1")
        if choice.strip().isdigit():
            idx = int(choice) - 1
            if not (0 <= idx < len(green)):
                typer.secho("Invalid selection.", fg=typer.colors.RED)
                raise typer.Exit(code=2)
            model = green[idx].id
        else:
            model = choice.strip()

    info = m.get(model)
    if info is None:
        typer.secho(
            f"Unknown model '{model}'. Run 'vantage ai models --all' to see options.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    if info.license_class is LicenseClass.YELLOW and not accept_yellow:
        typer.secho(
            f"'{model}' is license class YELLOW ({info.license_spdx}) — it carries usage "
            "restrictions and needs a recorded review before commercial use. Re-run with "
            "--accept-yellow to select it anyway.",
            fg=typer.colors.YELLOW,
        )
        raise typer.Exit(code=2)

    cfg = VantageConfig.load()
    cfg.ai.model = model
    if provider is not None:
        cfg.ai.provider = provider.lower()
    elif cfg.ai.provider == "none":
        # Pick a sensible provider if the user hasn't chosen one yet.
        cfg.ai.provider = "ollama"
    if model_path is not None:
        cfg.ai.model_path = model_path
    if ollama_url is not None:
        cfg.ai.ollama_url = ollama_url
    path = cfg.save()

    typer.secho(
        f"Selected {model} ({info.license_spdx}, {info.license_class.value}) via "
        f"provider '{cfg.ai.provider}'.",
        fg=typer.colors.GREEN,
    )
    typer.echo(f"Saved to {path}.")
    if cfg.ai.provider == "llama_cpp" and not cfg.ai.model_path:
        typer.secho(
            "llama_cpp selected but no --model-path set; provide a GGUF path before scanning.",
            fg=typer.colors.YELLOW,
        )
    typer.echo("Enable it on a scan with: vantage scan <url> --authorize --ai")


@ai_app.command("info")
def ai_info() -> None:
    """Show the configured on-premise AI provider/model and its availability."""
    import asyncio

    from vantage.app import build_ai_provider_from_env

    provider = build_ai_provider_from_env()
    if provider is None:
        typer.echo("AI provider: none (deterministic engines only).")
        typer.echo("Set VANTAGE_AI_PROVIDER=ollama|llama_cpp to enable the on-prem AI layer.")
        return
    available = asyncio.run(provider.available())
    typer.echo(f"AI provider: {provider.name}")
    typer.echo(f"Model:       {provider.model_id}")
    typer.echo(f"License:     {provider.model_license}")
    typer.secho(
        f"Available:   {available}",
        fg=typer.colors.GREEN if available else typer.colors.YELLOW,
    )
    if not available:
        typer.echo("(Model/runtime not reachable — install the model or start the daemon.)")


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
    ai: Annotated[
        bool,
        typer.Option("--ai", help="Enable the on-prem AI layer (uses VANTAGE_AI_* config)"),
    ] = False,
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

    from vantage.app import build_ai_provider_from_env

    # In local (Kali/host) mode, auto-detect installed tools so the planner can
    # decide which of the natively-installed engines to use per target.
    ai_provider = build_ai_provider_from_env() if ai else None
    if ai and ai_provider is None:
        typer.secho(
            "--ai set but no on-prem AI model is configured. Run 'vantage ai select' to "
            "choose one (or set VANTAGE_AI_PROVIDER=ollama|llama_cpp). Continuing without AI.",
            fg=typer.colors.YELLOW,
        )
    sapp = VantageApp.build(
        bind_oss=not no_oss,
        sandbox_mode=sandbox,
        auto_detect=(sandbox.lower() == "local"),
        ai_provider=ai_provider,
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
