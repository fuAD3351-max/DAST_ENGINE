"""FastAPI control-plane surface.

Exposes the same capabilities as the CLI over HTTP: engine registry, license
governance status, target registration and scan execution/reporting. This is a
reference control plane - authentication/RBAC/multi-tenancy hooks are indicated
where an enterprise deployment wires in its identity provider.

Scans run in a background task; the reference build executes them in-process for
simplicity. A production deployment routes them to the worker queue.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, Field

from sentinel import __version__
from sentinel.domain import (
    ApplicationKind,
    AuthorizationMethod,
    AuthorizationRecord,
    Scan,
    ScanPolicy,
    ScanProfile,
    Target,
    utcnow,
)
from sentinel.domain.target import ScopeRule
from sentinel.findings import reporting
from sentinel.scope.engine import default_scope_rules_for


class TargetCreate(BaseModel):
    name: str
    base_urls: list[str] = Field(min_length=1)
    kind: ApplicationKind = ApplicationKind.UNKNOWN
    authorized: bool = Field(
        default=False,
        description="Caller asserts authorization to test these targets.",
    )
    scope_rules: list[ScopeRule] = Field(default_factory=list)


class ScanCreate(BaseModel):
    target_id: str
    profile: ScanProfile = ScanProfile.STANDARD


def get_app_state() -> Any:  # overridden via dependency_overrides in tests
    raise HTTPException(status_code=500, detail="app state not configured")


def create_api(sentinel_app: Any | None = None, *, tenant: str = "default") -> FastAPI:
    """Build the FastAPI app. If ``sentinel_app`` is None it is built lazily."""
    from sentinel.app import SentinelApp

    api = FastAPI(title="Sentinel DAST Control Plane", version=__version__)
    state: dict[str, Any] = {"app": sentinel_app, "targets": {}, "reports": {}}

    def app_() -> Any:
        if state["app"] is None:
            state["app"] = SentinelApp.build()
        return state["app"]

    @api.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @api.get("/engines")
    def engines() -> list[dict[str, Any]]:
        return [
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
                "notes": e.notes,
            }
            for e in app_().registry.all()
        ]

    @api.post("/targets", status_code=201)
    def create_target(body: TargetCreate) -> dict[str, Any]:
        auth = (
            AuthorizationRecord(
                method=AuthorizationMethod.SIGNED_ATTESTATION,
                verified_at=utcnow(),
                verified_by="api",
            )
            if body.authorized
            else None
        )
        target = Target(
            tenant_id=tenant,
            name=body.name,
            base_urls=body.base_urls,
            kind=body.kind,
            scope_rules=body.scope_rules,
            authorization=auth,
        )
        if not target.scope_rules:
            target = target.model_copy(update={"scope_rules": default_scope_rules_for(target)})
        state["targets"][target.id] = target
        return {"id": target.id, "authorized": target.is_authorized()}

    @api.get("/targets/{target_id}")
    def get_target(target_id: str) -> dict[str, Any]:
        target = state["targets"].get(target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="target not found")
        result: dict[str, Any] = target.model_dump(mode="json")
        return result

    @api.post("/scans", status_code=201)
    async def create_scan(body: ScanCreate) -> dict[str, Any]:
        target = state["targets"].get(body.target_id)
        if target is None:
            raise HTTPException(status_code=404, detail="target not found")
        if not target.is_authorized():
            raise HTTPException(
                status_code=403,
                detail="target has no valid authorization record; cannot scan",
            )
        scan = Scan(
            tenant_id=tenant,
            target_id=target.id,
            policy=ScanPolicy(profile=body.profile),
            created_by="api",
        )
        report = await app_().orchestrator.run(scan, target)
        state["reports"][report.scan.id] = report
        return {
            "scan_id": report.scan.id,
            "state": report.scan.state.value,
            "findings": len(report.findings),
            "by_severity": reporting.summarize(report.findings),
        }

    @api.get("/scans/{scan_id}/report")
    def get_report(scan_id: str, fmt: str = "json") -> Any:
        report = state["reports"].get(scan_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        from fastapi.responses import PlainTextResponse

        if fmt == "json":
            import json

            return json.loads(reporting.to_json(report))
        return PlainTextResponse(reporting.render(report, fmt))

    api.dependency_overrides[get_app_state] = app_  # allow tests to introspect
    return api


# Default ASGI app for `uvicorn sentinel.api.app:app`.
app = create_api()


AppDep = Annotated[Any, Depends(get_app_state)]
