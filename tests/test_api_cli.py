"""API and CLI smoke tests."""

from __future__ import annotations

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from vantage.api.app import create_api
from vantage.app import VantageApp
from vantage.cli.main import app as cli_app

runner = CliRunner()


def _api_client() -> TestClient:
    sapp = VantageApp.build(bind_oss=False, validate_findings=False)
    return TestClient(create_api(sapp, tenant="test"))


def test_health() -> None:
    client = _api_client()
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_engines_endpoint_lists_governed_engines() -> None:
    client = _api_client()
    r = client.get("/engines")
    assert r.status_code == 200
    engines = {e["id"]: e for e in r.json()}
    assert engines["trufflehog"]["license_class"] == "RED"
    assert engines["trufflehog"]["usable"] is False
    assert engines["vantage-headers"]["usable"] is True


def test_scan_requires_authorization() -> None:
    client = _api_client()
    r = client.post(
        "/targets", json={"name": "x", "base_urls": ["https://x.invalid/"], "authorized": False}
    )
    tid = r.json()["id"]
    r2 = client.post("/scans", json={"target_id": tid, "profile": "passive"})
    assert r2.status_code == 403


def test_scan_flow_authorized() -> None:
    client = _api_client()
    r = client.post(
        "/targets",
        json={"name": "x", "base_urls": ["https://x.invalid/"], "authorized": True},
    )
    assert r.status_code == 201
    tid = r.json()["id"]
    assert r.json()["authorized"] is True
    r2 = client.post("/scans", json={"target_id": tid, "profile": "passive"})
    assert r2.status_code == 201
    scan_id = r2.json()["scan_id"]
    rep = client.get(f"/scans/{scan_id}/report", params={"fmt": "json"})
    assert rep.status_code == 200


def test_cli_version() -> None:
    result = runner.invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert "Vantage DAST" in result.stdout


def test_cli_license_check_passes() -> None:
    result = runner.invoke(cli_app, ["license", "check"])
    assert result.exit_code == 0


def test_cli_engine_list() -> None:
    result = runner.invoke(cli_app, ["engine", "list"])
    assert result.exit_code == 0
    assert "nuclei" in result.stdout


def test_cli_scan_refuses_without_authorize() -> None:
    result = runner.invoke(cli_app, ["scan", "https://x.invalid/"])
    assert result.exit_code == 2
    assert "authorize" in result.stdout.lower()


def test_console_ui_served() -> None:
    client = _api_client()
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert "Vantage" in body and "DAST Console" in body
    # Self-contained: no external script/style origins (air-gapped safe).
    assert "cdn" not in body.lower()
    assert "http://" not in body.replace("http://127.0.0.1", "").replace("http://{", "")
    assert "https://" not in body


def test_console_ui_alias() -> None:
    r = _api_client().get("/ui")
    assert r.status_code == 200
    assert "DAST Console" in r.text
