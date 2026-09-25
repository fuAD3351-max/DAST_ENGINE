"""Run Vantage against the bundled vulnerable demo app, end-to-end, offline.

Starts the deliberately-vulnerable app on localhost, scans it with the native
engines, and prints the report. Use it to see the platform's capabilities
without any external target.

    python examples/run_demo.py [--format markdown|json|sarif] [--confirmed-only]

For your own locally-installed vulnerable app (e.g. OWASP Juice Shop on :3000),
skip this and run the CLI directly:

    vantage scan http://127.0.0.1:3000/ --authorize --profile standard
"""

from __future__ import annotations

import argparse
import asyncio
import threading
import time
from http.server import ThreadingHTTPServer

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


def _start_app(host: str, port: int) -> ThreadingHTTPServer:
    # Import the handler from the sibling module.
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "vuln_app", Path(__file__).parent / "vulnerable-app" / "app.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    srv = ThreadingHTTPServer((host, port), module.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


async def _run(fmt: str, confirmed_only: bool, host: str, port: int) -> int:
    url = f"http://{host}:{port}/"
    app = VantageApp.build(bind_oss=False)  # native engines; real HTTP to localhost
    target = Target(
        tenant_id="demo",
        name="vulnerable-demo",
        base_urls=[url],
        kind=ApplicationKind.TRADITIONAL_WEB,
        authorization=AuthorizationRecord(
            method=AuthorizationMethod.SIGNED_ATTESTATION,
            verified_at=utcnow(),
            verified_by="run_demo",
        ),
    )
    target = target.model_copy(update={"scope_rules": default_scope_rules_for(target)})
    scan = Scan(
        tenant_id="demo",
        target_id=target.id,
        policy=ScanPolicy(profile=ScanProfile.STANDARD),
        created_by="run_demo",
    )
    report = await app.orchestrator.run(scan, target)
    if confirmed_only:
        report = reporting.filter_confirmed(report)
    print(reporting.render(report, fmt))
    return len(report.findings)


def main() -> None:
    ap = argparse.ArgumentParser(description="Run Vantage against the vulnerable demo app")
    ap.add_argument("--format", default="markdown", choices=["markdown", "json", "sarif"])
    ap.add_argument("--confirmed-only", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()

    srv = _start_app(args.host, args.port)
    time.sleep(0.5)
    try:
        n = asyncio.run(_run(args.format, args.confirmed_only, args.host, args.port))
        print(f"\n[demo] {n} finding(s) reported.", flush=True)
    finally:
        srv.shutdown()
        srv.server_close()


if __name__ == "__main__":
    main()
