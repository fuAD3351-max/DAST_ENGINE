"""A deliberately-insecure demo web app for exercising Vantage DAST.

FOR AUTHORIZED TESTING ONLY. This app intentionally ships weak *configuration*
so Vantage's native engines have something real to detect. Every "secret" here
is fake and every weakness is benign — it is a target range, not a real service.
Run it only on a host you control (defaults to 127.0.0.1).

Weaknesses planted (all detectable by the native engines):
* no security headers (CSP / HSTS / X-Content-Type-Options / Referrer-Policy)
* a Set-Cookie with no Secure/HttpOnly/SameSite
* a Server version banner (information disclosure)
* permissive CORS (Access-Control-Allow-Origin: * with credentials)
* a fake AWS-style key embedded in a served .js file (secret exposure)
* a reflected, inert marker on /search (reflection-consistency validation)
* a directory-listing-style page

Stdlib only; no dependencies.

    python examples/vulnerable-app/app.py --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

FAKE_JS = (
    "// demo bundle — FAKE credentials for DAST testing only\n"
    "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
    "fetch('/api/user/1');\nfetch('/api/user/2');\n"
    "const api = '/api/orders';\n"
)

INDEX = (
    "<html><head><title>Vulnerable Demo</title></head><body>"
    "<h1>Vantage target range</h1>"
    "<a href='/search?q=hello'>search</a> "
    "<a href='/files/'>files</a> "
    "<script src='/static/app.js'></script>"
    "</body></html>"
)


class Handler(BaseHTTPRequestHandler):
    server_version = "DemoServer/1.4.2"  # version banner (info disclosure)
    sys_version = ""

    def _headers(self, status: int, ctype: str, extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        # Intentionally omit CSP/HSTS/X-Content-Type-Options/Referrer-Policy.
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path

        if path == "/":
            # Insecure cookie: no Secure/HttpOnly/SameSite. Permissive CORS.
            self._headers(
                200,
                "text/html",
                {
                    "Set-Cookie": "sid=abc123",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )
            self.wfile.write(INDEX.encode())
        elif path == "/static/app.js":
            self._headers(200, "application/javascript")
            self.wfile.write(FAKE_JS.encode())
        elif path == "/search":
            q = parse_qs(parts.query).get("q", [""])[0]
            # Reflect the input verbatim (inert marker → reflection validation).
            body = f"<html><body>results for: {q}</body></html>"
            self._headers(200, "text/html")
            self.wfile.write(body.encode())
        elif path.rstrip("/") == "/files":
            body = (
                "<html><head><title>Directory listing</title></head>"
                "<body><h1>Index of /files</h1><ul><li>notes.txt</li></ul></body></html>"
            )
            self._headers(200, "text/html")
            self.wfile.write(body.encode())
        elif path.startswith("/api/"):
            self._headers(200, "application/json")
            self.wfile.write(b'{"ok": true}')
        else:
            self._headers(404, "text/plain")
            self.wfile.write(b"not found")

    def log_message(self, *args: object) -> None:  # silence default logging
        return


def main() -> None:
    ap = argparse.ArgumentParser(description="Vantage deliberately-vulnerable demo app")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"Vulnerable demo app on http://{args.host}:{args.port} (authorized testing only)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
