# Testing Vantage against a vulnerable app

Two ways to exercise the platform: the **bundled demo target** (zero setup,
fully offline), or **your own locally-installed vulnerable app** (Juice Shop,
DVWA, etc.) for further development.

> Authorized testing only. Scan only hosts you control. The bundled demo binds
> to `127.0.0.1` and its "secrets" are fake.

## Option A — the bundled demo target (offline, one command)

```bash
python examples/run_demo.py                 # markdown report
python examples/run_demo.py --confirmed-only # only validated/corroborated findings
python examples/run_demo.py --format json   # machine-readable, includes proofs
```

This starts `examples/vulnerable-app/app.py` on localhost and scans it with the
native engines. Expected results (no external tools needed):

- `missing_security_header` (CSP/HSTS/X-Content-Type-Options/Referrer-Policy) — **confirmed**
- `cors_misconfiguration` (ACAO `*` + credentials) — **confirmed**
- `insecure_cookie` (no Secure/HttpOnly/SameSite) — **confirmed**
- `secret_exposure` — a fake AWS key found in the crawled `/static/app.js`
  (via the discovery→audit feedback loop), value **redacted**, severity HIGH
- `information_disclosure` — discovered endpoints (server banner, `/api/user/{id}`, …)

Every finding carries a Proof-of-Vulnerability bundle (verdict + differential +
reproduction + integrity hash). `--confirmed-only` shows just the
confirmed/corroborated ones — the low-false-positive view. (Single-engine
findings such as the secret show in the full report as `reported`; they are not
hidden, just separated from validated ones.)

Run the vulnerable app on its own (e.g. to point other tools at it):

```bash
python examples/vulnerable-app/app.py --host 127.0.0.1 --port 8000
```

## Option B — your own vulnerable app (for development)

Install a target on your Linux box, then point the CLI at it. Examples:

```bash
# OWASP Juice Shop (Node)
docker run --rm -p 3000:3000 bkimminich/juice-shop
vantage scan http://127.0.0.1:3000/ --authorize --profile standard --format markdown

# DVWA
docker run --rm -p 8080:80 vulnerables/web-dvwa
vantage scan http://127.0.0.1:8080/ --authorize --profile standard
```

Notes for local targets:
- A `127.0.0.1`/`10.x`/`192.168.x` target is in scope automatically because the
  auto-generated scope rule *is* that private host (the private-address guard
  only blocks private hosts that are **not** explicitly in scope).
- `--profile passive` sends no crafted input; `standard` adds active/template
  checks; `deep` widens coverage.
- Add the isolated OSS engines for deeper coverage:
  `--sandbox local` (uses natively-installed Kali tools, auto-detected) or
  `--sandbox docker` (pulls pinned engine images). Native-only is the default
  shown above and needs nothing installed.
- Turn on the on-prem AI triage with `--ai` after `vantage ai install`.

## What this proves

The demo exercises the whole native pipeline end-to-end over real HTTP:
crawl → discovery→audit feedback → header/cookie/CORS/secret/TLS analysis →
validation (config findings become `confirmed`) → correlation (crawler+headers
merge into one corroborated finding per endpoint) → risk scoring → proof bundles.
The integration test `tests/test_demo_integration.py` runs exactly this and
asserts the planted weaknesses are found, secrets are redacted, and no finding
references an out-of-scope host.
