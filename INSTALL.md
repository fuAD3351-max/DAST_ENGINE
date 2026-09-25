# Installing Vantage DAST on Linux

Step-by-step install from the GitHub repo. Tested on Debian/Ubuntu/Kali; adjust
the package-manager commands for your distro.

> Authorized testing only — scan systems you own or are explicitly authorized to
> assess. The CLI refuses to scan a target without `--authorize`.

---

## 0. Prerequisites

Required:
- **Python 3.11+** and `pip`, plus `git`.

Optional (enable more capabilities; skip if you only want the native engines):
- **Docker** — to run isolated open-source engines (`--sandbox docker`).
- Native engine binaries (Kali ships them) — for `--sandbox local`.
- **Ollama** or a GGUF file — for the on-prem AI layer.
- **Go 1.24+** — only if you want to build the optional Go egress proxy.

```bash
# Debian / Ubuntu / Kali
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git
```

---

## 1. Clone the repository

```bash
git clone https://github.com/fuAD3351-max/DAST_ENGINE.git
cd DAST_ENGINE
```

The active development branch is `claude/busy-tesla-e9m4et` and is the default,
so the clone above checks it out. If your clone landed elsewhere, switch to it:

```bash
git checkout claude/busy-tesla-e9m4et
```

---

## 2. Create a virtualenv and install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install .            # runtime install
# or, for development (tests, linters, type checker):
# pip install -e ".[dev]"
```

Optional extras:
```bash
pip install ".[ai]"        # on-prem LLM runtime (llama-cpp-python)
pip install ".[postgres]"  # PostgreSQL driver for the finding store
```

---

## 3. Verify the install

```bash
vantage version
vantage license check      # license-governance build gate (should print PASS)
vantage engine list        # the license-governed engine registry
```

If you installed the dev extras, run the test suite:
```bash
pytest -q                  # ~98 tests, fully offline
```

---

## 4. See it work against the bundled vulnerable app (offline)

```bash
python examples/run_demo.py                  # scans a bundled vulnerable target
python examples/run_demo.py --confirmed-only # only validated/corroborated findings
```

Expected: findings for missing security headers, insecure cookie, permissive
CORS, an exposed (fake) secret in crawled JS, and discovered endpoints — each
with a Proof-of-Vulnerability bundle.

---

## 5. Launch the web console (UI)

```bash
uvicorn vantage.api.app:app --host 0.0.0.0 --port 8080
```
Open **http://127.0.0.1:8080/** (also at `/ui`). It's a self-contained,
air-gapped console (engine registry, targets, scans, findings + proofs).

Environment variables the server honours:
- `VANTAGE_DATABASE_URL` (e.g. `postgresql+psycopg://user:pass@host/db`; default: in-memory SQLite)
- `VANTAGE_SANDBOX` = `auto` | `docker` | `local` | `fake`
- `VANTAGE_AUTODETECT` = `1` to auto-enable installed native engines

---

## 6. Scan your own target

Native engines only (nothing else to install):
```bash
vantage scan http://127.0.0.1:3000/ --authorize --profile standard --format markdown
```

With the isolated open-source engines (Nuclei/ffuf/…):
```bash
# on Kali (native binaries): auto-detects installed tools
vantage scan http://127.0.0.1:3000/ --authorize --sandbox local
# anywhere with Docker (pulls pinned engine images):
vantage scan http://127.0.0.1:3000/ --authorize --sandbox docker
```

Profiles: `passive` (no crafted input) · `standard` · `deep`.
Add `--confirmed-only` for the low-false-positive view, `--ai` for AI triage.

Try a known-vulnerable app:
```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop      # OWASP Juice Shop
vantage scan http://127.0.0.1:3000/ --authorize --sandbox docker
```

---

## 7. Install the on-premise AI model (optional)

```bash
vantage ai models          # list commercially-licensed on-prem models
vantage ai select          # choose one (interactive), persisted to config
vantage ai install         # fetch + verify the pinned model (Ollama or GGUF)
vantage ai info            # show provider/model/availability
# then add --ai to a scan
```
Default model: **Qwen2.5-7B-Instruct (Apache-2.0)**. Air-gapped: stage a GGUF and
`vantage ai install --backend llama_cpp --from /path/to/model.gguf`.

---

## 8. Containerised / one-shot deployments (optional)

```bash
# Control plane only (engines run as sidecars/host):
docker build -f deploy/Dockerfile -t vantage-dast .
docker run --rm -p 8080:8080 vantage-dast

# All-in-one on Kali (bundles native GREEN engines + AI):
docker build -f deploy/Dockerfile.kali -t vantage-dast:kali .
docker run --rm -p 8080:8080 vantage-dast:kali

# Private-cloud stack (control plane + Postgres + Redis):
docker compose -f deploy/docker-compose.yml up --build

# Native install on an existing Kali/Linux host (venv + engines + AI + verify):
sudo ./deploy/install-kali.sh --with-green-engines
```
A systemd unit is provided at `deploy/vantage.service`.

---

## 9. Optional: build the Go egress proxy

```bash
cd components/egress-proxy
go build -o vantage-egress-proxy .
go test ./...
```

---

## Troubleshooting

- **`vantage: command not found`** — activate the venv (`source .venv/bin/activate`).
- **`license check` fails** — a dependency/engine violates the license policy;
  the message names it. See `third_party/`.
- **Scan finds nothing** — confirm the target is reachable and in scope; a raw
  private IP target is in scope automatically, a hostname you must be able to
  resolve.
- **Docker sandbox errors** — ensure your user can run `docker`; otherwise use
  `--sandbox local` (host binaries) or native-only (omit `--sandbox`).

## Uninstall

```bash
deactivate 2>/dev/null || true
rm -rf .venv           # remove the environment
# and delete the cloned DAST_ENGINE directory
```
