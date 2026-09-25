#!/usr/bin/env bash
# Install Vantage DAST on an existing Kali Linux / Debian host and enable the
# security engines that are already installed natively.
#
# Vantage runs the engines as native binaries (LocalSubprocessRunner). Only
# permissively licensed (GREEN) engines are installed by this script; GPL/AGPL
# tools that ship with Kali are intentionally left for a separate, reviewed
# decision (see docs/architecture/engine-architecture.md).
#
# Usage:  sudo ./deploy/install-kali.sh [--with-green-engines]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_ENGINES="${1:-}"

echo "[*] Installing Vantage DAST from ${REPO_ROOT}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[*] Installing Python..."
  apt-get update && apt-get install -y python3 python3-pip python3-venv
fi

if [[ "${WITH_ENGINES}" == "--with-green-engines" ]]; then
  echo "[*] Installing GREEN (permissively licensed) engines available in Kali..."
  apt-get update
  # Best-effort: package names vary across Kali snapshots.
  for pkg in nuclei ffuf feroxbuster katana httpx-toolkit subfinder dnsx gitleaks; do
    apt-get install -y --no-install-recommends "${pkg}" 2>/dev/null \
      && echo "    installed ${pkg}" \
      || echo "    (skipped ${pkg}: not available)"
  done
fi

echo "[*] Creating virtualenv at ${REPO_ROOT}/.venv"
python3 -m venv "${REPO_ROOT}/.venv"
"${REPO_ROOT}/.venv/bin/pip" install --upgrade pip
"${REPO_ROOT}/.venv/bin/pip" install "${REPO_ROOT}"

echo "[*] Verifying license policy (build gate)..."
"${REPO_ROOT}/.venv/bin/vantage" license check

echo "[*] Detecting installed engines..."
"${REPO_ROOT}/.venv/bin/vantage" engine detect || true

cat <<EOF

[+] Vantage DAST installed.

    Run a scan using natively-installed Kali tools:
      ${REPO_ROOT}/.venv/bin/vantage scan https://target.you.own/ \\
          --authorize --sandbox local --profile standard

    Start the API control plane (local engines):
      VANTAGE_SANDBOX=local VANTAGE_AUTODETECT=1 \\
        ${REPO_ROOT}/.venv/bin/uvicorn vantage.api.app:app --host 0.0.0.0 --port 8080

    Only scan systems you own or are explicitly authorized to test.
EOF
