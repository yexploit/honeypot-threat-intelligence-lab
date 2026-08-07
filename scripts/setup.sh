#!/usr/bin/env bash
# Setup Honeypot Threat Intelligence Lab (Linux / macOS / Git Bash)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "[*] Installing Python dependencies..."
python3 -m pip install -r requirements.txt

if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "[+] Created .env from .env.example"
fi

echo "[*] Checking Docker (optional for live Cowrie + ELK)..."
if command -v docker >/dev/null 2>&1; then
  docker --version
  echo "[+] Docker available. Start honeypot with: ./scripts/start_lab.sh"
  echo "    Start with ELK:               ./scripts/start_lab.sh --elk"
else
  echo "[!] Docker not found - offline analysis with sample data still works."
fi

echo "[OK] Setup complete. Run analysis: ./scripts/run_analysis.sh"
