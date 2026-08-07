#!/usr/bin/env bash
# Stop all lab containers
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose --profile elk down
echo "[OK] Lab stopped."
