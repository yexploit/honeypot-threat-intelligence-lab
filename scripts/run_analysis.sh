#!/usr/bin/env bash
# Run full threat-intel analysis pipeline (works offline with sample data)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

LOG="${1:-data/sample_cowrie/cowrie.json}"
EXTRA=()
if [[ "${2:-}" == "--live-feeds" ]]; then
  EXTRA+=(--live-feeds)
fi

python3 -m honeypot_lab -f "$LOG" "${EXTRA[@]}"
