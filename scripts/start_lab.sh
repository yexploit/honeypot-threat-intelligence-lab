#!/usr/bin/env bash
# Start Cowrie honeypot (optional ELK) via Docker Compose
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ELK=0
for arg in "$@"; do
  case "$arg" in
    --elk|-e) ELK=1 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "[!] Docker is required for live honeypot deployment."
  exit 1
fi

if [[ ! -f .env ]]; then
  cp .env.example .env
fi

echo "[!] SAFETY: Only expose ports on isolated lab VMs / cloud honeypot hosts."
echo "[!] Do not forward 22/23 on production machines. Default maps 2222/2223."

if [[ "$ELK" -eq 1 ]]; then
  echo "[*] Starting Cowrie + ELK Stack..."
  docker compose --profile elk up -d
  echo "[+] Kibana: http://localhost:${KIBANA_PORT:-5601}"
  echo "[+] Elasticsearch: http://localhost:${ES_PORT:-9200}"
else
  echo "[*] Starting Cowrie honeypot..."
  docker compose up -d cowrie
fi

echo "[+] Cowrie SSH (mapped):   localhost:${COWRIE_SSH_PORT:-2222}"
echo "[+] Cowrie Telnet (mapped): localhost:${COWRIE_TELNET_PORT:-2223}"
echo "[*] Copy live logs later with: docker cp honeypot_cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json ./data/live_cowrie.json"
