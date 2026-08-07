# Start Cowrie honeypot (optional ELK) via Docker Compose — Windows
param(
  [switch]$Elk
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
  Write-Host "[!] Docker Desktop is required for live honeypot deployment."
  exit 1
}

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
}

Write-Host "[!] SAFETY: Only expose ports on isolated lab VMs / cloud honeypot hosts."
Write-Host "[!] Do not forward 22/23 on production machines. Default maps 2222/2223."

if ($Elk) {
  Write-Host "[*] Starting Cowrie + ELK Stack..."
  docker compose --profile elk up -d
  Write-Host "[+] Kibana: http://localhost:5601"
  Write-Host "[+] Elasticsearch: http://localhost:9200"
} else {
  Write-Host "[*] Starting Cowrie honeypot..."
  docker compose up -d cowrie
}

Write-Host "[+] Cowrie SSH (mapped):    localhost:2222"
Write-Host "[+] Cowrie Telnet (mapped): localhost:2223"
Write-Host "[*] Copy live logs later with:"
Write-Host '    docker cp honeypot_cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json .\data\live_cowrie.json'
