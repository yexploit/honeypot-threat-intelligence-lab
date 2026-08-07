# Stop all lab containers — Windows
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
docker compose --profile elk down
Write-Host "[OK] Lab stopped."
