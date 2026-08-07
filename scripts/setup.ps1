# Setup Honeypot Threat Intelligence Lab (Windows PowerShell)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "[*] Installing Python dependencies..."
python -m pip install -r requirements.txt

if (-not (Test-Path ".env")) {
  Copy-Item ".env.example" ".env"
  Write-Host "[+] Created .env from .env.example"
}

Write-Host "[*] Checking Docker (optional for live Cowrie + ELK)..."
if (Get-Command docker -ErrorAction SilentlyContinue) {
  docker --version
  Write-Host "[+] Docker available. Start honeypot with: .\scripts\start_lab.ps1"
  Write-Host "    Start with ELK:               .\scripts\start_lab.ps1 -Elk"
} else {
  Write-Host "[!] Docker not found - offline analysis with sample data still works."
}

Write-Host "[OK] Setup complete. Run analysis: .\scripts\run_analysis.ps1"
