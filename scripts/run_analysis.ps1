# Run full threat-intel analysis pipeline (works offline with sample data) — Windows
param(
  [string]$LogFile = "data\sample_cowrie\cowrie.json",
  [switch]$LiveFeeds
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$argsList = @("-m", "honeypot_lab", "-f", $LogFile)
if ($LiveFeeds) {
  $argsList += "--live-feeds"
}
python @argsList
