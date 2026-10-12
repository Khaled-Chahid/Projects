$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $env:LOCALAPPDATA "CloudRiskTool\venv\Scripts\python.exe"
Set-Location $Root

if (-not (Test-Path $Python)) { throw "Run scripts\quickstart.ps1 first." }
& $Python -m cloud_risk_tool scan --target localstack --output-dir output
