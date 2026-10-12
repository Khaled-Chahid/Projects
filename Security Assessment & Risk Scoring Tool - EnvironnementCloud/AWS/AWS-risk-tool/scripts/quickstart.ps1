$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Runtime = Join-Path $env:LOCALAPPDATA "CloudRiskTool"
$Venv = Join-Path $Runtime "venv"
$Python = Join-Path $Venv "Scripts\python.exe"
Set-Location $Root

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker is not installed or not in PATH." }
if (-not (Get-Command python -ErrorAction SilentlyContinue)) { throw "Python is not installed or not in PATH." }

New-Item -ItemType Directory -Force -Path $Runtime | Out-Null
if (-not (Test-Path $Python)) { python -m venv $Venv }
& $Python -m pip install --upgrade pip
& $Python -m pip install -e .
& .\scripts\start-lab.ps1
& .\scripts\scan-localstack.ps1
Write-Host "Report: $Root\output\report.html"
