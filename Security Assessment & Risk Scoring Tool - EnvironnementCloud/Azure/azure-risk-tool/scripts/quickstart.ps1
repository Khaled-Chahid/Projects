$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or is not available in PATH."
}
docker info | Out-Null
if (-not (Test-Path .\.venv\Scripts\python.exe)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv .venv
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        & python -m venv .venv
    } else {
        throw "Python 3.10 or newer is required."
    }
}
$Python = Join-Path $Root ".venv\Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install -e .
docker compose -f .\topaz\compose.yml up -d --build
& $Python .\topaz\init-azure.py
& $Python -m azure_risk_tool scan --output .\output
$Report = Join-Path $Root "output\report.html"
if (Test-Path $Report) {
    Start-Process $Report
}
