$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
docker compose -f .\topaz\compose.yml down -v --remove-orphans
docker compose -f .\topaz\compose.yml up -d --build
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
& $Python -m pip install -e .
& $Python .\topaz\init-azure.py
