$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
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
& $Python -m azure_risk_tool scan --output .\output
