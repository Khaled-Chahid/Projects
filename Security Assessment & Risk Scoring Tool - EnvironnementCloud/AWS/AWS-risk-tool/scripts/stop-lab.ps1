$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Compose = Join-Path $Root "localstack\compose.yml"
Set-Location $Root

docker compose -f $Compose down
