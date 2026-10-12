$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Compose = Join-Path $Root "localstack\compose.yml"
Set-Location $Root

docker compose -f $Compose up -d --build --force-recreate --wait

for ($i = 1; $i -le 90; $i++) {
    docker exec cloud-risk-localstack test -f /tmp/cloud-risk-lab-ready 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "LocalStack lab is ready."
        docker compose -f $Compose ps
        exit 0
    }
    Start-Sleep -Seconds 2
}

docker compose -f $Compose logs localstack
throw "LocalStack started, but the lab initialization did not complete."
