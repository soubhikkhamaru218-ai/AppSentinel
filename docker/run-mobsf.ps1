# AppSentinel // Launch MobSF in Docker
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting MobSF (Mobile Security Framework) in Docker..." -ForegroundColor Cyan
Write-Host "Source: https://github.com/MobSF/Mobile-Security-Framework-MobSF" -ForegroundColor DarkGray
Write-Host "========================================================" -ForegroundColor Cyan

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $projectRoot

docker compose up -d mobsf

Write-Host "`nMobSF Container launched successfully!" -ForegroundColor Green
Write-Host "Web Interface: http://localhost:8001" -ForegroundColor Yellow
Write-Host "AppSentinel configured to communicate via REST API." -ForegroundColor Gray
