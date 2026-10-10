@echo off
REM AppSentinel // Launch MobSF in Docker
echo ========================================================
echo Starting MobSF (Mobile Security Framework) in Docker...
echo Source: https://github.com/MobSF/Mobile-Security-Framework-MobSF
echo ========================================================

cd /d "%~dp0.."
docker compose up -d mobsf

echo.
echo MobSF Container is running!
echo URL: http://localhost:8001
echo Check container status with: docker ps
pause
