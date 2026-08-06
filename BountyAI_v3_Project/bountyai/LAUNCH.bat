@echo off
title BountyAI - Launch
color 0A
cls

echo.
echo  =========================================================
echo    BountyAI v3.0  -  Clean Launch
echo  =========================================================
echo.

:: ── Step 1: Kill any old server on port 5000
echo  [1/3] Freeing port 5000...
FOR /F "tokens=5 delims= " %%a IN ('netstat -ano ^| findstr ":5000 " 2^>nul') DO (
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 1 /nobreak >nul
echo       Done.

:: ── Step 2: Auto-fix HTML bugs
echo  [2/3] Running HTML auto-fix...
python "%~dp0server\master_fix.py"

:: ── Step 3: Start server
echo  [3/3] Starting server...
echo.
echo  =========================================================
echo    URL:   http://localhost:5000
echo    API:   http://localhost:5000/api/health
echo    Press Ctrl+C to stop
echo  =========================================================
echo.

timeout /t 2 /nobreak >nul
start "" "http://localhost:5000"
python "%~dp0server\server.py"
pause
