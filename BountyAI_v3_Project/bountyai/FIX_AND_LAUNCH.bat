@echo off
title BountyAI FIX + LAUNCH
color 0A
cls
echo.
echo  =========================================================
echo    STEP 1: Killing old server...
echo  =========================================================
FOR /F "tokens=5 delims= " %%a IN ('netstat -ano ^| findstr ":5000 " 2^>nul') DO taskkill /PID %%a /F >nul 2>&1
timeout /t 1 /nobreak >nul

echo.
echo  =========================================================
echo    STEP 2: Fixing broken HTML tabs...
echo  =========================================================
python "%~dp0server\FIX_NOW.py"
if %errorlevel% neq 0 (
    echo [ERROR] Fix script failed - trying python3...
    python3 "%~dp0server\FIX_NOW.py"
)

echo.
echo  =========================================================
echo    STEP 3: Starting server...
echo    App: http://localhost:5000
echo    Press Ctrl+C to stop
echo  =========================================================
echo.
timeout /t 2 /nobreak >nul
start "" "http://localhost:5000"
python "%~dp0server\server.py"
pause
