@echo off
title BountyAI Launcher
color 0A
cls

echo.
echo   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗ █████╗ ██╗
echo   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝██╔══██╗██║
echo   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ ███████║██║
echo   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  ██╔══██║██║
echo   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   ██║  ██║██║
echo   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝╚═╝
echo.
echo   AI-Powered Bug Bounty Assistant  ^|  FYP 2025-26
echo   Domains: AI + Full Stack + Cybersecurity
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    python3 --version >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Python not found! Install from https://python.org
        pause
        exit /b 1
    )
    set PY=python3
) else (
    set PY=python
)
echo [OK] Python found

:: Kill old server on port 5000 if running
FOR /F "tokens=5 delims= " %%a IN ('netstat -ano ^| findstr ":5000 " 2^>nul') DO taskkill /PID %%a /F >nul 2>&1
timeout /t 1 /nobreak >nul

:: Create .env if needed
if not exist "%~dp0.env" (
    copy "%~dp0.env.example" "%~dp0.env" >nul
    echo [INFO] .env created - edit to add your API keys
) else (
    echo [OK] .env found
)

:: Open browser after 1.5 seconds
start "" timeout /t 2 /nobreak >nul & start http://localhost:5000

echo.
echo  +--------------------------------------------------+
echo  ^|   BountyAI is starting...                       ^|
echo  ^|                                                  ^|
echo  ^|   App:    http://localhost:5000                  ^|
echo  ^|   API:    http://localhost:5000/api/health       ^|
echo  ^|                                                  ^|
echo  ^|   Browser will open automatically               ^|
echo  ^|   Press Ctrl+C to stop                          ^|
echo  +--------------------------------------------------+
echo.

%PY% "%~dp0server\server.py"
pause
