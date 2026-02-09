@echo off
title StealthLink Agent
color 0A

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Administrator privileges required.
    echo     Right-click this file and select "Run as administrator".
    pause
    exit /b 1
)

echo ============================================
echo   StealthLink Agent for Windows
echo ============================================
echo.

:: Check if PowerShell is available
where powershell >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] PowerShell is required but not found.
    pause
    exit /b 1
)

:: Launch PowerShell script
powershell -ExecutionPolicy Bypass -File "%~dp0stealthlink-agent.ps1" %*

if %errorlevel% neq 0 (
    echo.
    echo [!] StealthLink Agent exited with error code %errorlevel%
)

pause
