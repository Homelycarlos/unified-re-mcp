@echo off
title NexusRE-MCP Universal IDE Installer
color 0b

:: 1. Auto-Elevate to Administrator (Windows 10 / Windows 11 compatibility)
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:: 2. Force execution in the exact same directory as the batch file
pushd "%~dp0"

echo =======================================================
echo     NEXUSRE-MCP UNIVERSAL IDE AUTO-INSTALLER
echo =======================================================
echo.
echo [*] Scanning system for supported IDEs and code clients...

:: 3. Detect Python executable
set PYTHON_CMD=python
%PYTHON_CMD% --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    set PYTHON_CMD=py
    py --version >nul 2>&1
    IF ERRORLEVEL 1 (
        color 0c
        echo [ERROR] Python is not installed or not in your system PATH!
        echo Please install Python 3.10 or higher from python.org, select "Add to PATH", and try again.
        pause
        exit /b 1
    )
)

:: 4. Ensure uv is installed
%PYTHON_CMD% -m uv --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [~] 'uv' package manager not found. Installing via pip...
    %PYTHON_CMD% -m pip install uv >nul 2>&1
)

:: 5. Run the new universal installer engine
echo [*] Launching the python MCP installer engine...
%PYTHON_CMD% -m uv run main.py --install

echo.
pause
