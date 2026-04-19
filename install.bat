@echo off
title NexusRE-MCP Installer
color 0b

echo ==================================================
echo         NEXUSRE-MCP ONE-CLICK INSTALLER
echo ==================================================
echo.

:: Check for Python
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    color 0c
    echo [ERROR] Python is not installed or not in your system PATH!
    echo Please install Python 3.10 or higher from python.org, select "Add to PATH", and try again.
    pause
    exit /b 1
)

:: Check for uv package manager
python -m uv --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [~] 'uv' package manager not found. Installing via pip...
    python -m pip install uv
    IF %ERRORLEVEL% NEQ 0 (
        color 0c
        echo [ERROR] Failed to install 'uv' package manager via pip.
        pause
        exit /b 1
    )
)

echo [*] Synchronizing dependencies...
python -m uv sync

echo.
echo [*] Launching Setup Wizard...
python -m uv run main.py setup

echo.
pause
