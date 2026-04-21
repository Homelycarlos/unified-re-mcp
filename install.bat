@echo off
title NexusRE-MCP Installer
color 0b

:: Auto-Elevate to Administrator
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo [*] Requesting Administrator privileges...
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:: Force execution in the exact same directory as the batch file
pushd "%~dp0"

echo ==================================================
echo         NEXUSRE-MCP ONE-CLICK INSTALLER
echo ==================================================
echo.

:: Check for uv
where uv >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    if exist "%USERPROFILE%\.cargo\bin\uv.exe" (
        set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
    ) else (
        echo [*] 'uv' package manager not found. Downloading standalone version...
        powershell -ExecutionPolicy Bypass -Command "irm https://astral.sh/uv/install.ps1 | iex"
        if exist "%USERPROFILE%\.cargo\bin\uv.exe" (
            set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
        ) else (
            color 0c
            echo [ERROR] Failed to install uv. Please ensure you have internet access.
            pause
            exit /b 1
        )
    )
)

echo [*] Syncing internal Python toolchain...
uv python install 3.12 --quiet

echo [*] Synchronizing dependencies...
uv sync

echo.
echo [*] Launching Setup Wizard...
uv run main.py setup

echo.
pause
