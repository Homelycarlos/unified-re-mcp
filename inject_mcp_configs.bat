@echo off
title NexusRE-MCP Universal IDE Installer
color 0b

:: 1. Auto-Elevate to Administrator
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
echo [*] Scanning system for dependencies...

:: 3. Check for `uv` (The blazing fast Python package manager)
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

:: 4. Auto-install Sandboxed Python (No system guis, no PATH issues)
echo [*] Syncing internal Python toolchain...
uv python install 3.12 --quiet

:: 5. Run the new universal installer engine
echo.
echo [*] Launching the auto-installer engine...
uv run main.py --install

echo.
pause
