@echo off
REM ============================================================================
REM letsgo-wsl.bat — Windows-via-WSL2 launcher for MXD nodes
REM
REM This is the prebuilt-binary path for Windows. It uses WSL2 (Windows
REM Subsystem for Linux) under the hood:
REM   1. Checks if WSL2 is installed; if not, runs `wsl --install`
REM   2. (Reboot required after first WSL install — Windows handles this)
REM   3. Clones AlanRuno/mxd inside WSL and runs ./letsgo testnet|mainnet
REM      which downloads the prebuilt bundle from the GitHub Release.
REM
REM Total time on a clean machine: ~5-10 min (mostly WSL+Ubuntu download).
REM On a machine that already has WSL2: ~30 seconds (just the prebuilt
REM tarball download + extract + node start).
REM
REM Requirements: Windows 10 21H2+ or Windows 11 (any edition). Admin
REM rights ONLY needed on first run if WSL isn't installed yet.
REM
REM Companion files in this repo:
REM   - letsgo (bash) — the Linux/WSL/macOS path; this .bat delegates here
REM   - letsgo.bat    — MSYS2/MinGW64 path (compiles from source on Windows)
REM ============================================================================

setlocal

if "%~1"=="" (
    echo Usage: %~nx0 ^<testnet^|mainnet^> [letsgo options]
    echo.
    echo Examples:
    echo   %~nx0 testnet                  Quick start on testnet
    echo   %~nx0 mainnet                  Connect to mainnet
    echo   %~nx0 testnet --reset          Reset local data first
    echo.
    echo Requirements: Windows 10 21H2+ or Windows 11.
    echo This script will install WSL2 + Ubuntu automatically if not present.
    exit /b 1
)

set NETWORK_TYPE=%~1
if not "%NETWORK_TYPE%"=="testnet" if not "%NETWORK_TYPE%"=="mainnet" (
    echo Error: first argument must be 'testnet' or 'mainnet' ^(got '%NETWORK_TYPE%'^)
    exit /b 1
)

REM Forward extra args
set EXTRA_ARGS=
shift
:collect_args
if "%~1"=="" goto args_done
set EXTRA_ARGS=%EXTRA_ARGS% %1
shift
goto collect_args
:args_done

echo ============================================================
echo   MXD Node Quick Start — Windows via WSL2
echo ============================================================
echo.

REM 1. Is WSL installed at all?
where wsl >nul 2>&1
if errorlevel 1 (
    echo WSL not found on this system.
    echo.
    echo This script will install WSL2 + Ubuntu 22.04 ^(~600 MB download^).
    echo You'll be prompted for admin permission and may need to REBOOT.
    echo After reboot, just re-run this .bat to continue.
    echo.
    pause
    wsl --install -d Ubuntu-22.04
    echo.
    echo If Windows asked you to reboot, please reboot now and re-run this script.
    pause
    exit /b 0
)

REM 2. Is Ubuntu-22.04 distro registered?
wsl -l -q 2>nul | findstr /B /C:"Ubuntu-22.04" >nul
if errorlevel 1 (
    echo WSL is installed but Ubuntu-22.04 isn't. Installing it now...
    wsl --install -d Ubuntu-22.04
    if errorlevel 1 (
        echo Failed to install Ubuntu-22.04. You may need to run:
        echo   wsl --update
        echo and try again.
        pause
        exit /b 1
    )
    echo Ubuntu-22.04 installed. If this was the first WSL install, please reboot.
    pause
    exit /b 0
)

REM 3. Run letsgo inside Ubuntu. Clone the repo if not already there.
echo Running letsgo %NETWORK_TYPE%%EXTRA_ARGS% inside WSL Ubuntu-22.04...
echo.
wsl -d Ubuntu-22.04 -- bash -c "set -e; sudo apt-get update -qq && sudo apt-get install -y -qq git curl ca-certificates; if [ ! -d ~/mxd ]; then git clone --depth 1 https://github.com/AlanRuno/mxd.git ~/mxd; else (cd ~/mxd && git pull --ff-only --quiet); fi; cd ~/mxd && ./letsgo %NETWORK_TYPE%%EXTRA_ARGS%"

if errorlevel 1 (
    echo.
    echo letsgo exited with an error. To debug, open WSL directly:
    echo   wsl -d Ubuntu-22.04
    echo and re-run inside:
    echo   cd ~/mxd ^&^& ./letsgo %NETWORK_TYPE%
    pause
    exit /b 1
)

echo.
echo Node is running inside WSL. To check status from PowerShell:
echo   curl http://localhost:8080/status
echo To stop:
echo   wsl -d Ubuntu-22.04 -- pkill mxd_node
echo.
endlocal
