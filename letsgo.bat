@echo off
setlocal

REM Check if network type argument is provided
if "%~1"=="" (
    echo Usage: %~nx0 [testnet^|mainnet]
    echo.
    echo Examples:
    echo   %~nx0 testnet   Build and run node on testnet
    echo   %~nx0 mainnet   Build and run node on mainnet
    exit /b 1
)

set NETWORK_TYPE=%~1

REM Validate network type
if not "%NETWORK_TYPE%"=="testnet" (
    if not "%NETWORK_TYPE%"=="mainnet" (
        echo Error: network type must be 'testnet' or 'mainnet'
        exit /b 1
    )
)

REM Check for MSYS2 installation at standard locations
set BASH_EXE=
if exist "C:\msys64\usr\bin\bash.exe" (
    set BASH_EXE=C:\msys64\usr\bin\bash.exe
) else if exist "C:\msys32\usr\bin\bash.exe" (
    set BASH_EXE=C:\msys32\usr\bin\bash.exe
) else (
    echo ===============================================
    echo   ERROR: MSYS2 Not Found
    echo ===============================================
    echo.
    echo MSYS2 is required to build MXD on Windows.
    echo.
    echo Please install MSYS2 from: https://www.msys2.org
    echo.
    echo After installation:
    echo   1. Open MSYS2 MinGW 64-bit shell
    echo   2. Run: pacman -Syu
    echo   3. Run: pacman -S mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake
    echo.
    pause
    exit /b 1
)

echo ===============================================
echo   MXD Node Quick Start - Windows
echo ===============================================
echo Network: %NETWORK_TYPE%
echo.

REM Get script directory and convert backslashes to forward slashes for bash
set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:\=/%

REM Launch MSYS2 bash and execute the existing letsgo bash script
echo Launching MSYS2 to build and run node...
echo.
"%BASH_EXE%" --login -c "cd '%SCRIPT_DIR%' && ./letsgo %NETWORK_TYPE%"

if errorlevel 1 (
    echo.
    echo ===============================================
    echo   Build or execution failed
    echo ===============================================
    pause
    exit /b 1
)

echo.
pause
