@echo off
setlocal

REM Parse arguments with defaults
set CONFIG_FILE=%~1
set NETWORK_TYPE=%~2

if "%CONFIG_FILE%"=="" set CONFIG_FILE=default_config.json
if "%NETWORK_TYPE%"=="" set NETWORK_TYPE=testnet

REM Show usage if help is requested
if "%~1"=="-h" goto :usage
if "%~1"=="--help" goto :usage
if "%~1"=="/?" goto :usage

REM Validate network type
if not "%NETWORK_TYPE%"=="testnet" (
    if not "%NETWORK_TYPE%"=="mainnet" (
        echo Error: network_type must be 'testnet' or 'mainnet'
        goto :usage
    )
)

REM Check for MSYS2 installation
set BASH_EXE=
if exist "C:\msys64\usr\bin\bash.exe" (
    set BASH_EXE=C:\msys64\usr\bin\bash.exe
) else if exist "C:\msys32\usr\bin\bash.exe" (
    set BASH_EXE=C:\msys32\usr\bin\bash.exe
) else (
    echo ERROR: MSYS2 not found at C:\msys64 or C:\msys32
    echo.
    echo Please install MSYS2 from: https://www.msys2.org
    echo.
    pause
    exit /b 1
)

REM Get script directory and convert to bash-compatible path
set SCRIPT_DIR=%~dp0
set SCRIPT_DIR=%SCRIPT_DIR:\=/%

REM Execute switch_network.sh via MSYS2 bash
"%BASH_EXE%" --login -c "cd '%SCRIPT_DIR%' && ./switch_network.sh '%CONFIG_FILE%' %NETWORK_TYPE%"

if errorlevel 1 (
    echo.
    echo Network switch failed
    pause
    exit /b 1
)

echo.
pause
exit /b 0

:usage
echo Usage: %~nx0 [config_file] [network_type]
echo.
echo Arguments:
echo   config_file   - Path to config file (default: default_config.json^)
echo   network_type  - 'testnet' or 'mainnet' (default: testnet^)
echo.
echo Examples:
echo   %~nx0                              Switch default_config.json to testnet
echo   %~nx0 node.json mainnet           Switch node.json to mainnet
echo   %~nx0 custom.json testnet         Switch custom.json to testnet
echo.
pause
exit /b 0
