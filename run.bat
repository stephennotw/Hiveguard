@echo off
REM HiveGuard Bootstrap — Windows CMD
REM Downloads portable Node.js if not found, then runs the scanner.
REM Usage: run.bat [hiveguard flags]
REM Example: run.bat --offline --output C:\results --verbose

setlocal enabledelayedexpansion

REM All bootstrap messages go to stderr: stdout carries --json output.

REM Change to the directory where this script lives
cd /d "%~dp0"

set "SCRIPT_DIR=%~dp0"
set "NODE_DIR=%SCRIPT_DIR%.node"
set "NODE_EXE=%NODE_DIR%\node.exe"
set "HIVEGUARD_JS=%SCRIPT_DIR%bin\hiveguard.js"
set "NODE_VERSION=v22.15.0"
set "NODE_DIST=https://nodejs.org/dist/%NODE_VERSION%"

REM --- Pre-create output directory if --output is specified ---
set "OUTPUT_DIR="
set "PREV_ARG="
for %%a in (%*) do (
    if "!PREV_ARG!"=="--output" (
        set "OUTPUT_DIR=%%~a"
    )
    set "PREV_ARG=%%~a"
)
if defined OUTPUT_DIR (
    if not exist "!OUTPUT_DIR!" (
        mkdir "!OUTPUT_DIR!" 2>nul
        >&2 echo [bootstrap] Created output directory: !OUTPUT_DIR!
    )
)

>&2 echo.
>&2 echo   HiveGuard Bootstrap (Windows CMD)
>&2 echo   ==================================
>&2 echo.

REM --- 1. Check system Node.js ---
where node >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%v in ('node --version 2^>nul') do set "NODE_VER=%%v"
    >&2 echo [bootstrap] Using system Node.js (!NODE_VER!^)
    >&2 echo [bootstrap] Starting HiveGuard scan...
    >&2 echo.
    node "%HIVEGUARD_JS%" %*
    exit /b !errorlevel!
)

REM --- 2. Check portable Node.js ---
if exist "%NODE_EXE%" (
    for /f "tokens=*" %%v in ('"%NODE_EXE%" --version 2^>nul') do set "NODE_VER=%%v"
    >&2 echo [bootstrap] Using portable Node.js (.node\node.exe, !NODE_VER!^)
    >&2 echo [bootstrap] Starting HiveGuard scan...
    >&2 echo.
    "%NODE_EXE%" "%HIVEGUARD_JS%" %*
    exit /b !errorlevel!
)

REM --- 3. Download portable Node.js ---
>&2 echo [bootstrap] Node.js not found on this system.
>&2 echo [bootstrap] Downloading portable Node.js %NODE_VERSION%...

if not exist "%NODE_DIR%" mkdir "%NODE_DIR%"

set "ARCH=x64"
set "ZIP_NAME=node-%NODE_VERSION%-win-%ARCH%.zip"
set "URL=%NODE_DIST%/%ZIP_NAME%"
set "ZIP_PATH=%TEMP%\%ZIP_NAME%"
set "EXTRACT_DIR=%TEMP%\node-%NODE_VERSION%-win-%ARCH%"

>&2 echo [bootstrap] URL: %URL%

REM Try PowerShell inline command (not a .ps1 script — execution policy does not block this)
powershell -NoProfile -NonInteractive -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '%URL%' -OutFile '%ZIP_PATH%' -UseBasicParsing" 2>nul

if not exist "%ZIP_PATH%" (
    REM Fallback: try curl (built into Windows 10+)
    >&2 echo [bootstrap] PowerShell download failed, trying curl...
    curl -fsSL "%URL%" -o "%ZIP_PATH%" 2>nul
)

if not exist "%ZIP_PATH%" (
    >&2 echo.
    >&2 echo [bootstrap] ERROR: Failed to download Node.js.
    >&2 echo             Please install Node.js 18+ manually: https://nodejs.org
    >&2 echo             Then run: node bin\hiveguard.js %*
    exit /b 3
)

>&2 echo [bootstrap] Extracting...
powershell -NoProfile -NonInteractive -Command "$ProgressPreference='SilentlyContinue'; Expand-Archive -Path '%ZIP_PATH%' -DestinationPath '%TEMP%' -Force" 2>nul

if not exist "%EXTRACT_DIR%\node.exe" (
    >&2 echo [bootstrap] ERROR: Extraction failed.
    >&2 echo             Please install Node.js 18+ manually: https://nodejs.org
    del /f "%ZIP_PATH%" 2>nul
    exit /b 3
)

copy /y "%EXTRACT_DIR%\node.exe" "%NODE_EXE%" >nul

REM Cleanup
del /f "%ZIP_PATH%" 2>nul
rmdir /s /q "%EXTRACT_DIR%" 2>nul

if not exist "%NODE_EXE%" (
    >&2 echo [bootstrap] ERROR: Failed to install portable Node.js.
    exit /b 3
)

for /f "tokens=*" %%v in ('"%NODE_EXE%" --version 2^>nul') do set "NODE_VER=%%v"
>&2 echo [bootstrap] Node.js %NODE_VERSION% installed to .node\node.exe (!NODE_VER!^)
>&2 echo [bootstrap] Starting HiveGuard scan...
>&2 echo.
"%NODE_EXE%" "%HIVEGUARD_JS%" %*
exit /b !errorlevel!
