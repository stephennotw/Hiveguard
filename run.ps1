<# 
  HiveGuard Bootstrap — Windows
  Downloads portable Node.js if not found, then runs the scanner.
  Usage: .\run.ps1 [hiveguard flags]
  Example: .\run.ps1 --offline --output C:\results --verbose
#>

$ErrorActionPreference = 'Stop'
$HiveGuardArgs = $args
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$NodeDir = Join-Path $ScriptDir '.node'
$NodeExe = Join-Path $NodeDir 'node.exe'
$HiveGuardJs = Join-Path (Join-Path $ScriptDir 'bin') 'hiveguard.js'
$RequiredMajor = 18
$NodeVersion = 'v22.15.0'
$NodeDistBase = "https://nodejs.org/dist/$NodeVersion"

function Get-NodeMajor($exePath) {
    try {
        $ver = & $exePath --version 2>$null
        if ($ver -match '^v(\d+)') { return [int]$Matches[1] }
    } catch {}
    return 0
}

function Find-SystemNode {
    $systemNode = Get-Command node -ErrorAction SilentlyContinue
    if ($systemNode) {
        $major = Get-NodeMajor $systemNode.Source
        if ($major -ge $RequiredMajor) {
            Write-Host "[bootstrap] Using system Node.js ($($systemNode.Source), v$major)" -ForegroundColor Green
            return $systemNode.Source
        }
        Write-Host "[bootstrap] System Node.js too old (v$major, need >=$RequiredMajor)" -ForegroundColor Yellow
    }
    return $null
}

function Install-PortableNode {
    if (Test-Path $NodeExe) {
        $major = Get-NodeMajor $NodeExe
        if ($major -ge $RequiredMajor) {
            Write-Host "[bootstrap] Using portable Node.js (.node/node.exe, v$major)" -ForegroundColor Green
            return $NodeExe
        }
        Write-Host "[bootstrap] Portable Node.js too old (v$major), re-downloading..." -ForegroundColor Yellow
    }

    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $zipName = "node-$NodeVersion-win-$arch.zip"
    $url = "$NodeDistBase/$zipName"
    $zipPath = Join-Path $env:TEMP $zipName
    $extractDir = Join-Path $env:TEMP "node-$NodeVersion-win-$arch"

    Write-Host "[bootstrap] Downloading Node.js $NodeVersion ($arch)..." -ForegroundColor Cyan
    Write-Host "            $url" -ForegroundColor DarkGray

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Host "[bootstrap] ERROR: Failed to download Node.js: $_" -ForegroundColor Red
        Write-Host "            Install Node.js 18+ manually: https://nodejs.org" -ForegroundColor Yellow
        exit 3
    }

    Write-Host "[bootstrap] Extracting..." -ForegroundColor Cyan
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force

    if (!(Test-Path $NodeDir)) { New-Item -ItemType Directory -Path $NodeDir -Force | Out-Null }
    Copy-Item (Join-Path $extractDir 'node.exe') $NodeExe -Force

    # Cleanup
    Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue

    $major = Get-NodeMajor $NodeExe
    Write-Host "[bootstrap] Node.js $NodeVersion installed to .node/node.exe" -ForegroundColor Green
    return $NodeExe
}

# --- Main ---
Write-Host ""
Write-Host "  HiveGuard Bootstrap (Windows)" -ForegroundColor Cyan
Write-Host "  =============================" -ForegroundColor DarkGray
Write-Host ""

# 1. Try system node
$node = Find-SystemNode

# 2. Fall back to portable node
if (-not $node) {
    $node = Install-PortableNode
}

# 3. Run HiveGuard
Write-Host "[bootstrap] Starting HiveGuard scan..." -ForegroundColor Cyan
Write-Host ""

& $node $HiveGuardJs @HiveGuardArgs
exit $LASTEXITCODE
