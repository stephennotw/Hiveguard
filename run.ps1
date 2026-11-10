<# 
  HiveGuard Bootstrap — Windows
  Downloads portable Node.js if not found, then runs the scanner.
  Usage: .\run.ps1 [hiveguard flags]
  Example: .\run.ps1 --offline --output C:\results --verbose
#>

$ErrorActionPreference = 'Stop'

# Bootstrap messages go to stderr: Write-Host reaches stdout when output is redirected,
# which would corrupt --json output.
function Write-Log([string]$Message = '') { [Console]::Error.WriteLine($Message) }
$HiveGuardArgs = $args

# Pre-create output directory if --output is specified
for ($i = 0; $i -lt $HiveGuardArgs.Count; $i++) {
    if ($HiveGuardArgs[$i] -eq '--output' -and ($i + 1) -lt $HiveGuardArgs.Count) {
        $outDir = $HiveGuardArgs[$i + 1]
        if (-not (Test-Path $outDir)) {
            New-Item -ItemType Directory -Path $outDir -Force | Out-Null
            Write-Log "[bootstrap] Created output directory: $outDir"
        }
        break
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

# Change to the directory where this script lives
Set-Location -Path $ScriptDir

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
            Write-Log "[bootstrap] Using system Node.js ($($systemNode.Source), v$major)"
            return $systemNode.Source
        }
        Write-Log "[bootstrap] System Node.js too old (v$major, need >=$RequiredMajor)"
    }
    return $null
}

function Install-PortableNode {
    if (Test-Path $NodeExe) {
        $major = Get-NodeMajor $NodeExe
        if ($major -ge $RequiredMajor) {
            Write-Log "[bootstrap] Using portable Node.js (.node/node.exe, v$major)"
            return $NodeExe
        }
        Write-Log "[bootstrap] Portable Node.js too old (v$major), re-downloading..."
    }

    $arch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }
    $zipName = "node-$NodeVersion-win-$arch.zip"
    $url = "$NodeDistBase/$zipName"
    $zipPath = Join-Path $env:TEMP $zipName
    $extractDir = Join-Path $env:TEMP "node-$NodeVersion-win-$arch"

    Write-Log "[bootstrap] Downloading Node.js $NodeVersion ($arch)..."
    Write-Log "            $url"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Log "[bootstrap] ERROR: Failed to download Node.js: $_"
        Write-Log "            Install Node.js 18+ manually: https://nodejs.org"
        exit 3
    }

    Write-Log "[bootstrap] Extracting..."
    if (Test-Path $extractDir) { Remove-Item -Recurse -Force $extractDir }
    Expand-Archive -Path $zipPath -DestinationPath $env:TEMP -Force

    if (!(Test-Path $NodeDir)) { New-Item -ItemType Directory -Path $NodeDir -Force | Out-Null }
    Copy-Item (Join-Path $extractDir 'node.exe') $NodeExe -Force

    # Cleanup
    Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $extractDir -ErrorAction SilentlyContinue

    $major = Get-NodeMajor $NodeExe
    Write-Log "[bootstrap] Node.js $NodeVersion installed to .node/node.exe"
    return $NodeExe
}

# --- Main ---
Write-Log ""
Write-Log "  HiveGuard Bootstrap (Windows)"
Write-Log "  ============================="
Write-Log ""

# 1. Try system node
$node = Find-SystemNode

# 2. Fall back to portable node
if (-not $node) {
    $node = Install-PortableNode
}

# 3. Run HiveGuard
Write-Log "[bootstrap] Starting HiveGuard scan..."
Write-Log ""

& $node $HiveGuardJs @HiveGuardArgs
exit $LASTEXITCODE
