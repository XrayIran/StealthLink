#Requires -RunAsAdministrator
<#
.SYNOPSIS
    StealthLink Agent for Windows - Setup and launcher script.
.DESCRIPTION
    Downloads, configures, and runs the StealthLink agent on Windows.
    Requires Npcap for rawtcp carrier support.
#>

param(
    [string]$ConfigPath = "",
    [string]$GatewayAddr = "",
    [string]$SharedKey = "",
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$Version
)

$ErrorActionPreference = "Stop"
$StealthLinkVersion = "1.0.0"
$InstallDir = "$env:ProgramFiles\StealthLink"
$ConfigFile = "$InstallDir\config.yaml"
$BinaryName = "stealthlink-agent.exe"
$ToolsBinaryName = "stealthlink-tools.exe"
$GithubRepo = "stealthlink/stealthlink"

function Write-Info { param([string]$msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok { param([string]$msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param([string]$msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param([string]$msg) Write-Host "[-] $msg" -ForegroundColor Red }

function Write-Banner {
    Write-Host ""
    Write-Host "  ____  _             _ _   _     _     _       _    " -ForegroundColor Cyan
    Write-Host " / ___|| |_ ___  __ _| | |_| |__ | |   (_)_ __ | | __" -ForegroundColor Cyan
    Write-Host " \___ \| __/ _ \/ _` | | __| '_ \| |   | | '_ \| |/ /" -ForegroundColor Cyan
    Write-Host "  ___) | ||  __/ (_| | | |_| | | | |___| | | | |   < " -ForegroundColor Cyan
    Write-Host " |____/ \__\___|\__,_|_|\__|_| |_|_____|_|_| |_|_|\_\" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Agent for Windows - v$StealthLinkVersion" -ForegroundColor White
    Write-Host ""
}

function Test-NpcapInstalled {
    $npcapPath = "$env:SystemRoot\System32\Npcap"
    return (Test-Path $npcapPath) -or (Test-Path "$env:ProgramFiles\Npcap")
}

function Install-Npcap {
    Write-Info "Npcap is required for raw packet capture (rawtcp carrier)."
    Write-Info "Downloading Npcap installer..."

    $npcapUrl = "https://npcap.com/dist/npcap-1.80.exe"
    $npcapInstaller = "$env:TEMP\npcap-installer.exe"

    try {
        Invoke-WebRequest -Uri $npcapUrl -OutFile $npcapInstaller -UseBasicParsing
        Write-Info "Running Npcap installer (follow the prompts)..."
        Start-Process -FilePath $npcapInstaller -Wait
        Remove-Item $npcapInstaller -ErrorAction SilentlyContinue
    } catch {
        Write-Warn "Could not download Npcap automatically."
        Write-Warn "Please install Npcap manually from: https://npcap.com/"
        Write-Host "Press any key to continue without Npcap..." -ForegroundColor Yellow
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

function Get-Architecture {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "amd64" }
        "Arm64" { return "arm64" }
        default {
            # Fallback
            if ([Environment]::Is64BitOperatingSystem) { return "amd64" }
            Write-Err "Unsupported architecture: $arch"
            exit 1
        }
    }
}

function Install-StealthLink {
    Write-Banner
    Write-Info "Installing StealthLink Agent..."

    # Create install directory
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }

    # Check Npcap
    if (-not (Test-NpcapInstalled)) {
        Write-Warn "Npcap not detected."
        $installNpcap = Read-Host "Install Npcap for rawtcp support? (Y/n)"
        if ($installNpcap -ne "n") {
            Install-Npcap
        }
    } else {
        Write-Ok "Npcap detected."
    }

    # Download binary
    $arch = Get-Architecture
    Write-Info "Detected architecture: $arch"
    Write-Info "Downloading StealthLink v$StealthLinkVersion..."

    $downloadUrl = "https://github.com/$GithubRepo/releases/download/v$StealthLinkVersion/stealthlink-windows-$arch-v$StealthLinkVersion.zip"
    $zipPath = "$env:TEMP\stealthlink-windows.zip"
    $extractPath = "$env:TEMP\stealthlink-extract"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    } catch {
        Write-Err "Download failed: $_"
        Write-Err "URL: $downloadUrl"
        exit 1
    }

    # Extract
    Write-Info "Extracting..."
    if (Test-Path $extractPath) { Remove-Item $extractPath -Recurse -Force }
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

    # Copy binaries
    $binaries = Get-ChildItem -Path $extractPath -Recurse -Filter "*.exe"
    foreach ($bin in $binaries) {
        Copy-Item $bin.FullName -Destination $InstallDir -Force
        Write-Ok "Installed: $($bin.Name)"
    }

    # Copy example configs if present
    $configs = Get-ChildItem -Path $extractPath -Recurse -Filter "*.yaml*"
    foreach ($cfg in $configs) {
        $dest = Join-Path $InstallDir $cfg.Name
        if (-not (Test-Path $dest)) {
            Copy-Item $cfg.FullName -Destination $dest
            Write-Ok "Config example: $($cfg.Name)"
        }
    }

    # Cleanup
    Remove-Item $zipPath -ErrorAction SilentlyContinue
    Remove-Item $extractPath -Recurse -ErrorAction SilentlyContinue

    # Add to PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($currentPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "Machine")
        Write-Ok "Added $InstallDir to system PATH."
    }

    Write-Ok "StealthLink Agent installed to $InstallDir"
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor White
    Write-Host "  1. Edit config: notepad $ConfigFile"
    Write-Host "  2. Run agent: stealthlink-agent.exe --config $ConfigFile"
    Write-Host ""
}

function Uninstall-StealthLink {
    Write-Warn "This will remove StealthLink from $InstallDir"
    $confirm = Read-Host "Are you sure? (y/N)"
    if ($confirm -ne "y") {
        Write-Info "Cancelled."
        return
    }

    # Stop any running processes
    Get-Process -Name "stealthlink-agent" -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name "stealthlink-tools" -ErrorAction SilentlyContinue | Stop-Process -Force

    # Remove from PATH
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $newPath = ($currentPath -split ";" | Where-Object { $_ -ne $InstallDir }) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")

    # Remove directory
    if (Test-Path $InstallDir) {
        Remove-Item $InstallDir -Recurse -Force
        Write-Ok "Removed $InstallDir"
    }

    Write-Ok "StealthLink uninstalled."
}

function Start-Agent {
    Write-Banner

    $agentBin = Join-Path $InstallDir $BinaryName
    if (-not (Test-Path $agentBin)) {
        Write-Err "Agent binary not found at $agentBin"
        Write-Info "Run with -Install flag to install first."
        exit 1
    }

    # Determine config
    $cfg = $ConfigFile
    if ($ConfigPath) { $cfg = $ConfigPath }
    if (-not (Test-Path $cfg)) {
        Write-Err "Config not found: $cfg"
        Write-Info "Create a config file or run the wizard."
        exit 1
    }

    Write-Info "Starting StealthLink Agent..."
    Write-Info "Config: $cfg"
    Write-Host ""

    # Configure SOCKS5 proxy hint
    Write-Host "Browser proxy configuration:" -ForegroundColor White
    Write-Host "  If your config includes a socks5 service, configure your browser:" -ForegroundColor Gray
    Write-Host "  Settings > Network > Proxy > Manual > SOCKS Host: 127.0.0.1" -ForegroundColor Gray
    Write-Host ""

    try {
        & $agentBin --config $cfg
    } catch {
        Write-Err "Agent exited with error: $_"
        exit 1
    }
}

# Main
if ($Version) {
    Write-Host "StealthLink Agent for Windows v$StealthLinkVersion"
    $agentBin = Join-Path $InstallDir $BinaryName
    if (Test-Path $agentBin) {
        & $agentBin version 2>$null
    }
    exit 0
}

if ($Install) {
    Install-StealthLink
    exit 0
}

if ($Uninstall) {
    Uninstall-StealthLink
    exit 0
}

# Default: start agent
Start-Agent
