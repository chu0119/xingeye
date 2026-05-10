# XingEye Tool Setup Script
# Run as Administrator for nmap installation
# PowerShell: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
# Usage: .\scripts\setup-tools.ps1

$ErrorActionPreference = "Stop"
$Proxy = "http://127.0.0.1:7897"  # Set to "" if no proxy

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  XingEye - Tool Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Helper: download with optional proxy
function Download-File {
    param($Url, $Output)
    Write-Host "  Downloading: $Url" -ForegroundColor Gray
    if ($Proxy) {
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing -Proxy $Proxy
    } else {
        Invoke-WebRequest -Uri $Url -OutFile $Output -UseBasicParsing
    }
}

# 1. nmap
Write-Host "[1/4] Installing nmap..." -ForegroundColor Yellow
$nmapInstalled = Test-Path "C:\Program Files (x86)\Nmap\nmap.exe"
if ($nmapInstalled) {
    Write-Host "  nmap already installed." -ForegroundColor Green
} else {
    Write-Host "  Downloading nmap installer (~33MB)..." -ForegroundColor Gray
    $nmapUrl = "https://nmap.org/dist/nmap-7.95-setup.exe"
    $nmapOut = "$env:TEMP\nmap-setup.exe"
    Download-File -Url $nmapUrl -Output $nmapOut
    Write-Host "  Installing nmap (silent)..." -ForegroundColor Gray
    Start-Process -FilePath $nmapOut -ArgumentList "/S" -Wait -NoNewWindow
    Remove-Item $nmapOut -Force
    if (Test-Path "C:\Program Files (x86)\Nmap\nmap.exe") {
        Write-Host "  nmap installed successfully." -ForegroundColor Green
    } else {
        Write-Host "  nmap installation may have failed. Please install manually from https://nmap.org/download.html" -ForegroundColor Red
    }
}

# Create tools directory
$ToolsDir = "D:\netscan"
New-Item -ItemType Directory -Force -Path "$ToolsDir\naabu" | Out-Null
New-Item -ItemType Directory -Force -Path "$ToolsDir\httpx" | Out-Null

# 2. naabu
Write-Host "[2/4] Downloading naabu..." -ForegroundColor Yellow
$naabuDir = "$ToolsDir\naabu"
if (Test-Path "$naabuDir\naabu.exe") {
    Write-Host "  naabu already exists." -ForegroundColor Green
} else {
    $naabuUrl = "https://github.com/projectdiscovery/naabu/releases/download/v2.5.0/naabu_2.5.0_windows_amd64.zip"
    $naabuZip = "$env:TEMP\naabu.zip"
    try {
        Download-File -Url $naabuUrl -Output $naabuZip
        Expand-Archive -Path $naabuZip -DestinationPath $naabuDir -Force
        Remove-Item $naabuZip -Force
        Write-Host "  naabu v2.5.0 installed." -ForegroundColor Green
    } catch {
        Write-Host "  Failed to download naabu. Download manually from:" -ForegroundColor Red
        Write-Host "  https://github.com/projectdiscovery/naabu/releases" -ForegroundColor Red
    }
}

# 3. httpx
Write-Host "[3/4] Downloading httpx..." -ForegroundColor Yellow
$httpxDir = "$ToolsDir\httpx"
if (Test-Path "$httpxDir\httpx.exe") {
    Write-Host "  httpx already exists." -ForegroundColor Green
} else {
    $httpxUrl = "https://github.com/projectdiscovery/httpx/releases/download/v1.8.1/httpx_1.8.1_windows_amd64.zip"
    $httpxZip = "$env:TEMP\httpx.zip"
    try {
        Download-File -Url $httpxUrl -Output $httpxZip
        Expand-Archive -Path $httpxZip -DestinationPath $httpxDir -Force
        Remove-Item $httpxZip -Force
        Write-Host "  httpx v1.8.1 installed." -ForegroundColor Green
    } catch {
        Write-Host "  Failed to download httpx. Download manually from:" -ForegroundColor Red
        Write-Host "  https://github.com/projectdiscovery/httpx/releases" -ForegroundColor Red
    }
}

# 4. nuclei
Write-Host "[4/4] Downloading nuclei..." -ForegroundColor Yellow
$nucleiDir = "$ToolsDir\nuclei"
if (Test-Path "$nucleiDir\nuclei.exe") {
    Write-Host "  nuclei already exists." -ForegroundColor Green
} else {
    $nucleiUrl = "https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_windows_amd64.zip"
    $nucleiZip = "$env:TEMP\nuclei.zip"
    try {
        Download-File -Url $nucleiUrl -Output $nucleiZip
        Expand-Archive -Path $nucleiZip -DestinationPath $nucleiDir -Force
        Remove-Item $nucleiZip -Force
        Write-Host "  nuclei v3.8.0 installed." -ForegroundColor Green
    } catch {
        Write-Host "  Failed to download nuclei. Download manually from:" -ForegroundColor Red
        Write-Host "  https://github.com/projectdiscovery/nuclei/releases" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Tools installed:" -ForegroundColor White
Write-Host "  nmap  : C:\Program Files (x86)\Nmap\nmap.exe" -ForegroundColor Gray
Write-Host "  naabu : $naabuDir\naabu.exe" -ForegroundColor Gray
Write-Host "  httpx : $httpxDir\httpx.exe" -ForegroundColor Gray
Write-Host "  nuclei: $nucleiDir\nuclei.exe" -ForegroundColor Gray
Write-Host ""
Write-Host "If any tool failed to download, check your internet connection"
Write-Host "or proxy settings (currently: $Proxy)."
Write-Host ""
Write-Host "You can now run: npm run dev" -ForegroundColor Cyan
