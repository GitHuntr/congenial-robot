# CCAF Installation Script for Windows
# Run this script as Administrator

param(
    [string]$InstallPath = "C:\Program Files\CCAF",
    [int]$Port = 5000
)

$ErrorActionPreference = "Stop"

Write-Host "=================================" -ForegroundColor Blue
Write-Host "CCAF Installation Script" -ForegroundColor Blue
Write-Host "=================================" -ForegroundColor Blue

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

# Create installation directory
Write-Host "Creating installation directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $InstallPath | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallPath\data\database" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallPath\data\logs" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallPath\data\backups" | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallPath\configs" | Out-Null

# Check if Python is installed
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Python not found. Please install Python 3.8+ from python.org" -ForegroundColor Red
    exit 1
}

# Install CCAF
Write-Host "Installing CCAF..." -ForegroundColor Yellow
Set-Location $InstallPath

# Create virtual environment
python -m venv venv
& ".\venv\Scripts\Activate.ps1"

# Upgrade pip
python -m pip install --upgrade pip

# Install CCAF (assuming we're in the source directory)
if (Test-Path "setup.py") {
    pip install -e .
} else {
    Write-Host "Please copy CCAF source code to $InstallPath" -ForegroundColor Red
    exit 1
}

# Create default configuration
$configContent = @'
{
  "database": {
    "path": "C:\\Program Files\\CCAF\\data\\database\\ccaf.db"
  },
  "security": {
    "secret_key": "GENERATE_A_SECURE_KEY_HERE"
  },
  "web": {
    "host": "0.0.0.0",
    "port": 5000,
    "enable_ssl": false
  },
  "logging": {
    "level": "INFO",
    "file_path": "C:\\Program Files\\CCAF\\data\\logs\\ccaf.log"
  },
  "modules": {
    "intrusion_detection": true,
    "bandwidth_control": true,
    "content_filter": true,
    "vpn_integration": false,
    "threat_intelligence": true
  }
}
'@

$configContent | Out-File -FilePath "$InstallPath\configs\production.json" -Encoding UTF8

# Create Windows service
Write-Host "Creating Windows service..." -ForegroundColor Yellow
$servicePath = "$InstallPath\venv\Scripts\python.exe"
$serviceArgs = "$InstallPath\app.py --env production"

# Use NSSM to create service (if available) or create a batch file
$batchContent = @"
@echo off
cd /d "$InstallPath"
call venv\Scripts\activate.bat
python app.py --env production
"@

$batchContent | Out-File -FilePath "$InstallPath\start_ccaf.bat" -Encoding ASCII

# Configure Windows Firewall
Write-Host "Configuring Windows Firewall..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "CCAF Web Interface" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow
    Write-Host "Firewall rule created for port $Port" -ForegroundColor Green
} catch {
    Write-Host "Failed to create firewall rule. Please manually allow port $Port" -ForegroundColor Yellow
}

Write-Host "=================================" -ForegroundColor Green
Write-Host "CCAF Installation Complete!" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green
Write-Host "To start CCAF:" -ForegroundColor Yellow
Write-Host "  Run '$InstallPath\start_ccaf.bat' as Administrator" -ForegroundColor White
Write-Host "Web interface will be available at:" -ForegroundColor Yellow
Write-Host "  http://localhost:$Port" -ForegroundColor White
Write-Host "Default login: admin / admin123" -ForegroundColor Red
Write-Host "Please change the default password!" -ForegroundColor Red