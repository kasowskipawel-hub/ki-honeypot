# KI Honeypot — Windows Installer
# Run as Administrator in PowerShell:
#   irm https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.ps1 | iex
# Or with key:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main/install.ps1))) -Key "HPOT-XXXX-XXXX-XXXX-XXXX"

param(
    [string]$Key      = $env:LICENSE_KEY,
    [string]$Mistral  = $env:MISTRAL_API_KEY,
    [string]$Pass     = ""
)

$ErrorActionPreference = "Stop"

$REPO_RAW    = "https://raw.githubusercontent.com/kasowskipawel-hub/ki-honeypot/main"
$INSTALL_DIR = "C:\ki-honeypot"
$IMAGE       = "ghcr.io/kasowskipawel-hub/ki-honeypot:latest"

function Write-OK  { param($m) Write-Host "  [OK] $m"    -ForegroundColor Green }
function Write-Inf { param($m) Write-Host "  [..] $m"    -ForegroundColor Cyan  }
function Write-Err { param($m) Write-Host "  [!!] $m" -ForegroundColor Red; exit 1 }

Clear-Host
Write-Host ""
Write-Host "  ██╗  ██╗██╗    ██╗  ██╗ ██████╗ ███╗  ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗" -ForegroundColor Cyan
Write-Host "  ██║ ██╔╝██║    ██║  ██║██╔═══██╗████╗ ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝" -ForegroundColor Cyan
Write-Host "  █████╔╝ ██║    ███████║██║   ██║██╔██╗██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║   " -ForegroundColor Cyan
Write-Host "  ██╔═██╗ ██║    ██╔══██║██║   ██║██║╚████║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║   " -ForegroundColor Cyan
Write-Host "  ██║  ██╗██║    ██║  ██║╚██████╔╝██║ ╚███║███████╗   ██║   ██║     ╚██████╔╝   ██║   " -ForegroundColor Cyan
Write-Host "  ╚═╝  ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝   " -ForegroundColor Cyan
Write-Host ""
Write-Host "  KI Honeypot — Windows Installer" -ForegroundColor White
Write-Host ""

# ── Admin check ───────────────────────────────────────────────────────────────
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
if (-not $isAdmin) { Write-Err "Please run PowerShell as Administrator and try again." }

# ── License key ───────────────────────────────────────────────────────────────
if (-not $Key) {
    $Key = Read-Host "  Enter your license key (HPOT-XXXX-XXXX-XXXX-XXXX)"
}
if ($Key -notmatch "^HPOT-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$") {
    Write-Err "Invalid license key format. Expected: HPOT-XXXX-XXXX-XXXX-XXXX"
}

if (-not $Pass) {
    $Pass = "honeypot" + (-join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object {[char]$_}))
}

# ── Docker Desktop check ──────────────────────────────────────────────────────
Write-Inf "Checking Docker Desktop..."

$dockerOk = $false
try {
    $v = docker version --format "{{.Server.Version}}" 2>$null
    if ($v) { $dockerOk = $true; Write-OK "Docker $v is running" }
} catch {}

if (-not $dockerOk) {
    Write-Inf "Docker Desktop not found. Installing via winget..."
    try {
        winget install -e --id Docker.DockerDesktop --accept-source-agreements --accept-package-agreements --silent
        Write-OK "Docker Desktop installed."
        Write-Host ""
        Write-Host "  Docker Desktop was just installed." -ForegroundColor Yellow
        Write-Host "  Please:" -ForegroundColor Yellow
        Write-Host "    1. Start Docker Desktop from the Start menu" -ForegroundColor Yellow
        Write-Host "    2. Wait until the whale icon in the system tray turns green" -ForegroundColor Yellow
        Write-Host "    3. Run this installer again" -ForegroundColor Yellow
        Write-Host ""
        exit 0
    } catch {
        Write-Err "Could not install Docker Desktop automatically.`n  Please install manually: https://www.docker.com/products/docker-desktop/`n  Then run this installer again."
    }
}

# Verify compose plugin
try { docker compose version 2>$null | Out-Null } catch {
    Write-Err "Docker Compose not available. Please update Docker Desktop to version 4.x or later."
}

# ── Install dir ───────────────────────────────────────────────────────────────
Write-Inf "Creating install directory: $INSTALL_DIR"
New-Item -ItemType Directory -Force -Path $INSTALL_DIR | Out-Null

# ── Download docker-compose.yml ───────────────────────────────────────────────
Write-Inf "Downloading docker-compose.yml..."
Invoke-WebRequest -Uri "$REPO_RAW/docker-compose.yml" -OutFile "$INSTALL_DIR\docker-compose.yml" -UseBasicParsing

# ── Write .env ────────────────────────────────────────────────────────────────
@"
LICENSE_KEY=$Key
DASH_PASSWORD=$Pass
MISTRAL_API_KEY=$Mistral
"@ | Set-Content -Path "$INSTALL_DIR\.env" -Encoding UTF8

# ── Firewall rules ────────────────────────────────────────────────────────────
Write-Inf "Adding Windows Firewall rules..."
$ports = @(80,443,8080,4443,22,2222,6379,445,3389,23,8545,9090,3333,5555,4444,7777,9999,14444,2375,6443,9200,27017,8888)
foreach ($port in $ports) {
    $ruleName = "KI-Honeypot-$port"
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort $port -ErrorAction SilentlyContinue | Out-Null
    }
}
Write-OK "Firewall rules added ($(($ports).Count) ports)"

# ── Pull image ────────────────────────────────────────────────────────────────
Write-Inf "Pulling KI Honeypot image (this may take a minute)..."
Set-Location $INSTALL_DIR
docker pull $IMAGE
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to pull Docker image. Check your internet connection." }

# ── Start containers ──────────────────────────────────────────────────────────
Write-Inf "Starting KI Honeypot..."
docker compose up -d
if ($LASTEXITCODE -ne 0) { Write-Err "Failed to start containers. Check 'docker compose logs' for details." }

# ── Autostart via Task Scheduler ─────────────────────────────────────────────
Write-Inf "Registering autostart task..."
$action  = New-ScheduledTaskAction -Execute "docker" -Argument "compose -f `"$INSTALL_DIR\docker-compose.yml`" up -d" -WorkingDirectory $INSTALL_DIR
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "KI-Honeypot-Autostart" -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Write-OK "Autostart registered (runs at system boot)"

# ── Done ──────────────────────────────────────────────────────────────────────
$ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -UseBasicParsing -ErrorAction SilentlyContinue)
if (-not $ip) { $ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch "^(127\.|169\.)" } | Select-Object -First 1).IPAddress }

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║   KI Honeypot installed successfully!            ║" -ForegroundColor Green
Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  Dashboard:  http://${ip}:9090" -ForegroundColor White
Write-Host "  ║  Password:   $Pass" -ForegroundColor White
Write-Host "  ║  License:    $Key" -ForegroundColor White
Write-Host "  ╠══════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  Files:      $INSTALL_DIR" -ForegroundColor White
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor Cyan
Write-Host "    docker logs ki-honeypot          (live logs)"
Write-Host "    docker compose -f $INSTALL_DIR\docker-compose.yml down  (stop)"
Write-Host ""

# Open dashboard in browser
Start-Process "http://localhost:9090"
