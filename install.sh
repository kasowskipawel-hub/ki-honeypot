#!/bin/bash
# win443-honeypot — one-line installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/kasowskipawel-hub/win443-honeypot/main/install.sh | bash -s -- --key HPOT-XXXX-XXXX-XXXX-XXXX
#   or with optional Mistral AI key:
#   ... | bash -s -- --key HPOT-XXXX-XXXX-XXXX-XXXX --mistral sk-...

set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/kasowskipawel-hub/win443-honeypot/main"
INSTALL_DIR="/opt/win443-honeypot"
IMAGE="ghcr.io/kasowskipawel-hub/win443-honeypot:latest"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
LICENSE_KEY=""
MISTRAL_KEY=""
DASH_PASS="honeypot$(openssl rand -hex 4 2>/dev/null || echo 2026)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --key)     LICENSE_KEY="$2"; shift 2 ;;
    --mistral) MISTRAL_KEY="$2"; shift 2 ;;
    --pass)    DASH_PASS="$2";   shift 2 ;;
    *) warn "Unknown arg: $1"; shift ;;
  esac
done

[[ -z "$LICENSE_KEY" ]] && error "License key required. Usage: install.sh --key HPOT-XXXX-XXXX-XXXX-XXXX"

echo ""
echo "  ██╗    ██╗██╗███╗   ██╗██╗  ██╗██╗  ██╗██████╗ "
echo "  ██║    ██║██║████╗  ██║██║  ██║██║  ██║╚════██╗"
echo "  ██║ █╗ ██║██║██╔██╗ ██║███████║███████║  ███╔╝ "
echo "  ██║███╗██║██║██║╚██╗██║╚════██║╚════██║ ██╔╝   "
echo "  ╚███╔███╔╝██║██║ ╚████║     ██║     ██║ ███████╗"
echo "   ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝     ╚═╝     ╚═╝╚══════╝"
echo "  win443-honeypot installer"
echo ""

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Please run as root (sudo bash install.sh ...)"

# ── OS check ──────────────────────────────────────────────────────────────────
if ! command -v apt-get &>/dev/null && ! command -v yum &>/dev/null; then
  error "Unsupported OS. Requires Debian/Ubuntu or RHEL/CentOS."
fi

# ── Docker ────────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  info "Installing Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
else
  info "Docker already installed: $(docker --version)"
fi

# Docker Compose v2 (plugin)
if ! docker compose version &>/dev/null; then
  info "Installing Docker Compose plugin..."
  apt-get install -y docker-compose-plugin 2>/dev/null || \
    yum install -y docker-compose-plugin 2>/dev/null || \
    error "Could not install docker-compose-plugin. Install manually."
fi

# ── Install dir ───────────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

info "Downloading docker-compose.yml..."
curl -sSL "$REPO_RAW/docker-compose.yml" -o docker-compose.yml

# ── .env ──────────────────────────────────────────────────────────────────────
cat > .env << ENVEOF
LICENSE_KEY=${LICENSE_KEY}
DASH_PASSWORD=${DASH_PASS}
MISTRAL_API_KEY=${MISTRAL_KEY}
ENVEOF

# ── UFW ───────────────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
  info "Opening firewall ports..."
  for port in 80 443 8080 4443 22 2222 6379 445 3389 3333 5555 2375 8545 9200 27017; do
    ufw allow "${port}/tcp" > /dev/null 2>&1 || true
  done
  ufw allow 9090/tcp > /dev/null 2>&1 || true
fi

# ── Pull + start ──────────────────────────────────────────────────────────────
info "Pulling image (this may take a minute)..."
docker pull "$IMAGE"

info "Starting honeypot stack..."
docker compose up -d

# ── Systemd autostart ─────────────────────────────────────────────────────────
cat > /etc/systemd/system/win443-honeypot.service << SVCEOF
[Unit]
Description=win443 Honeypot Stack
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${INSTALL_DIR}
ExecStart=docker compose up -d
ExecStop=docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable win443-honeypot > /dev/null 2>&1

# ── Done ──────────────────────────────────────────────────────────────────────
IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  win443-honeypot installed successfully!         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║${NC}  Dashboard: http://${IP}:9090"
echo -e "${GREEN}║${NC}  Password:  ${DASH_PASS}"
echo -e "${GREEN}║${NC}  License:   ${LICENSE_KEY}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
info "Logs: docker logs win443-honeypot"
info "Stop: docker compose -f ${INSTALL_DIR}/docker-compose.yml down"
