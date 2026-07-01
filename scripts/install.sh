#!/bin/bash
# Nawasara Agent — one-liner installer
# Usage: curl -sSL https://nawasara.ponorogo.go.id/agent/install.sh | bash
# Or non-interactive:
#   NAWASARA_API_KEY=nwa_xxx NAWASARA_URL=https://... NAWASARA_AGENT_NAME=web-xxx bash install.sh

set -euo pipefail

AGENT_VERSION="${NAWASARA_AGENT_VERSION:-latest}"
DASHBOARD_URL="${NAWASARA_URL:-https://nawasara.ponorogo.go.id}"
API_KEY="${NAWASARA_API_KEY:-}"
AGENT_NAME="${NAWASARA_AGENT_NAME:-$(hostname)}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/nawasara-agent"
DATA_DIR="/var/lib/nawasara-agent"
BINARY="$INSTALL_DIR/nawasara-agent"
CONFIG="$CONFIG_DIR/config.yaml"
SERVICE_FILE="/etc/systemd/system/nawasara-agent.service"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || error "Run as root (sudo bash install.sh)"

# Detect OS + arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) error "Unsupported architecture: $ARCH" ;;
esac

info "Nawasara Agent installer — OS=$OS ARCH=$ARCH"

# Prompt for API key if not set
if [ -z "$API_KEY" ]; then
  read -rp "Enter your Nawasara API key (nwa_...): " API_KEY
  [ -z "$API_KEY" ] && error "API key required"
fi

# Download binary
# Primary: via Dashboard proxy (handles version resolution + redirect to GitHub Releases)
# Fallback: direct GitHub Releases URL
GITHUB_REPO="${NAWASARA_GITHUB_REPO:-nawasara/agent}"
DOWNLOAD_URL="$DASHBOARD_URL/agent/download/$AGENT_VERSION/$OS/$ARCH/nawasara-agent"
FALLBACK_URL="https://github.com/$GITHUB_REPO/releases/latest/download/nawasara-agent-$OS-$ARCH"

info "Downloading binary..."
if ! curl -fsSL --connect-timeout 10 "$DOWNLOAD_URL" -o "$BINARY.tmp" 2>/dev/null; then
  warn "Dashboard download failed, falling back to GitHub Releases..."
  curl -fsSL "$FALLBACK_URL" -o "$BINARY.tmp" || error "Download failed from both Dashboard and GitHub."
fi
chmod +x "$BINARY.tmp"
mv "$BINARY.tmp" "$BINARY"
info "Binary installed: $BINARY"

# Create directories
mkdir -p "$CONFIG_DIR/plugins/available" "$CONFIG_DIR/plugins/enabled" "$CONFIG_DIR/rules"
mkdir -p "$DATA_DIR"
chmod 700 "$CONFIG_DIR" "$DATA_DIR"

# Detect web server
WEB_SERVER="auto"
if systemctl is-active --quiet nginx 2>/dev/null; then WEB_SERVER="nginx"; fi
if systemctl is-active --quiet apache2 2>/dev/null; then WEB_SERVER="apache"; fi
if systemctl is-active --quiet httpd 2>/dev/null; then WEB_SERVER="apache"; fi
info "Detected web server: $WEB_SERVER"

# Write config
cat > "$CONFIG" << EOF
api_key: $API_KEY
dashboard_url: $DASHBOARD_URL
agent_name: $AGENT_NAME
agent_id: ""

collector:
  web_server: $WEB_SERVER
  ssh_log: auto
  metrics_interval: 30s

analyzer:
  rules_dir: /etc/nawasara-agent/rules/
  rules_sync_interval: 6h
  correlation_window: 5m
  default_threshold: 20

reporter:
  push_timeout: 10s
  retry_interval: 30s
  buffer_db: /var/lib/nawasara-agent/buffer.db
  buffer_max_age: 168h
  buffer_max_size_mb: 100
  heartbeat_interval: 60s

executor:
  enabled: false

plugins:
  dir: /etc/nawasara-agent/plugins/available/
  enabled:
    - nginx
    - ssh
EOF
chmod 600 "$CONFIG"
info "Config written: $CONFIG"

# Register agent with Dashboard
# /api/agent/register is an open endpoint (no auth needed — api_key is returned by this call)
info "Registering agent with Dashboard..."
HOSTNAME_FULL=$(hostname -f 2>/dev/null || hostname)
OS_FULL=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 || echo "$OS")
IP_LOCAL=$(hostname -I 2>/dev/null | awk '{print $1}')
REG_RESPONSE=$(curl -s -X POST "$DASHBOARD_URL/api/agent/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\":\"$AGENT_NAME\",
    \"hostname\":\"$HOSTNAME_FULL\",
    \"os\":\"$OS_FULL\",
    \"arch\":\"$ARCH\",
    \"agent_version\":\"$AGENT_VERSION\",
    \"web_server\":\"$WEB_SERVER\",
    \"ip_local\":\"$IP_LOCAL\"
  }" 2>/dev/null || true)

AGENT_ID=$(echo "$REG_RESPONSE" | grep -o '"agent_id":"[^"]*"' | cut -d'"' -f4)
NEW_API_KEY=$(echo "$REG_RESPONSE" | grep -o '"api_key":"[^"]*"' | cut -d'"' -f4)

if [ -n "$AGENT_ID" ] && [ -n "$NEW_API_KEY" ]; then
  # Update config with credentials returned by registration
  sed -i "s|^api_key: .*|api_key: $NEW_API_KEY|" "$CONFIG"
  sed -i "s|^agent_id: .*|agent_id: $AGENT_ID|" "$CONFIG"
  chmod 600 "$CONFIG"
  info "Registered: agent_id=$AGENT_ID"
  info "API key saved to config (keep this file secure — key will not be shown again)"
else
  warn "Registration failed. Check that $DASHBOARD_URL is reachable."
  warn "Response: $REG_RESPONSE"
  warn "You can register manually: curl -X POST $DASHBOARD_URL/api/agent/register -H 'Content-Type: application/json' -d '{\"name\":\"$AGENT_NAME\",...}'"
fi

# Install systemd service
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Nawasara Security Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/nawasara-agent run --config /etc/nawasara-agent/config.yaml
Restart=always
RestartSec=5s
LimitNOFILE=65536
CPUQuota=10%
MemoryMax=128M

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nawasara-agent
systemctl start nawasara-agent

info "Service started. Status:"
systemctl status nawasara-agent --no-pager -l | head -15
info "Done! Nawasara Agent is running. Logs: journalctl -u nawasara-agent -f"
