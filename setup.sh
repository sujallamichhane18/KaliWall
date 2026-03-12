#!/usr/bin/env bash
# KaliWall — One-line setup script for Linux
# Usage: chmod +x setup.sh && ./setup.sh
#
# This script:
#   1. Installs Go (if not present)
#   2. Downloads dependencies
#   3. Builds the KaliWall daemon and CLI
#   4. Creates data directory
#   5. Optionally installs systemd service
#   6. Starts the KaliWall daemon

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  KaliWall — Enterprise Firewall Setup  ${NC}"
echo -e "${GREEN}========================================${NC}"

# 1. Check / Install Go
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Go not found. Installing Go 1.22...${NC}"
    GO_TAR="go1.22.0.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"
    echo 'export PATH="/usr/local/go/bin:$PATH"' >> ~/.bashrc
    rm -f "/tmp/${GO_TAR}"
    echo -e "${GREEN}[+] Go installed: $(go version)${NC}"
else
    echo -e "${GREEN}[+] Go already installed: $(go version)${NC}"
fi

# 2. Navigate to project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 3. Download dependencies
echo -e "${YELLOW}[*] Downloading Go dependencies...${NC}"
go mod tidy

# 4. Build daemon
echo -e "${YELLOW}[*] Building KaliWall daemon...${NC}"
go build -o kaliwall main.go
echo -e "${GREEN}[+] Daemon built: ./kaliwall${NC}"

# 5. Build CLI tool
echo -e "${YELLOW}[*] Building KaliWall CLI...${NC}"
go build -o kaliwall-cli ./cmd/kaliwall-cli
echo -e "${GREEN}[+] CLI built: ./kaliwall-cli${NC}"

# 6. Create data directory
mkdir -p data logs
echo -e "${GREEN}[+] Data directories created${NC}"

# 7. Install systemd service (optional)
install_service() {
    echo -e "${YELLOW}[*] Installing systemd service...${NC}"
    cat > /tmp/kaliwall.service <<EOF
[Unit]
Description=KaliWall Enterprise Firewall
After=network.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${SCRIPT_DIR}/kaliwall
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    sudo mv /tmp/kaliwall.service /etc/systemd/system/kaliwall.service
    sudo systemctl daemon-reload
    sudo systemctl enable kaliwall
    echo -e "${GREEN}[+] Systemd service installed and enabled${NC}"
    echo -e "${GREEN}[+] Use: sudo systemctl start kaliwall${NC}"
    echo -e "${GREEN}[+] Use: sudo systemctl status kaliwall${NC}"
}

# Check for --service flag
if [[ "${1:-}" == "--service" ]]; then
    install_service
    echo -e "${GREEN}[+] Starting KaliWall via systemd...${NC}"
    sudo systemctl start kaliwall
    sudo systemctl status kaliwall --no-pager
    exit 0
fi

# Check for --daemon flag
if [[ "${1:-}" == "--daemon" ]]; then
    echo -e "${GREEN}[+] Starting KaliWall in daemon mode...${NC}"
    echo -e "${YELLOW}[!] Run with sudo for live iptables integration${NC}"
    nohup ./kaliwall > logs/kaliwall-daemon.log 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > kaliwall.pid
    echo -e "${GREEN}[+] KaliWall daemon started (PID: ${DAEMON_PID})${NC}"
    echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
    echo -e "${GREEN}[+] CLI:    ./kaliwall-cli status${NC}"
    echo -e "${GREEN}[+] Logs:   tail -f logs/kaliwall-daemon.log${NC}"
    echo -e "${YELLOW}[!] Stop:   kill \$(cat kaliwall.pid)${NC}"
    exit 0
fi

# 8. Run in foreground (default)
echo ""
echo -e "${GREEN}[+] Starting KaliWall...${NC}"
echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
echo -e "${GREEN}[+] CLI:    ./kaliwall-cli status${NC}"
echo -e "${YELLOW}[!] Run with sudo for live iptables integration${NC}"
echo -e "${YELLOW}[!] Use --daemon flag to run in background${NC}"
echo -e "${YELLOW}[!] Use --service flag to install as systemd service${NC}"
echo ""
./kaliwall
