#!/usr/bin/env bash
# KaliWall start script
# Usage:
#   ./start.sh            # start in foreground
#   ./start.sh --daemon   # start in background
#   ./start.sh --service  # start systemd service

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -x "./kaliwall" ]]; then
    echo -e "${YELLOW}[!] kaliwall binary not found. Run ./setup.sh first.${NC}"
    exit 1
fi

mkdir -p logs data

case "${1:-}" in
    --daemon)
        echo -e "${GREEN}[+] Starting KaliWall in daemon mode...${NC}"
        nohup ./kaliwall > logs/kaliwall-daemon.log 2>&1 &
        DAEMON_PID=$!
        echo "$DAEMON_PID" > kaliwall.pid
        echo -e "${GREEN}[+] KaliWall started (PID: ${DAEMON_PID})${NC}"
        echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
        echo -e "${GREEN}[+] Logs:   tail -f logs/kaliwall-daemon.log${NC}"
        echo -e "${YELLOW}[!] Stop:   kill $(cat kaliwall.pid)${NC}"
        ;;
    --service)
        echo -e "${GREEN}[+] Starting KaliWall systemd service...${NC}"
        sudo systemctl start kaliwall
        sudo systemctl status kaliwall --no-pager
        ;;
    "")
        echo -e "${GREEN}[+] Starting KaliWall...${NC}"
        echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
        echo -e "${YELLOW}[!] Run with sudo for live firewall integration${NC}"
        ./kaliwall
        ;;
    *)
        echo "Usage: ./start.sh [--daemon|--service]"
        exit 1
        ;;
esac

echo "Made with ❤️ by Sujal Lamichhane"
