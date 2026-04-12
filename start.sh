#!/usr/bin/env bash
# KaliWall start script
# Usage:
#   ./start.sh                 # start in background (default)
#   ./start.sh --foreground    # start in foreground
#   ./start.sh --daemon        # start in background
#   ./start.sh --stop          # stop daemon started by this script
#   ./start.sh --status        # show daemon/service status
#   ./start.sh --logs          # show last 120 lines of daemon log
#   ./start.sh --logs-follow   # follow daemon log in real time
#   ./start.sh --service       # start systemd service
#   ./start.sh --service-logs  # show service logs via journalctl

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Keep web UI path explicit so startup remains stable even if cwd handling changes.
export KALIWALL_WEB_DIR="${KALIWALL_WEB_DIR:-${SCRIPT_DIR}/web}"

PID_FILE="kaliwall.pid"
LOG_FILE="logs/kaliwall-daemon.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
DPI_ARGS=("--dpi" "--dpi-lite")

if [[ "${KALIWALL_DPI:-1}" == "0" ]]; then
    DPI_ARGS=()
fi
if [[ -n "${KALIWALL_DPI_INTERFACE:-}" ]]; then
    DPI_ARGS+=("--dpi-interface" "${KALIWALL_DPI_INTERFACE}")
fi

usage() {
    cat <<EOF
Usage: ./start.sh [option]

Options:
    --foreground    Start in foreground (interactive)
  --daemon        Start in background and write PID to ${PID_FILE}
  --stop          Stop background process from ${PID_FILE}
  --status        Show daemon and systemd status
  --logs          Show last 120 lines from ${LOG_FILE}
  --logs-follow   Follow ${LOG_FILE}
  --service       Start systemd service kaliwall
  --service-logs  Show journal logs for systemd service
EOF
}

is_running_pid() {
    local pid="$1"
    kill -0 "$pid" 2>/dev/null
}

stop_pid_graceful() {
    local pid="$1"
    local label="${2:-process}"

    if [[ -z "$pid" ]]; then
        return 1
    fi
    if ! is_running_pid "$pid"; then
        return 1
    fi

    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 25); do
        if ! is_running_pid "$pid"; then
            echo -e "${GREEN}[+] Stopped ${label} (PID: ${pid})${NC}"
            return 0
        fi
        sleep 0.2
    done

    kill -9 "$pid" 2>/dev/null || true
    for _ in $(seq 1 10); do
        if ! is_running_pid "$pid"; then
            echo -e "${GREEN}[+] Force-stopped ${label} (PID: ${pid})${NC}"
            return 0
        fi
        sleep 0.1
    done

    echo -e "${YELLOW}[!] Failed to stop ${label} (PID: ${pid})${NC}"
    return 1
}

rotate_log_if_needed() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(wc -c < "$LOG_FILE")
        if [[ "$size" -ge "$MAX_LOG_SIZE" ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.1"
        fi
    fi
}

if [[ ! -x "./kaliwall" ]]; then
    echo -e "${YELLOW}[!] kaliwall binary not found. Run ./setup.sh first.${NC}"
    exit 1
fi

mkdir -p logs data

case "${1:-}" in
    --foreground)
        echo -e "${GREEN}[+] Starting KaliWall in foreground...${NC}"
        echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
        echo -e "${YELLOW}[!] Run with sudo for live firewall integration${NC}"
        ./kaliwall "${DPI_ARGS[@]}"
        ;;
    --daemon)
        if [[ -f "$PID_FILE" ]]; then
            OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [[ -n "${OLD_PID}" ]] && is_running_pid "$OLD_PID"; then
                echo -e "${YELLOW}[!] KaliWall already running with PID ${OLD_PID}${NC}"
                echo "Made with ❤️ by Sujal Lamichhane"
                exit 0
            fi
            rm -f "$PID_FILE"
        fi
        rotate_log_if_needed
        echo -e "${GREEN}[+] Starting KaliWall in daemon mode...${NC}"
        nohup ./kaliwall "${DPI_ARGS[@]}" > "$LOG_FILE" 2>&1 &
        DAEMON_PID=$!
        echo "$DAEMON_PID" > "$PID_FILE"
        echo -e "${GREEN}[+] KaliWall started (PID: ${DAEMON_PID})${NC}"
        echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
        echo -e "${GREEN}[+] Logs:   ./start.sh --logs${NC}"
        echo -e "${GREEN}[+] Follow: ./start.sh --logs-follow${NC}"
        echo -e "${YELLOW}[!] Stop:   ./start.sh --stop${NC}"
        ;;
    --stop)
        stopped_any=0

        if [[ -f "$PID_FILE" ]]; then
            DAEMON_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [[ -n "${DAEMON_PID}" ]] && stop_pid_graceful "$DAEMON_PID" "daemon"; then
                stopped_any=1
            else
                echo -e "${YELLOW}[!] PID file process not running or could not be stopped${NC}"
            fi
            rm -f "$PID_FILE"
        else
            echo -e "${YELLOW}[!] No PID file found (${PID_FILE}); checking running processes...${NC}"
        fi

        if command -v pgrep >/dev/null 2>&1; then
            mapfile -t EXTRA_PIDS < <(pgrep -f "${SCRIPT_DIR}/kaliwall" 2>/dev/null || true)
            for pid in "${EXTRA_PIDS[@]:-}"; do
                [[ -z "$pid" || "$pid" == "$$" ]] && continue
                if stop_pid_graceful "$pid" "kaliwall process"; then
                    stopped_any=1
                fi
            done
        fi

        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet kaliwall; then
            echo -e "${YELLOW}[!] kaliwall systemd service is active; stopping it...${NC}"
            if systemctl stop kaliwall >/dev/null 2>&1 || sudo systemctl stop kaliwall >/dev/null 2>&1; then
                echo -e "${GREEN}[+] kaliwall systemd service stopped${NC}"
                stopped_any=1
            else
                echo -e "${YELLOW}[!] Unable to stop systemd service automatically${NC}"
            fi
        fi

        if [[ "$stopped_any" -eq 1 ]]; then
            echo -e "${GREEN}[+] KaliWall stop sequence completed${NC}"
        else
            echo -e "${YELLOW}[!] No running KaliWall process found${NC}"
        fi
        ;;
    --status)
        if [[ -f "$PID_FILE" ]]; then
            DAEMON_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [[ -n "${DAEMON_PID}" ]] && is_running_pid "$DAEMON_PID"; then
                echo -e "${GREEN}[+] Daemon status: running (PID ${DAEMON_PID})${NC}"
            else
                echo -e "${YELLOW}[!] Daemon status: not running (stale PID file)${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Daemon status: not running${NC}"
        fi
        if command -v systemctl >/dev/null 2>&1; then
            echo ""
            systemctl is-active kaliwall >/dev/null 2>&1 && \
                echo -e "${GREEN}[+] Systemd service: active${NC}" || \
                echo -e "${YELLOW}[!] Systemd service: inactive${NC}"
        fi
        ;;
    --logs)
        if [[ ! -f "$LOG_FILE" ]]; then
            echo -e "${YELLOW}[!] Log file not found: ${LOG_FILE}${NC}"
            exit 1
        fi
        tail -n 120 "$LOG_FILE"
        ;;
    --logs-follow)
        if [[ ! -f "$LOG_FILE" ]]; then
            echo -e "${YELLOW}[!] Log file not found: ${LOG_FILE}${NC}"
            exit 1
        fi
        tail -f "$LOG_FILE"
        ;;
    --service)
        echo -e "${GREEN}[+] Starting KaliWall systemd service...${NC}"
        sudo systemctl start kaliwall
        sudo systemctl status kaliwall --no-pager
        ;;
    --service-logs)
        echo -e "${GREEN}[+] Showing systemd logs (last 120 lines)...${NC}"
        journalctl -u kaliwall -n 120 --no-pager
        ;;
    "")
        if [[ -f "$PID_FILE" ]]; then
            OLD_PID=$(cat "$PID_FILE" 2>/dev/null || true)
            if [[ -n "${OLD_PID}" ]] && is_running_pid "$OLD_PID"; then
                echo -e "${YELLOW}[!] KaliWall already running with PID ${OLD_PID}${NC}"
                echo "Made with ❤️ by Sujal Lamichhane"
                exit 0
            fi
            rm -f "$PID_FILE"
        fi
        rotate_log_if_needed
        echo -e "${GREEN}[+] Starting KaliWall in daemon mode (default)...${NC}"
        nohup ./kaliwall "${DPI_ARGS[@]}" > "$LOG_FILE" 2>&1 &
        DAEMON_PID=$!
        echo "$DAEMON_PID" > "$PID_FILE"
        echo -e "${GREEN}[+] KaliWall started (PID: ${DAEMON_PID})${NC}"
        echo -e "${GREEN}[+] Web UI: http://localhost:8080${NC}"
        echo -e "${GREEN}[+] Logs:   ./start.sh --logs${NC}"
        echo -e "${GREEN}[+] Follow: ./start.sh --logs-follow${NC}"
        echo -e "${YELLOW}[!] Stop:   ./start.sh --stop${NC}"
        ;;
    *)
        usage
        exit 1
        ;;
esac

echo "Made with ❤️ by Sujal Lamichhane"
