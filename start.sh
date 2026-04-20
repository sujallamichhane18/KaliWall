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
#   ./start.sh --ml-status     # probe ML anomaly runtime and model health

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

select_ml_model_path() {
    local base_dir="$1"
    local default_path="${base_dir}/machinelearning/xgboost_anomaly_model.joblib"
    local candidates=(
        "${base_dir}/machinelearning/xgboost_anomaly_model.json"
        "${base_dir}/machinelearning/xgboost_anomaly_model.ubj"
        "${base_dir}/machinelearning/xgboost_anomaly_model.joblib"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        if [[ -f "${candidate}" ]]; then
            printf '%s' "${candidate}"
            return 0
        fi
    done

    printf '%s' "${default_path}"
}

# Keep web UI path explicit so startup remains stable even if cwd handling changes.
export KALIWALL_WEB_DIR="${KALIWALL_WEB_DIR:-${SCRIPT_DIR}/web}"

# ML anomaly inference defaults.
ML_VENV_PYTHON="${SCRIPT_DIR}/.venv-ml/bin/python"
if [[ -z "${KALIWALL_ML_PYTHON_CMD:-}" ]]; then
    if [[ -x "${ML_VENV_PYTHON}" ]]; then
        export KALIWALL_ML_PYTHON_CMD="${ML_VENV_PYTHON}"
    elif command -v python3 >/dev/null 2>&1; then
        export KALIWALL_ML_PYTHON_CMD="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        export KALIWALL_ML_PYTHON_CMD="$(command -v python)"
    else
        export KALIWALL_ML_PYTHON_CMD="python3"
    fi
fi
export KALIWALL_ML_ANOMALY_ENABLED="${KALIWALL_ML_ANOMALY_ENABLED:-1}"
export KALIWALL_ML_SCRIPT_PATH="${KALIWALL_ML_SCRIPT_PATH:-${SCRIPT_DIR}/machinelearning/infer_xgboost.py}"
if [[ -z "${KALIWALL_ML_MODEL_PATH:-}" ]]; then
    export KALIWALL_ML_MODEL_PATH="$(select_ml_model_path "${SCRIPT_DIR}")"
fi
export KALIWALL_ML_METADATA_PATH="${KALIWALL_ML_METADATA_PATH:-${SCRIPT_DIR}/machinelearning/training_metadata.json}"
export KALIWALL_ML_FORCE_CPU="${KALIWALL_ML_FORCE_CPU:-1}"
export KALIWALL_ML_OVERRIDE_RULES_ENABLED="${KALIWALL_ML_OVERRIDE_RULES_ENABLED:-1}"
export KALIWALL_ML_OVERRIDE_RULES_PATH="${KALIWALL_ML_OVERRIDE_RULES_PATH:-${SCRIPT_DIR}/configs/ml-override-rules.yaml}"
export KALIWALL_ML_SCAN_OVERRIDE_ENABLED="${KALIWALL_ML_SCAN_OVERRIDE_ENABLED:-1}"

PID_FILE="kaliwall.pid"
LOG_FILE="logs/kaliwall-daemon.log"
MAX_LOG_SIZE=$((5 * 1024 * 1024))
DPI_ARGS=("--dpi" "--dpi-lite")
ML_LAST_STATUS="unknown"
ML_LAST_DETAIL="not checked"

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
  --ml-status     Probe ML anomaly runtime and model health
EOF
}

command_reference_exists() {
    local cmd="$1"
    if [[ -z "$cmd" ]]; then
        return 1
    fi
    if [[ "$cmd" == */* ]]; then
        [[ -x "$cmd" ]]
    else
        command -v "$cmd" >/dev/null 2>&1
    fi
}

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    printf '%s' "$value"
}

refresh_ml_status() {
    ML_LAST_STATUS="unknown"
    ML_LAST_DETAIL="not checked"

    if [[ "${KALIWALL_ML_ANOMALY_ENABLED}" == "0" ]]; then
        ML_LAST_STATUS="disabled"
        ML_LAST_DETAIL="KALIWALL_ML_ANOMALY_ENABLED=0"
        return 0
    fi

    if ! command_reference_exists "${KALIWALL_ML_PYTHON_CMD}"; then
        ML_LAST_STATUS="not-ready"
        ML_LAST_DETAIL="python command not found: ${KALIWALL_ML_PYTHON_CMD}"
        return 0
    fi

    if [[ ! -f "${KALIWALL_ML_SCRIPT_PATH}" ]]; then
        ML_LAST_STATUS="not-ready"
        ML_LAST_DETAIL="script not found: ${KALIWALL_ML_SCRIPT_PATH}"
        return 0
    fi

    if [[ ! -f "${KALIWALL_ML_MODEL_PATH}" ]]; then
        ML_LAST_STATUS="not-ready"
        ML_LAST_DETAIL="model not found: ${KALIWALL_ML_MODEL_PATH}"
        return 0
    fi

    local payload
    payload=$(printf '{"model_path":"%s","metadata_path":"%s","features":{}}' \
        "$(json_escape "${KALIWALL_ML_MODEL_PATH}")" \
        "$(json_escape "${KALIWALL_ML_METADATA_PATH}")")

    local output
    if ! output=$(printf '%s' "${payload}" | "${KALIWALL_ML_PYTHON_CMD}" "${KALIWALL_ML_SCRIPT_PATH}" 2>&1); then
        ML_LAST_STATUS="error"
        ML_LAST_DETAIL="${output}"
        return 0
    fi

    if [[ "${output}" == *'"ok":true'* ]]; then
        local score
        local threshold
        local feature_count
        local inference_device
        local model_name
        score=$(printf '%s' "${output}" | sed -n 's/.*"score":\([0-9.]*\).*/\1/p' | head -n 1)
        threshold=$(printf '%s' "${output}" | sed -n 's/.*"threshold":\([0-9.]*\).*/\1/p' | head -n 1)
        feature_count=$(printf '%s' "${output}" | sed -n 's/.*"feature_count":\([0-9]*\).*/\1/p' | head -n 1)
        inference_device=$(printf '%s' "${output}" | sed -n 's/.*"inference_device":"\([^"]*\)".*/\1/p' | head -n 1)
        model_name="$(basename "${KALIWALL_ML_MODEL_PATH}")"
        ML_LAST_STATUS="running"
        if [[ -n "${score}" && -n "${threshold}" && -n "${feature_count}" ]]; then
            if [[ -n "${inference_device}" ]]; then
                ML_LAST_DETAIL="model=${model_name}, score=${score}, threshold=${threshold}, features=${feature_count}, device=${inference_device}"
            else
                ML_LAST_DETAIL="model=${model_name}, score=${score}, threshold=${threshold}, features=${feature_count}"
            fi
        else
            ML_LAST_DETAIL="model=${model_name}, inference OK"
        fi
        return 0
    fi

    ML_LAST_STATUS="error"
    ML_LAST_DETAIL="${output}"
}

print_ml_status() {
    refresh_ml_status
    case "${ML_LAST_STATUS}" in
        running)
            echo -e "${GREEN}[+] ML anomaly model: RUNNING (${ML_LAST_DETAIL})${NC}"
            ;;
        disabled)
            echo -e "${YELLOW}[!] ML anomaly model: DISABLED (${ML_LAST_DETAIL})${NC}"
            ;;
        not-ready)
            echo -e "${YELLOW}[!] ML anomaly model: NOT READY (${ML_LAST_DETAIL})${NC}"
            ;;
        error)
            echo -e "${YELLOW}[!] ML anomaly model: ERROR (${ML_LAST_DETAIL})${NC}"
            ;;
        *)
            echo -e "${YELLOW}[!] ML anomaly model: UNKNOWN (${ML_LAST_DETAIL})${NC}"
            ;;
    esac
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
        print_ml_status
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
        print_ml_status
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
        echo ""
        print_ml_status
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
    --ml-status)
        print_ml_status
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
        print_ml_status
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
