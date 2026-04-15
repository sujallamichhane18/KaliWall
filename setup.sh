#!/usr/bin/env bash
# KaliWall setup script for Linux
# Usage: chmod +x setup.sh && ./setup.sh
#
# This script only sets up KaliWall:
#   1. Detects and installs missing prerequisites
#   2. Installs Go only when needed
#   3. Downloads dependencies
#   4. Builds the KaliWall daemon and CLI
#   5. Creates data directory
#   6. Optionally installs systemd service

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ML_VENV_DIR=""
ML_PREFERRED_MODEL_PATH=""

echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN}  KaliWall  Firewall Setup${NC}"
echo -e "${GREEN}=======================================${NC}"

run_as_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        "$@"
        return
    fi
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}[!] sudo is required to run: $*${NC}"
        exit 1
    else
        sudo "$@"
    fi
}

append_missing_package() {
    local pkg="$1"
    for existing in "${missing_packages[@]:-}"; do
        if [[ "${existing}" == "${pkg}" ]]; then
            return 0
        fi
    done
    missing_packages+=("${pkg}")
}

ensure_apt_packages() {
    local packages=("$@")
    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi
    if ! command -v apt-get &> /dev/null; then
        echo -e "${RED}[!] apt-get is not available. Install these prerequisites manually: ${packages[*]}${NC}"
        exit 1
    fi
    echo -e "${YELLOW}[*] Installing missing system dependencies: ${packages[*]}${NC}"
    run_as_root apt-get update
    run_as_root apt-get install -y "${packages[@]}"
}

go_meets_minimum_version() {
    local version_string="${1#go}"
    version_string="${version_string%% *}"

    if [[ "${version_string}" == devel* ]]; then
        return 0
    fi

    if [[ ! "${version_string}" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?$ ]]; then
        return 1
    fi

    local major="${BASH_REMATCH[1]}"
    local minor="${BASH_REMATCH[2]}"

    if (( major > 1 )); then
        return 0
    fi
    if (( major < 1 )); then
        return 1
    fi
    (( minor >= 21 ))
}

install_go() {
    echo -e "${YELLOW}[*] Go not found or outdated. Installing Go 1.22...${NC}"
    local GO_TAR="go1.22.0.linux-amd64.tar.gz"
    curl -fsSL "https://go.dev/dl/${GO_TAR}" -o "/tmp/${GO_TAR}"
    run_as_root rm -rf /usr/local/go
    run_as_root tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    export PATH="/usr/local/go/bin:$PATH"

    local USER_HOME="${HOME}"
    if [[ -n "${SUDO_USER:-}" ]]; then
        if command -v getent &> /dev/null; then
            USER_HOME="$(getent passwd "${SUDO_USER}" | cut -d: -f6)"
        else
            USER_HOME="$(eval echo "~${SUDO_USER}")"
        fi
    fi

    if [[ -n "${USER_HOME}" && -f "${USER_HOME}/.bashrc" ]] && ! grep -q '/usr/local/go/bin' "${USER_HOME}/.bashrc"; then
        echo 'export PATH="/usr/local/go/bin:$PATH"' >> "${USER_HOME}/.bashrc"
    fi

    rm -f "/tmp/${GO_TAR}"
    echo -e "${GREEN}[+] Go installed: $(go version)${NC}"
}

setup_ml_python_env() {
    echo -e "${YELLOW}[*] Preparing ML Python runtime...${NC}"

    local python_cmd=""
    if command -v python3 &> /dev/null; then
        python_cmd="$(command -v python3)"
    elif command -v python &> /dev/null; then
        python_cmd="$(command -v python)"
    fi

    if [[ -z "${python_cmd}" ]]; then
        echo -e "${RED}[!] Python 3 is required for ML inference but was not found${NC}"
        exit 1
    fi

    local venv_dir="${SCRIPT_DIR}/.venv-ml"
    local venv_python="${venv_dir}/bin/python"
    local requirements_file="${SCRIPT_DIR}/machinelearning/requirements.txt"
    local joblib_model="${SCRIPT_DIR}/machinelearning/xgboost_anomaly_model.joblib"
    local json_model="${SCRIPT_DIR}/machinelearning/xgboost_anomaly_model.json"
    local ubj_model="${SCRIPT_DIR}/machinelearning/xgboost_anomaly_model.ubj"

    "${python_cmd}" -m venv "${venv_dir}"

    echo -e "${YELLOW}[*] Installing ML Python dependencies...${NC}"
    "${venv_python}" -m pip install --upgrade pip >/dev/null
    if [[ -f "${requirements_file}" ]]; then
        "${venv_python}" -m pip install -r "${requirements_file}"
    else
        "${venv_python}" -m pip install numpy joblib xgboost
    fi

    if ! "${venv_python}" - <<'PY'
import importlib
for module_name in ("numpy", "joblib", "xgboost"):
    importlib.import_module(module_name)
print("ok")
PY
    then
        echo -e "${RED}[!] ML Python dependency validation failed${NC}"
        exit 1
    fi

    ML_VENV_DIR="${venv_dir}"
    echo -e "${GREEN}[+] ML runtime ready: ${venv_python}${NC}"

    if [[ -f "${joblib_model}" && ! -f "${json_model}" ]]; then
        echo -e "${YELLOW}[*] Exporting joblib model to Booster JSON for compatibility...${NC}"
        if "${venv_python}" - <<PY
import sys
from pathlib import Path

import joblib
import xgboost as xgb

joblib_model = Path(r"${joblib_model}")
json_model = Path(r"${json_model}")

model = joblib.load(joblib_model)
booster = None
if isinstance(model, xgb.Booster):
    booster = model
elif hasattr(model, "get_booster"):
    booster = model.get_booster()

if booster is None:
    print("Model does not expose Booster interface; keeping original artifact", file=sys.stderr)
    sys.exit(0)

booster.save_model(json_model)
print(f"Saved Booster JSON model: {json_model}")
PY
        then
            echo -e "${GREEN}[+] Booster JSON export ready: ${json_model}${NC}"
        else
            echo -e "${YELLOW}[!] Unable to export Booster JSON; continuing with available model artifact${NC}"
        fi
    fi

    if [[ -f "${json_model}" ]]; then
        ML_PREFERRED_MODEL_PATH="${json_model}"
    elif [[ -f "${ubj_model}" ]]; then
        ML_PREFERRED_MODEL_PATH="${ubj_model}"
    elif [[ -f "${joblib_model}" ]]; then
        ML_PREFERRED_MODEL_PATH="${joblib_model}"
    else
        ML_PREFERRED_MODEL_PATH="${joblib_model}"
    fi
    echo -e "${GREEN}[+] ML model path selected: ${ML_PREFERRED_MODEL_PATH}${NC}"

    if [[ ! -f "${ML_PREFERRED_MODEL_PATH}" ]]; then
        echo -e "${YELLOW}[!] Model file not found yet: ${ML_PREFERRED_MODEL_PATH}${NC}"
    fi
}

missing_packages=()
for dependency in curl tar; do
    if command -v "${dependency}" &> /dev/null; then
        echo -e "${GREEN}[+] Found dependency: ${dependency} ($(command -v "${dependency}"))${NC}"
    else
        missing_packages+=("${dependency}")
    fi
done

if command -v python3 &> /dev/null; then
    echo -e "${GREEN}[+] Found dependency: python3 ($(command -v python3))${NC}"
else
    append_missing_package "python3"
fi

if command -v pip3 &> /dev/null; then
    echo -e "${GREEN}[+] Found dependency: pip3 ($(command -v pip3))${NC}"
else
    append_missing_package "python3-pip"
fi

if python3 -m venv --help >/dev/null 2>&1; then
    echo -e "${GREEN}[+] Found dependency: python3-venv${NC}"
else
    append_missing_package "python3-venv"
fi

ensure_apt_packages "${missing_packages[@]}"

# 1. Check / Install Go
if command -v go &> /dev/null; then
    current_go_version="$(go version | awk '{print $3}')"
    if go_meets_minimum_version "${current_go_version}"; then
        echo -e "${GREEN}[+] Go already installed: $(go version)${NC}"
    else
        install_go
    fi
else
    install_go
fi

# 2. Navigate to project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 2.5. Prepare Python ML runtime used by anomaly model integration
setup_ml_python_env

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

    local WEB_INSTALL_ROOT="/usr/local/share/kaliwall"
    local WEB_INSTALL_DIR="${WEB_INSTALL_ROOT}/web"
    local ML_PYTHON="${SCRIPT_DIR}/.venv-ml/bin/python"

    if [[ ! -x "${ML_PYTHON}" ]]; then
        if command -v python3 &> /dev/null; then
            ML_PYTHON="$(command -v python3)"
        elif command -v python &> /dev/null; then
            ML_PYTHON="$(command -v python)"
        fi
    fi

    echo -e "${YELLOW}[*] Installing web assets to ${WEB_INSTALL_DIR}...${NC}"
    run_as_root mkdir -p "${WEB_INSTALL_ROOT}"
    run_as_root rm -rf "${WEB_INSTALL_DIR}"
    run_as_root mkdir -p "${WEB_INSTALL_DIR}"
    run_as_root cp -a "${SCRIPT_DIR}/web/." "${WEB_INSTALL_DIR}/"

    cat > /tmp/kaliwall.service <<EOF
[Unit]
Description=KaliWall Firewall
After=network.target

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${SCRIPT_DIR}/kaliwall
Environment=KALIWALL_WEB_DIR=${WEB_INSTALL_DIR}
Environment="KALIWALL_ML_ANOMALY_ENABLED=1"
Environment="KALIWALL_ML_PYTHON_CMD=${ML_PYTHON}"
Environment="KALIWALL_ML_SCRIPT_PATH=${SCRIPT_DIR}/machinelearning/infer_xgboost.py"
Environment="KALIWALL_ML_MODEL_PATH=${ML_PREFERRED_MODEL_PATH:-${SCRIPT_DIR}/machinelearning/xgboost_anomaly_model.joblib}"
Environment="KALIWALL_ML_METADATA_PATH=${SCRIPT_DIR}/machinelearning/training_metadata.json"
Environment="KALIWALL_ML_FORCE_CPU=1"
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    run_as_root mv /tmp/kaliwall.service /etc/systemd/system/kaliwall.service
    run_as_root systemctl daemon-reload
    run_as_root systemctl enable kaliwall
    echo -e "${GREEN}[+] Systemd service installed and enabled${NC}"
    echo -e "${GREEN}[+] Use start.sh or systemctl to run KaliWall${NC}"
}

# Check for --service flag
if [[ "${1:-}" == "--service" ]]; then
    install_service
    echo -e "${GREEN}[+] Service setup complete${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}[+] Setup complete${NC}"
echo -e "${GREEN}[+] Binary: ./kaliwall${NC}"
echo -e "${GREEN}[+] CLI:    ./kaliwall-cli${NC}"
if [[ -n "${ML_VENV_DIR}" ]]; then
    echo -e "${GREEN}[+] ML Python env: ${ML_VENV_DIR}/bin/python${NC}"
fi
echo -e "${GREEN}[+] Next:   ./start.sh${NC}"
echo -e "${GREEN}[+] Logs:   ./start.sh --logs${NC}"
echo -e "${GREEN}[+] Follow: ./start.sh --logs-follow${NC}"
echo -e "${YELLOW}[!] Run with sudo for live firewall integration${NC}"
echo ""
echo "Made with ❤️ by Sujal Lamichhane"
