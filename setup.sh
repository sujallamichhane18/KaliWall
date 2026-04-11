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

echo -e "${GREEN}=======================================${NC}"
echo -e "${GREEN}  KaliWall ❤️ Firewall Setup${NC}"
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

missing_packages=()
for dependency in curl tar; do
    if command -v "${dependency}" &> /dev/null; then
        echo -e "${GREEN}[+] Found dependency: ${dependency} ($(command -v "${dependency}"))${NC}"
    else
        missing_packages+=("${dependency}")
    fi
done

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
Description=KaliWall Firewall
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
echo -e "${GREEN}[+] Next:   ./start.sh${NC}"
echo -e "${GREEN}[+] Logs:   ./start.sh --logs${NC}"
echo -e "${GREEN}[+] Follow: ./start.sh --logs-follow${NC}"
echo -e "${YELLOW}[!] Run with sudo for live firewall integration${NC}"
echo ""
echo "Made with ❤️ by Sujal Lamichhane"
