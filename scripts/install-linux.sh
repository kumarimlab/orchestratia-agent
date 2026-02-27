#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Linux (pip-based)
#
# Installs the agent daemon via pip and registers with the hub.
#
# Usage:
#   bash install-linux.sh <REGISTRATION_TOKEN>
#
# What this does:
#   0. Uninstalls any existing agent (clean slate)
#   1. Checks prerequisites (python3.10+, tmux, claude)
#   2. Installs orchestratia-agent via pip
#   3. Registers with the hub using your one-time token
#   4. Installs a systemd service for persistent operation
#
# Always safe to re-run — uninstalls first, then installs fresh.
# ──────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Colors & symbols ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

PASS="${GREEN}✓${NC}"
FAIL="${RED}✗${NC}"
WARN="${YELLOW}!${NC}"
ARROW="${CYAN}→${NC}"
STEP_COLOR="${BLUE}"

CONFIG_DIR="/etc/orchestratia"
LOG_DIR="/var/log/orchestratia"
SERVICE_NAME="orchestratia-agent"
TOTAL_STEPS=5
ERRORS=0

# Optional: install from git URL instead of PyPI
INSTALL_SOURCE="${ORCHESTRATIA_INSTALL_SOURCE:-orchestratia-agent}"

# ── Helper functions ────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║        Orchestratia Agent Installer (Linux)      ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() {
    local num=$1
    local title=$2
    echo ""
    echo -e "${STEP_COLOR}[${num}/${TOTAL_STEPS}]${NC} ${BOLD}${title}${NC}"
}

info() { echo -e "     ${ARROW} $1"; }
ok()   { echo -e "     ${PASS} $1"; }
warn() { echo -e "     ${WARN} ${YELLOW}$1${NC}"; }
fail() { echo -e "     ${FAIL} ${RED}$1${NC}"; ERRORS=$((ERRORS + 1)); }

fatal() {
    echo ""
    echo -e "  ${FAIL} ${RED}${BOLD}FATAL: $1${NC}"
    echo -e "     ${DIM}Installation aborted.${NC}"
    echo ""
    exit 1
}

check_command() { command -v "$1" >/dev/null 2>&1; }

# ── Validate arguments ──────────────────────────────────────────────

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
    echo ""
    echo -e "${RED}${BOLD}Error: Registration token required.${NC}"
    echo ""
    echo "Usage:"
    echo "  bash install-linux.sh <REGISTRATION_TOKEN>"
    echo ""
    echo "Get a token from the Orchestratia dashboard:"
    echo "  Agents → Register Agent → Generate Token"
    echo ""
    exit 1
fi

TOKEN="$1"

if [[ ! "$TOKEN" =~ ^orcreg_ ]]; then
    echo ""
    echo -e "${RED}${BOLD}Error: Invalid token format.${NC}"
    echo "Token must start with 'orcreg_'."
    echo ""
    exit 1
fi

# ── Resolve the real (non-root) user ─────────────────────────────────
# The service must run as the user who owns the repos, never root.
# If invoked via sudo, $SUDO_USER has the real user.

if [ "$(id -u)" -eq 0 ]; then
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        RUN_USER="$SUDO_USER"
    else
        echo ""
        echo -e "${RED}${BOLD}Error: Do not run this installer as root.${NC}"
        echo ""
        echo "The agent service must run as the user who owns the repos."
        echo "Run as a regular user (sudo is used internally where needed):"
        echo ""
        echo "  bash install-linux.sh <TOKEN>"
        echo ""
        exit 1
    fi
else
    RUN_USER="$(whoami)"
fi

RUN_HOME=$(eval echo "~${RUN_USER}")

# ── Main installer ──────────────────────────────────────────────────

print_header

info "Service will run as user: ${BOLD}${RUN_USER}${NC} (home: ${RUN_HOME})"

# Step 1: Clean up existing installation
step 1 "Removing existing installation (if any)"

EXISTING=false

if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    EXISTING=true
    sudo systemctl stop "$SERVICE_NAME" 2>/dev/null && ok "Stopped running service" || warn "Could not stop service"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    EXISTING=true
    sudo systemctl disable "$SERVICE_NAME" 2>/dev/null && ok "Disabled service" || warn "Could not disable service"
fi

if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    EXISTING=true
    sudo rm -f "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null && ok "Removed service file" || warn "Could not remove service file"
    sudo systemctl daemon-reload 2>/dev/null || true
fi

# Remove old git-based installation if present
if [ -d "/opt/orchestratia-agent" ]; then
    EXISTING=true
    sudo rm -rf "/opt/orchestratia-agent" 2>/dev/null && ok "Removed legacy /opt/orchestratia-agent" || warn "Could not remove"
fi

# Uninstall pip package
if pip3 show orchestratia-agent >/dev/null 2>&1; then
    EXISTING=true
    pip3 uninstall -y orchestratia-agent >/dev/null 2>&1 && ok "Uninstalled pip package" || warn "Could not uninstall"
fi

if [ "$EXISTING" = false ]; then
    ok "No existing installation found"
fi

# Step 2: Prerequisites
step 2 "Checking prerequisites"

if check_command python3; then
    PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
    if [ "$PYTHON_MAJOR" -ge 3 ] && [ "$PYTHON_MINOR" -ge 10 ]; then
        ok "Python ${PYTHON_VER}"
    else
        fatal "Python 3.10+ required, found ${PYTHON_VER}. Please upgrade."
    fi
else
    fatal "python3 not found. Install it: sudo apt install python3"
fi

if check_command pip3; then
    ok "pip3 available"
else
    info "pip3 not found, installing..."
    if sudo apt-get install -y python3-pip >/dev/null 2>&1; then
        ok "pip3 installed"
    else
        fail "Could not install pip3. Install manually: sudo apt install python3-pip"
    fi
fi

if check_command tmux; then
    ok "tmux $(tmux -V | awk '{print $2}')"
else
    info "tmux not found, installing..."
    if sudo apt-get install -y tmux >/dev/null 2>&1; then
        ok "tmux installed"
    else
        warn "Could not install tmux. Sessions won't survive daemon restarts."
    fi
fi

if check_command claude; then
    CLAUDE_VER=$(claude --version 2>/dev/null || echo "installed")
    ok "Claude Code ${CLAUDE_VER}"
else
    warn "Claude Code CLI not found in PATH"
    info "Install: npm install -g @anthropic-ai/claude-code && claude auth login"
fi

# Step 3: Install package
step 3 "Installing orchestratia-agent"

info "Installing via pip..."
PIP_OUTPUT=""
# Try plain install first, then --user, then --break-system-packages (pip 23+/Python 3.11+)
if PIP_OUTPUT=$(pip3 install -q "$INSTALL_SOURCE" 2>&1); then
    ok "Package installed"
elif PIP_OUTPUT=$(pip3 install -q --user "$INSTALL_SOURCE" 2>&1); then
    ok "Package installed (--user)"
    # Ensure ~/.local/bin is in PATH for this session and the service
    USER_BIN="${RUN_HOME}/.local/bin"
    if [ -d "$USER_BIN" ] && [[ ":$PATH:" != *":$USER_BIN:"* ]]; then
        export PATH="$USER_BIN:$PATH"
        info "Added $USER_BIN to PATH"
    fi
elif pip3 install --help 2>&1 | grep -q "break-system-packages" && \
     PIP_OUTPUT=$(pip3 install -q --break-system-packages "$INSTALL_SOURCE" 2>&1); then
    ok "Package installed (--break-system-packages)"
else
    fail "pip3 install failed:"
    echo -e "     ${DIM}${PIP_OUTPUT}${NC}"
    info "Try manually: pip3 install --user $INSTALL_SOURCE"
    fatal "Cannot proceed without the agent package."
fi

AGENT_BIN=$(which orchestratia-agent 2>/dev/null || echo "")
# Fallback: check common --user install location
if [ -z "$AGENT_BIN" ] && [ -x "${RUN_HOME}/.local/bin/orchestratia-agent" ]; then
    AGENT_BIN="${RUN_HOME}/.local/bin/orchestratia-agent"
fi
if [ -n "$AGENT_BIN" ]; then
    ok "Binary: ${AGENT_BIN}"
else
    fail "orchestratia-agent not found in PATH after install"
fi

# Step 4: Register with hub
step 4 "Registering with Orchestratia hub"

sudo mkdir -p "$CONFIG_DIR" "$LOG_DIR"
sudo chown "${RUN_USER}:${RUN_USER}" "$CONFIG_DIR" "$LOG_DIR" 2>/dev/null || true

info "Using one-time registration token..."
REGISTER_OUTPUT=""
if REGISTER_OUTPUT=$(orchestratia-agent --register "$TOKEN" --config "${CONFIG_DIR}/config.yaml" 2>&1); then
    if echo "$REGISTER_OUTPUT" | grep -qi "api.key\|registered\|success\|saved"; then
        ok "Registered successfully"
    else
        ok "Registration command completed"
    fi
    while IFS= read -r line; do
        if echo "$line" | grep -qiE "api.key|orc_|config|registered|saved|hub_url"; then
            info "${DIM}${line}${NC}"
        fi
    done <<< "$REGISTER_OUTPUT"
else
    fail "Registration failed"
    while IFS= read -r line; do
        echo -e "     ${DIM}${line}${NC}"
    done <<< "$REGISTER_OUTPUT"
    info "Common causes:"
    info "  - Token already used (tokens are one-time)"
    info "  - Token expired (check expiry on dashboard)"
    info "  - Network issue (can this server reach the hub?)"
fi

# Step 5: Systemd service
step 5 "Setting up systemd service"

AGENT_BIN=$(which orchestratia-agent 2>/dev/null || echo "/usr/local/bin/orchestratia-agent")

sudo tee /etc/systemd/system/${SERVICE_NAME}.service >/dev/null <<SERVICEEOF
[Unit]
Description=Orchestratia Agent Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
ExecStart=${AGENT_BIN} --config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

StandardOutput=journal
StandardError=journal
SyslogIdentifier=orchestratia-agent

[Install]
WantedBy=multi-user.target
SERVICEEOF
ok "Service file created"

sudo systemctl daemon-reload 2>/dev/null && ok "systemd reloaded" || fail "daemon-reload failed"
sudo systemctl enable "$SERVICE_NAME" 2>/dev/null && ok "Service enabled (starts on boot)" || fail "Could not enable service"
sudo systemctl start "$SERVICE_NAME" 2>/dev/null && ok "Service started" || {
    fail "Could not start service"
    info "Check logs: sudo journalctl -u ${SERVICE_NAME} -n 20"
}

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    ok "Service is ${GREEN}running${NC}"
else
    STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")
    warn "Service status: ${STATUS}"
    info "Check logs: sudo journalctl -u ${SERVICE_NAME} -n 20"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"

if [ "$ERRORS" -eq 0 ]; then
    echo ""
    echo -e "  ${GREEN}${BOLD}✓ Installation complete — no errors${NC}"
    echo ""
    echo -e "  ${DIM}The agent is running and reporting to the hub.${NC}"
    echo -e "  ${DIM}Check the dashboard to see it online.${NC}"
else
    echo ""
    echo -e "  ${YELLOW}${BOLD}! Installation finished with ${ERRORS} warning(s)${NC}"
    echo ""
    echo -e "  ${DIM}Review the warnings above. The agent may still work.${NC}"
fi

echo ""
echo -e "  ${DIM}Useful commands:${NC}"
echo -e "    Status:   sudo systemctl status ${SERVICE_NAME}"
echo -e "    Logs:     sudo journalctl -u ${SERVICE_NAME} -f"
echo -e "    Restart:  sudo systemctl restart ${SERVICE_NAME}"
echo -e "    Stop:     sudo systemctl stop ${SERVICE_NAME}"
echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
