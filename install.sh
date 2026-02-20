#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer
#
# Installs the agent daemon and registers this server with the hub.
# The registration token (passed as argument) contains the hub URL.
#
# Usage:
#   bash install.sh <REGISTRATION_TOKEN>
#
# What this does:
#   0. Uninstalls any existing agent (clean slate)
#   1. Checks prerequisites (python3, git, claude)
#   2. Clones the agent daemon to /opt/orchestratia-agent
#   3. Installs Python dependencies
#   4. Registers with the hub using your one-time token
#   5. Installs a systemd service for persistent operation
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
NC='\033[0m' # No Color

PASS="${GREEN}✓${NC}"
FAIL="${RED}✗${NC}"
WARN="${YELLOW}!${NC}"
ARROW="${CYAN}→${NC}"
STEP_COLOR="${BLUE}"

INSTALL_DIR="/opt/orchestratia-agent"
CONFIG_DIR="/etc/orchestratia"
LOG_DIR="/var/log/orchestratia"
RUN_DIR="/var/run/orchestratia"
REPO_URL="https://github.com/kumarimlab/orchestratia-agent.git"
SERVICE_NAME="orchestratia-agent"
TOTAL_STEPS=7
ERRORS=0

# ── Helper functions ────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║          Orchestratia Agent Installer            ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() {
    local num=$1
    local title=$2
    echo ""
    echo -e "${STEP_COLOR}[${num}/${TOTAL_STEPS}]${NC} ${BOLD}${title}${NC}"
}

info() {
    echo -e "     ${ARROW} $1"
}

ok() {
    echo -e "     ${PASS} $1"
}

warn() {
    echo -e "     ${WARN} ${YELLOW}$1${NC}"
}

fail() {
    echo -e "     ${FAIL} ${RED}$1${NC}"
    ERRORS=$((ERRORS + 1))
}

fatal() {
    echo ""
    echo -e "  ${FAIL} ${RED}${BOLD}FATAL: $1${NC}"
    echo -e "     ${DIM}Installation aborted.${NC}"
    echo ""
    exit 1
}

check_command() {
    local cmd=$1
    local name=${2:-$1}
    if command -v "$cmd" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# ── Validate arguments ──────────────────────────────────────────────

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
    echo ""
    echo -e "${RED}${BOLD}Error: Registration token required.${NC}"
    echo ""
    echo "Usage:"
    echo "  bash install.sh <REGISTRATION_TOKEN>"
    echo ""
    echo "Get a token from the Orchestratia dashboard:"
    echo "  Agents → Register Agent → Generate Token"
    echo ""
    exit 1
fi

TOKEN="$1"

# Validate token format
if [[ ! "$TOKEN" =~ ^orcreg_ ]]; then
    echo ""
    echo -e "${RED}${BOLD}Error: Invalid token format.${NC}"
    echo ""
    echo "Token must start with 'orcreg_'. You provided:"
    echo "  ${TOKEN:0:20}..."
    echo ""
    echo "Get a valid token from the Orchestratia dashboard."
    echo ""
    exit 1
fi

# ── Main installer ──────────────────────────────────────────────────

print_header

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

if [ -d "$INSTALL_DIR" ]; then
    EXISTING=true
    OLD_COMMIT=$(cd "$INSTALL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    sudo rm -rf "$INSTALL_DIR" 2>/dev/null && ok "Removed ${INSTALL_DIR} (was ${OLD_COMMIT})" || warn "Could not remove ${INSTALL_DIR}"
fi

if [ -d "$CONFIG_DIR" ]; then
    EXISTING=true
    sudo rm -rf "$CONFIG_DIR" 2>/dev/null && ok "Removed ${CONFIG_DIR}" || warn "Could not remove ${CONFIG_DIR}"
fi

if [ -d "$LOG_DIR" ]; then
    EXISTING=true
    sudo rm -rf "$LOG_DIR" 2>/dev/null && ok "Removed ${LOG_DIR}" || warn "Could not remove ${LOG_DIR}"
fi

if [ -d "$RUN_DIR" ]; then
    EXISTING=true
    sudo rm -rf "$RUN_DIR" 2>/dev/null && ok "Removed ${RUN_DIR}" || warn "Could not remove ${RUN_DIR}"
fi

if [ "$EXISTING" = false ]; then
    ok "No existing installation found"
fi

# Step 2: Prerequisites
step 2 "Checking prerequisites"

# Python 3
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

# Git
if check_command git; then
    ok "git $(git --version | awk '{print $3}')"
else
    fatal "git not found. Install it: sudo apt install git"
fi

# pip3
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

# Claude Code (warning only, not fatal)
if check_command claude; then
    CLAUDE_VER=$(claude --version 2>/dev/null || echo "installed")
    ok "Claude Code ${CLAUDE_VER}"
else
    warn "Claude Code CLI not found in PATH"
    info "The daemon needs it for interactive sessions. Install:"
    info "npm install -g @anthropic-ai/claude-code && claude auth login"
fi

# Sudo access
if sudo -n true 2>/dev/null; then
    ok "sudo access"
else
    info "sudo may prompt for your password during installation"
fi

# Step 3: Create directories
step 3 "Creating directories"

for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR"; do
    if sudo mkdir -p "$dir" 2>/dev/null; then
        ok "Created ${dir}"
    else
        fail "Could not create ${dir}"
    fi
done

# Ensure ownership
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" 2>/dev/null || {
    fail "Could not set directory ownership"
}

# Step 4: Clone agent code
step 4 "Installing agent daemon"

info "Cloning from ${REPO_URL}..."
if git clone "$REPO_URL" "$INSTALL_DIR" 2>&1 | tail -1; then
    COMMIT=$(cd "$INSTALL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "")
    ok "Installed to ${INSTALL_DIR} (${COMMIT})"
else
    fail "git clone failed. Check network and repo access."
    fatal "Cannot proceed without the agent code."
fi

# Step 5: Python dependencies
step 5 "Installing Python dependencies"

info "Installing httpx, websockets, pyyaml, psutil..."
PIP_OUTPUT=""
if PIP_OUTPUT=$(pip3 install -q -r "$INSTALL_DIR/requirements.txt" 2>&1); then
    ok "Dependencies installed"
elif PIP_OUTPUT=$(pip3 install -q --break-system-packages -r "$INSTALL_DIR/requirements.txt" 2>&1); then
    ok "Dependencies installed (with --break-system-packages)"
else
    fail "pip3 install failed:"
    echo -e "     ${DIM}${PIP_OUTPUT}${NC}"
    info "Try manually: pip3 install httpx websockets pyyaml psutil"
fi

# Verify imports work
if python3 -c "import httpx, websockets, yaml, psutil" 2>/dev/null; then
    ok "All imports verified"
else
    fail "Some Python packages failed to import"
    info "Try: pip3 install httpx websockets pyyaml psutil"
fi

# Step 6: Register with hub
step 6 "Registering with Orchestratia hub"

info "Using one-time registration token..."
REGISTER_OUTPUT=""
if REGISTER_OUTPUT=$(python3 "$INSTALL_DIR/daemon.py" --register "$TOKEN" 2>&1); then
    # Check for success indicators in output
    if echo "$REGISTER_OUTPUT" | grep -qi "api.key\|registered\|success\|saved"; then
        ok "Registered successfully"
    else
        ok "Registration command completed"
    fi
    # Show key lines from output (API key, config path, etc.)
    while IFS= read -r line; do
        if echo "$line" | grep -qiE "api.key|orc_|config|registered|saved|hub_url"; then
            info "${DIM}${line}${NC}"
        fi
    done <<< "$REGISTER_OUTPUT"
else
    fail "Registration failed"
    echo ""
    # Show the full output for debugging
    while IFS= read -r line; do
        echo -e "     ${DIM}${line}${NC}"
    done <<< "$REGISTER_OUTPUT"
    echo ""
    info "Common causes:"
    info "  - Token already used (tokens are one-time)"
    info "  - Token expired (check expiry on dashboard)"
    info "  - Network issue (can this server reach the hub?)"
    info "  - Token was revoked by admin"
fi

# Step 7: Systemd service
step 7 "Setting up systemd service"

# Update the service file with the current user if not ubuntu
CURRENT_USER=$(whoami)
if [ "$CURRENT_USER" != "ubuntu" ]; then
    info "Adjusting service file for user: ${CURRENT_USER}"
    sudo sed -i "s/User=ubuntu/User=${CURRENT_USER}/" "$INSTALL_DIR/orchestratia-agent.service"
    sudo sed -i "s/Group=ubuntu/Group=${CURRENT_USER}/" "$INSTALL_DIR/orchestratia-agent.service"
fi

if sudo cp "$INSTALL_DIR/orchestratia-agent.service" /etc/systemd/system/ 2>/dev/null; then
    ok "Service file installed"
else
    fail "Could not copy service file to /etc/systemd/system/"
fi

if sudo systemctl daemon-reload 2>/dev/null; then
    ok "systemd reloaded"
else
    fail "systemctl daemon-reload failed"
fi

if sudo systemctl enable "$SERVICE_NAME" 2>/dev/null; then
    ok "Service enabled (starts on boot)"
else
    fail "Could not enable service"
fi

if sudo systemctl start "$SERVICE_NAME" 2>/dev/null; then
    ok "Service started"
else
    fail "Could not start service"
    info "Check logs: sudo journalctl -u ${SERVICE_NAME} -n 20"
fi

# Wait a moment and check status
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
