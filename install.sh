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
# Supports: Linux (systemd), macOS (launchd)
#
# What this does:
#   0. Uninstalls any existing agent (clean slate)
#   1. Checks prerequisites (python3, git, claude)
#   2. Clones the agent daemon to /opt/orchestratia-agent
#   3. Installs Python dependencies
#   4. Registers with the hub using your one-time token
#   5. Installs a persistent service (systemd on Linux, launchd on macOS)
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
TOTAL_STEPS=8
ERRORS=0

# ── OS detection ──────────────────────────────────────────────────
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Linux)  OS_TYPE="linux" ;;
    Darwin) OS_TYPE="darwin" ;;
    *)      echo "Unsupported OS: $OS_TYPE"; exit 1 ;;
esac

LAUNCHD_LABEL="com.orchestratia.agent"
LAUNCHD_PLIST="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"

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

# Package install helper (macOS: brew, Linux: apt)
pkg_install() {
    local pkg="$1"
    if [ "$OS_TYPE" = "darwin" ]; then
        if check_command brew; then
            # brew refuses to run as root — use the real user
            sudo -u "$RUN_USER" brew install "$pkg" 2>/dev/null
        else
            return 1
        fi
    else
        sudo apt-get install -y "$pkg" >/dev/null 2>&1
    fi
}

pkg_install_hint() {
    local pkg="$1"
    if [ "$OS_TYPE" = "darwin" ]; then
        echo "brew install $pkg"
    else
        echo "sudo apt install $pkg"
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
        echo "  bash install.sh <TOKEN>"
        echo ""
        exit 1
    fi
else
    RUN_USER="$(whoami)"
fi

RUN_HOME=$(eval echo "~${RUN_USER}")
RUN_GROUP=$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")

# ── Main installer ──────────────────────────────────────────────────

print_header

info "Service will run as user: ${BOLD}${RUN_USER}${NC} (home: ${RUN_HOME})"
info "Platform: ${BOLD}${OS_TYPE}${NC}"

# Step 1: Clean up existing installation
step 1 "Removing existing installation (if any)"

EXISTING=false

# Service cleanup: systemd (Linux) or launchd (macOS)
if [ "$OS_TYPE" = "linux" ]; then
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
elif [ "$OS_TYPE" = "darwin" ]; then
    if sudo launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep -q "$LAUNCHD_LABEL"; then
        EXISTING=true
        sudo launchctl bootout system/"$LAUNCHD_LABEL" 2>/dev/null && ok "Stopped running service" || warn "Could not stop service"
    fi

    if [ -f "$LAUNCHD_PLIST" ]; then
        EXISTING=true
        sudo rm -f "$LAUNCHD_PLIST" 2>/dev/null && ok "Removed plist" || warn "Could not remove plist"
    fi
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

# Also remove user-level config (default_config_path() checks ~/.config first,
# so a stale config there would shadow the fresh /etc/orchestratia/config.yaml)
USER_CONFIG_DIR="${RUN_HOME}/.config/orchestratia"
if [ -d "$USER_CONFIG_DIR" ]; then
    EXISTING=true
    sudo -u "$RUN_USER" rm -rf "$USER_CONFIG_DIR" 2>/dev/null && ok "Removed ${USER_CONFIG_DIR}" || warn "Could not remove ${USER_CONFIG_DIR}"
fi

# Clean stale Orchestratia env vars from shell startup files.
# Older versions or manual setup may have added exports to .bashrc/.profile
# that override the env vars injected by tmux -e (v0.3.3+).
# Check both .bashrc (Linux default) and .zshrc (macOS default)
for RCFILE in "${RUN_HOME}/.bashrc" "${RUN_HOME}/.zshrc" "${RUN_HOME}/.bash_profile"; do
    if [ -f "$RCFILE" ] && grep -q 'ORCHESTRATIA' "$RCFILE" 2>/dev/null; then
        EXISTING=true
        # Remove the Orchestratia block: comment header + export/alias lines
        if [ "$OS_TYPE" = "darwin" ]; then
            sudo -u "$RUN_USER" sed -i '' '/^# Orchestratia/d;/^# All .* agents run/d;/^# Project scoping/d;/^# Per-session override/d;/^# Example: ORCHESTRATIA/d;/^export ORCHESTRATIA_/d;/^alias orc-/d' "$RCFILE"
        else
            sudo -u "$RUN_USER" sed -i '/^# Orchestratia/d;/^# All .* agents run/d;/^# Project scoping/d;/^# Per-session override/d;/^# Example: ORCHESTRATIA/d;/^export ORCHESTRATIA_/d;/^alias orc-/d' "$RCFILE"
        fi
        ok "Cleaned stale ORCHESTRATIA vars from ${RCFILE}"
    fi
done

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

# macOS: check Xcode Command Line Tools first (git and python3 depend on it)
if [ "$OS_TYPE" = "darwin" ]; then
    # xcode-select -p can return a path even when the tools are broken
    # (e.g. after a macOS upgrade). Test that xcrun actually works.
    if ! xcode-select -p >/dev/null 2>&1 || ! xcrun --version >/dev/null 2>&1; then
        info "Xcode Command Line Tools not found — required for git and python3"
        # Reset stale path so the installer dialog shows up
        sudo xcode-select --reset 2>/dev/null || true
        info "Launching installer (a dialog will appear)..."
        xcode-select --install 2>/dev/null || true
        # Wait for the GUI installer to finish (polls every 5s)
        info "Waiting for installation to complete..."
        while ! xcrun --version >/dev/null 2>&1; do
            sleep 5
        done
        ok "Xcode Command Line Tools installed"
    else
        ok "Xcode Command Line Tools"
    fi

    # Check for Homebrew (needed for tmux/pip installs)
    # Under sudo, /opt/homebrew/bin (Apple Silicon) is often not in PATH.
    # Check the well-known locations before declaring it missing.
    if ! check_command brew; then
        if [ -x /opt/homebrew/bin/brew ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        elif [ -x /usr/local/bin/brew ]; then
            eval "$(/usr/local/bin/brew shellenv)"
        fi
    fi
    if check_command brew; then
        ok "Homebrew $(brew --version 2>/dev/null | head -1 | awk '{print $2}')"
    else
        info "Homebrew not found — installing (needed for tmux)..."
        if sudo -u "$RUN_USER" NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" 2>&1 | tail -5; then
            # Add Homebrew to PATH for the rest of this script
            if [ -x /opt/homebrew/bin/brew ]; then
                eval "$(/opt/homebrew/bin/brew shellenv)"
            elif [ -x /usr/local/bin/brew ]; then
                eval "$(/usr/local/bin/brew shellenv)"
            fi
            ok "Homebrew installed"
        else
            warn "Could not auto-install Homebrew"
            info "Install manually: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        fi
    fi
fi

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
    fatal "python3 not found. Install it: $(pkg_install_hint python3)"
fi

# Git
if check_command git; then
    ok "git $(git --version | awk '{print $3}')"
else
    fatal "git not found. Install it: $(pkg_install_hint git)"
fi

# pip3
if check_command pip3; then
    ok "pip3 available"
else
    info "pip3 not found, installing..."
    if [ "$OS_TYPE" = "darwin" ]; then
        # macOS: try ensurepip first (built into Apple python), then brew
        if sudo -u "$RUN_USER" python3 -m ensurepip --upgrade >/dev/null 2>&1 && check_command pip3; then
            ok "pip3 installed (ensurepip)"
        elif pkg_install python3; then
            ok "pip3 installed (brew python3)"
        else
            fail "Could not install pip3. Try: python3 -m ensurepip --upgrade"
        fi
    else
        if pkg_install python3-pip; then
            ok "pip3 installed"
        else
            fail "Could not install pip3. Install manually: $(pkg_install_hint python3-pip)"
        fi
    fi
fi

# tmux (required for session resilience)
if check_command tmux; then
    ok "tmux $(tmux -V | awk '{print $2}')"
else
    info "tmux not found, installing..."
    if pkg_install tmux; then
        ok "tmux installed"
    else
        fatal "Could not install tmux. Install manually: $(pkg_install_hint tmux)"
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

# Ensure ownership (use the real user, not root)
sudo chown "${RUN_USER}:${RUN_GROUP}" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" 2>/dev/null || {
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

# Clean up any stale pip installs from ALL locations.
# Python resolves user site-packages (~/.local/) before system site-packages.
# If an old version exists in ~/.local/, it shadows any new system install.
info "Removing stale package versions..."
sudo -u "$RUN_USER" HOME="$RUN_HOME" pip3 uninstall -y orchestratia-agent 2>/dev/null || true
pip3 uninstall -y orchestratia-agent 2>/dev/null || true
find "$RUN_HOME"/.local/lib -path "*/orchestratia_agent*" -exec rm -rf {} + 2>/dev/null || true
find "$RUN_HOME"/.local/lib -path "*/orchestratia*agent*" -exec rm -rf {} + 2>/dev/null || true
find /usr/local/lib -path "*/orchestratia_agent*" -exec rm -rf {} + 2>/dev/null || true
find /usr/local/lib -path "*/orchestratia*agent*" -exec rm -rf {} + 2>/dev/null || true
ok "Cleaned stale installs"

# Strategy: install deps from requirements.txt FIRST (explicit, reliable),
# then install the package with --no-deps (just entry points + code).
# This avoids pip's unreliable dependency resolution for local directory
# installs on older pip versions (pip 22.x on Ubuntu 22.04).

# Helper: try pip install with --user, then plain, then --break-system-packages.
# All arguments are passed directly to pip (e.g., -r file.txt, --no-deps, pkg).
pip_install_as_user() {
    local out=""
    if out=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" pip3 install --user "$@" 2>&1); then
        echo "$out"
        return 0
    elif out=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" pip3 install "$@" 2>&1); then
        echo "$out"
        return 0
    elif pip3 install --help 2>&1 | grep -q "break-system-packages" && \
         out=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" pip3 install --break-system-packages "$@" 2>&1); then
        echo "$out"
        return 0
    else
        echo "$out"
        return 1
    fi
}

# 1. Install dependencies from requirements.txt (flat list, no build system needed)
info "Installing dependencies..."
if pip_install_as_user -q -r "$INSTALL_DIR/requirements.txt" >/dev/null 2>&1; then
    ok "Dependencies installed"
else
    # Retry without -q to show errors
    PIP_OUTPUT=$(pip_install_as_user -r "$INSTALL_DIR/requirements.txt" 2>&1) || true
    echo -e "     ${DIM}${PIP_OUTPUT}${NC}"
    warn "Some dependencies may have failed to install"
fi

# 2. Install the package itself (entry points + code only, deps already handled)
info "Installing orchestratia-agent package..."
if pip_install_as_user -q --no-deps "$INSTALL_DIR" >/dev/null 2>&1; then
    ok "Package installed"
else
    PIP_OUTPUT=$(pip_install_as_user --no-deps "$INSTALL_DIR" 2>&1) || true
    fail "pip3 install failed:"
    echo -e "     ${DIM}${PIP_OUTPUT}${NC}"
fi

# Show installed version
PKG_VER=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" pip3 show orchestratia-agent 2>/dev/null | grep '^Version:' | awk '{print $2}' || echo "unknown")
ok "orchestratia-agent ${PKG_VER}"

# Verify all imports work
IMPORT_CHECK="import httpx, websockets, yaml, psutil, pyte, orchestratia_agent"
if sudo -u "$RUN_USER" HOME="$RUN_HOME" python3 -c "$IMPORT_CHECK" 2>/dev/null; then
    ok "All imports verified"
else
    fail "Some imports failed after install"
    info "Try manually: pip3 install --user httpx websockets pyyaml psutil pyte"
fi

# Step 6: Register with hub
step 6 "Registering with Orchestratia hub"

info "Using one-time registration token..."
# Find the installed entry point; fall back to running daemon.py directly
AGENT_CMD=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" which orchestratia-agent 2>/dev/null || echo "")
if [ -z "$AGENT_CMD" ] && [ -x "${RUN_HOME}/.local/bin/orchestratia-agent" ]; then
    AGENT_CMD="${RUN_HOME}/.local/bin/orchestratia-agent"
fi
if [ -z "$AGENT_CMD" ]; then
    AGENT_CMD="python3 $INSTALL_DIR/daemon.py"
    info "Using fallback: ${AGENT_CMD}"
fi
REGISTER_OUTPUT=""
if REGISTER_OUTPUT=$(sudo -u "$RUN_USER" HOME="$RUN_HOME" $AGENT_CMD --config "${CONFIG_DIR}/config.yaml" --register "$TOKEN" 2>&1); then
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

# Verify config was actually created
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    fatal "Registration did not create ${CONFIG_FILE}. Cannot start service without config."
fi

if ! grep -q "api_key:" "$CONFIG_FILE" 2>/dev/null; then
    fatal "Config exists but has no api_key — registration did not complete. Check the token and try again."
fi

ok "Config verified: ${CONFIG_FILE}"

# Step 7: Persistent service
step 7 "Setting up persistent service"

if [ "$OS_TYPE" = "linux" ]; then
    # ── systemd (Linux) ──────────────────────────────────────────────
    # Update the service file with the resolved user
    if [ "$RUN_USER" != "ubuntu" ]; then
        info "Adjusting service file for user: ${RUN_USER}"
        sudo sed -i "s/User=ubuntu/User=${RUN_USER}/" "$INSTALL_DIR/orchestratia-agent.service"
        sudo sed -i "s/Group=ubuntu/Group=${RUN_USER}/" "$INSTALL_DIR/orchestratia-agent.service"
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

elif [ "$OS_TYPE" = "darwin" ]; then
    # ── launchd (macOS) ──────────────────────────────────────────────
    # Find the python3 path to use in the plist
    PYTHON3_PATH=$(which python3)

    info "Creating launchd plist..."
    sudo tee "$LAUNCHD_PLIST" >/dev/null <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${LAUNCHD_LABEL}</string>

    <key>ProgramArguments</key>
    <array>
        <string>${PYTHON3_PATH}</string>
        <string>${INSTALL_DIR}/daemon.py</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/config.yaml</string>
    </array>

    <key>UserName</key>
    <string>${RUN_USER}</string>

    <key>WorkingDirectory</key>
    <string>${INSTALL_DIR}</string>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>

    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.err</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
        <key>HOME</key>
        <string>${RUN_HOME}</string>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:${RUN_HOME}/.local/bin:${RUN_HOME}/.npm-global/bin</string>
    </dict>

    <key>ProcessType</key>
    <string>Standard</string>
</dict>
</plist>
PLIST_EOF

    if [ -f "$LAUNCHD_PLIST" ]; then
        ok "Plist created: ${LAUNCHD_PLIST}"
    else
        fail "Could not create ${LAUNCHD_PLIST}"
    fi

    # Load the service
    if sudo launchctl bootstrap system "$LAUNCHD_PLIST" 2>/dev/null || \
       sudo launchctl load -w "$LAUNCHD_PLIST" 2>/dev/null; then
        ok "Service loaded (starts on boot)"
    else
        fail "Could not load service"
        info "Try manually: sudo launchctl bootstrap system ${LAUNCHD_PLIST}"
    fi
fi

# Install CLI tool — pip installs entry point to ~/.local/bin/ (user install).
# Ensure it's accessible system-wide via /usr/local/bin/ symlink.
info "Installing orchestratia CLI tool..."
USER_CLI="${RUN_HOME}/.local/bin/orchestratia"
if [ -f "$USER_CLI" ]; then
    # Symlink the pip-installed entry point to /usr/local/bin/ so it's always on PATH
    sudo ln -sf "$USER_CLI" /usr/local/bin/orchestratia 2>/dev/null && \
        ok "CLI installed: /usr/local/bin/orchestratia -> ${USER_CLI}" || \
        warn "Could not symlink CLI; available at ${USER_CLI}"
elif command -v orchestratia >/dev/null 2>&1; then
    CLI_PATH=$(command -v orchestratia)
    ok "CLI available: ${CLI_PATH}"
else
    # Fallback: symlink the shim script directly
    if sudo chmod +x "$INSTALL_DIR/cli.py" && sudo ln -sf "$INSTALL_DIR/cli.py" /usr/local/bin/orchestratia 2>/dev/null; then
        ok "CLI installed: /usr/local/bin/orchestratia (shim fallback)"
    else
        warn "Could not install CLI to /usr/local/bin/orchestratia"
        info "Manual install: sudo ln -sf ${INSTALL_DIR}/cli.py /usr/local/bin/orchestratia"
    fi
fi

# Wait a moment and check status
sleep 2
if [ "$OS_TYPE" = "linux" ]; then
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        ok "Service is ${GREEN}running${NC}"
    else
        STATUS=$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo "unknown")
        warn "Service status: ${STATUS}"
        info "Check logs: sudo journalctl -u ${SERVICE_NAME} -n 20"
    fi
elif [ "$OS_TYPE" = "darwin" ]; then
    if sudo launchctl list "$LAUNCHD_LABEL" 2>/dev/null | grep -q '"PID"'; then
        ok "Service is ${GREEN}running${NC}"
    else
        # Check if it loaded at all
        if sudo launchctl list "$LAUNCHD_LABEL" >/dev/null 2>&1; then
            warn "Service loaded but may not be running yet"
        else
            warn "Service status: unknown"
        fi
        info "Check logs: cat ${LOG_DIR}/agent.log"
    fi
fi

# Step 8: Claude Code integration (skill + session hook)
step 8 "Setting up Claude Code integration"

# 8a. Symlink skill file to ~/.claude/skills/orchestratia/
# Symlink (not copy) so updates to /opt/orchestratia-agent/ are reflected immediately.
SKILL_DIR="${RUN_HOME}/.claude/skills/orchestratia"
if sudo -u "$RUN_USER" mkdir -p "$SKILL_DIR" 2>/dev/null; then
    if sudo -u "$RUN_USER" ln -sf "$INSTALL_DIR/claude-skill/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
        ok "Skill symlinked: ${SKILL_DIR}/SKILL.md -> ${INSTALL_DIR}/claude-skill/SKILL.md"
    else
        warn "Could not symlink skill file to ${SKILL_DIR}"
    fi
else
    warn "Could not create ${SKILL_DIR}"
fi

# 8b. Make hook script executable
if [ -f "$INSTALL_DIR/claude-skill/orchestratia-context.sh" ]; then
    chmod +x "$INSTALL_DIR/claude-skill/orchestratia-context.sh"
    ok "Hook script: ${INSTALL_DIR}/claude-skill/orchestratia-context.sh"
else
    warn "Hook script not found at ${INSTALL_DIR}/claude-skill/orchestratia-context.sh"
fi

# 8c. Merge SessionStart hook into ~/.claude/settings.json
CLAUDE_SETTINGS="${RUN_HOME}/.claude/settings.json"
HOOK_SCRIPT="$INSTALL_DIR/claude-skill/orchestratia-context.sh"

sudo -u "$RUN_USER" mkdir -p "${RUN_HOME}/.claude" 2>/dev/null || true

if sudo -u "$RUN_USER" python3 -c "
import json, os, sys

path = '$CLAUDE_SETTINGS'
hook_cmd = '$HOOK_SCRIPT'

# Load existing settings or start fresh
settings = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        settings = {}

# Ensure hooks.SessionStart structure exists
hooks = settings.setdefault('hooks', {})
session_start = hooks.setdefault('SessionStart', [])

# Check if orchestratia hook already exists (avoid duplicates)
already_exists = False
for entry in session_start:
    if isinstance(entry, dict):
        for h in entry.get('hooks', []):
            if isinstance(h, dict) and 'orchestratia' in h.get('command', ''):
                already_exists = True
                break

if not already_exists:
    session_start.append({
        'hooks': [{
            'type': 'command',
            'command': hook_cmd,
            'timeout': 10000
        }]
    })

with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')

print('ok')
" 2>/dev/null; then
    ok "SessionStart hook registered in ${CLAUDE_SETTINGS}"
else
    warn "Could not update ${CLAUDE_SETTINGS}"
    info "Manual setup: add SessionStart hook pointing to ${HOOK_SCRIPT}"
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
if [ "$OS_TYPE" = "linux" ]; then
    echo -e "    Status:   sudo systemctl status ${SERVICE_NAME}"
    echo -e "    Logs:     sudo journalctl -u ${SERVICE_NAME} -f"
    echo -e "    Restart:  sudo systemctl restart ${SERVICE_NAME}"
    echo -e "    Stop:     sudo systemctl stop ${SERVICE_NAME}"
elif [ "$OS_TYPE" = "darwin" ]; then
    echo -e "    Status:   sudo launchctl list ${LAUNCHD_LABEL}"
    echo -e "    Logs:     tail -f ${LOG_DIR}/agent.log"
    echo -e "    Restart:  sudo launchctl kickstart -k system/${LAUNCHD_LABEL}"
    echo -e "    Stop:     sudo launchctl bootout system/${LAUNCHD_LABEL}"
fi
echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
