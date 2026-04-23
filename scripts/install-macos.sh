#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — macOS (pip-based + launchd)
#
# Installs the agent daemon via pip and registers with the hub.
#
# Usage:
#   bash install-macos.sh <REGISTRATION_TOKEN>
#
# What this does:
#   1. Checks prerequisites (python3.10+, optionally tmux via brew)
#   2. Installs orchestratia-agent via pip
#   3. Registers with the hub
#   4. Installs a launchd agent for persistent operation
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

PLIST_LABEL="com.orchestratia.agent"
PLIST_PATH="$HOME/Library/LaunchAgents/${PLIST_LABEL}.plist"
CONFIG_DIR="$HOME/Library/Application Support/Orchestratia"
LOG_DIR="$HOME/Library/Logs/Orchestratia"
TOTAL_STEPS=5
ERRORS=0

# Install from the public GitHub repo by default (the package is not on
# PyPI). Override with ORCHESTRATIA_INSTALL_SOURCE for forks / pinned tags.
INSTALL_SOURCE="${ORCHESTRATIA_INSTALL_SOURCE:-git+https://github.com/kumarimlab/orchestratia-agent.git@main}"

# ── Helper functions ────────────────────────────────────────────────

print_header() {
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║        Orchestratia Agent Installer (macOS)      ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

step() { echo ""; echo -e "${STEP_COLOR}[$1/${TOTAL_STEPS}]${NC} ${BOLD}$2${NC}"; }
info() { echo -e "     ${ARROW} $1"; }
ok()   { echo -e "     ${PASS} $1"; }
warn() { echo -e "     ${WARN} ${YELLOW}$1${NC}"; }
fail() { echo -e "     ${FAIL} ${RED}$1${NC}"; ERRORS=$((ERRORS + 1)); }
fatal() { echo ""; echo -e "  ${FAIL} ${RED}${BOLD}FATAL: $1${NC}"; echo ""; exit 1; }
check_command() { command -v "$1" >/dev/null 2>&1; }

# ── Validate arguments ──────────────────────────────────────────────

if [ $# -lt 1 ] || [ -z "${1:-}" ]; then
    echo ""
    echo -e "${RED}${BOLD}Error: Registration token required.${NC}"
    echo ""
    echo "Usage: bash install-macos.sh <REGISTRATION_TOKEN>"
    echo ""
    exit 1
fi

TOKEN="$1"
[[ "$TOKEN" =~ ^orcreg_ ]] || fatal "Invalid token format (must start with orcreg_)"

# ── Main installer ──────────────────────────────────────────────────

print_header

# Step 1: Cleanup
step 1 "Removing existing installation (if any)"

EXISTING=false
if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
    EXISTING=true
    launchctl unload "$PLIST_PATH" 2>/dev/null && ok "Unloaded launchd agent" || warn "Could not unload"
fi

if [ -f "$PLIST_PATH" ]; then
    EXISTING=true
    rm -f "$PLIST_PATH" && ok "Removed plist" || warn "Could not remove plist"
fi

if pip3 show orchestratia-agent >/dev/null 2>&1; then
    EXISTING=true
    pip3 uninstall -y orchestratia-agent >/dev/null 2>&1 && ok "Uninstalled pip package" || warn "Could not uninstall"
fi

[ "$EXISTING" = false ] && ok "No existing installation found"

# Step 2: Prerequisites
step 2 "Checking prerequisites"

if check_command python3; then
    PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')
    if [ "$PYTHON_MINOR" -ge 10 ]; then
        ok "Python ${PYTHON_VER}"
    else
        fatal "Python 3.10+ required, found ${PYTHON_VER}"
    fi
else
    fatal "python3 not found. Install from python.org or: brew install python"
fi

if check_command pip3; then
    ok "pip3 available"
else
    fatal "pip3 not found. Install Python from python.org (includes pip)"
fi

# Git is required for pip install from GitHub URL (ships with Xcode CLT on macOS)
if check_command git; then
    ok "git available"
else
    fatal "git not found. Install Xcode Command Line Tools: xcode-select --install"
fi

if check_command tmux; then
    ok "tmux $(tmux -V | awk '{print $2}') — sessions will survive restarts"
else
    warn "tmux not installed — sessions won't survive daemon restarts"
    if check_command brew; then
        info "Install with: brew install tmux"
    fi
fi

if check_command claude; then
    ok "Claude Code CLI found"
else
    warn "Claude Code CLI not found in PATH"
    info "Install: npm install -g @anthropic-ai/claude-code && claude auth login"
fi

# Step 3: Install package
step 3 "Installing orchestratia-agent"

info "Installing via pip..."
if pip3 install -q "$INSTALL_SOURCE" 2>&1; then
    ok "Package installed"
else
    fail "pip install failed"
    fatal "Cannot proceed without the agent package."
fi

AGENT_BIN=$(which orchestratia-agent 2>/dev/null || echo "")
[ -n "$AGENT_BIN" ] && ok "Binary: ${AGENT_BIN}" || fail "Binary not found in PATH"

# Step 4: Register
step 4 "Registering with Orchestratia hub"

mkdir -p "$CONFIG_DIR" "$LOG_DIR"

info "Using one-time registration token..."
if orchestratia-agent --register "$TOKEN" --config "${CONFIG_DIR}/config.yaml" 2>&1; then
    ok "Registered successfully"
else
    fail "Registration failed — check token and network"
fi

# Step 5: launchd agent
step 5 "Setting up launchd agent"

AGENT_BIN=$(which orchestratia-agent 2>/dev/null || echo "orchestratia-agent")
mkdir -p "$HOME/Library/LaunchAgents"

cat > "$PLIST_PATH" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${AGENT_BIN}</string>
        <string>--config</string>
        <string>${CONFIG_DIR}/config.yaml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>${LOG_DIR}/agent.log</string>
    <key>StandardErrorPath</key>
    <string>${LOG_DIR}/agent.err</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
    </dict>
</dict>
</plist>
PLISTEOF
ok "Plist created: ${PLIST_PATH}"

launchctl load "$PLIST_PATH" 2>/dev/null && ok "launchd agent loaded" || fail "Could not load launchd agent"

sleep 2
if launchctl list | grep -q "$PLIST_LABEL" 2>/dev/null; then
    ok "Agent is ${GREEN}running${NC}"
else
    warn "Agent may not be running"
    info "Check: launchctl list | grep orchestratia"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
if [ "$ERRORS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}Installation complete${NC}"
else
    echo -e "  ${YELLOW}${BOLD}Installation finished with ${ERRORS} warning(s)${NC}"
fi
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Open your dashboard at ${CYAN}https://orchestratia.com${NC}"
echo -e "    2. Your agent is running and reporting to the hub"
echo ""
echo -e "  ${DIM}Commands:${NC}  ${CYAN}orchestratia status${NC}  ${DIM}|${NC}  ${CYAN}launchctl list | grep orchestratia${NC}"
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
