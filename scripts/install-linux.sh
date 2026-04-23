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
TOTAL_STEPS=6
ERRORS=0

# Install from the public GitHub repo by default (the package is not on
# PyPI). Users can override with ORCHESTRATIA_INSTALL_SOURCE=<spec> for
# a custom pip spec (e.g. a fork, a PR branch, a pinned tag, or a local
# checkout path).
INSTALL_SOURCE="${ORCHESTRATIA_INSTALL_SOURCE:-git+https://github.com/kumarimlab/orchestratia-agent.git@main}"

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

# CRITICAL: Ensure KillMode=process is set on the live unit BEFORE
# stopping the service. Default systemd KillMode=control-group kills
# every process in the cgroup — including tmux sessions spawned by the
# agent — so a plain `systemctl stop` destroys all live terminals.
# Earlier versions of install-linux.sh (and some historical .service
# files shipped outside this script) lacked KillMode=process, so this
# patch-before-stop step rescues users migrating from those.
LIVE_SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
if [ -f "$LIVE_SERVICE_FILE" ] && ! grep -q "KillMode=process" "$LIVE_SERVICE_FILE" 2>/dev/null; then
    # Patch the live unit: append KillMode=process into the [Service]
    # block and reload. The upcoming stop will respect the new value.
    if sudo grep -q "^\[Service\]" "$LIVE_SERVICE_FILE"; then
        sudo sed -i '/^\[Service\]/a KillMode=process' "$LIVE_SERVICE_FILE" 2>/dev/null && \
            sudo systemctl daemon-reload 2>/dev/null && \
            info "Patched service unit (KillMode=process) to preserve tmux sessions"
    fi
fi

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

# Uninstall pip package. Check BOTH locations:
#   (1) System site-packages (what `sudo pip3` sees)
#   (2) The real user's site-packages (~/.local). The script runs as
#       root via sudo, so its default pip context is root's, not the
#       target user's. If a previous install used `pip install --user`,
#       it lives under ~/.local/ and stays invisible to `sudo pip3
#       show` — yet ~/.local/bin is typically earlier in PATH than
#       /usr/local/bin, so the old user-level binary shadows the new
#       system install. This was the cause of "fresh install reports
#       old version" reports.
# Also clean up orphan entry-point scripts that some pip versions
# leave behind after a failed/partial uninstall.

uninstall_pip() {
    # $1 = user context ("root" or target username), rest = pip flags
    local user="$1"; shift
    local flags="$*"
    if [ "$user" = "root" ]; then
        pip3 uninstall -y $flags orchestratia-agent >/dev/null 2>&1
    else
        sudo -u "$user" pip3 uninstall -y $flags orchestratia-agent >/dev/null 2>&1
    fi
}

for ctx in "root" "$RUN_USER"; do
    # Does this context have the package installed?
    if [ "$ctx" = "root" ]; then
        HAS=$(pip3 show orchestratia-agent >/dev/null 2>&1 && echo y || echo n)
    else
        HAS=$(sudo -u "$ctx" pip3 show orchestratia-agent >/dev/null 2>&1 && echo y || echo n)
    fi
    if [ "$HAS" = "y" ]; then
        EXISTING=true
        if uninstall_pip "$ctx"; then
            ok "Uninstalled pip package ($ctx)"
        elif uninstall_pip "$ctx" "--break-system-packages"; then
            ok "Uninstalled pip package ($ctx)"
        else
            warn "Could not uninstall ($ctx) — reinstall will overwrite"
        fi
    fi
done

# Remove any lingering entry-point scripts from either location. Safe
# if they don't exist. This prevents a ghost `~/.local/bin/orchestratia-agent`
# from winning PATH resolution after pip uninstall.
for bin in orchestratia-agent orchestratia orchestratia-connect; do
    rm -f "/usr/local/bin/$bin" 2>/dev/null || true
    [ -n "$RUN_HOME" ] && rm -f "$RUN_HOME/.local/bin/$bin" 2>/dev/null || true
done

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

# Git is required for pip install from GitHub URL
if check_command git; then
    ok "git available"
else
    info "git not found, installing..."
    if sudo apt-get install -y git >/dev/null 2>&1; then
        ok "git installed"
    else
        fatal "Could not install git. Install manually: sudo apt install git"
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
# Flags:
#   --upgrade          — replace an existing install with the new version
#   --force-reinstall  — reinstall even if the version is already present
#   --no-cache-dir     — never reuse a wheel from pip's cache. pip caches
#                        wheels by git URL; if the URL string is the same
#                        across releases (we use @main), the old wheel
#                        would be reused and pip would never see the new
#                        version. This flag guarantees a fresh build.
PIP_FLAGS="--upgrade --force-reinstall --no-cache-dir -q"

# Always install system-wide (under /usr/local) so the binary is on a
# PATH the systemd service (which runs as $RUN_USER) can reach. We
# deliberately skip --user here: when the script runs as root via sudo,
# --user would put files in /root/.local, which is never what anyone
# wants. If plain install fails due to PEP 668, fall back to
# --break-system-packages (the same flag the uninstall step uses).
if PIP_OUTPUT=$(pip3 install $PIP_FLAGS "$INSTALL_SOURCE" 2>&1); then
    ok "Package installed"
elif pip3 install --help 2>&1 | grep -q "break-system-packages" && \
     PIP_OUTPUT=$(pip3 install $PIP_FLAGS --break-system-packages "$INSTALL_SOURCE" 2>&1); then
    ok "Package installed (--break-system-packages)"
else
    fail "pip3 install failed:"
    echo -e "     ${DIM}${PIP_OUTPUT}${NC}"
    info "Try manually: sudo pip3 install --break-system-packages $INSTALL_SOURCE"
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
StartLimitBurst=5
StartLimitIntervalSec=60

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
ExecStart=${AGENT_BIN} --config ${CONFIG_DIR}/config.yaml
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1

# Only kill the agent process on stop, not its children.
# tmux sessions spawned by the agent live in the same cgroup but must
# survive agent restarts — the agent's session-recovery loop re-attaches
# to orphan tmux sessions on startup. Default KillMode=control-group
# would kill tmux and destroy all live terminals on every restart.
KillMode=process

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

# Step 6: AI Agent integration (Claude Code, Gemini CLI, Codex CLI)
step 6 "Setting up AI agent integrations"

HOOK_DIR="${RUN_HOME}/.orchestratia/agent-skills/hooks"
REPO_BASE="https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/agent-skills"

# Download shared hook scripts into the user's home so they run as the user.
sudo -u "$RUN_USER" mkdir -p "$HOOK_DIR"
if sudo -u "$RUN_USER" curl -fsSL "$REPO_BASE/hooks/orchestratia-context.sh" -o "$HOOK_DIR/orchestratia-context.sh" 2>/dev/null && \
   sudo -u "$RUN_USER" curl -fsSL "$REPO_BASE/hooks/orchestratia-pretooluse.sh" -o "$HOOK_DIR/orchestratia-pretooluse.sh" 2>/dev/null; then
    sudo -u "$RUN_USER" chmod +x "$HOOK_DIR/orchestratia-context.sh" "$HOOK_DIR/orchestratia-pretooluse.sh"
    ok "Hook scripts downloaded"
else
    warn "Could not download hook scripts"
fi

CONTEXT_HOOK_CMD="bash \"$HOOK_DIR/orchestratia-context.sh\""
PRETOOL_HOOK_CMD="bash \"$HOOK_DIR/orchestratia-pretooluse.sh\""

# Merge hook entries into a JSON settings file. Idempotent — existing
# orchestratia entries are left alone (detected by substring match).
# Uses Python via sudo -u so the file is owned by the target user.
merge_json_hooks() {
    local path="$1"
    local session_event="$2"
    local pretool_event="$3"
    local context_cmd="$4"
    local pretool_cmd="$5"
    sudo -u "$RUN_USER" python3 - "$path" "$session_event" "$pretool_event" "$context_cmd" "$pretool_cmd" <<'PYEOF' >/dev/null 2>&1
import json, os, sys
path, session_event, pretool_event, context_cmd, pretool_cmd = sys.argv[1:6]
settings = {}
if os.path.exists(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            settings = json.load(f)
    except Exception:
        pass
hooks = settings.setdefault('hooks', {})
for event, cmd in [(session_event, context_cmd), (pretool_event, pretool_cmd)]:
    event_list = hooks.setdefault(event, [])
    if not any('orchestratia' in str(e) for e in event_list):
        event_list.append({'hooks': [{'type': 'command', 'command': cmd, 'timeout': 10000 if 'context' in cmd else 30000}]})
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
PYEOF
    return $?
}

CLAUDE_DETECTED=false
GEMINI_DETECTED=false
CODEX_DETECTED=false

# ── Claude Code ──
if sudo -u "$RUN_USER" bash -lc 'command -v claude >/dev/null 2>&1'; then
    CLAUDE_DETECTED=true
    CLAUDE_SKILL_DIR="${RUN_HOME}/.claude/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$CLAUDE_SKILL_DIR" "${RUN_HOME}/.claude"
    if sudo -u "$RUN_USER" curl -fsSL "$REPO_BASE/claude/SKILL.md" -o "$CLAUDE_SKILL_DIR/SKILL.md" 2>/dev/null; then
        ok "Claude Code skill installed"
    else
        warn "Could not download Claude SKILL.md"
    fi
    if merge_json_hooks "${RUN_HOME}/.claude/settings.json" "SessionStart" "PreToolUse" "$CONTEXT_HOOK_CMD" "$PRETOOL_HOOK_CMD"; then
        ok "Claude Code hooks configured"
    else
        warn "Could not configure Claude Code hooks"
    fi
fi

# ── Gemini CLI ──
if sudo -u "$RUN_USER" bash -lc 'command -v gemini >/dev/null 2>&1'; then
    GEMINI_DETECTED=true
    GEMINI_SKILL_DIR="${RUN_HOME}/.gemini/skills/orchestratia"
    SHARED_SKILL_DIR="${RUN_HOME}/.agents/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$GEMINI_SKILL_DIR" "$SHARED_SKILL_DIR" "${RUN_HOME}/.gemini"
    if sudo -u "$RUN_USER" curl -fsSL "$REPO_BASE/gemini/SKILL.md" -o "$GEMINI_SKILL_DIR/SKILL.md" 2>/dev/null; then
        sudo -u "$RUN_USER" cp -f "$GEMINI_SKILL_DIR/SKILL.md" "$SHARED_SKILL_DIR/SKILL.md" 2>/dev/null || true
        ok "Gemini CLI skill installed"
    else
        warn "Could not download Gemini SKILL.md"
    fi
    if merge_json_hooks "${RUN_HOME}/.gemini/settings.json" "SessionStart" "BeforeTool" "$CONTEXT_HOOK_CMD" "$PRETOOL_HOOK_CMD"; then
        ok "Gemini CLI hooks configured"
    else
        warn "Could not configure Gemini CLI hooks"
    fi
fi

# ── Codex CLI ──
# Codex uses a TOML config + separate hooks.json, not the
# settings.json pattern used by Claude/Gemini. The feature flag
# `codex_hooks = true` must be enabled in config.toml for hook events
# to actually fire.
if sudo -u "$RUN_USER" bash -lc 'command -v codex >/dev/null 2>&1'; then
    CODEX_DETECTED=true
    CODEX_SKILL_DIR="${RUN_HOME}/.codex/skills/orchestratia"
    SHARED_SKILL_DIR="${RUN_HOME}/.agents/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$CODEX_SKILL_DIR" "$SHARED_SKILL_DIR" "${RUN_HOME}/.codex"
    if sudo -u "$RUN_USER" curl -fsSL "$REPO_BASE/codex/SKILL.md" -o "$CODEX_SKILL_DIR/SKILL.md" 2>/dev/null; then
        sudo -u "$RUN_USER" cp -f "$CODEX_SKILL_DIR/SKILL.md" "$SHARED_SKILL_DIR/SKILL.md" 2>/dev/null || true
        ok "Codex CLI skill installed"
    else
        warn "Could not download Codex SKILL.md"
    fi

    # Enable codex_hooks feature flag in config.toml (idempotent).
    CODEX_CONFIG="${RUN_HOME}/.codex/config.toml"
    if sudo -u "$RUN_USER" test -f "$CODEX_CONFIG"; then
        if ! sudo -u "$RUN_USER" grep -q "codex_hooks" "$CODEX_CONFIG" 2>/dev/null; then
            sudo -u "$RUN_USER" bash -c "printf '\n[features]\ncodex_hooks = true\n' >> '$CODEX_CONFIG'"
        fi
    else
        sudo -u "$RUN_USER" bash -c "printf '[features]\ncodex_hooks = true\n' > '$CODEX_CONFIG'"
    fi

    # Write hooks.json (Codex reads a separate file, not settings.json).
    # Idempotent: skip the write if orchestratia entries already exist.
    CODEX_HOOKS="${RUN_HOME}/.codex/hooks.json"
    if sudo -u "$RUN_USER" test -f "$CODEX_HOOKS" && sudo -u "$RUN_USER" grep -q "orchestratia" "$CODEX_HOOKS" 2>/dev/null; then
        ok "Codex CLI hooks already configured"
    else
        if sudo -u "$RUN_USER" python3 - "$CODEX_HOOKS" "$CONTEXT_HOOK_CMD" "$PRETOOL_HOOK_CMD" <<'PYEOF' >/dev/null 2>&1
import json, os, sys
path, context_cmd, pretool_cmd = sys.argv[1:4]
data = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": context_cmd, "timeout": 10000}]}
        ],
        "PreToolUse": [
            {"matcher": ".*", "hooks": [{"type": "command", "command": pretool_cmd, "timeout": 30000}]}
        ]
    }
}
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2)
    f.write('\n')
PYEOF
        then
            ok "Codex CLI hooks configured (feature flag enabled)"
        else
            warn "Could not configure Codex CLI hooks"
        fi
    fi
fi

# Summary of detected AI agents — single configured line + single note
# for what else is supported. Neutral tone, not red for "not installed".
CONFIGURED=""
AVAILABLE=""
[ "$CLAUDE_DETECTED" = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Claude Code" || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Claude Code"
[ "$GEMINI_DETECTED" = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Gemini CLI"  || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Gemini CLI"
[ "$CODEX_DETECTED"  = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Codex CLI"   || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Codex CLI"
[ -n "$CONFIGURED" ] && ok "Configured: ${CONFIGURED}"
[ -n "$AVAILABLE" ]  && echo -e "     ${DIM}- Also supported (install separately if needed): ${AVAILABLE}${NC}"

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"

if [ "$ERRORS" -eq 0 ]; then
    echo ""
    echo -e "  ${GREEN}${BOLD}Installation complete${NC}"
else
    echo ""
    echo -e "  ${YELLOW}${BOLD}Installation finished with ${ERRORS} warning(s)${NC}"
fi

echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Open your dashboard at ${CYAN}https://orchestratia.com${NC}"
echo -e "    2. Your agent is running and reporting to the hub"
echo ""
echo -e "  ${DIM}Commands:${NC}  ${CYAN}orchestratia status${NC}  ${DIM}|${NC}  ${CYAN}sudo systemctl status ${SERVICE_NAME}${NC}"
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
