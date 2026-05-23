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
# Isolated venv for the agent. Keeps us out of system Python — no PEP 668
# collisions, no Debian-managed-dep RECORD-not-found errors, no
# --user-vs-system entry-point guessing, and `orchestratia update` runs
# without sudo because the venv is owned by $RUN_USER. v0.13.0+ uses
# this; earlier versions installed via pip3 system-wide.
VENV_DIR="/opt/orchestratia-venv"
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

# /opt/orchestratia-agent is intentionally preserved here — it's the
# live source tree that provides agent-skills/ (SKILL.md files and hook
# shell scripts). Step 6 refreshes it via `git pull` or `git clone` as
# appropriate. Deleting it here would break any symlinks the previous
# install created under ~/.claude/skills/ and ~/.gemini/skills/ until
# the new clone finishes, which is pointless churn.

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

# Remove the v0.13.0+ venv if present. Migrating from pre-0.13 (pip-based)
# to 0.13+ (venv-based) is a clean slate — venv install can't merge into
# the old layout.
if [ -d "$VENV_DIR" ]; then
    EXISTING=true
    sudo rm -rf "$VENV_DIR" 2>/dev/null && ok "Removed venv ($VENV_DIR)" || warn "Could not remove $VENV_DIR"
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

# Claude Code is typically installed per-user via npm install -g --prefix
# ~/.npm-global, which puts it in ~/.npm-global/bin/. The installer runs
# as root via sudo and doesn't see those user-level PATH entries. Shell
# out as the target user with a login shell so .bashrc/.profile are
# sourced and ~/.npm-global/bin is picked up.
if sudo -u "$RUN_USER" bash -lc 'command -v claude >/dev/null 2>&1'; then
    CLAUDE_VER=$(sudo -u "$RUN_USER" bash -lc 'claude --version 2>/dev/null' || echo "installed")
    ok "Claude Code ${CLAUDE_VER}"
else
    warn "Claude Code CLI not found in ${RUN_USER}'s PATH"
    info "Install: sudo -u ${RUN_USER} npm install -g @anthropic-ai/claude-code && claude auth login"
fi

# Step 3: Install package
step 3 "Installing orchestratia-agent"

# v0.13.0+ uses an isolated venv at $VENV_DIR instead of system pip3.
# Eliminates an entire class of install/upgrade bugs:
#   - PEP 668 externally-managed-environment errors (Ubuntu 24.04+)
#   - Debian-managed dep collisions (PyJWT, PyYAML — "Cannot uninstall X,
#     RECORD file not found")
#   - Entry-point generation failures from stale system setuptools
#   - --user vs system entry-point landing-spot guessing
#   - "orchestratia update" needing sudo (venv is owned by RUN_USER)

# Ensure python3-venv + ensurepip are present. Ubuntu/Debian splits venv
# into multiple pieces:
#   - `python3-venv` (or `python${ver}-venv`) installs the venv module
#   - ensurepip is bundled with python3.X but Debian sometimes ships
#     python3 *without* it (most common on Ubuntu 22.04 with stock
#     python3.10) — `python3 -m venv --help` then succeeds while
#     `python3 -m venv <path>` fails at create-time with
#     "ensurepip is not available".
#
# We test the actual breaking condition (`import ensurepip`) instead of
# `--help`, then install both the version-specific and generic venv
# packages so any apt-shipped layout works.
if ! python3 -c "import ensurepip" >/dev/null 2>&1 \
   || ! python3 -m venv --help >/dev/null 2>&1; then
    info "Python venv/ensurepip support missing — installing..."

    # apt-get update first — stale package lists are the #1 reason
    # `apt install <pkg>` fails on a freshly-provisioned box. Cheap to
    # run on a machine that's already current; mandatory on one that
    # isn't.
    APT_UPDATE_OUT=""
    if ! APT_UPDATE_OUT=$(sudo apt-get update -qq 2>&1); then
        warn "apt-get update reported errors:"
        echo -e "     ${DIM}${APT_UPDATE_OUT}${NC}"
    fi

    # Try the version-specific name first (Ubuntu 22.04 needs
    # python3.10-venv specifically; the generic python3-venv is a
    # virtual package that may resolve to the wrong version).
    INSTALL_OUT=""
    PYVENV_PKG="python${PYTHON_VER}-venv"
    if ! INSTALL_OUT=$(sudo apt-get install -y "$PYVENV_PKG" 2>&1); then
        # Fall back to the generic name (Debian-style).
        PYVENV_PKG="python3-venv"
        if ! INSTALL_OUT=$(sudo apt-get install -y "$PYVENV_PKG" 2>&1); then
            fail "Could not install $PYVENV_PKG:"
            # Show the last 10 lines of apt's output — usually contains
            # the actual reason (missing repo, held package, etc).
            echo "$INSTALL_OUT" | tail -10 | while IFS= read -r line; do
                echo -e "     ${DIM}${line}${NC}"
            done
            info "Run manually to see the full error:"
            info "  sudo apt-get update && sudo apt-get install -y $PYVENV_PKG"
            fatal "Cannot proceed without venv support."
        fi
    fi
    ok "Installed $PYVENV_PKG"

    # Re-verify after install. If still broken, fail loudly here rather
    # than letting the venv create step report the same error one
    # screen later.
    if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
        fail "ensurepip still unavailable after installing $PYVENV_PKG"
        info "Try manually: sudo apt-get install -y python3-venv python3-pip-whl"
        fatal "Python venv support is broken on this system."
    fi
fi

info "Creating venv at $VENV_DIR..."
sudo mkdir -p "$(dirname "$VENV_DIR")"
if ! VENV_OUT=$(sudo python3 -m venv "$VENV_DIR" 2>&1); then
    fail "Could not create venv:"
    echo -e "     ${DIM}${VENV_OUT}${NC}"
    fatal "Cannot proceed without the venv."
fi
ok "Venv created"

# Bootstrap fresh pip + setuptools + wheel inside the venv. Distros'
# bundled ensurepip seeds are sometimes years old and ship the exact
# setuptools versions that fail to render console_scripts entry-points
# on PEP 517 builds — the failure mode that prompted this whole refactor.
# `--quiet` makes failures quieter; we capture stdout/stderr so the
# fatal path still shows what went wrong.
if ! BOOTSTRAP_OUT=$(sudo "$VENV_DIR/bin/pip" install --upgrade --quiet pip setuptools wheel 2>&1); then
    fail "Could not bootstrap pip/setuptools/wheel in venv:"
    echo -e "     ${DIM}${BOOTSTRAP_OUT}${NC}"
    fatal "Cannot proceed without a working venv pip."
fi
ok "Venv pip bootstrapped"

info "Installing agent into venv..."
if ! VENV_INSTALL_OUT=$(sudo "$VENV_DIR/bin/pip" install --quiet "$INSTALL_SOURCE" 2>&1); then
    fail "venv pip install failed:"
    echo -e "     ${DIM}${VENV_INSTALL_OUT}${NC}"
    info "Try manually: sudo $VENV_DIR/bin/pip install $INSTALL_SOURCE"
    fatal "Cannot proceed without the agent package."
fi
ok "Package installed in venv"

# Hand the venv to RUN_USER so `orchestratia update` (which runs as the
# daemon user) can write into venv/lib/python*/site-packages without sudo.
sudo chown -R "${RUN_USER}:${RUN_USER}" "$VENV_DIR" 2>/dev/null || true

# PATH-discoverable wrappers at /usr/local/bin/ so users still type
# `orchestratia status` etc from any shell. Each wrapper is a 2-line
# stub that execs the venv binary — venv activation isn't needed
# because venv's bin/orchestratia-agent shebang already points at the
# venv's python interpreter, so subprocess imports resolve to venv
# site-packages automatically.
for bin in orchestratia-agent orchestratia; do
    sudo tee "/usr/local/bin/$bin" >/dev/null <<WRAPPER
#!/bin/sh
exec "$VENV_DIR/bin/$bin" "\$@"
WRAPPER
    sudo chmod +x "/usr/local/bin/$bin"
done

# Sanity-check the entry point actually exists. If pip fell back to a
# wheel that skipped console_scripts (the original v0.12.0 install bug),
# this catches it loudly instead of silently shipping a broken install.
if [ ! -x "$VENV_DIR/bin/orchestratia-agent" ]; then
    fail "venv install completed but $VENV_DIR/bin/orchestratia-agent is missing"
    info "pip files: sudo $VENV_DIR/bin/pip show -f orchestratia-agent"
    fatal "Entry-point script was not created."
fi

AGENT_BIN="$VENV_DIR/bin/orchestratia-agent"
ok "Binary: ${AGENT_BIN}"
ok "Wrappers: /usr/local/bin/orchestratia{,-agent}"

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

# Use $AGENT_BIN as set by step 3 — the absolute venv path. Don't
# `which` it: $PATH under sudo doesn't reliably include /usr/local/bin
# on every distro, and the venv path is canonical anyway.

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
#
# Architecture: git-clone the repo to /opt/orchestratia-agent and
# symlink SKILL.md files from ~/.claude/skills/orchestratia/ (etc.)
# into the cloned tree. Hooks in settings.json point directly at hook
# scripts inside the cloned tree. This mirrors the design of the
# top-level install.sh and lets `git pull` inside /opt refresh skill
# content without a full re-install.
step 6 "Setting up AI agent integrations"

INSTALL_DIR="/opt/orchestratia-agent"
REPO_URL="https://github.com/kumarimlab/orchestratia-agent.git"

# Ensure the asset tree exists and is fresh at /opt/orchestratia-agent.
# On a fresh box: clone. On an existing install: fetch + hard reset so
# the tree matches origin/main regardless of local state.
#
# Git 2.35+ has a "dubious ownership" safety check that refuses to
# operate on a repo whose dir is owned by a different user than the
# caller. Our scripts run as root via sudo but the repo dir was
# chown'd to $RUN_USER on a previous install — that combination trips
# the check. Mark the dir safe globally before any git operation.
if sudo git config --global --get-all safe.directory 2>/dev/null | grep -qx "$INSTALL_DIR" ; then
    :
else
    sudo git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
fi

git_fetch_reset() {
    sudo git -C "$INSTALL_DIR" fetch --depth 1 origin main 2>&1 && \
    sudo git -C "$INSTALL_DIR" reset --hard FETCH_HEAD 2>&1
}

if [ -d "$INSTALL_DIR/.git" ]; then
    GIT_OUT=$(git_fetch_reset)
    if [ $? -eq 0 ]; then
        ok "Asset tree refreshed: $INSTALL_DIR"
    else
        warn "Could not refresh $INSTALL_DIR — falling back to fresh clone"
        info "Git error: $(echo "$GIT_OUT" | tail -1)"
        # Re-clone the tree so Step 6 can create valid symlinks even
        # if the existing checkout is corrupt / ownership-locked.
        sudo rm -rf "$INSTALL_DIR" 2>/dev/null || true
        if sudo git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" >/dev/null 2>&1; then
            ok "Asset tree re-cloned: $INSTALL_DIR"
        else
            fail "git clone fallback also failed for $REPO_URL"
        fi
    fi
else
    sudo rm -rf "$INSTALL_DIR" 2>/dev/null || true
    if sudo git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" >/dev/null 2>&1; then
        ok "Asset tree cloned: $INSTALL_DIR"
    else
        fail "git clone failed for $REPO_URL"
    fi
fi

# Give the asset tree to RUN_USER so symlinks + reads work without sudo.
sudo chown -R "${RUN_USER}:${RUN_USER}" "$INSTALL_DIR" 2>/dev/null || true

HOOK_CONTEXT="$INSTALL_DIR/agent-skills/hooks/orchestratia-context.sh"
HOOK_PRETOOLUSE="$INSTALL_DIR/agent-skills/hooks/orchestratia-pretooluse.sh"

# Make hook scripts executable (git clone preserves the +x bit but
# defensive chmod in case someone re-checked out without it).
sudo chmod +x "$INSTALL_DIR/agent-skills/hooks/"*.sh 2>/dev/null || true

# Merge hook entries into a JSON settings file.
# REPLACES any existing orchestratia hook entries with fresh ones, so
# stale paths from earlier installs (e.g. pointing at an old /opt dir
# that was since re-cloned) get updated. Non-orchestratia hooks are
# preserved untouched.
merge_json_hooks() {
    local SETTINGS_PATH="$1"
    local SESSION_EVENT="$2"
    local PRETOOL_EVENT="$3"
    local HOOK_CONTEXT_CMD="$4"
    local HOOK_PRETOOL_CMD="$5"
    sudo -u "$RUN_USER" python3 -c "
import json, os
path = '$SETTINGS_PATH'
settings = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        settings = {}
hooks = settings.setdefault('hooks', {})
session_list = hooks.setdefault('$SESSION_EVENT', [])
hooks['$SESSION_EVENT'] = [e for e in session_list if 'orchestratia' not in str(e)]
hooks['$SESSION_EVENT'].append({'hooks': [{'type': 'command', 'command': '$HOOK_CONTEXT_CMD', 'timeout': 10000}]})
pretool_list = hooks.setdefault('$PRETOOL_EVENT', [])
hooks['$PRETOOL_EVENT'] = [e for e in pretool_list if 'orchestratia' not in str(e)]
hooks['$PRETOOL_EVENT'].append({'hooks': [{'type': 'command', 'command': '$HOOK_PRETOOL_CMD', 'timeout': 30000}]})
os.makedirs(os.path.dirname(path), exist_ok=True)
with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
print('ok')
" 2>/dev/null
}

CLAUDE_DETECTED=false
GEMINI_DETECTED=false
CODEX_DETECTED=false

# ── Claude Code ──
if sudo -u "$RUN_USER" bash -lc 'command -v claude >/dev/null 2>&1'; then
    CLAUDE_DETECTED=true
    SKILL_DIR="${RUN_HOME}/.claude/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$SKILL_DIR" "${RUN_HOME}/.claude" 2>/dev/null || true
    # Remove any existing SKILL.md first so `ln -sf` replaces a stale
    # symlink (including dangling ones pointing at a prior /opt dir
    # that was deleted) or a copied file from the old curl-based path.
    sudo -u "$RUN_USER" rm -f "$SKILL_DIR/SKILL.md" 2>/dev/null || true
    if sudo -u "$RUN_USER" ln -sf "$INSTALL_DIR/agent-skills/claude/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
        ok "Claude Code skill installed"
    else
        warn "Could not create Claude skill symlink"
    fi
    if merge_json_hooks "${RUN_HOME}/.claude/settings.json" "SessionStart" "PreToolUse" "$HOOK_CONTEXT" "$HOOK_PRETOOLUSE" | grep -q "ok"; then
        ok "Claude Code hooks configured"
    else
        warn "Could not configure Claude Code hooks"
    fi
fi

# ── Gemini CLI ──
if sudo -u "$RUN_USER" bash -lc 'command -v gemini >/dev/null 2>&1'; then
    GEMINI_DETECTED=true
    SKILL_DIR="${RUN_HOME}/.gemini/skills/orchestratia"
    SHARED_DIR="${RUN_HOME}/.agents/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$SKILL_DIR" "$SHARED_DIR" "${RUN_HOME}/.gemini" 2>/dev/null || true
    sudo -u "$RUN_USER" rm -f "$SKILL_DIR/SKILL.md" "$SHARED_DIR/SKILL.md" 2>/dev/null || true
    if sudo -u "$RUN_USER" ln -sf "$INSTALL_DIR/agent-skills/gemini/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
        sudo -u "$RUN_USER" cp "$INSTALL_DIR/agent-skills/gemini/SKILL.md" "$SHARED_DIR/SKILL.md" 2>/dev/null || true
        ok "Gemini CLI skill installed"
    else
        warn "Could not create Gemini skill symlink"
    fi
    if merge_json_hooks "${RUN_HOME}/.gemini/settings.json" "SessionStart" "BeforeTool" "$HOOK_CONTEXT" "$HOOK_PRETOOLUSE" | grep -q "ok"; then
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
    SKILL_DIR="${RUN_HOME}/.codex/skills/orchestratia"
    SHARED_DIR="${RUN_HOME}/.agents/skills/orchestratia"
    sudo -u "$RUN_USER" mkdir -p "$SKILL_DIR" "$SHARED_DIR" "${RUN_HOME}/.codex" 2>/dev/null || true
    sudo -u "$RUN_USER" rm -f "$SKILL_DIR/SKILL.md" "$SHARED_DIR/SKILL.md" 2>/dev/null || true
    if sudo -u "$RUN_USER" ln -sf "$INSTALL_DIR/agent-skills/codex/SKILL.md" "$SKILL_DIR/SKILL.md" 2>/dev/null; then
        sudo -u "$RUN_USER" cp "$INSTALL_DIR/agent-skills/codex/SKILL.md" "$SHARED_DIR/SKILL.md" 2>/dev/null || true
        ok "Codex CLI skill installed"
    else
        warn "Could not create Codex skill symlink"
    fi

    # Enable codex_hooks feature flag in config.toml (idempotent).
    CODEX_CONFIG="${RUN_HOME}/.codex/config.toml"
    if [ -f "$CODEX_CONFIG" ]; then
        if ! grep -q "codex_hooks" "$CODEX_CONFIG" 2>/dev/null; then
            echo -e "\n[features]\ncodex_hooks = true" | sudo -u "$RUN_USER" tee -a "$CODEX_CONFIG" >/dev/null
        fi
    else
        echo -e "[features]\ncodex_hooks = true" | sudo -u "$RUN_USER" tee "$CODEX_CONFIG" >/dev/null
    fi

    # Always rewrite hooks.json (cheap, guarantees fresh paths).
    CODEX_HOOKS="${RUN_HOME}/.codex/hooks.json"
    sudo -u "$RUN_USER" tee "$CODEX_HOOKS" >/dev/null <<CODEXEOF
{
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "$HOOK_CONTEXT", "timeout": 10000}]}
    ],
    "PreToolUse": [
      {"matcher": ".*", "hooks": [{"type": "command", "command": "$HOOK_PRETOOLUSE", "timeout": 30000}]}
    ]
  }
}
CODEXEOF
    ok "Codex CLI hooks configured (feature flag enabled)"
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
