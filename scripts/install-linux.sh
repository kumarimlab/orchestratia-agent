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

# Install log — every step gets a timestamped entry here so users can
# share a single file when something fails, instead of copy-pasting
# terminal output. Created early; if we can't write to /var/log/, fall
# back to /tmp so a non-root invocation doesn't break the install.
INSTALL_LOG_DIR="/var/log/orchestratia"
INSTALL_LOG=""
if sudo mkdir -p "$INSTALL_LOG_DIR" 2>/dev/null; then
    INSTALL_LOG="$INSTALL_LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
    sudo touch "$INSTALL_LOG" 2>/dev/null && sudo chmod 0640 "$INSTALL_LOG" 2>/dev/null
fi
if [ -z "$INSTALL_LOG" ] || [ ! -w "$INSTALL_LOG" ] && ! sudo test -w "$INSTALL_LOG" 2>/dev/null; then
    INSTALL_LOG="/tmp/orchestratia-install-$(date +%Y%m%d-%H%M%S).log"
    touch "$INSTALL_LOG" 2>/dev/null || INSTALL_LOG=""
fi

# Helper — append a line to the install log, never fails (so log
# writes can't break the installer). Strips ANSI escapes so the log
# is plain text suitable for pasting/grepping.
_log_to_file() {
    if [ -n "$INSTALL_LOG" ]; then
        local line="$1"
        # Strip ANSI color codes for the log copy.
        line=$(echo "$line" | sed -E 's/\x1b\[[0-9;]*[mK]//g')
        local stamp
        stamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        if [ -w "$INSTALL_LOG" ]; then
            echo "[$stamp] $line" >> "$INSTALL_LOG" 2>/dev/null || true
        else
            echo "[$stamp] $line" | sudo tee -a "$INSTALL_LOG" >/dev/null 2>&1 || true
        fi
    fi
}
# Isolated venv for the agent. Keeps us out of system Python — no PEP 668
# collisions, no Debian-managed-dep RECORD-not-found errors, no
# --user-vs-system entry-point guessing. The venv is root's: root runs this
# code, so `sudo orchestratia update` upgrades it. v0.13.0+ uses this;
# earlier versions installed via pip3 system-wide.
VENV_DIR="/opt/orchestratia-venv"
TOTAL_STEPS=6
ERRORS=0

# Install from the public GitHub repo (the package is not on PyPI).
#
# Pinned to the latest RELEASE TAG, not to @main. Tracking a branch meant a
# fresh install silently picked up whatever had just been pushed — unreleased,
# unbuilt, and not what `--version` reported. Windows already installs from
# releases/latest and macOS from a versioned formula; this makes Linux agree
# with them, so cutting a tag is what ships code on every platform.
#
# The tag is resolved after git is confirmed available (see below), because
# `git ls-remote` is what does the lookup — no GitHub API, so no rate limits
# and no token needed.
AGENT_REPO_URL="https://github.com/kumarimlab/orchestratia-agent.git"
# Used only if tag resolution fails. Bump alongside a release.
FALLBACK_TAG="v0.28.1"
# Empty unless the user overrode it; resolved later if so.
INSTALL_SOURCE="${ORCHESTRATIA_INSTALL_SOURCE:-}"

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
    _log_to_file "── [${num}/${TOTAL_STEPS}] ${title} ──"
}

info() { echo -e "     ${ARROW} $1"; _log_to_file "INFO: $1"; }
ok()   { echo -e "     ${PASS} $1"; _log_to_file "OK:   $1"; }
warn() { echo -e "     ${WARN} ${YELLOW}$1${NC}"; _log_to_file "WARN: $1"; }
fail() { echo -e "     ${FAIL} ${RED}$1${NC}"; ERRORS=$((ERRORS + 1)); _log_to_file "FAIL: $1"; }

fatal() {
    echo ""
    echo -e "  ${FAIL} ${RED}${BOLD}FATAL: $1${NC}"
    _log_to_file "FATAL: $1"
    if [ -n "$INSTALL_LOG" ]; then
        echo ""
        echo -e "     ${DIM}Install log saved to: ${BOLD}${INSTALL_LOG}${NC}"
        echo -e "     ${DIM}Share this file when reporting the failure:${NC}"
        echo -e "       ${CYAN}cat ${INSTALL_LOG}${NC}"
    fi
    echo ""
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

# Files this installer creates as root are root's and readable by the daemon user (never group-writable).
umask 022

# Root never imports from the caller's directory: `python3 -c`/`-m` put the cwd first on sys.path, so a planted
# ~/ensurepip.py or ~/venv/__main__.py would run as root. Resolve a relative install source first, then leave.
if [ -n "$INSTALL_SOURCE" ] && [ -e "$INSTALL_SOURCE" ] && [ "${INSTALL_SOURCE#/}" = "$INSTALL_SOURCE" ]; then
    INSTALL_SOURCE="$(cd "$(dirname "$INSTALL_SOURCE")" && pwd)/$(basename "$INSTALL_SOURCE")"
fi
cd / || exit 1

# ── Main installer ──────────────────────────────────────────────────

print_header

# Log system context at the top of every install log so failures don't
# require a second round-trip to ask "what OS / Python / pip version".
_log_to_file "=== Orchestratia Agent install start ==="
_log_to_file "Installer version: 0.13.5"
_log_to_file "Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
_log_to_file "Hostname: $(hostname 2>/dev/null || echo unknown)"
_log_to_file "uname: $(uname -a 2>/dev/null || echo unknown)"
if [ -f /etc/os-release ]; then
    _log_to_file "OS: $(. /etc/os-release; echo "${PRETTY_NAME:-unknown} (${ID:-?} ${VERSION_ID:-?})")"
fi
_log_to_file "RUN_USER: ${RUN_USER}"
_log_to_file "RUN_HOME: ${RUN_HOME}"
_log_to_file "INSTALL_SOURCE: ${INSTALL_SOURCE}"
_log_to_file "VENV_DIR: ${VENV_DIR}"

info "Service will run as user: ${BOLD}${RUN_USER}${NC} (home: ${RUN_HOME})"
if [ -n "$INSTALL_LOG" ]; then
    info "Install log: ${INSTALL_LOG}"
fi

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
# shell scripts). Step 6 replaces it with a fresh root-owned clone, swapped
# in whole. Deleting it here would break any symlinks the previous
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
        python3 -I -m pip uninstall -y $flags orchestratia-agent >/dev/null 2>&1
    else
        sudo -u "$user" pip3 uninstall -y $flags orchestratia-agent >/dev/null 2>&1
    fi
}

for ctx in "root" "$RUN_USER"; do
    # Does this context have the package installed?
    if [ "$ctx" = "root" ]; then
        HAS=$(python3 -I -m pip show orchestratia-agent >/dev/null 2>&1 && echo y || echo n)
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
# Copies an interrupted `sudo orchestratia update` left beside it.
sudo rm -rf "${VENV_DIR}".old-* 2>/dev/null || true

if [ "$EXISTING" = false ]; then
    ok "No existing installation found"
fi

# Step 2: Prerequisites
step 2 "Checking prerequisites"

if check_command python3; then
    PYTHON_VER=$(python3 -I -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    PYTHON_MAJOR=$(python3 -I -c 'import sys; print(sys.version_info.major)')
    PYTHON_MINOR=$(python3 -I -c 'import sys; print(sys.version_info.minor)')
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

# Resolve the newest release tag now that git is available. sort -V orders
# versions properly, so v0.9.10 beats v0.9.9 (a plain sort would not).
if [ -z "$INSTALL_SOURCE" ]; then
    LATEST_TAG=$(git ls-remote --tags --refs "$AGENT_REPO_URL" 'v*' 2>/dev/null \
        | awk -F/ '{print $NF}' | sort -V | tail -1)
    if [ -n "$LATEST_TAG" ]; then
        ok "Latest release: ${LATEST_TAG}"
    else
        LATEST_TAG="$FALLBACK_TAG"
        warn "Could not reach ${AGENT_REPO_URL} to list releases; using ${LATEST_TAG}"
    fi
    INSTALL_SOURCE="git+${AGENT_REPO_URL}@${LATEST_TAG}"
else
    info "Using ORCHESTRATIA_INSTALL_SOURCE override: ${INSTALL_SOURCE}"
fi
_log_to_file "Resolved INSTALL_SOURCE: ${INSTALL_SOURCE}"

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

# Hostname resolution check. On VMware / non-cloud-init images that
# don't auto-populate /etc/hosts, every sudo invocation can block 5-30s
# waiting for DNS to resolve the local hostname during PAM. That makes
# grant-setup look like a permissions bug. Warn here so it's fixed
# before the agent tries to run sudo commands. See
# dogfood-claude-diagnoses-bug.md for the full case study.
HN=$(hostname 2>/dev/null)
if [ -n "$HN" ]; then
    DNS_ELAPSED=$(( $(date +%s%N) ))
    getent ahosts "$HN" >/dev/null 2>&1 || true
    DNS_ELAPSED=$(( ($(date +%s%N) - DNS_ELAPSED) / 1000000 ))  # ms
    if [ "$DNS_ELAPSED" -gt 1000 ]; then
        warn "Hostname '$HN' takes ${DNS_ELAPSED}ms to resolve (expected <100ms)."
        info "Slow sudo will cause grant-setup timeouts. Fix:"
        info "  echo '127.0.1.1 $HN' | sudo tee -a /etc/hosts"
        _log_to_file "WARN_HOSTNAME_SLOW: ${HN} took ${DNS_ELAPSED}ms"
    else
        ok "Hostname resolves in ${DNS_ELAPSED}ms"
    fi
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
if ! python3 -I -c "import ensurepip" >/dev/null 2>&1 \
   || ! python3 -I -m venv --help >/dev/null 2>&1; then
    info "Python venv/ensurepip support missing — installing..."

    # Detect distro — universe-enable logic is Ubuntu-only. On Debian,
    # python3-venv lives in `main` so the fallback path doesn't apply.
    IS_UBUNTU=false
    if [ -f /etc/os-release ] && grep -q '^ID=ubuntu' /etc/os-release; then
        IS_UBUNTU=true
    fi

    # Some minimal Ubuntu cloud images (custom AMIs, container bases,
    # stripped-down provisioning) ship with the `universe` repo disabled,
    # which is where every pythonX.Y-venv package lives. If our first
    # apt install fails with "no installation candidate" / "Unable to
    # locate", try enabling universe and retry once. Universe is a stock
    # Canonical component, not a third-party PPA — enabling it has the
    # same trust footprint as `apt install` itself.
    enable_universe() {
        info "Enabling Ubuntu universe repository (Canonical component, not a third-party PPA)..."
        if command -v add-apt-repository >/dev/null 2>&1; then
            sudo add-apt-repository -y universe >/dev/null 2>&1 || return 1
        else
            # add-apt-repository isn't always installed on minimal images.
            # Write the source list ourselves; named so the operator can
            # see/revert what we added (rm /etc/apt/sources.list.d/orchestratia-universe.list).
            local CODENAME=""
            CODENAME=$(lsb_release -cs 2>/dev/null || \
                       (. /etc/os-release && echo "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"))
            if [ -z "$CODENAME" ]; then
                warn "Could not determine Ubuntu codename to enable universe"
                return 1
            fi
            echo "deb http://archive.ubuntu.com/ubuntu/ ${CODENAME} universe" | \
                sudo tee /etc/apt/sources.list.d/orchestratia-universe.list >/dev/null
            sudo tee -a /etc/apt/sources.list.d/orchestratia-universe.list >/dev/null <<UNIV_EOF
deb http://archive.ubuntu.com/ubuntu/ ${CODENAME}-updates universe
deb http://security.ubuntu.com/ubuntu/ ${CODENAME}-security universe
UNIV_EOF
        fi
        sudo apt-get update -qq >/dev/null 2>&1
        return 0
    }

    # apt_install_with_universe_fallback <pkg> -> 0/1, sets INSTALL_OUT
    apt_install_with_universe_fallback() {
        local pkg="$1"
        if INSTALL_OUT=$(sudo apt-get install -y "$pkg" 2>&1); then
            return 0
        fi
        # Recognise the "package not available" failure mode that the
        # universe fix is for. Other failures (held package, conflict)
        # would not benefit from enabling universe.
        if echo "$INSTALL_OUT" | grep -qE 'no installation candidate|Unable to locate package' \
           && [ "$IS_UBUNTU" = true ]; then
            if enable_universe; then
                if INSTALL_OUT=$(sudo apt-get install -y "$pkg" 2>&1); then
                    return 0
                fi
            fi
        fi
        return 1
    }

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
    if ! apt_install_with_universe_fallback "$PYVENV_PKG"; then
        # Fall back to the generic name (Debian-style).
        PYVENV_PKG="python3-venv"
        if ! apt_install_with_universe_fallback "$PYVENV_PKG"; then
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
    if ! python3 -I -c "import ensurepip" >/dev/null 2>&1; then
        fail "ensurepip still unavailable after installing $PYVENV_PKG"
        info "Try manually: sudo apt-get install -y python3-venv python3-pip-whl"
        fatal "Python venv support is broken on this system."
    fi
fi

info "Creating venv at $VENV_DIR..."
sudo mkdir -p "$(dirname "$VENV_DIR")"
if ! VENV_OUT=$(sudo python3 -I -m venv "$VENV_DIR" 2>&1); then
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
if ! BOOTSTRAP_OUT=$(sudo "$VENV_DIR/bin/python3" -I -m pip install --no-cache-dir --upgrade --quiet pip setuptools wheel 2>&1); then
    fail "Could not bootstrap pip/setuptools/wheel in venv:"
    echo -e "     ${DIM}${BOOTSTRAP_OUT}${NC}"
    fatal "Cannot proceed without a working venv pip."
fi
ok "Venv pip bootstrapped"

info "Installing agent into venv..."
if ! VENV_INSTALL_OUT=$(sudo "$VENV_DIR/bin/python3" -I -m pip install --no-cache-dir --quiet "$INSTALL_SOURCE" 2>&1); then
    fail "venv pip install failed:"
    echo -e "     ${DIM}${VENV_INSTALL_OUT}${NC}"
    info "Try manually: cd / && sudo $VENV_DIR/bin/python3 -I -m pip install --no-cache-dir $INSTALL_SOURCE"
    fatal "Cannot proceed without the agent package."
fi
ok "Package installed in venv"

# The venv stays root's: root runs this code (sudo orchestratia …, the scan-data timer), so no other account may
# change it. `sudo orchestratia update` upgrades it.

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
    info "pip files: cd / && sudo $VENV_DIR/bin/python3 -I -m pip show -f orchestratia-agent"
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

# The config holds this server's API key. Registration runs as root, and an install
# from before this line left it root-owned and world-readable — readable by every
# local user, including locked-down project users. The daemon user owns it, nobody
# else reads it. Also repairs an existing install on upgrade.
if [ -f "${CONFIG_DIR}/config.yaml" ]; then
    sudo chown "${RUN_USER}:${RUN_USER}" "${CONFIG_DIR}/config.yaml"
    sudo chmod 0600 "${CONFIG_DIR}/config.yaml"
fi
sudo chmod 0750 "$CONFIG_DIR"

# Step 5: Systemd service
step 5 "Setting up systemd service"

# Access grants go through ONE root-owned helper (installed by `secure-install` in step 6), never through broad sudo
# rules. Remove the rules earlier installers wrote: each of them let this account become root.
sudo rm -f "/etc/sudoers.d/${SERVICE_NAME}"
# uninstall.sh expires the orchestratia account (day 1) so grant logins stop; a reinstall lifts only that marker (an
# expiry an admin set stays). The agent re-adds the keys of the grants the hub still lists.
if id orchestratia >/dev/null 2>&1 && [ "$(sudo getent shadow orchestratia | cut -d: -f8)" = "1" ]; then
    sudo usermod -e "" orchestratia && ok "Access-grant logins re-enabled for the orchestratia account"
fi

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
# Reserve the upload folders for root at every boot (/etc/tmpfiles.d/orchestratia.conf,
# applied now with systemd-tmpfiles --create) and give the service user its private
# 0700 folder — uploads never land in a folder another local user could own.
if sudo "$VENV_DIR/bin/orchestratia-agent" provision-tier --upload-dirs \
        --daemon-user "$RUN_USER" --config /etc/orchestratia/config.yaml; then
    ok "Upload folders reserved"
else
    warn "Could not reserve the upload folders — run: sudo orchestratia-agent provision-tier --upload-dirs --daemon-user ${RUN_USER}"
fi

# Keep the restricted-tier download helper + sudoers rule in step with this release.
if [ -f /etc/orchestratia/config.yaml ] && grep -q "orcp-" /etc/orchestratia/config.yaml 2>/dev/null; then
    if sudo "$VENV_DIR/bin/orchestratia-agent" provision-tier --refresh-existing \
            --daemon-user "$RUN_USER" --config /etc/orchestratia/config.yaml; then
        ok "Restricted tier refreshed"
    else
        warn "Could not refresh the restricted tier — run: sudo orchestratia-agent provision-tier --refresh-existing"
    fi
fi

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

# Step 5b: pre-fetch the code editor (optional, non-fatal).
# The agent downloads a pinned, checksum-verified code-server into the service user's
# home on first use anyway; doing it here makes the first "Open Editor" instant.
info "Preparing the code editor (optional)..."
if sudo -u "$RUN_USER" "$AGENT_BIN" ensure-code-server >/dev/null 2>&1; then
    ok "Code editor ready"
else
    warn "Code editor not pre-installed — it will download the first time you open it"
fi

# Step 6: AI Agent integration (Claude Code, Gemini CLI, Codex CLI)
#
# Architecture: git-clone the repo to /opt/orchestratia-agent and
# symlink SKILL.md files from ~/.claude/skills/orchestratia/ (etc.)
# into the cloned tree. Hooks in settings.json point directly at hook
# scripts inside the cloned tree. The tree is root's; `sudo orchestratia
# update` swaps in a fresh clone to refresh skill content.
step 6 "Setting up AI agent integrations"

INSTALL_DIR="/opt/orchestratia-agent"
REPO_URL="https://github.com/kumarimlab/orchestratia-agent.git"

# A fresh root-owned clone every time, swapped in whole: root never runs git inside a tree another account could
# have changed (a planted .git/config runs code on fetch/reset).
NEW_TREE="$(sudo mktemp -d /opt/.orchestratia-agent.new-XXXXXX)"
sudo chmod 0755 "$NEW_TREE"
if sudo git -c core.hooksPath=/dev/null clone --quiet --depth 1 --no-tags "$REPO_URL" "$NEW_TREE" >/dev/null 2>&1; then
    sudo rm -rf "${INSTALL_DIR}.old"
    if [ -e "$INSTALL_DIR" ] || [ -L "$INSTALL_DIR" ]; then sudo mv "$INSTALL_DIR" "${INSTALL_DIR}.old"; fi
    sudo mv "$NEW_TREE" "$INSTALL_DIR"
    sudo rm -rf "${INSTALL_DIR}.old"
    ok "Asset tree cloned: $INSTALL_DIR"
else
    sudo rm -rf "$NEW_TREE"
    fail "git clone failed for $REPO_URL"
fi

# Root-owned, read-only for everyone else; refuses (and says why) when anything isn't.
if sudo "$VENV_DIR/bin/orchestratia-agent" secure-install --daemon-user "$RUN_USER"; then
    ok "Agent code is root-owned"
else
    warn "Could not secure the install — run: sudo orchestratia update"
fi

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

# ── Helper: strip stale orchestratia statusLine + Notification entries ──
# v0.15–v0.19 registered a statusLine command and a Notification hook that
# point at hook scripts this version no longer ships. merge_json_hooks only
# manages SessionStart/PreToolUse, so clear these two here on (re)install so
# they don't dangle at a missing script. Idempotent; only touches entries that
# reference an orchestratia hook.
clear_stale_hooks() {
    local SETTINGS_PATH="$1"
    [ -f "$SETTINGS_PATH" ] || { echo noop; return 0; }
    sudo -u "$RUN_USER" python3 -c "
import json, os
path = '$SETTINGS_PATH'
changed = False
settings = {}
if os.path.exists(path):
    try:
        with open(path) as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        settings = {}

sl = settings.get('statusLine')
if isinstance(sl, dict) and 'orchestratia' in str(sl.get('command', '')):
    settings.pop('statusLine', None)
    changed = True

hooks = settings.get('hooks')
if isinstance(hooks, dict) and isinstance(hooks.get('Notification'), list):
    kept = [e for e in hooks['Notification'] if 'orchestratia' not in str(e)]
    if len(kept) != len(hooks['Notification']):
        changed = True
        if kept:
            hooks['Notification'] = kept
        else:
            hooks.pop('Notification', None)

if changed:
    with open(path, 'w') as f:
        json.dump(settings, f, indent=2)
        f.write('\n')
print('cleared' if changed else 'noop')
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
    if clear_stale_hooks "${RUN_HOME}/.claude/settings.json" | grep -q cleared; then
        ok "Removed stale orchestratia statusLine/Notification hooks"
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
