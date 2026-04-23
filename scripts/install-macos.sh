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
TOTAL_STEPS=6
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
    if pip3 uninstall -y orchestratia-agent >/dev/null 2>&1; then
        ok "Uninstalled pip package"
    elif pip3 uninstall -y --break-system-packages orchestratia-agent >/dev/null 2>&1; then
        ok "Uninstalled pip package"
    else
        warn "Could not uninstall — reinstall will overwrite"
    fi
fi

# Clean up stale entry-point scripts that may have been left behind by
# previous partial installs or by pip install --user runs. This prevents
# a ghost binary from shadowing the new one via PATH ordering.
for bin in orchestratia-agent orchestratia orchestratia-connect; do
    rm -f "/usr/local/bin/$bin" "/opt/homebrew/bin/$bin" 2>/dev/null || true
    [ -n "${HOME:-}" ] && rm -f "$HOME/.local/bin/$bin" 2>/dev/null || true
done

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
# --upgrade --force-reinstall --no-cache-dir forces a fresh build from
# git, bypassing pip's wheel cache. Without these, pip reuses a cached
# wheel keyed by the git URL string, so re-installs never see new
# versions pushed to main.
if pip3 install --upgrade --force-reinstall --no-cache-dir -q "$INSTALL_SOURCE" 2>&1; then
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

# Step 6: AI Agent integration (Claude Code, Gemini CLI, Codex CLI)
step 6 "Setting up AI agent integrations"

HOOK_DIR="$HOME/.orchestratia/agent-skills/hooks"
REPO_BASE="https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/agent-skills"

mkdir -p "$HOOK_DIR"
if curl -fsSL "$REPO_BASE/hooks/orchestratia-context.sh" -o "$HOOK_DIR/orchestratia-context.sh" 2>/dev/null && \
   curl -fsSL "$REPO_BASE/hooks/orchestratia-pretooluse.sh" -o "$HOOK_DIR/orchestratia-pretooluse.sh" 2>/dev/null; then
    chmod +x "$HOOK_DIR/orchestratia-context.sh" "$HOOK_DIR/orchestratia-pretooluse.sh"
    ok "Hook scripts downloaded"
else
    warn "Could not download hook scripts"
fi

CONTEXT_HOOK_CMD="bash \"$HOOK_DIR/orchestratia-context.sh\""
PRETOOL_HOOK_CMD="bash \"$HOOK_DIR/orchestratia-pretooluse.sh\""

merge_json_hooks() {
    local path="$1" session_event="$2" pretool_event="$3" context_cmd="$4" pretool_cmd="$5"
    python3 - "$path" "$session_event" "$pretool_event" "$context_cmd" "$pretool_cmd" <<'PYEOF' >/dev/null 2>&1
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

CLAUDE_DETECTED=false; GEMINI_DETECTED=false; CODEX_DETECTED=false

if check_command claude; then
    CLAUDE_DETECTED=true
    CLAUDE_SKILL_DIR="$HOME/.claude/skills/orchestratia"
    mkdir -p "$CLAUDE_SKILL_DIR" "$HOME/.claude"
    if curl -fsSL "$REPO_BASE/claude/SKILL.md" -o "$CLAUDE_SKILL_DIR/SKILL.md" 2>/dev/null; then
        ok "Claude Code skill installed"
    else
        warn "Could not download Claude SKILL.md"
    fi
    if merge_json_hooks "$HOME/.claude/settings.json" "SessionStart" "PreToolUse" "$CONTEXT_HOOK_CMD" "$PRETOOL_HOOK_CMD"; then
        ok "Claude Code hooks configured"
    else
        warn "Could not configure Claude Code hooks"
    fi
fi

if check_command gemini; then
    GEMINI_DETECTED=true
    GEMINI_SKILL_DIR="$HOME/.gemini/skills/orchestratia"
    SHARED_SKILL_DIR="$HOME/.agents/skills/orchestratia"
    mkdir -p "$GEMINI_SKILL_DIR" "$SHARED_SKILL_DIR" "$HOME/.gemini"
    if curl -fsSL "$REPO_BASE/gemini/SKILL.md" -o "$GEMINI_SKILL_DIR/SKILL.md" 2>/dev/null; then
        cp -f "$GEMINI_SKILL_DIR/SKILL.md" "$SHARED_SKILL_DIR/SKILL.md" 2>/dev/null || true
        ok "Gemini CLI skill installed"
    else
        warn "Could not download Gemini SKILL.md"
    fi
    merge_json_hooks "$HOME/.gemini/settings.json" "SessionStart" "BeforeTool" "$CONTEXT_HOOK_CMD" "$PRETOOL_HOOK_CMD" \
        && ok "Gemini CLI hooks configured" \
        || warn "Could not configure Gemini CLI hooks"
fi

if check_command codex; then
    CODEX_DETECTED=true
    CODEX_SKILL_DIR="$HOME/.codex/skills/orchestratia"
    SHARED_SKILL_DIR="$HOME/.agents/skills/orchestratia"
    mkdir -p "$CODEX_SKILL_DIR" "$SHARED_SKILL_DIR" "$HOME/.codex"
    if curl -fsSL "$REPO_BASE/codex/SKILL.md" -o "$CODEX_SKILL_DIR/SKILL.md" 2>/dev/null; then
        cp -f "$CODEX_SKILL_DIR/SKILL.md" "$SHARED_SKILL_DIR/SKILL.md" 2>/dev/null || true
        ok "Codex CLI skill installed"
    else
        warn "Could not download Codex SKILL.md"
    fi
fi

CONFIGURED=""; AVAILABLE=""
[ "$CLAUDE_DETECTED" = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Claude Code" || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Claude Code"
[ "$GEMINI_DETECTED" = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Gemini CLI"  || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Gemini CLI"
[ "$CODEX_DETECTED"  = true ] && CONFIGURED="${CONFIGURED}${CONFIGURED:+, }Codex CLI"   || AVAILABLE="${AVAILABLE}${AVAILABLE:+, }Codex CLI"
[ -n "$CONFIGURED" ] && ok "Configured: ${CONFIGURED}"
[ -n "$AVAILABLE" ]  && echo -e "     ${DIM}- Also supported (install separately if needed): ${AVAILABLE}${NC}"

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
