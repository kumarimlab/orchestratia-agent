#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Uninstaller
#
# Completely removes the agent daemon from this server.
# Supports: Linux (systemd), macOS (launchd)
#
# Usage:
#   bash uninstall.sh           # Interactive (asks for confirmation)
#   bash uninstall.sh --force   # No prompts, just remove everything
#
# What this removes:
#   1. Stops and disables the service (systemd or launchd)
#   2. Removes the service file
#   3. Removes agent code (/opt/orchestratia-agent)
#   4. Removes config (/etc/orchestratia)
#   5. Removes logs (/var/log/orchestratia)
#   6. Removes runtime dir (/var/run/orchestratia)
#
# Does NOT remove:
#   - Python packages (httpx, websockets, etc.) — shared deps
#   - Claude Code CLI
#   - The agent's registration in the hub DB (deregister from dashboard)
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

SERVICE_NAME="orchestratia-agent"
INSTALL_DIR="/opt/orchestratia-agent"
CONFIG_DIR="/etc/orchestratia"
LOG_DIR="/var/log/orchestratia"
RUN_DIR="/var/run/orchestratia"

LAUNCHD_LABEL="com.orchestratia.agent"
LAUNCHD_PLIST_USER="$HOME/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
LAUNCHD_PLIST_SYSTEM="/Library/LaunchDaemons/${LAUNCHD_LABEL}.plist"
# Check both user-level (install-macos.sh) and system-level locations
if [ -f "$LAUNCHD_PLIST_USER" ]; then
    LAUNCHD_PLIST="$LAUNCHD_PLIST_USER"
else
    LAUNCHD_PLIST="$LAUNCHD_PLIST_SYSTEM"
fi

TOTAL_STEPS=4

# ── OS detection ──────────────────────────────────────────────────
OS_TYPE="$(uname -s)"
case "$OS_TYPE" in
    Linux)  OS_TYPE="linux" ;;
    Darwin) OS_TYPE="darwin" ;;
    *)      echo "Unsupported OS: $OS_TYPE"; exit 1 ;;
esac

# ── Helper functions ────────────────────────────────────────────────

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

skip() {
    echo -e "     ${DIM}– $1 (not found, skipping)${NC}"
}

# ── Confirmation ────────────────────────────────────────────────────

FORCE=false
if [ "${1:-}" = "--force" ] || [ "${1:-}" = "-f" ]; then
    FORCE=true
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║         Orchestratia Agent Uninstaller           ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}Detected OS: ${OS_TYPE}${NC}"
echo ""

# Show what will be removed
echo -e "  ${DIM}This will remove:${NC}"
if [ "$OS_TYPE" = "linux" ]; then
    [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ] && echo -e "    ${ARROW} systemd service: ${SERVICE_NAME}"
elif [ "$OS_TYPE" = "darwin" ]; then
    [ -f "$LAUNCHD_PLIST" ] && echo -e "    ${ARROW} launchd service: ${LAUNCHD_LABEL}"
fi
[ -d "$INSTALL_DIR" ] && echo -e "    ${ARROW} agent code: ${INSTALL_DIR}"
[ -d "$CONFIG_DIR" ] && echo -e "    ${ARROW} config: ${CONFIG_DIR}"
[ -d "$LOG_DIR" ] && echo -e "    ${ARROW} logs: ${LOG_DIR}"
[ -d "$RUN_DIR" ] && echo -e "    ${ARROW} runtime: ${RUN_DIR}"
echo ""

if [ "$FORCE" = false ]; then
    echo -ne "  ${YELLOW}${BOLD}Continue? [y/N]${NC} "
    read -r REPLY
    if [[ ! "$REPLY" =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "  ${DIM}Uninstall cancelled.${NC}"
        echo ""
        exit 0
    fi
fi

# ── Step 1: Stop and disable service ────────────────────────────────

step 1 "Stopping service"

if [ "$OS_TYPE" = "linux" ]; then
    # ── Linux: systemd ──
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        if sudo systemctl stop "$SERVICE_NAME" 2>/dev/null; then
            ok "Service stopped"
        else
            warn "Could not stop service (may need manual cleanup)"
        fi
    else
        skip "Service not running"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        if sudo systemctl disable "$SERVICE_NAME" 2>/dev/null; then
            ok "Service disabled"
        else
            warn "Could not disable service"
        fi
    else
        skip "Service not enabled"
    fi

    if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
        if sudo rm "/etc/systemd/system/${SERVICE_NAME}.service" 2>/dev/null; then
            ok "Service file removed"
        else
            warn "Could not remove service file"
        fi
        sudo systemctl daemon-reload 2>/dev/null && ok "systemd reloaded" || true
    else
        skip "Service file"
    fi

elif [ "$OS_TYPE" = "darwin" ]; then
    # ── macOS: launchd ──
    # Try user-level first (install-macos.sh), then system-level
    if launchctl list "$LAUNCHD_LABEL" &>/dev/null; then
        launchctl unload "$LAUNCHD_PLIST" 2>/dev/null && ok "User agent unloaded" || true
    fi
    if sudo launchctl list "$LAUNCHD_LABEL" &>/dev/null 2>/dev/null; then
        if sudo launchctl bootout "system/${LAUNCHD_LABEL}" 2>/dev/null; then
            ok "System service stopped and unloaded"
        else
            sudo launchctl unload "$LAUNCHD_PLIST" 2>/dev/null && ok "System service unloaded (legacy)" || warn "Could not unload service"
            sudo launchctl remove "$LAUNCHD_LABEL" 2>/dev/null || true
        fi
    fi

    # Remove plist from both locations
    for plist in "$LAUNCHD_PLIST_USER" "$LAUNCHD_PLIST_SYSTEM"; do
        if [ -f "$plist" ]; then
            rm -f "$plist" 2>/dev/null || sudo rm -f "$plist" 2>/dev/null
            ok "Plist removed: ${plist}"
        fi
    done
fi

# ── Step 2: Remove agent code ───────────────────────────────────────

step 2 "Removing agent code"

if [ -d "$INSTALL_DIR" ]; then
    # Show what version was installed
    if [ -d "$INSTALL_DIR/.git" ]; then
        COMMIT=$(cd "$INSTALL_DIR" && git rev-parse --short HEAD 2>/dev/null || echo "unknown")
        info "Installed version: ${COMMIT}"
    fi
    if sudo rm -rf "$INSTALL_DIR" 2>/dev/null; then
        ok "Removed ${INSTALL_DIR}"
    else
        warn "Could not remove ${INSTALL_DIR}"
    fi
else
    skip "${INSTALL_DIR}"
fi

# ── Step 3: Remove config ──────────────────────────────────────────

step 3 "Removing configuration"

if [ -d "$CONFIG_DIR" ]; then
    # Show config details before removing
    if [ -f "$CONFIG_DIR/config.yaml" ]; then
        AGENT_NAME=$(grep 'agent_name:' "$CONFIG_DIR/config.yaml" 2>/dev/null | awk '{print $2}' || echo "unknown")
        HUB_URL=$(grep 'hub_url:' "$CONFIG_DIR/config.yaml" 2>/dev/null | awk '{print $2}' || echo "unknown")
        info "Agent name: ${AGENT_NAME}"
        info "Hub URL: ${HUB_URL}"
    fi
    if sudo rm -rf "$CONFIG_DIR" 2>/dev/null; then
        ok "Removed ${CONFIG_DIR}"
    else
        warn "Could not remove ${CONFIG_DIR}"
    fi
else
    skip "${CONFIG_DIR}"
fi

# ── Step 4: Remove logs and runtime ────────────────────────────────

step 4 "Removing logs and runtime data"

if [ -d "$LOG_DIR" ]; then
    LOG_SIZE=$(du -sh "$LOG_DIR" 2>/dev/null | awk '{print $1}' || echo "?")
    info "Log size: ${LOG_SIZE}"
    if sudo rm -rf "$LOG_DIR" 2>/dev/null; then
        ok "Removed ${LOG_DIR}"
    else
        warn "Could not remove ${LOG_DIR}"
    fi
else
    skip "${LOG_DIR}"
fi

if [ -d "$RUN_DIR" ]; then
    if sudo rm -rf "$RUN_DIR" 2>/dev/null; then
        ok "Removed ${RUN_DIR}"
    else
        warn "Could not remove ${RUN_DIR}"
    fi
else
    skip "${RUN_DIR}"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
echo -e "  ${GREEN}${BOLD}✓ Agent uninstalled${NC} ${DIM}(${OS_TYPE})${NC}"
echo ""
echo -e "  ${DIM}Note: The agent still appears in the hub dashboard.${NC}"
echo -e "  ${DIM}It will show as 'offline' after ~90 seconds.${NC}"
echo -e "  ${DIM}To re-install, generate a new token and run install.sh.${NC}"
echo ""
echo -e "${BOLD}──────────────────────────────────────────────────${NC}"
echo ""
