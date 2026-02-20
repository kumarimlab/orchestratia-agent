#!/usr/bin/env bash
set -euo pipefail

# Orchestratia Agent - Quick Setup Script
# Usage: curl -sSL https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/setup.sh | bash

INSTALL_DIR="/opt/orchestratia-agent"
CONFIG_DIR="/etc/orchestratia"
LOG_DIR="/var/log/orchestratia"
RUN_DIR="/var/run/orchestratia"

echo "=== Orchestratia Agent Setup ==="
echo ""

# Check prerequisites
echo "[1/6] Checking prerequisites..."
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found. Install it first."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "ERROR: git not found. Install it first."; exit 1; }

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  Python: $PYTHON_VER"

# Install screen if missing
if ! command -v screen >/dev/null 2>&1; then
    echo "  Installing screen..."
    sudo apt-get install -y screen >/dev/null 2>&1
fi
echo "  screen: $(screen -v 2>&1 | head -1)"

# Check claude
if command -v claude >/dev/null 2>&1; then
    echo "  claude: $(claude --version 2>/dev/null || echo 'installed')"
else
    echo "  WARNING: 'claude' CLI not found in PATH."
    echo "  Install it: npm install -g @anthropic-ai/claude-code"
    echo "  Then authenticate: claude auth login"
fi

# Create directories
echo ""
echo "[2/6] Creating directories..."
sudo mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR"
sudo chown "$(whoami):$(whoami)" "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR"

# Clone or update repo
echo ""
echo "[3/6] Installing agent daemon..."
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR" && git pull --quiet
    echo "  Updated existing installation"
else
    git clone https://github.com/kumarimlab/orchestratia-agent.git "$INSTALL_DIR" 2>/dev/null || {
        # If clone fails (repo doesn't exist yet), copy from local if available
        echo "  Git clone failed. If running locally, files should already be in place."
    }
    echo "  Installed to $INSTALL_DIR"
fi

# Install Python dependencies
echo ""
echo "[4/6] Installing Python dependencies..."
pip3 install -q -r "$INSTALL_DIR/requirements.txt" 2>/dev/null || \
pip3 install -q --break-system-packages -r "$INSTALL_DIR/requirements.txt" 2>/dev/null
echo "  Done"

# Config
echo ""
echo "[5/6] Setting up config..."
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$INSTALL_DIR/config.yaml.example" "$CONFIG_DIR/config.yaml"
    echo "  Created $CONFIG_DIR/config.yaml from template"
    echo "  >>> EDIT THIS FILE with your hub_url, agent_name, and repos <<<"
else
    echo "  Config already exists at $CONFIG_DIR/config.yaml (not overwritten)"
fi

# Systemd service
echo ""
echo "[6/6] Installing systemd service..."
sudo cp "$INSTALL_DIR/orchestratia-agent.service" /etc/systemd/system/
sudo systemctl daemon-reload
echo "  Service installed (not started)"

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit config:    sudo nano $CONFIG_DIR/config.yaml"
echo "  2. First run:      python3 $INSTALL_DIR/daemon.py --config $CONFIG_DIR/config.yaml"
echo "  3. Save API key:   Copy the orc_xxx key printed on first run into config.yaml"
echo "  4. Start service:  sudo systemctl enable --now orchestratia-agent"
echo "  5. Check status:   sudo systemctl status orchestratia-agent"
echo ""
echo "Read the full guide: cat $INSTALL_DIR/ORCHESTRATIA.md"
