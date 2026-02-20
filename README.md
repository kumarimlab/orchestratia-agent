# Orchestratia Agent

Lightweight daemon that connects your dev server to the [Orchestratia](https://github.com/kumarimlab/orchestratia) hub. It registers as an agent, receives task assignments, spawns Claude Code in persistent screen sessions, and streams output back in real-time.

## Quick Install

```bash
# One-liner setup
git clone https://github.com/kumarimlab/orchestratia-agent.git /opt/orchestratia-agent
cd /opt/orchestratia-agent && bash setup.sh
```

## What It Does

- **Registers** with the Orchestratia hub on startup
- **Heartbeats** every 30s with CPU, memory, disk stats
- **Polls** for assigned tasks every 10s
- **Spawns Claude Code** in detached `screen` sessions
- **Streams output** to the hub via WebSocket in real-time
- **Reports** task completion or failure
- **Reconciles** orphaned screen sessions on restart

## Requirements

- Python 3.10+
- `screen` (for persistent sessions)
- `claude` CLI (installed and authenticated)
- Network access to the Orchestratia hub

## Configuration

Copy and edit the config:

```bash
sudo mkdir -p /etc/orchestratia
cp config.yaml.example /etc/orchestratia/config.yaml
nano /etc/orchestratia/config.yaml
```

Key settings:
- `hub_url` - Your Orchestratia hub URL
- `api_key` - Leave empty for first run, then paste the key it prints
- `agent_name` - Human-readable name for this server
- `repos` - Map of repo names to local paths

## Running

**First run** (to register and get API key):
```bash
python3 daemon.py --config /etc/orchestratia/config.yaml
```

**As a systemd service** (persistent):
```bash
sudo cp orchestratia-agent.service /etc/systemd/system/
sudo systemctl enable --now orchestratia-agent
```

## For Claude Code Instances

If you're a Claude Code instance on this server, read `ORCHESTRATIA.md` for the full self-setup guide. You can also drop `ORCHESTRATIA.md` into any project root to make Claude aware of the orchestration system.

## License

MIT
