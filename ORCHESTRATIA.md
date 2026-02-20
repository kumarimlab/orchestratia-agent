# Orchestratia Agent - Self-Setup Guide

This file is designed to be read by Claude Code instances. If you are Claude Code running on a dev server, follow these instructions to register yourself as an Orchestratia agent and start receiving tasks.

**Orchestratia** is your coordination hub. It assigns you tasks, streams your output in real-time to the admin dashboard, and relays human responses when you need help.

---

## Quick Overview

```
You (Claude Code on this server)
    |
    |-- Register with hub (one-time)
    |-- Heartbeat every 30s (automatic via daemon)
    |-- Poll for tasks (automatic via daemon)
    |-- Execute tasks in screen sessions
    |-- Stream output to hub via WebSocket
    |-- Request human help when stuck
    `-- Report completion/failure
```

---

## Step 1: Check Prerequisites

Before setting up, verify these are installed on this server:

```bash
# Required
python3 --version    # Need 3.10+
screen -v            # For persistent sessions
claude --version     # Claude Code CLI must be installed and authenticated

# Install if missing
sudo apt install -y screen
pip3 install httpx websockets pyyaml psutil
```

Claude Code must already be authenticated on this server (`claude` should work without login prompts).

---

## Step 2: Install the Agent Daemon

If not already installed:

```bash
# Clone the agent repo
sudo mkdir -p /opt/orchestratia-agent
sudo chown $(whoami):$(whoami) /opt/orchestratia-agent
git clone https://github.com/kumarimlab/orchestratia-agent.git /opt/orchestratia-agent

# Or if already cloned, pull latest
cd /opt/orchestratia-agent && git pull

# Install Python dependencies
pip3 install -r /opt/orchestratia-agent/requirements.txt
```

---

## Step 3: Register (One Command)

Registration requires a **one-time token** from the admin dashboard. The token is self-contained — it encodes the hub URL, so you only need the token itself.

1. Ask your admin to generate a token from the dashboard (Agents -> Register Agent)
2. Run this single command with the token:

```bash
python3 /opt/orchestratia-agent/daemon.py --register <TOKEN>
```

For example:
```bash
python3 /opt/orchestratia-agent/daemon.py --register orcreg_aHR0cHM6Ly9zdGFnaW5nLm9yY2hlc3RyYXRpYS5jb20.abc123def456
```

**That's it.** The daemon will:
1. Extract the hub URL from the token
2. Create `/etc/orchestratia/config.yaml` automatically (or update existing)
3. Register with the hub using the token
4. Save the permanent API key to config (token is consumed and removed)
5. Start heartbeating and polling for tasks

The config file is auto-managed — no manual editing needed for registration.

---

## Step 4: Customize Config (Optional)

After registration, you can edit `/etc/orchestratia/config.yaml` to add repos and tune settings:

```yaml
agent_name: "your-server-name"

repos:
  your-repo-name:
    path: /home/ubuntu/your-repo
    branch: main

claude:
  binary: claude
  allowed_tools: "Bash,Read,Edit,Write,Grep,Glob"
  max_turns: 50
  timeout_minutes: 30
```

---

## Step 5: Run as a Service (Persistent)

---

## Step 6: Run as a Service (Persistent)

```bash
# Install systemd service
sudo cp /opt/orchestratia-agent/orchestratia-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable orchestratia-agent
sudo systemctl start orchestratia-agent

# Check status
sudo systemctl status orchestratia-agent

# View logs
sudo journalctl -u orchestratia-agent -f
```

The daemon will now:
- Start on boot
- Restart automatically if it crashes
- Send heartbeats every 30s (hub shows you as ONLINE)
- Poll for tasks every 10s

---

## How Tasks Work

Once registered and running, the flow is:

1. **Admin creates a task** on the dashboard (https://staging.orchestratia.com/tasks/new)
2. **Admin assigns it to your agent** by selecting your name in the agent dropdown
3. **Daemon picks it up** via polling (within 10 seconds)
4. **Daemon spawns Claude Code** in a detached `screen` session with the task spec as the prompt
5. **Output streams in real-time** to the hub dashboard via WebSocket
6. **When Claude finishes**, the daemon detects the screen session exited and reports success/failure

---

## Requesting Human Help (Intervention)

If you (as Claude Code) are executing a task and get stuck, need clarification, or need approval, the daemon supports an intervention flow. The task execution happens in a screen session managed by the daemon, which handles the intervention API calls.

The intervention endpoints available to the daemon:
- `POST /api/v1/agents/tasks/{task_id}/help` - Request human help (body: `{"question": "...", "context": "..."}`)
- `GET /api/v1/agents/interventions/{id}` - Poll for the human's response

The admin sees the request in the Interventions page and responds. The response is relayed back.

---

## Directory Layout on This Server

```
/opt/orchestratia-agent/          # Agent daemon code (this repo)
    daemon.py                     # The daemon process
    config.yaml.example           # Config template
    requirements.txt              # Python dependencies
    orchestratia-agent.service    # Systemd unit file
    ORCHESTRATIA.md               # This file

/etc/orchestratia/
    config.yaml                   # Your server-specific config (with API key)

/var/log/orchestratia/
    task-{uuid}.log               # Claude output logs per task

/var/run/orchestratia/
    # PID files (future use)
```

---

## Hub Details

| Item | Value |
|------|-------|
| Hub URL | https://staging.orchestratia.com |
| Dashboard | https://staging.orchestratia.com (login required) |
| API Docs | https://staging.orchestratia.com/docs |
| Agent Auth | `X-API-Key` header with `orc_` prefixed key |
| Heartbeat Timeout | 90 seconds (agent goes OFFLINE if no heartbeat) |
| Task Poll Interval | 10 seconds |

---

## Agent API Reference

All agent endpoints (except register) use `X-API-Key` header for authentication.

```
POST /api/v1/agents/register          # Register with one-time token (first run only)
POST /api/v1/agents/heartbeat         # System stats, every 30s
GET  /api/v1/agents/tasks/poll        # Get assigned tasks
POST /api/v1/agents/tasks/{id}/start  # Mark task as running
POST /api/v1/agents/tasks/{id}/complete  # Report success
POST /api/v1/agents/tasks/{id}/fail   # Report failure
POST /api/v1/agents/tasks/{id}/help   # Request human intervention
GET  /api/v1/agents/interventions/{id}   # Poll for intervention response
WS   /ws/agent                        # Real-time output streaming
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `screen is not installed` | `sudo apt install screen` |
| Agent shows OFFLINE | Check daemon is running: `systemctl status orchestratia-agent` |
| Tasks not picked up | Verify `api_key` in config matches registered key |
| WebSocket disconnect | Daemon auto-reconnects; check network/firewall |
| Claude not found | Ensure `claude` is in PATH or set full path in config `claude.binary` |
| Permission denied on logs | `sudo chown $(whoami) /var/log/orchestratia` |

---

*This file can be placed in any project root as `ORCHESTRATIA.md` so Claude Code instances are aware of the orchestration system.*
