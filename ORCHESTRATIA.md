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

1. Ask your admin to generate a token from the dashboard (Servers -> Register Server)
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
server_name: "your-server-name"

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
2. **Admin assigns it to a session** on your server from the dashboard
3. **Daemon picks it up** via polling (within 10 seconds)
4. **Daemon spawns Claude Code** in a detached `screen` session with the task spec as the prompt
5. **Output streams in real-time** to the hub dashboard via WebSocket
6. **When Claude finishes**, the daemon detects the screen session exited and reports success/failure

---

## Requesting Help (Interventions)

If you (as Claude Code) are executing a task and get stuck, need clarification, or need approval, the daemon supports an intervention flow. The task execution happens in a screen session managed by the daemon, which handles the intervention API calls.

The intervention endpoints available to the daemon:
- `POST /api/v1/servers/tasks/{task_id}/help` - Request help (body: `{"question": "...", "context": "...", "intervention_type": "help|question"}`)
- `GET /api/v1/servers/interventions/{id}` - Poll for the response
- `GET /api/v1/server/interventions?task_id=...&status=pending` - List pending interventions
- `POST /api/v1/server/interventions/{id}/respond` - Respond to intervention programmatically

With `intervention_type: "help"` (default), the admin responds from the dashboard. With `intervention_type: "question"`, an orchestrator agent can respond programmatically — enabling fully autonomous multi-agent coordination.

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
POST /api/v1/servers/register          # Register with one-time token (first run only)
POST /api/v1/servers/heartbeat         # System stats, every 30s
GET  /api/v1/servers/tasks/poll        # Get assigned tasks
POST /api/v1/servers/tasks/{id}/start  # Mark task as running
POST /api/v1/servers/tasks/{id}/complete  # Report success
POST /api/v1/servers/tasks/{id}/fail   # Report failure
POST /api/v1/servers/tasks/{id}/help   # Request intervention (type: help/question/approval)
POST /api/v1/server/tasks/{id}/notes   # Add note to task
GET  /api/v1/server/tasks/{id}/notes   # List notes for task
POST /api/v1/server/tasks/{id}/plan    # Submit plan for review
GET  /api/v1/servers/interventions/{id}   # Poll for intervention response
GET  /api/v1/server/interventions      # List interventions (filter: task_id, status)
POST /api/v1/server/interventions/{id}/respond  # Respond to intervention
WS   /ws/server                        # Real-time output + task event subscriptions
```

### WebSocket Task Subscriptions

After authenticating on `/ws/server`, send `{"type": "subscribe_task", "task_id": "..."}` to receive real-time `task_event` messages for that task (status changes, notes, interventions, completions). Send `{"type": "unsubscribe_task", "task_id": "..."}` to stop.

---

## Upgrading the Agent

To upgrade to the latest version, use the built-in CLI command:

```bash
orchestratia update
```

This will pull the latest code from GitHub and reinstall the package. On Linux (installed via `install.sh`), it does `git pull` + `pip reinstall` from `/opt/orchestratia-agent`. On macOS, it does `pip install --upgrade` from GitHub.

**Do NOT run** `pip3 install --upgrade orchestratia-agent` — the package is not on PyPI.

After updating, restart the daemon:

```bash
sudo systemctl restart orchestratia-agent
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
