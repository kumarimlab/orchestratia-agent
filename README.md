# Orchestratia Agent

Agent daemon for [Orchestratia](https://github.com/kumarimlab/orchestratia) -- connects dev servers to the Orchestratia hub for AI agent orchestration. Manages interactive PTY sessions controlled from the web dashboard.

## Quick Install

Get a registration token from the Orchestratia dashboard (Servers > Register Server), then run the one-liner for your platform:

**Linux:**

```bash
bash <(curl -sL https://install.orchestratia.com/linux) <TOKEN>
```

**macOS:**

```bash
bash <(curl -sL https://install.orchestratia.com/macos) <TOKEN>
```

**Windows (PowerShell as Administrator):**

```powershell
$env:ORC_TOKEN='<TOKEN>'; irm https://install.orchestratia.com/windows | iex
```

## Manual Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/kumarimlab/orchestratia-agent.git
```

Register with the hub using your one-time token:

```bash
orchestratia-agent --register <TOKEN>
```

Start the daemon:

```bash
orchestratia-agent
```

## Configuration

### Config file locations

| Platform | Path |
|----------|------|
| Linux    | `/etc/orchestratia/config.yaml` |
| macOS    | `~/Library/Application Support/Orchestratia/config.yaml` |
| Windows  | `%LOCALAPPDATA%\Orchestratia\config.yaml` |

The `--register` command creates the config file automatically. To create one manually, copy the example:

```bash
# Linux
sudo mkdir -p /etc/orchestratia
sudo cp config.yaml.example /etc/orchestratia/config.yaml
```

### Example config

```yaml
hub_url: "https://staging.orchestratia.com"

# After registration, the API key is saved here automatically.
# For first-time setup, use --register instead of editing this directly.
api_key: "orc_..."

server_name: "dev-linux-staging"

repos:
  my-project:
    path: /home/ubuntu/my-project
    branch: main

claude:
  binary: claude
  allowed_tools: "Bash,Read,Edit,Write,Grep,Glob"
  max_turns: 50
  timeout_minutes: 30
```

### Log file locations

| Platform | Path |
|----------|------|
| Linux    | `/var/log/orchestratia/` |
| macOS    | `~/Library/Logs/Orchestratia/` |
| Windows  | `%LOCALAPPDATA%\Orchestratia\logs\` |

## Usage

### Daemon commands

```bash
# Register with the hub (one-time setup)
orchestratia-agent --register <TOKEN>

# Start the daemon (reads default config for your platform)
orchestratia-agent

# Start with a custom config file
orchestratia-agent --config /path/to/config.yaml

# Enable debug logging
orchestratia-agent --debug

# Verbose output (noisy libraries stay quieter)
orchestratia-agent --verbose

# Print version
orchestratia-agent --version
```

### Running as a service

**Linux (systemd):**

```bash
sudo cp orchestratia-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now orchestratia-agent

# Check status
sudo systemctl status orchestratia-agent
sudo journalctl -u orchestratia-agent -f
```

**macOS (launchd):**

The install script creates a launchd agent at `~/Library/LaunchAgents/com.orchestratia.agent.plist` automatically.

```bash
# Manual control
launchctl load ~/Library/LaunchAgents/com.orchestratia.agent.plist
launchctl unload ~/Library/LaunchAgents/com.orchestratia.agent.plist
```

**Windows (NSSM service):**

The install script creates a Windows service via NSSM automatically.

```powershell
# Manual control
nssm start OrchestratiAgent
nssm stop OrchestratiAgent
nssm status OrchestratiAgent
```

### CLI commands

The `orchestratia` CLI is available inside PTY sessions spawned by the daemon. It lets AI agents (Claude Code, etc.) communicate tasks with each other through the hub.

```bash
# Create a task for another agent
orchestratia task create --title "Fix auth bug" --spec "The login flow fails when..." --priority high

# Check for tasks assigned to this session
orchestratia task check

# View task details
orchestratia task view <TASK_ID>

# Mark a task as complete
orchestratia task complete <TASK_ID> --result "Fixed by updating the token validation logic"

# Check task status
orchestratia task status <TASK_ID>

# List tasks (optionally filter by status)
orchestratia task list
orchestratia task list --status pending
```

The CLI reads its configuration from environment variables set automatically by the daemon when spawning sessions: `ORCHESTRATIA_HUB_URL`, `ORCHESTRATIA_API_KEY`, `ORCHESTRATIA_SESSION_ID`, and `ORCHESTRATIA_PROJECT_ID`.

## Platform Details

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| PTY method | `pty` + `fork` | `pty` + `fork` | pywinpty ConPTY |
| Session persistence | tmux (survives daemon restarts) | tmux (survives daemon restarts) | None |
| Default shell | `/bin/bash` | `/bin/zsh` | `pwsh.exe` / `powershell.exe` / `cmd.exe` |
| Service manager | systemd | launchd | NSSM |
| Min version | Any | Any | Windows 10 1809+ (Build 17763) |

On Linux and macOS, if `tmux` is available, sessions are launched inside tmux. This means sessions survive daemon restarts -- the daemon reattaches to orphaned `orc-*` tmux sessions on startup. On Windows, ConPTY sessions do not persist across restarts.

## Development

```bash
git clone https://github.com/kumarimlab/orchestratia-agent.git
cd orchestratia-agent

# Install in editable mode
pip install -e .

# Run the daemon
orchestratia-agent --debug

# Run tests
python -m pytest
```

### Dependencies

- [httpx](https://www.python-httpx.org/) -- HTTP client for registration and heartbeats
- [websockets](https://websockets.readthedocs.io/) -- WebSocket connection to the hub
- [PyYAML](https://pyyaml.org/) -- Configuration file parsing
- [psutil](https://github.com/giampaolo/psutil) -- System info collection (CPU, memory, disk)
- [pywinpty](https://github.com/andfoy/pywinpty) -- ConPTY on Windows (installed automatically on Windows only)

## Architecture

```
orchestratia_agent/
  __init__.py          Package metadata and version
  __main__.py          python -m orchestratia_agent entry point
  main.py              Daemon entry point, argument parsing, signal handling, async main loop
  config.py            Config loading/saving, platform-aware default paths, token parsing
  hub.py               Hub communication: HTTP registration, heartbeats, WebSocket message loop
  session.py           ManagedSession class: async reader/capture loops, WebSocket relay
  session_base.py      SessionBackend protocol and SessionHandle dataclass
  session_posix.py     Linux/macOS backend: fork + pty + optional tmux
  session_windows.py   Windows backend: pywinpty ConPTY
  tmux.py              tmux helpers: availability check, session discovery
  system.py            Cross-platform system info gathering (CPU, memory, disk)
  logging_config.py    Colored log output with debug/verbose modes
  cli.py               orchestratia CLI for inter-agent task communication
```

The daemon connects to the hub via two channels:

1. **HTTP** (httpx) -- Registration on startup, heartbeats every 30 seconds with system stats.
2. **WebSocket** (websockets) -- Bidirectional channel for session lifecycle. The hub sends `session_start`, `session_input`, `session_resize`, `session_close`, and `session_kill` messages. The agent sends back `session_output` (base64-encoded PTY data), `session_started`, `session_closed`, and `session_screen` (periodic tmux pane captures).

Auto-reconnect with exponential backoff (1s to 30s) handles network interruptions. On reconnect, the daemon reports all alive sessions and reattaches to any orphaned tmux sessions it discovers.

## License

MIT
