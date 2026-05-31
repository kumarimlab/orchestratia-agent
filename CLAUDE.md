# Orchestratia Agent — project context

> **Local & gitignored.** This file is per-host context for agents working in
> this repo. It is **not** committed (this repo is PUBLIC). It must contain
> **no** orchestrator-role text — role is injected at runtime by the
> SessionStart hook (`orchestratia context-prompt`, keyed on
> `ORCHESTRATIA_ROLE`). No AI attribution in any commit to this repo.

## What this repo is

`kumarimlab/orchestratia-agent` — the **agent daemon** that runs on dev/prod
servers and connects them to the Orchestratia hub. Python package
`orchestratia_agent/`. Distinct from the hub repo (`kumarimlab/orchestratia`,
private) which is the coordination backend + dashboard.

## Layout (key modules)

- `hub.py` — WebSocket connection to the hub; session_start / input / resize /
  recovery message routing; stamps session env vars (incl. `ORCHESTRATIA_ROLE`).
- `session_posix.py` / `session_windows.py` — PTY backends (tmux / ConPTY).
- `mcp_server.py` — per-session FastMCP server on loopback; registers the
  worker toolset, and the orchestrator toolset when `role == "orchestrator"`.
- `governance_hook.py` — worker→orchestrator governance routing + the
  `role_system_prompt()` source of truth for role text.
- `agent_registry.py` — per-agent specs (CLI command, workspace markers,
  `system_prompt_file`).
- `cli.py` — the `orchestratia` CLI (task/code/server/session/… +
  `context-prompt`, used by the SessionStart hook).
- `agent-skills/hooks/` — `orchestratia-context.sh`/`.ps1` (SessionStart) and
  `orchestratia-pretooluse.sh`/`.ps1` (governance/approval). Installed to
  `/opt/orchestratia-agent/agent-skills/hooks/` and referenced directly from
  `~/.claude/settings.json`.

## Deploy / propagation (Linux)

- `/opt/orchestratia-agent` is a **git checkout on `main`**; the Python package
  is pip-installed to `~/.local/lib/python3.12/site-packages/orchestratia_agent/`.
- `orchestratia update` = `git fetch` + `git reset --hard origin/main` in
  `/opt` (refreshes hooks + skills in place) **and** a pip reinstall (refreshes
  the package). Then `sudo systemctl restart orchestratia-agent`.
- A daemon restart drops any local orchestrator's native MCP tools until the
  loopback MCP route is re-pinned.

## Release flow

Bump `pyproject.toml` + `orchestratia_agent/__init__.py`, commit, push `main`,
`git tag -a vX.Y.Z` + push tag (tags trigger the Windows `.exe` build +
Homebrew bump — pushing to `main` alone triggers no release). Then bump
`LATEST_AGENT_VERSION` in the hub's `backend/app/api/v1/agent_versions.py`.

## Conventions

- Hooks must be fast and must **never** crash a session — fail open / silent.
- Role is hub-authoritative, defaults to `worker`, and is **never** inferred
  from session name or filesystem location.
