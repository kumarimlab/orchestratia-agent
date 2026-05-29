#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────
# Orchestratia Claude Code SessionStart Hook
#
# This script runs automatically when Claude Code starts a session.
# Its stdout is injected into Claude's conversation context.
#
# Requirements:
#   - ORCHESTRATIA_HUB_URL env var (set by agent daemon in tmux sessions)
#   - orchestratia CLI on PATH
#
# If not in an Orchestratia session, exits silently (no output).
# ──────────────────────────────────────────────────────────────────────

# Not in an Orchestratia session — exit silently
if [ -z "${ORCHESTRATIA_HUB_URL:-}" ]; then
    exit 0
fi

# Check if CLI is available
if ! command -v orchestratia >/dev/null 2>&1; then
    echo "Orchestratia: CLI not found on PATH. Install: pip install git+https://github.com/kumarimlab/orchestratia-agent.git"
    exit 0
fi

# Get status from hub (5 second timeout)
STATUS_JSON=$(timeout 5 orchestratia status --json 2>/dev/null)

if [ -z "$STATUS_JSON" ]; then
    echo "Orchestratia: Hub unreachable. CLI available offline: orchestratia --help"
    exit 0
fi

# Parse JSON and format output using Python (guaranteed available on agent servers)
python3 -c "
import json, sys, os

try:
    d = json.loads(sys.stdin.read())
except (json.JSONDecodeError, ValueError):
    print('Orchestratia: Could not parse status response')
    sys.exit(0)

if not d.get('connected'):
    err = d.get('error', 'unknown')
    print(f'Orchestratia: Hub unreachable. CLI available offline: orchestratia --help')
    sys.exit(0)

server = d.get('server_name', 'unknown')
session = d.get('session_name', 'unknown')

# Role is the hub-stamped ORCHESTRATIA_ROLE env var (default 'worker').
# We do NOT infer it from the session name — name is cosmetic and a worker
# could be named anything; role must be authoritative and fail-safe.
role = os.environ.get('ORCHESTRATIA_ROLE', 'worker')

project = d.get('project_name', '')
tasks = d.get('tasks', [])
summary = d.get('task_summary', {})
running = summary.get('running', 0)
pending = summary.get('pending', 0)
total = summary.get('total', 0)

# Build output
bar = '=' * 58
print(bar)
print(f'Orchestratia Agent: {server} / {session} ({role})')

if project:
    print(f'Project: {project}')

if total > 0:
    print(f'Assigned Tasks: {running} running, {pending} pending')
    for t in tasks:
        tid = t.get('id', '')[:8]
        title = t.get('title', '')
        status = t.get('status', '')
        arrow = '*' if status == 'running' else ' '
        print(f'  {arrow} [{tid}] \"{title}\" ({status})')
else:
    print('No assigned tasks. Waiting for orchestrator.')

print()
print('Use /orchestratia for workflow details')
print(bar)
" <<< "$STATUS_JSON"

# Inject the role-appropriate system prompt (orchestrator vs worker). This is
# the on-disk-free delivery channel for the role: its stdout is merged into
# the agent's context by Claude Code, so the role travels with the session and
# is never written to a CLAUDE.md (which would leak into child sessions via the
# directory tree). Role is read from ORCHESTRATIA_ROLE inside the command.
echo
timeout 5 orchestratia context-prompt 2>/dev/null || true
