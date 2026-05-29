#!/usr/bin/env bash
# Orchestratia Notification hook — fires when Claude Code parks on a prompt it
# needs the user to answer (permission_prompt / elicitation_dialog), restricted
# via the settings.json matcher so the buggy idle_prompt (which fires after
# every response) never reaches us. It tells the daemon so the worker's
# orchestrator is WOKEN to peek + answer (send_keys) or escalate.
#
# Must be fast and must never error (fail-open) — a Notification hook that
# blocks or crashes would degrade the worker's UX.

# Not in an Orchestratia session -> stay silent and succeed.
if [ -z "${ORCHESTRATIA_HUB_URL:-}" ] || [ -z "${ORCHESTRATIA_SESSION_ID:-}" ]; then
  exit 0
fi

# Read the Notification payload Claude Code pipes on stdin.
INPUT=$(cat 2>/dev/null || true)

python3 -c "
import json, sys, os, urllib.request

try:
    data = json.loads(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}

msg = str(data.get('message') or '')
low = msg.lower()
# The settings.json matcher already restricts us to permission/elicitation
# notifications; derive a coarse kind for the orchestrator's wake message.
kind = 'permission' if any(k in low for k in ('permission', 'approve', 'trust', 'allow')) else 'input'

session_id = os.environ.get('ORCHESTRATIA_SESSION_ID', '')
project_id = os.environ.get('ORCHESTRATIA_PROJECT_ID', '')
port = os.environ.get('ORCHESTRATIA_MCP_PORT', '8765')

try:
    payload = json.dumps({
        'session_id': session_id,
        'project_id': project_id,
        'kind': kind,
        'message': msg[:200],
    }).encode()
    req = urllib.request.Request(
        'http://127.0.0.1:' + str(port) + '/attention',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    urllib.request.urlopen(req, timeout=2).read()
except Exception:
    pass
" "$INPUT" 2>/dev/null

# Always succeed — never block or fail the worker on our account.
exit 0
