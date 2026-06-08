#!/usr/bin/env bash
# Orchestratia PreToolUse hook (POSIX) — checks approval rules and logs
# permission requests before every tool execution. Must be fast (<50ms).
#
# Thin wrapper: all matching logic lives in permission_match.py (the single
# source of truth, shared with the Windows .ps1 wrapper). Input JSON on stdin,
# decision JSON on stdout, exit 2 = block.
#
# Environment: ORCHESTRATIA_HUB_URL, ORCHESTRATIA_SESSION_ID,
#              ORCHESTRATIA_PROJECT_ID set by the agent daemon.

set -euo pipefail

# Skip if not inside an Orchestratia-managed session.
if [ -z "${ORCHESTRATIA_HUB_URL:-}" ]; then
  exit 0
fi

# No Python → don't interfere with the tool call.
command -v python3 >/dev/null 2>&1 || exit 0

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$DIR/permission_match.py"
