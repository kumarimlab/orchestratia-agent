#!/usr/bin/env bash
# Orchestratia PreToolUse hook — checks approval rules and logs permission requests.
# Runs before every Claude Code tool execution. Must be fast (<50ms).
#
# Input: JSON on stdin with tool_name, tool_input, session_id
# Output: JSON on stdout with permissionDecision (allow/deny/ask)
# Exit: 0 = proceed with decision, 2 = block (for deny)
#
# Environment: ORCHESTRATIA_SESSION_ID, ORCHESTRATIA_PROJECT_ID set by agent daemon

set -euo pipefail

# Skip if not in an Orchestratia session
if [ -z "${ORCHESTRATIA_HUB_URL:-}" ]; then
  exit 0
fi

# Read stdin (Claude Code pipes hook input here)
INPUT=$(cat)

# Use Python for JSON processing + rule matching (guaranteed available)
exec python3 -c "
import json, sys, os, fnmatch, hashlib, time

# Parse hook input
try:
    data = json.loads('''$INPUT'''.replace(\"'\", \"\\\\'\") if len(sys.argv) < 2 else sys.argv[1])
except:
    try:
        data = json.loads(sys.stdin.read()) if sys.stdin.readable() else {}
    except:
        data = {}

tool_name = data.get('tool_name', '')
tool_input = data.get('tool_input', {})

if not tool_name:
    sys.exit(0)

session_id = os.environ.get('ORCHESTRATIA_SESSION_ID', '')
project_id = os.environ.get('ORCHESTRATIA_PROJECT_ID', '')

# Detect which AI agent is running
agent_name = os.environ.get('ORCHESTRATIA_AGENT_NAME', '')
if not agent_name:
    claude_tools = {'Edit','Write','Read','Glob','Grep','WebFetch','Agent','Skill','MultiEdit','NotebookEdit','ToolSearch','EnterPlanMode','ExitPlanMode','TaskCreate','TaskUpdate','TaskList','TaskGet','TaskOutput','AskUserQuestion'}
    gemini_tools = {'run_shell_command','write_file','read_file','grep_search','glob_search','web_fetch','replace','create_file','activate_skill'}
    if tool_name in claude_tools:
        agent_name = 'claude'
    elif tool_name in gemini_tools:
        agent_name = 'gemini'
    elif tool_name == 'shell' or os.environ.get('CODEX_SANDBOX_DIR'):
        agent_name = 'codex'
    else:
        agent_name = 'claude'

# Determine the parameter to match against
# Supports Claude Code, Gemini CLI, and Codex CLI tool names
param = ''
if tool_name in ('Bash', 'run_shell_command', 'shell'):
    param = tool_input.get('command', '')
elif tool_name in ('Edit', 'Write', 'Read', 'MultiEdit', 'write_file', 'read_file', 'replace', 'create_file'):
    param = tool_input.get('file_path', '') or tool_input.get('path', '')
elif tool_name in ('WebFetch', 'web_fetch'):
    param = tool_input.get('url', '')
elif tool_name in ('Glob', 'Grep', 'grep_search', 'glob_search'):
    param = tool_input.get('pattern', '')
elif tool_name == 'Agent':
    param = tool_input.get('prompt', '')[:200] if tool_input.get('prompt') else ''

# Load cached rules
server_id_hash = hashlib.md5(os.environ.get('ORCHESTRATIA_API_KEY', 'default').encode()).hexdigest()[:12]
rules_path = os.path.join(os.environ.get('TMPDIR', '/tmp'), f'orchestratia-rules-{server_id_hash}.json')

rules = []
try:
    with open(rules_path) as f:
        rules = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

# Match rules in priority order (pre-sorted by hub: deny first, then by scope narrowness)
decision = 'ask'  # default: let Claude Code prompt normally
matched_rule_id = None
matched_rule_name = None
reason = None

for rule in rules:
    if not rule.get('is_active', True):
        continue

    # Match tool pattern (exact or wildcard)
    tp = rule.get('tool_pattern', '')
    if tp != '*' and not fnmatch.fnmatch(tool_name, tp):
        continue

    # Match param pattern (if specified)
    pp = rule.get('param_pattern')
    if pp and param and not fnmatch.fnmatch(param, pp):
        continue

    # Scope check: tenant (no scope_id), project, or server
    scope_type = rule.get('scope_type', 'tenant')
    scope_id = rule.get('scope_id')
    if scope_type == 'project' and scope_id and scope_id != project_id:
        continue
    # server scope is already filtered by the hub when caching rules

    # Agent filter check
    agent_f = rule.get('agent_filter', 'all')
    if agent_f != 'all' and agent_name:
        if agent_name not in [a.strip() for a in agent_f.split(',')]:
            continue

    # Match found
    action = rule.get('action', 'allow')
    decision = 'allow' if action == 'allow' else 'deny'
    matched_rule_id = rule.get('id')
    matched_rule_name = rule.get('name', '')
    reason = f\"{'Auto-approved' if action == 'allow' else 'Blocked'} by rule: {matched_rule_name}\"
    break

# Append log entry to local file (daemon flushes to hub periodically)
log_path = os.path.join(os.environ.get('TMPDIR', '/tmp'), f'orchestratia-permlog-{server_id_hash}.jsonl')
log_entry = {
    'session_id': session_id or None,
    'project_id': project_id or None,
    'tool_name': tool_name,
    'tool_input': tool_input,
    'decision': 'allowed' if decision == 'allow' else ('denied' if decision == 'deny' else 'asked'),
    'matched_rule_id': matched_rule_id,
    'reason': reason,
    'agent_name': agent_name or None,
    'created_at': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime()),
}
try:
    with open(log_path, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
except (OSError, IOError):
    pass  # non-fatal: disk full, permissions, etc.

# Output decision to Claude Code
if decision == 'deny':
    output = {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'deny',
            'permissionDecisionReason': reason or 'Blocked by Orchestratia approval rule',
        }
    }
    print(json.dumps(output))
    sys.exit(2)
elif decision == 'allow':
    output = {
        'hookSpecificOutput': {
            'hookEventName': 'PreToolUse',
            'permissionDecision': 'allow',
            'permissionDecisionReason': reason or 'Auto-approved by Orchestratia',
        }
    }
    print(json.dumps(output))
    sys.exit(0)
else:
    # 'ask' — let Claude Code handle normally, we just logged it
    sys.exit(0)
" "$INPUT" 2>/dev/null
