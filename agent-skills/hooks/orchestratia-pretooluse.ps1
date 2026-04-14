# Orchestratia PreToolUse hook (Windows) — checks approval rules and logs permission requests.
# Runs before every Claude Code tool execution. Must be fast (<50ms).

$ErrorActionPreference = "SilentlyContinue"

# Skip if not in an Orchestratia session
if (-not $env:ORCHESTRATIA_HUB_URL) { exit 0 }

# Read stdin
$inputJson = [Console]::In.ReadToEnd()

# Use Python for JSON processing + rule matching
$pythonScript = @"
import json, sys, os, fnmatch, hashlib, time

try:
    data = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {}
except:
    data = {}

tool_name = data.get('tool_name', '')
tool_input = data.get('tool_input', {})

if not tool_name:
    sys.exit(0)

session_id = os.environ.get('ORCHESTRATIA_SESSION_ID', '')
project_id = os.environ.get('ORCHESTRATIA_PROJECT_ID', '')

# Determine the parameter to match against
param = ''
if tool_name == 'Bash':
    param = tool_input.get('command', '')
elif tool_name in ('Edit', 'Write', 'Read', 'MultiEdit'):
    param = tool_input.get('file_path', '')
elif tool_name == 'WebFetch':
    param = tool_input.get('url', '')
elif tool_name in ('Glob', 'Grep'):
    param = tool_input.get('pattern', '')
elif tool_name == 'Agent':
    param = tool_input.get('prompt', '')[:200] if tool_input.get('prompt') else ''

# Load cached rules
server_id_hash = hashlib.md5(os.environ.get('ORCHESTRATIA_API_KEY', 'default').encode()).hexdigest()[:12]
tmp_dir = os.environ.get('TEMP', os.environ.get('TMP', os.path.join(os.path.expanduser('~'), '.orchestratia')))
rules_path = os.path.join(tmp_dir, f'orchestratia-rules-{server_id_hash}.json')

rules = []
try:
    with open(rules_path) as f:
        rules = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    pass

# Match rules in priority order
decision = 'ask'
matched_rule_id = None
matched_rule_name = None
reason = None

for rule in rules:
    if not rule.get('is_active', True):
        continue

    tp = rule.get('tool_pattern', '')
    if tp != '*' and not fnmatch.fnmatch(tool_name, tp):
        continue

    pp = rule.get('param_pattern')
    if pp and param and not fnmatch.fnmatch(param, pp):
        continue

    scope_type = rule.get('scope_type', 'tenant')
    scope_id = rule.get('scope_id')
    if scope_type == 'project' and scope_id and scope_id != project_id:
        continue

    action = rule.get('action', 'allow')
    decision = 'allow' if action == 'allow' else 'deny'
    matched_rule_id = rule.get('id')
    matched_rule_name = rule.get('name', '')
    reason = f"{'Auto-approved' if action == 'allow' else 'Blocked'} by rule: {matched_rule_name}"
    break

# Append log entry
log_path = os.path.join(tmp_dir, f'orchestratia-permlog-{server_id_hash}.jsonl')
log_entry = {
    'session_id': session_id or None,
    'project_id': project_id or None,
    'tool_name': tool_name,
    'tool_input': tool_input,
    'decision': 'allowed' if decision == 'allow' else ('denied' if decision == 'deny' else 'asked'),
    'matched_rule_id': matched_rule_id,
    'reason': reason,
    'created_at': time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime()),
}
try:
    with open(log_path, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
except (OSError, IOError):
    pass

# Output decision
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
    sys.exit(0)
"@

# Write Python script to temp file and execute
$tempPy = [System.IO.Path]::GetTempFileName() + ".py"
try {
    $pythonScript | Out-File -FilePath $tempPy -Encoding utf8 -NoNewline
    $result = & python3 $tempPy $inputJson 2>$null
    $exitCode = $LASTEXITCODE
    if ($result) { Write-Output $result }
    exit $exitCode
} finally {
    Remove-Item -Path $tempPy -Force -ErrorAction SilentlyContinue
}
