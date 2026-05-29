# Orchestratia statusLine hook (Windows) — reports the worker's own
# context-window usage to the local daemon and prints a short status line.
#
# Core principle: MEASURE AT THE WORKER. Only this agent process knows its
# real context usage; the hub/orchestrator are consumers of what we report.
# Must never error out (fail open).

$ErrorActionPreference = "SilentlyContinue"

# Read stdin (Claude Code pipes the statusLine payload here).
$inputJson = [Console]::In.ReadToEnd()

# Not our session -> stay silent and succeed.
if (-not $env:ORCHESTRATIA_HUB_URL -or -not $env:ORCHESTRATIA_SESSION_ID) { exit 0 }

$pythonScript = @"
import json, sys, os, urllib.request

def out(line):
    try:
        sys.stdout.write(line)
    except Exception:
        pass

try:
    data = json.loads(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1] else {}
except Exception:
    data = {}
if not isinstance(data, dict):
    data = {}

session_id = os.environ.get('ORCHESTRATIA_SESSION_ID', '')
DEFAULT_WINDOW = 200000

window = DEFAULT_WINDOW
model = data.get('model') if isinstance(data.get('model'), dict) else {}
for key in ('context_window', 'context_length', 'max_input_tokens'):
    v = model.get(key) if isinstance(model, dict) else None
    if isinstance(v, (int, float)) and v > 0:
        window = int(v)
        break

def first_num(d, keys):
    if not isinstance(d, dict):
        return None
    for k in keys:
        v = d.get(k)
        if isinstance(v, (int, float)) and v >= 0:
            return int(v)
    return None

used = None
for container in (data, data.get('usage'), data.get('cost'), data.get('context')):
    if not isinstance(container, dict):
        continue
    u = first_num(container, (
        'used_tokens', 'total_tokens', 'context_tokens',
        'input_tokens', 'tokens',
    ))
    if u is not None:
        used = u
        break

if used is None and isinstance(data.get('usage'), dict):
    us = data['usage']
    parts = [first_num(us, (k,)) or 0 for k in (
        'input_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens',
    )]
    if any(parts):
        used = sum(parts)

transcript = data.get('transcript_path') or ''
if used is None and transcript and os.path.exists(transcript):
    try:
        last_usage_total = None
        with open(transcript, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                msg = rec.get('message') if isinstance(rec, dict) else None
                usage = msg.get('usage') if isinstance(msg, dict) else None
                if isinstance(usage, dict):
                    total = 0
                    for k in ('input_tokens', 'cache_read_input_tokens',
                              'cache_creation_input_tokens', 'output_tokens'):
                        v = usage.get(k)
                        if isinstance(v, (int, float)):
                            total += int(v)
                    if total > 0:
                        last_usage_total = total
        if last_usage_total is not None:
            used = last_usage_total
    except Exception:
        pass

if used is None and transcript and os.path.exists(transcript):
    try:
        used = int(os.path.getsize(transcript) / 4)
    except Exception:
        used = None

if used is None:
    used = 0

try:
    pct = round(min(100.0, max(0.0, (used / window) * 100.0)), 1) if window > 0 else 0.0
except Exception:
    pct = 0.0

try:
    port = os.environ.get('ORCHESTRATIA_MCP_PORT', '8765')
    payload = json.dumps({
        'session_id': session_id,
        'used_tokens': used,
        'window_size': window,
    }).encode()
    req = urllib.request.Request(
        'http://127.0.0.1:' + str(port) + '/context/report',
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    urllib.request.urlopen(req, timeout=2).read()
except Exception:
    pass

out('ctx ' + (str(int(pct)) if pct == int(pct) else str(pct)) + '%')
"@

# Write Python script to temp file and execute. Fail open.
$tempPy = [System.IO.Path]::GetTempFileName() + ".py"
try {
    $pythonScript | Out-File -FilePath $tempPy -Encoding utf8 -NoNewline
    $result = & python3 $tempPy $inputJson 2>$null
    if ($result) { Write-Output $result }
} catch {
} finally {
    Remove-Item -Path $tempPy -Force -ErrorAction SilentlyContinue
}
exit 0
