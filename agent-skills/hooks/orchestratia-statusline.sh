#!/usr/bin/env bash
# Orchestratia statusLine hook — reports the worker's own context-window
# usage to the local daemon and prints a short status line.
#
# Core principle: MEASURE AT THE WORKER. Only this agent process knows its
# real context usage; the hub/orchestrator are consumers of what we report.
#
# Claude Code invokes the statusLine command with a JSON payload on stdin
# (transcript_path, model block, possibly usage/cost). This hook:
#   (a) exits 0 silently if not an Orchestratia session,
#   (b) derives a context-token estimate (payload usage fields preferred,
#       else from the transcript at transcript_path),
#   (c) POSTs {session_id, used_tokens, window_size} to the loopback
#       /context/report endpoint,
#   (d) ALWAYS prints a short human status line (e.g. "ctx 42%").
# Must never error out (fail open).

# Read stdin (Claude Code pipes the statusLine payload here).
INPUT=$(cat 2>/dev/null || true)

# Not our session -> stay silent and succeed. A statusLine command that
# prints nothing simply shows no Orchestratia status; other tooling is
# unaffected.
if [ -z "${ORCHESTRATIA_HUB_URL:-}" ] || [ -z "${ORCHESTRATIA_SESSION_ID:-}" ]; then
  exit 0
fi

python3 -c "
import json, sys, os, urllib.request

def out(line):
    # Always print *something* so this works as a real statusLine.
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

# ── Window size: prefer a model context-window field if present. ──
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

# ── used_tokens: (1) direct usage fields anywhere in the payload. ──
used = None
# Common shapes across Claude Code versions: top-level usage, cost block,
# context block. Parse defensively — any of these may be absent.
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

# Some payloads nest a usage object with the canonical Anthropic counters.
if used is None and isinstance(data.get('usage'), dict):
    us = data['usage']
    parts = [first_num(us, (k,)) or 0 for k in (
        'input_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens',
    )]
    if any(parts):
        used = sum(parts)

# ── (2) Fall back to the transcript: read the last assistant turn's usage
#        (most accurate); else estimate from file size. ──
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

# Last-ditch estimate from transcript size (~4 chars/token).
if used is None and transcript and os.path.exists(transcript):
    try:
        used = int(os.path.getsize(transcript) / 4)
    except Exception:
        used = None

if used is None:
    used = 0

# ── Compute pct locally for the status line (mirror context_meter). ──
try:
    pct = round(min(100.0, max(0.0, (used / window) * 100.0)), 1) if window > 0 else 0.0
except Exception:
    pct = 0.0

# ── Report to the loopback daemon. Never fatal. ──
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

# ── Always print a short human status line. ──
out('ctx ' + (str(int(pct)) if pct == int(pct) else str(pct)) + '%')
" "$INPUT" 2>/dev/null

# Fail open: even if python errored, succeed so the statusLine never breaks.
exit 0
