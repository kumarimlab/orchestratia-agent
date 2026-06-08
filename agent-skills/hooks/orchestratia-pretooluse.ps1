# Orchestratia PreToolUse hook (Windows) — checks approval rules and logs
# permission requests before every tool execution. Must be fast (<50ms).
#
# Thin wrapper: all matching logic lives in permission_match.py (the single
# source of truth, shared with the POSIX .sh wrapper). Input JSON on stdin,
# decision JSON on stdout, exit 2 = block.

$ErrorActionPreference = "SilentlyContinue"

# Skip if not inside an Orchestratia-managed session.
if (-not $env:ORCHESTRATIA_HUB_URL) { exit 0 }

# Locate Python; if absent, don't interfere with the tool call.
$py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue).Source }
if (-not $py) { exit 0 }

$script = Join-Path $PSScriptRoot "permission_match.py"
if (-not (Test-Path $script)) { exit 0 }

# Pass the hook payload (stdin) straight through to the matcher and propagate
# its stdout (the decision JSON) and exit code (2 = block) to the CLI.
$stdin = [Console]::In.ReadToEnd()
$stdin | & $py $script
exit $LASTEXITCODE
