# ──────────────────────────────────────────────────────────────────────
# Orchestratia Claude Code SessionStart Hook (Windows)
#
# This script runs automatically when Claude Code starts a session.
# Its stdout is injected into Claude's conversation context.
#
# Requirements:
#   - ORCHESTRATIA_HUB_URL env var (set by agent daemon in sessions)
#   - orchestratia CLI on PATH
#
# If not in an Orchestratia session, exits silently (no output).
# ──────────────────────────────────────────────────────────────────────

# Not in an Orchestratia session — exit silently
if (-not $env:ORCHESTRATIA_HUB_URL) {
    exit 0
}

# Check if CLI is available
$cli = Get-Command "orchestratia" -ErrorAction SilentlyContinue
if (-not $cli) {
    Write-Output "Orchestratia: CLI not found on PATH. Ensure %LOCALAPPDATA%\Orchestratia is in PATH."
    exit 0
}

# Get status from hub (5 second timeout)
$statusJson = $null
try {
    $proc = Start-Process -FilePath $cli.Source -ArgumentList "status", "--json" `
        -NoNewWindow -Wait -PassThru -RedirectStandardOutput "$env:TEMP\orc_status.tmp" `
        -ErrorAction Stop
    if (Test-Path "$env:TEMP\orc_status.tmp") {
        $statusJson = Get-Content "$env:TEMP\orc_status.tmp" -Raw -ErrorAction SilentlyContinue
        Remove-Item "$env:TEMP\orc_status.tmp" -Force -ErrorAction SilentlyContinue
    }
} catch {
    # Timeout or error
}

if (-not $statusJson) {
    Write-Output "Orchestratia: Hub unreachable. CLI available offline: orchestratia --help"
    exit 0
}

# Parse JSON and format output
try {
    $d = $statusJson | ConvertFrom-Json

    if (-not $d.connected) {
        Write-Output "Orchestratia: Hub unreachable. CLI available offline: orchestratia --help"
        exit 0
    }

    $server = if ($d.server_name) { $d.server_name } else { "unknown" }
    $session = if ($d.session_name) { $d.session_name } else { "unknown" }

    # Derive role
    $role = "worker"
    if ($session) {
        $sl = $session.ToLower()
        if ($sl -match "orchestrat|platform|coordinator") {
            $role = "orchestrator"
        }
    }

    $project = $d.project_name
    $tasks = $d.tasks
    $summary = $d.task_summary
    $running = if ($summary.running) { $summary.running } else { 0 }
    $pending = if ($summary.pending) { $summary.pending } else { 0 }
    $total = if ($summary.total) { $summary.total } else { 0 }

    # Build output
    $bar = "=" * 58
    Write-Output $bar
    Write-Output "Orchestratia Agent: $server / $session ($role)"

    if ($project) {
        Write-Output "Project: $project"
    }

    if ($total -gt 0) {
        Write-Output "Assigned Tasks: $running running, $pending pending"
        foreach ($t in $tasks) {
            $tid = $t.id.Substring(0, [Math]::Min(8, $t.id.Length))
            $title = $t.title
            $status = $t.status
            $arrow = if ($status -eq "running") { "*" } else { " " }
            Write-Output "  $arrow [$tid] `"$title`" ($status)"
        }
    } else {
        Write-Output "No assigned tasks. Waiting for orchestrator."
    }

    Write-Output ""
    Write-Output "Use /orchestratia for workflow details"
    Write-Output $bar

} catch {
    Write-Output "Orchestratia: Could not parse status response"
    exit 0
}
