# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Uninstaller — Windows
#
# Removes the standalone agent from this Windows machine.
#
# Usage:
#   irm https://install.orchestratia.com/uninstall-windows | iex
#
# Or, to keep your config.yaml (useful if you plan to reinstall and want
# to preserve your registered identity):
#   $env:ORC_KEEP_CONFIG=1; irm https://install.orchestratia.com/uninstall-windows | iex
#
# What this removes:
#   1. Running orchestratia-agent.exe processes (incl. pty-host — sessions die)
#   2. Scheduled task "OrchestratiAgent"
#   3. PATH entries for $env:LOCALAPPDATA\Orchestratia and \Orchestratia\bin
#   4. $env:LOCALAPPDATA\Orchestratia\ (exe, wrappers, logs, config)
#
# Does NOT remove:
#   - Python / pip / Claude Code CLI / any external tools
#   - The agent's registration in the hub DB (deregister from dashboard)
#   - tmux-style session state (Windows uses ConPTY — sessions die with pty-host)
# ──────────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Continue"
$KeepConfig = $env:ORC_KEEP_CONFIG -eq "1"

$ConfigDir = "$env:LOCALAPPDATA\Orchestratia"
$BinDir = "$ConfigDir\bin"
$ServiceName = "OrchestratiAgent"
$AgentExePath = "$ConfigDir\orchestratia-agent.exe"

# ── Output helpers ───────────────────────────────────────────────────
function Write-Header {
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor White
    Write-Host "  ║       Orchestratia Agent Uninstaller (Windows)   ║" -ForegroundColor White
    Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor White
    Write-Host ""
}
function Write-Step { param([int]$N, [int]$Total, [string]$Msg)
    Write-Host ""
    Write-Host "  [$N/$Total] " -ForegroundColor Blue -NoNewline
    Write-Host $Msg -ForegroundColor White
}
function Write-Ok   { param([string]$Msg) Write-Host "       OK   $Msg" -ForegroundColor Green }
function Write-Info { param([string]$Msg) Write-Host "       ->   $Msg" -ForegroundColor Cyan }
function Write-Warn { param([string]$Msg) Write-Host "       !    $Msg" -ForegroundColor Yellow }
function Write-Skip { param([string]$Msg) Write-Host "       -    $Msg (not found)" -ForegroundColor DarkGray }

Write-Header

if ($KeepConfig) {
    Write-Host "  Mode: KEEP CONFIG (config.yaml will be preserved for reinstall)" -ForegroundColor Cyan
} else {
    Write-Host "  Mode: FULL REMOVAL" -ForegroundColor Cyan
}
Write-Host ""

$TotalSteps = 4

# ── Step 1: Stop running processes ───────────────────────────────────
Write-Step 1 $TotalSteps "Stopping running agent processes"

$found = $false
$procs = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
if ($procs) {
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $found = $true
        } catch { }
    }
    Start-Sleep -Seconds 1
    Write-Ok "Stopped orchestratia-agent.exe ($($procs.Count) process(es))"
}

# Also kill any python-based agent invocations (legacy pip installs)
$pythonProcs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match "orchestratia" }
if ($pythonProcs) {
    foreach ($p in $pythonProcs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    $found = $true
    Write-Ok "Stopped python-based agent ($($pythonProcs.Count) process(es))"
}

if (-not $found) {
    Write-Skip "No agent processes running"
}

# ── Step 2: Remove scheduled task ────────────────────────────────────
Write-Step 2 $TotalSteps "Removing scheduled task"

$task = Get-ScheduledTask -TaskName $ServiceName -ErrorAction SilentlyContinue
if ($task) {
    try {
        Unregister-ScheduledTask -TaskName $ServiceName -Confirm:$false -ErrorAction Stop
        Write-Ok "Removed scheduled task '$ServiceName'"
    } catch {
        Write-Warn "Could not remove scheduled task: $_"
    }
} else {
    Write-Skip "Scheduled task '$ServiceName'"
}

# Also check for legacy NSSM-based Windows service
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq "Running") {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    }
    $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssmExe) {
        & nssm remove $ServiceName confirm 2>$null
    } else {
        sc.exe delete $ServiceName 2>$null | Out-Null
    }
    Write-Ok "Removed legacy Windows service '$ServiceName'"
}

# ── Step 3: Clean PATH entries ───────────────────────────────────────
Write-Step 3 $TotalSteps "Cleaning user PATH"

try {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath) {
        $entries = $userPath.Split(";") | Where-Object { $_ -and $_ -ne $BinDir -and $_ -ne $ConfigDir }
        $newPath = ($entries -join ";")
        if ($newPath -ne $userPath) {
            [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
            Write-Ok "Removed Orchestratia entries from user PATH"
            # Also clean current session PATH so the user doesn't have to relaunch
            $sessionEntries = $env:Path.Split(";") | Where-Object { $_ -and $_ -ne $BinDir -and $_ -ne $ConfigDir }
            $env:Path = ($sessionEntries -join ";")
        } else {
            Write-Skip "PATH entries"
        }
    }
} catch {
    Write-Warn "Could not modify user PATH: $_"
}

# ── Step 4: Remove install directory ─────────────────────────────────
Write-Step 4 $TotalSteps "Removing install directory"

if (Test-Path $ConfigDir) {
    # Show agent identity before nuking
    $configFile = "$ConfigDir\config.yaml"
    if (Test-Path $configFile) {
        try {
            $cfg = Get-Content $configFile -Raw -ErrorAction SilentlyContinue
            if ($cfg -match "agent_name:\s*(\S+)") { Write-Info "Agent name: $($Matches[1])" }
            if ($cfg -match "hub_url:\s*(\S+)")    { Write-Info "Hub URL: $($Matches[1])" }
        } catch { }
    }

    if ($KeepConfig -and (Test-Path $configFile)) {
        # Stash config.yaml outside the dir, wipe everything, then restore it
        $stash = "$env:TEMP\orchestratia-config-stash-$(Get-Random).yaml"
        try {
            Copy-Item $configFile $stash -Force
            Remove-Item -Recurse -Force $ConfigDir -ErrorAction Stop
            New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
            Move-Item $stash "$ConfigDir\config.yaml" -Force
            Write-Ok "Removed $ConfigDir (kept config.yaml for reinstall)"
        } catch {
            Write-Warn "Could not fully clean directory: $_"
            if (Test-Path $stash) { Remove-Item $stash -Force -ErrorAction SilentlyContinue }
        }
    } else {
        try {
            Remove-Item -Recurse -Force $ConfigDir -ErrorAction Stop
            Write-Ok "Removed $ConfigDir"
        } catch {
            Write-Warn "Could not fully remove $ConfigDir : $_"
            Write-Info "Some files may be locked. Reboot and delete manually if needed."
        }
    }
} else {
    Write-Skip "$ConfigDir"
}

# ── Summary ──────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Agent uninstalled" -ForegroundColor Green
Write-Host ""
Write-Host "  Note: The agent still appears in the hub dashboard." -ForegroundColor DarkGray
Write-Host "  It will show as 'offline' after ~90 seconds." -ForegroundColor DarkGray
Write-Host "  To remove it from the dashboard, delete it manually under Servers." -ForegroundColor DarkGray
Write-Host ""
if ($KeepConfig) {
    Write-Host "  Config preserved at: $ConfigDir\config.yaml" -ForegroundColor DarkGray
    Write-Host "  To reinstall with the same identity, run the installer with no token." -ForegroundColor DarkGray
} else {
    Write-Host "  To reinstall, generate a new token from the dashboard and run:" -ForegroundColor DarkGray
    Write-Host "    `$env:ORC_TOKEN='orcreg_...'; irm https://install.orchestratia.com/windows | iex" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "  ──────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""
