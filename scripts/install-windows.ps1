# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Windows (Standalone .exe)
#
# Downloads the standalone orchestratia-agent.exe from GitHub Releases.
# No Python, pip, or git required.
#
# Two modes:
#   FRESH INSTALL (with token):
#     $env:ORC_TOKEN='orcreg_...'; irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex
#
#   UPGRADE (no token — uses existing config, preserves sessions):
#     irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex
#
# What this does:
#   1. Kills agent daemon (preserves pty-host so sessions stay alive)
#   2. Downloads orchestratia-agent.exe from latest GitHub Release
#   3. Registers with hub (fresh) or verifies existing config (upgrade)
#   4. Adds exe to user PATH
#   5. Creates a scheduled task (runs as current user at logon)
# ──────────────────────────────────────────────────────────────────────

$Token = if ($args.Count -gt 0) { $args[0] } elseif ($env:ORC_TOKEN) { $env:ORC_TOKEN } else { $null }

# Determine mode: fresh install (with token) or upgrade (no token, existing config)
$ConfigDir = "$env:LOCALAPPDATA\Orchestratia"
$ExistingConfig = Test-Path "$ConfigDir\config.yaml"
$UpgradeMode = $false

if (-not $Token) {
    if ($ExistingConfig) {
        $configContent = Get-Content "$ConfigDir\config.yaml" -Raw -ErrorAction SilentlyContinue
        if ($configContent -match "api_key:\s*orc_") {
            $UpgradeMode = $true
        }
    }
    if (-not $UpgradeMode) {
        Write-Host ""
        Write-Host "  Usage:" -ForegroundColor White
        Write-Host ""
        Write-Host '  Fresh install (one-liner):' -ForegroundColor DarkGray
        Write-Host '    $env:ORC_TOKEN=''orcreg_...''; irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex' -ForegroundColor Cyan
        Write-Host ""
        Write-Host '  Upgrade (no token needed — uses existing config):' -ForegroundColor DarkGray
        Write-Host '    irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex' -ForegroundColor Cyan
        Write-Host ""
        Write-Host '  No existing config found. Provide a registration token for fresh install.' -ForegroundColor Yellow
        Write-Host ""
        exit 1
    }
}

$ErrorActionPreference = "Continue"

# ── Logging ──────────────────────────────────────────────────────────
$LogDir = "$ConfigDir\logs"
$InstallLog = "$ConfigDir\install.log"
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
Start-Transcript -Path $InstallLog -Force | Out-Null
trap {
    Write-Host ""
    Write-Host "  UNEXPECTED ERROR: $_" -ForegroundColor Red
    Write-Host "  Log saved to: $InstallLog" -ForegroundColor Yellow
    Write-Host ""
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}

# ── Constants ────────────────────────────────────────────────────────
$ServiceName = "OrchestratiAgent"
$AgentExePath = "$ConfigDir\orchestratia-agent.exe"
$ReleaseUrl = if ($env:ORCHESTRATIA_EXE_URL) {
    $env:ORCHESTRATIA_EXE_URL
} else {
    "https://github.com/kumarimlab/orchestratia-agent/releases/latest/download/orchestratia-agent.exe"
}
$Errors = 0
$TotalSteps = 6

# ── Helper functions ─────────────────────────────────────────────────

function Write-Header {
    Write-Host ""
    Write-Host "========================================================" -ForegroundColor White
    Write-Host "      Orchestratia Agent Installer (Windows)            " -ForegroundColor White
    Write-Host "========================================================" -ForegroundColor White
    Write-Host ""
}

function Write-Step($Num, $Total, $Title) {
    Write-Host ""
    Write-Host "[$Num/$Total] " -ForegroundColor Blue -NoNewline
    Write-Host $Title -ForegroundColor White
}

function Write-Ok($Msg) {
    Write-Host "     + " -ForegroundColor Green -NoNewline
    Write-Host $Msg
}

function Write-Warn($Msg) {
    Write-Host "     ! " -ForegroundColor Yellow -NoNewline
    Write-Host $Msg -ForegroundColor Yellow
    $script:Errors++
}

function Write-Fail($Msg) {
    Write-Host "     x " -ForegroundColor Red -NoNewline
    Write-Host $Msg -ForegroundColor Red
    $script:Errors++
}

function Write-Info($Msg) {
    Write-Host "     > " -ForegroundColor Cyan -NoNewline
    Write-Host $Msg
}

function Write-Fatal($Msg) {
    Write-Host ""
    Write-Host "  FATAL: $Msg" -ForegroundColor Red
    Write-Host "     Installation aborted." -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}

# ── Validate ─────────────────────────────────────────────────────────

if ($Token -and -not $Token.StartsWith("orcreg_")) {
    Write-Fatal "Invalid token format (must start with orcreg_)"
}

# ── Main ─────────────────────────────────────────────────────────────

Write-Header
if ($UpgradeMode) {
    Write-Host "  Mode: UPGRADE (existing config found, preserving sessions)" -ForegroundColor Cyan
} else {
    Write-Host "  Mode: FRESH INSTALL" -ForegroundColor Cyan
}
Write-Host ""

# Step 1: Cleanup — remove ALL existing installations
Write-Step 1 $TotalSteps "Removing existing installation (if any)"

$existing = $false

# 1a. Kill running orchestratia-agent processes (but NOT the pty-host)
# The pty-host owns live ConPTY sessions — killing it destroys all terminal
# sessions. We only kill agent daemon processes and leave pty-host running
# so sessions survive reinstalls.
$runningProcs = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
if ($runningProcs) {
    $existing = $true
    $killed = 0
    $preserved = 0
    foreach ($p in $runningProcs) {
        try {
            $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.Id)" -ErrorAction SilentlyContinue
            $cmdLine = if ($wmiProc) { $wmiProc.CommandLine } else { "" }
            if ($cmdLine -match "--pty-host") {
                $preserved++
                Write-Info "Preserving pty-host process (PID $($p.Id)) — sessions stay alive"
            } else {
                Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                $killed++
            }
        } catch {
            # If we can't check the command line, kill it (safe default)
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            $killed++
        }
    }
    Start-Sleep -Seconds 1
    if ($killed -gt 0) { Write-Ok "Killed $killed agent process(es)" }
    if ($preserved -gt 0) { Write-Ok "Preserved $preserved pty-host process(es) (sessions intact)" }
}

# 1b. Also kill any python-based agent (pip install runs as python.exe)
$pythonProcs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -and $_.CommandLine -match "orchestratia" }
if ($pythonProcs) {
    $existing = $true
    foreach ($p in $pythonProcs) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1
    Write-Ok "Killed running pip-based agent process(es)"
}

# 1c. Stop and remove existing Windows service (NSSM)
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    $existing = $true
    if ($svc.Status -eq "Running") {
        Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Ok "Stopped existing service"
    }
    $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssmExe) {
        & nssm remove $ServiceName confirm 2>$null
    } else {
        sc.exe delete $ServiceName 2>$null
    }
    Write-Ok "Removed existing service"
}

# 1d. Remove existing scheduled task
$existingTask = Get-ScheduledTask -TaskName "OrchestratiAgent" -ErrorAction SilentlyContinue
if ($existingTask) {
    $existing = $true
    Unregister-ScheduledTask -TaskName "OrchestratiAgent" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Ok "Removed existing scheduled task"
}

# 1e. Remove existing exe
if (Test-Path $AgentExePath) {
    $existing = $true
    Remove-Item $AgentExePath -Force -ErrorAction SilentlyContinue
    Write-Ok "Removed existing executable"
}

# 1f. Detect and remove pip-installed version
$pipAgent = Get-Command "orchestratia-agent" -ErrorAction SilentlyContinue
if ($pipAgent -and $pipAgent.Source -ne $AgentExePath) {
    $existing = $true
    $pipPath = $pipAgent.Source
    Write-Info "Found existing installation at: $pipPath"

    # Check if it's a pip-installed script (lives in a Python Scripts directory)
    if ($pipPath -match "Python.*Scripts" -or $pipPath -match "site-packages" -or $pipPath -match "anaconda.*Scripts" -or $pipPath -match "conda.*Scripts" -or $pipPath -match "envs.*Scripts") {
        Write-Info "Detected pip-installed version, removing..."
        # Try pip uninstall
        $pipExe = Get-Command pip -ErrorAction SilentlyContinue
        if (-not $pipExe) { $pipExe = Get-Command pip3 -ErrorAction SilentlyContinue }
        if ($pipExe) {
            & $pipExe.Source uninstall orchestratia-agent -y 2>&1 | Out-Null
            Write-Ok "Ran pip uninstall orchestratia-agent"
        }
        # Also try python -m pip (more reliable)
        $pythonExe = Get-Command python -ErrorAction SilentlyContinue
        if (-not $pythonExe) { $pythonExe = Get-Command python3 -ErrorAction SilentlyContinue }
        if ($pythonExe) {
            & $pythonExe.Source -m pip uninstall orchestratia-agent -y 2>&1 | Out-Null
            Write-Ok "Ran python -m pip uninstall orchestratia-agent"
        }
        # Verify removal — delete script files directly if pip uninstall missed them
        if (Test-Path $pipPath) {
            Remove-Item $pipPath -Force -ErrorAction SilentlyContinue
            # Also remove the -script.py and .exe.manifest variants
            $pipDir = Split-Path $pipPath
            Remove-Item "$pipDir\orchestratia-agent-script.py" -Force -ErrorAction SilentlyContinue
            Remove-Item "$pipDir\orchestratia.exe" -Force -ErrorAction SilentlyContinue
            Remove-Item "$pipDir\orchestratia-script.py" -Force -ErrorAction SilentlyContinue
            Write-Ok "Cleaned up leftover pip script files"
        }
    } else {
        # It's some other installation (manual copy, etc.)
        Write-Warn "Found unknown installation at: $pipPath — remove it manually if needed"
    }
}

# 1g. Remove old config if it exists (but preserve api_key if already registered)
if (Test-Path "$ConfigDir\config.yaml") {
    # Keep the old config — registration will overwrite it anyway
    Write-Info "Existing config.yaml found (will be updated during registration)"
}

if (-not $existing) { Write-Ok "No existing installation found" }

# Step 2: Download executable
Write-Step 2 $TotalSteps "Downloading orchestratia-agent.exe"

# Check Windows version for ConPTY
$build = [System.Environment]::OSVersion.Version.Build
if ($build -ge 17763) {
    Write-Ok "Windows build $build (ConPTY supported)"
} else {
    Write-Warn "Windows build $build — ConPTY requires build 17763+ (Windows 10 1809)"
}

Write-Info "Downloading from: $ReleaseUrl"
try {
    # If pty-host is running, the exe file is locked. Rename it first.
    if (Test-Path $AgentExePath) {
        $oldExe = "$AgentExePath.old"
        Remove-Item $oldExe -Force -ErrorAction SilentlyContinue
        try {
            Rename-Item $AgentExePath $oldExe -Force -ErrorAction Stop
            Write-Ok "Renamed old exe (pty-host keeps running with in-memory copy)"
        } catch {
            # Can't rename — try direct overwrite (works if no pty-host running)
            Remove-Item $AgentExePath -Force -ErrorAction SilentlyContinue
        }
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $AgentExePath -UseBasicParsing -TimeoutSec 120
    $size = (Get-Item $AgentExePath).Length
    $sizeMB = [math]::Round($size / 1MB, 1)
    Write-Ok "Downloaded orchestratia-agent.exe ($sizeMB MB)"
    # Clean up old exe (may fail if still in use — that's fine)
    Remove-Item "$AgentExePath.old" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Fatal "Download failed: $_`n  URL: $ReleaseUrl"
}

# Verify it runs (console=False exe — must use Start-Process -Wait, not & $exe)
try {
    $verFile = "$ConfigDir\version.tmp"
    Start-Process -FilePath $AgentExePath -ArgumentList "--version" -Wait -NoNewWindow `
        -RedirectStandardOutput $verFile -ErrorAction Stop
    $ver = Get-Content $verFile -ErrorAction SilentlyContinue
    Remove-Item $verFile -Force -ErrorAction SilentlyContinue
    if ($ver) {
        Write-Ok "Verified: $ver"
    } else {
        # console=False may not produce capturable stdout — check agent.log instead
        $sizeMB2 = [math]::Round((Get-Item $AgentExePath).Length / 1MB, 1)
        Write-Ok "Binary OK ($sizeMB2 MB)"
    }
} catch {
    # Start-Process -Wait works even if output capture fails
    Write-Ok "Binary downloaded"
}

# Create orchestratia.exe (CLI tool) — same binary, detects name at runtime
$CliExePath = "$ConfigDir\orchestratia.exe"
try {
    Copy-Item $AgentExePath $CliExePath -Force -ErrorAction Stop
    Write-Ok "Created CLI tool: orchestratia.exe"
} catch {
    Write-Warn "Could not create orchestratia.exe: $_"
}

# Step 3: Register (or verify existing config for upgrades)
Write-Step 3 $TotalSteps "Registering with Orchestratia hub"

if ($UpgradeMode) {
    Write-Ok "Upgrade mode — using existing config.yaml"
    Write-Ok "Config: $ConfigDir\config.yaml"
    $configContent = Get-Content "$ConfigDir\config.yaml" -Raw -ErrorAction SilentlyContinue
    if ($configContent -match "api_key:\s*orc_") {
        Write-Ok "API key verified in config"
    } else {
        Write-Warn "Config exists but api_key not found — check manually"
    }
} else {
    Write-Info "Using one-time registration token..."
    # MUST use Start-Process -Wait: the exe is a WINDOWS subsystem app
    # (console=False). PowerShell's & operator does NOT wait for GUI apps,
    # causing the daemon to start before registration finishes.
    try {
        $regProc = Start-Process -FilePath $AgentExePath `
            -ArgumentList "--register", $Token, "--config", "`"$ConfigDir\config.yaml`"" `
            -Wait -NoNewWindow -PassThru -ErrorAction Stop
        if ($regProc.ExitCode -eq 0) {
            Write-Ok "Registered successfully"
        } else {
            Write-Fail "Registration exited with code $($regProc.ExitCode)"
        }
    } catch {
        Write-Fail "Registration failed: $_"
    }

    if (Test-Path "$ConfigDir\config.yaml") {
        Write-Ok "Config: $ConfigDir\config.yaml"
        $configContent = Get-Content "$ConfigDir\config.yaml" -Raw -ErrorAction SilentlyContinue
        if ($configContent -match "api_key:\s*orc_") {
            Write-Ok "API key verified in config"
        } else {
            Write-Warn "Config written but api_key not found — check manually"
        }
    } else {
        Write-Fatal "Registration did not create config. Cannot start service."
    }
}

# Step 4: Add to user PATH
Write-Step 4 $TotalSteps "Adding to user PATH"

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -and $userPath.Split(";") -contains $ConfigDir) {
    Write-Ok "Already in PATH: $ConfigDir"
} else {
    try {
        $newPath = if ($userPath) { "$userPath;$ConfigDir" } else { $ConfigDir }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        # Also update current session so orchestratia-agent works immediately
        $env:Path = "$env:Path;$ConfigDir"
        Write-Ok "Added to user PATH: $ConfigDir"
    } catch {
        Write-Warn "Could not add to PATH: $_"
        Write-Info "Run manually: [Environment]::SetEnvironmentVariable('Path', `"$userPath;$ConfigDir`", 'User')"
    }
}

# Verify that orchestratia-agent now resolves to our exe
$resolvedCmd = Get-Command "orchestratia-agent" -ErrorAction SilentlyContinue
if ($resolvedCmd -and $resolvedCmd.Source -eq $AgentExePath) {
    Write-Ok "Verified: 'orchestratia-agent' resolves to $AgentExePath"
} elseif ($resolvedCmd) {
    Write-Warn "'orchestratia-agent' resolves to $($resolvedCmd.Source) instead of $AgentExePath"
    Write-Info "An old installation may still be in PATH. Remove it or reorder PATH entries."
} else {
    Write-Info "Open a new PowerShell window for PATH changes to take effect"
}

# Step 5: Auto-start setup (Task Scheduler — runs as current user)
Write-Step 5 $TotalSteps "Setting up auto-start"

# Task Scheduler runs the agent as the current user, which is essential:
# - ConPTY sessions need a user profile (SYSTEM can't spawn shells)
# - Claude Code, git, node etc. are installed per-user
# - %LOCALAPPDATA% resolves to the correct config path
# NSSM services run as SYSTEM and can't do any of the above.

$TaskName = "OrchestratiAgent"
$ServiceInstalled = $false

# Remove any existing NSSM service from previous installs
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssmExe) {
        & nssm remove $ServiceName confirm 2>$null
    } else {
        sc.exe delete $ServiceName 2>$null
    }
    Write-Ok "Removed legacy NSSM service"
}

# Remove existing scheduled task
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

try {
    $taskAction = New-ScheduledTaskAction `
        -Execute $AgentExePath `
        -WorkingDirectory $ConfigDir `
        -ErrorAction Stop

    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn -ErrorAction Stop

    $taskSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -ErrorAction Stop

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $taskAction `
        -Trigger $taskTrigger `
        -Settings $taskSettings `
        -Description "Orchestratia agent daemon (runs as $env:USERNAME)" `
        -ErrorAction Stop | Out-Null

    Write-Ok "Scheduled task created (runs as $env:USERNAME at logon)"
    $ServiceInstalled = $true

    # Start it now
    Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Write-Info "Waiting for agent + pty-host to initialize..."
    Start-Sleep -Seconds 5

    # Verify agent processes are running
    $agentProcs = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
    if ($agentProcs -and $agentProcs.Count -ge 2) {
        Write-Ok "Agent is running ($($agentProcs.Count) processes — agent + pty-host)"
    } elseif ($agentProcs) {
        Write-Ok "Agent is running (PID: $($agentProcs[0].Id))"
        Write-Warn "Only $($agentProcs.Count) process — pty-host may not have started yet"
    } else {
        Write-Warn "Agent may not be running — check logs"
    }

    # Verify pty-host is listening on TCP
    $ptyHostUp = Test-NetConnection -ComputerName 127.0.0.1 -Port 19199 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($ptyHostUp) {
        Write-Ok "PTY host listening on port 19199 (sessions will persist)"
    } else {
        Write-Warn "PTY host not detected on port 19199"
        Write-Info "Check logs: Get-Content $LogDir\pty-host.log -Tail 20"
    }
} catch {
    Write-Warn "Register-ScheduledTask failed: $_"
    Write-Info "Trying schtasks.exe fallback (works without admin)..."

    # schtasks.exe fallback — creates a logon trigger task as the current user
    try {
        $schtasksArgs = @(
            "/Create"
            "/TN", $TaskName
            "/TR", "`"$AgentExePath`""
            "/SC", "ONLOGON"
            "/RL", "LIMITED"
            "/F"  # force overwrite if exists
        )
        $result = & schtasks.exe @schtasksArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "Scheduled task created via schtasks.exe"
            $ServiceInstalled = $true

            # Start it now
            schtasks.exe /Run /TN $TaskName 2>$null
            Write-Info "Waiting for agent + pty-host to initialize..."
            Start-Sleep -Seconds 5
            $proc = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Ok "Agent is running (PID: $($proc.Id))"
            } else {
                Write-Warn "Agent may not be running — check logs"
            }
            $ptyHostUp = Test-NetConnection -ComputerName 127.0.0.1 -Port 19199 -InformationLevel Quiet -WarningAction SilentlyContinue
            if ($ptyHostUp) {
                Write-Ok "PTY host listening on port 19199 (sessions will persist)"
            } else {
                Write-Warn "PTY host not detected on port 19199"
            }
        } else {
            Write-Fail "schtasks.exe also failed: $result"
        }
    } catch {
        Write-Fail "schtasks.exe fallback failed: $_"
    }
}

if (-not $ServiceInstalled) {
    Write-Fail "Auto-start setup failed. Run the agent manually:"
    Write-Info "& `"$AgentExePath`""
}

# Step 6: Claude Code integration (skill + session hook)
Write-Step 6 $TotalSteps "Setting up Claude Code integration"

# Claude Code discovers skills from ~/.claude/skills/<name>/SKILL.md
# and SessionStart hooks from ~/.claude/settings.json.
# Since the Windows installer uses a standalone .exe (no git clone),
# we download the skill and hook files from the public GitHub repo.

$ClaudeDir = "$env:USERPROFILE\.claude"
$SkillDir = "$ClaudeDir\skills\orchestratia"
$HookDir = "$ConfigDir\claude-skill"
$SkillUrl = "https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/claude-skill/SKILL.md"
$HookUrl = "https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/claude-skill/orchestratia-context.ps1"

# 6a. Download and install skill file
New-Item -ItemType Directory -Force -Path $SkillDir | Out-Null

try {
    Invoke-WebRequest -Uri $SkillUrl -OutFile "$SkillDir\SKILL.md" -UseBasicParsing -TimeoutSec 15
    Write-Ok "Skill installed: $SkillDir\SKILL.md"
} catch {
    Write-Warn "Could not download SKILL.md: $_"
    Write-Info "Manual: save $SkillUrl to $SkillDir\SKILL.md"
}

# 6b. Download session hook script
New-Item -ItemType Directory -Force -Path $HookDir | Out-Null

try {
    Invoke-WebRequest -Uri $HookUrl -OutFile "$HookDir\orchestratia-context.ps1" -UseBasicParsing -TimeoutSec 15
    Write-Ok "Hook script: $HookDir\orchestratia-context.ps1"
} catch {
    Write-Warn "Could not download orchestratia-context.ps1: $_"
    Write-Info "Manual: save $HookUrl to $HookDir\orchestratia-context.ps1"
}

# 6c. Merge SessionStart hook into ~/.claude/settings.json
$ClaudeSettings = "$ClaudeDir\settings.json"
New-Item -ItemType Directory -Force -Path $ClaudeDir | Out-Null

$HookCommand = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$HookDir\orchestratia-context.ps1`""

# Use Python for reliable JSON merge (same approach as Linux installer).
# PowerShell 5.x lacks ConvertFrom-Json -AsHashtable and writes BOM with UTF8.
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) { $PythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }

if ($PythonExe) {
    $pyScript = @"
import json, os, sys

settings_path = sys.argv[1]
hook_command = sys.argv[2]

settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, 'r', encoding='utf-8-sig') as f:
            settings = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print('WARN: Could not parse existing settings.json', file=sys.stderr)

hooks = settings.setdefault('hooks', {})
session_start = hooks.setdefault('SessionStart', [])

already_exists = any(
    any('orchestratia' in h.get('command', '') for h in entry.get('hooks', []))
    for entry in session_start
    if isinstance(entry, dict)
)

if not already_exists:
    session_start.append({
        'hooks': [{'type': 'command', 'command': hook_command, 'timeout': 10000}]
    })

with open(settings_path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"@
    $pyTmp = "$env:TEMP\orc_settings_merge.py"
    Set-Content -Path $pyTmp -Value $pyScript -Encoding ASCII
    try {
        & $PythonExe $pyTmp $ClaudeSettings $HookCommand 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Ok "SessionStart hook registered in $ClaudeSettings"
        } else {
            Write-Warn "Python JSON merge returned non-zero exit"
        }
    } catch {
        Write-Warn "Could not update settings.json via Python: $_"
    }
    Remove-Item $pyTmp -Force -ErrorAction SilentlyContinue
} else {
    # Fallback: pure PowerShell (PS 5.x compatible, no -AsHashtable)
    try {
        $needsWrite = $true
        if (Test-Path $ClaudeSettings) {
            $raw = Get-Content $ClaudeSettings -Raw -ErrorAction SilentlyContinue
            if ($raw -and $raw -match "orchestratia") {
                Write-Ok "Orchestratia hook already in $ClaudeSettings"
                $needsWrite = $false
            }
        }
        if ($needsWrite) {
            # Minimal valid settings with just the hook
            $json = @"
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "$($HookCommand -replace '\\', '\\\\' -replace '"', '\"')",
            "timeout": 10000
          }
        ]
      }
    ]
  }
}
"@
            Set-Content -Path $ClaudeSettings -Value $json -Encoding ASCII
            Write-Ok "SessionStart hook registered in $ClaudeSettings"
            Write-Warn "No Python found — wrote minimal settings.json (existing settings may be lost)"
        }
    } catch {
        Write-Warn "Could not update settings.json: $_"
        Write-Info "Manual: add SessionStart hook for $HookCommand"
    }
}

# ── Summary ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
if ($Errors -eq 0) {
    Write-Host "  Installation complete — no errors" -ForegroundColor Green
} else {
    Write-Host "  Installation finished with $Errors warning(s)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Installed to: $AgentExePath" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Sessions persist across agent restarts and reinstalls." -ForegroundColor DarkGray
Write-Host "  The pty-host process owns sessions independently." -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor DarkGray
Write-Host "    CLI:      orchestratia status"
Write-Host "    Tasks:    orchestratia task check"
Write-Host "    Skill:    /orchestratia (inside Claude Code)"
Write-Host "    Version:  orchestratia-agent --version"
Write-Host "    Test PTY: orchestratia-agent --test-pty"
Write-Host "    Status:   schtasks /Query /TN OrchestratiAgent"
Write-Host "    Start:    schtasks /Run /TN OrchestratiAgent"
Write-Host "    Stop:     schtasks /End /TN OrchestratiAgent"
Write-Host "    Logs:     Get-Content $LogDir\pty-host.log -Wait"
Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
Write-Host ""

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
if ($env:ORC_TOKEN) { Remove-Item Env:\ORC_TOKEN -ErrorAction SilentlyContinue }
