# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Windows (Standalone .exe)
#
# Downloads the standalone orchestratia-agent.exe from GitHub Releases.
# No Python, pip, or git required.
#
# Two modes:
#   FRESH INSTALL (with token):
#     $env:ORC_TOKEN='orcreg_...'; irm https://install.orchestratia.com/windows | iex
#
#   UPGRADE (no token — uses existing config, preserves sessions):
#     irm https://install.orchestratia.com/windows | iex
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
        Write-Host '    $env:ORC_TOKEN=''orcreg_...''; irm https://install.orchestratia.com/windows | iex' -ForegroundColor Cyan
        Write-Host ""
        Write-Host '  Upgrade (no token needed — uses existing config):' -ForegroundColor DarkGray
        Write-Host '    irm https://install.orchestratia.com/windows | iex' -ForegroundColor Cyan
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
    Write-Host "     " -NoNewline
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Msg
}

function Write-Warn($Msg) {
    Write-Host "     " -NoNewline
    Write-Host "[!]  " -ForegroundColor Yellow -NoNewline
    Write-Host $Msg -ForegroundColor Yellow
    $script:Errors++
}

function Write-Fail($Msg) {
    Write-Host "     " -NoNewline
    Write-Host "[X]  " -ForegroundColor Red -NoNewline
    Write-Host $Msg -ForegroundColor Red
    $script:Errors++
}

function Write-Info($Msg) {
    Write-Host "     " -NoNewline
    Write-Host "..   " -ForegroundColor DarkGray -NoNewline
    Write-Host $Msg -ForegroundColor DarkGray
}

function Write-Note($Msg) {
    # Neutral informational — not success, not warning. For "already present"
    # type messages so users don't read them as problems.
    Write-Host "     " -NoNewline
    Write-Host "[-]  " -ForegroundColor DarkGray -NoNewline
    Write-Host $Msg -ForegroundColor DarkGray
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
                Write-Note "Preserving session daemon — your terminals stay alive"
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
    if ($killed -gt 0) { Write-Ok "Stopped previous agent" }
    if ($preserved -gt 0) { Write-Note "Live sessions preserved" }
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

# 1e2. Clean old bin\ subdirectory (legacy PS1 wrapper installs)
$oldBinDir = "$ConfigDir\bin"
if (Test-Path $oldBinDir) {
    $existing = $true
    Remove-Item "$oldBinDir\*" -Force -ErrorAction SilentlyContinue
    Remove-Item $oldBinDir -Force -ErrorAction SilentlyContinue
    Write-Ok "Removed legacy bin\ directory"
}

# 1f. Detect and remove pip-installed version
$pipAgent = Get-Command "orchestratia-agent" -ErrorAction SilentlyContinue
if ($pipAgent -and $pipAgent.Source -ne $AgentExePath) {
    $existing = $true
    $pipPath = $pipAgent.Source
    Write-Info "Found existing installation at: $pipPath"

    # Check if it's a pip-installed or Orchestratia's own old install
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
            $pipDir = Split-Path $pipPath
            Remove-Item "$pipDir\orchestratia-agent-script.py" -Force -ErrorAction SilentlyContinue
            Remove-Item "$pipDir\orchestratia.exe" -Force -ErrorAction SilentlyContinue
            Remove-Item "$pipDir\orchestratia-script.py" -Force -ErrorAction SilentlyContinue
            Write-Ok "Cleaned up leftover pip script files"
        }
    } elseif ($pipPath -match "Orchestratia") {
        # Previous Orchestratia install (old PS1 wrapper or bin directory)
        Write-Info "Detected previous Orchestratia installation, cleaning up..."
        $pipDir = Split-Path $pipPath
        Remove-Item $pipPath -Force -ErrorAction SilentlyContinue
        Remove-Item "$pipDir\orchestratia-agent.ps1" -Force -ErrorAction SilentlyContinue
        Remove-Item "$pipDir\orchestratia.ps1" -Force -ErrorAction SilentlyContinue
        Remove-Item "$pipDir\orchestratia-agent.exe" -Force -ErrorAction SilentlyContinue
        Remove-Item "$pipDir\orchestratia.exe" -Force -ErrorAction SilentlyContinue
        # Clean the bin directory if it's now empty
        if ((Test-Path $pipDir) -and (Get-ChildItem $pipDir -ErrorAction SilentlyContinue).Count -eq 0) {
            Remove-Item $pipDir -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "Removed previous Orchestratia installation"
    } else {
        # Unknown installation — remove it anyway since we're doing a fresh install
        Write-Info "Removing previous installation at: $pipPath"
        Remove-Item $pipPath -Force -ErrorAction SilentlyContinue
        Write-Ok "Removed old installation"
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

Write-Info "Fetching agent binary…"
try {
    # If pty-host is running, the exe file is locked. Rename it first.
    if (Test-Path $AgentExePath) {
        $oldExe = "$AgentExePath.old"
        Remove-Item $oldExe -Force -ErrorAction SilentlyContinue
        try {
            Rename-Item $AgentExePath $oldExe -Force -ErrorAction Stop
            Write-Note "Preparing to replace previous agent"
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

# Fetch the CLI wrappers (.cmd/.ps1 shims). These route interactive
# invocations like `orchestratia status` through Start-Process with
# explicit stdout redirection so the windowed-subsystem exe's output
# reaches the parent shell. Without them, bare `orchestratia-agent
# --version` at a PowerShell prompt shows nothing.
$BinDir = "$ConfigDir\bin"
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$WrapperBase = "https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/windows-wrappers"
$wrappersFetched = 0
foreach ($name in @("orchestratia.cmd", "orchestratia.ps1", "orchestratia-agent.cmd", "orchestratia-agent.ps1")) {
    try {
        Invoke-WebRequest -Uri "$WrapperBase/$name" -OutFile "$BinDir\$name" -UseBasicParsing -TimeoutSec 15 -ErrorAction Stop
        $wrappersFetched++
    } catch {
        Write-Warn "Could not download $name : $_"
    }
}
if ($wrappersFetched -eq 4) {
    Write-Ok "CLI wrappers installed in $BinDir"
} elseif ($wrappersFetched -gt 0) {
    Write-Warn "Only $wrappersFetched/4 CLI wrappers fetched — some commands may not display output"
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

# Two entries go on PATH:
#   1. $BinDir  — CLI wrappers (.cmd/.ps1). MUST be earlier in PATH than
#                 $ConfigDir so `orchestratia-agent` resolves to the
#                 .cmd wrapper (visible output) rather than the .exe
#                 (silent because of the windowed subsystem).
#   2. $ConfigDir — the exe dir, kept in PATH for backward compat and
#                   for users who explicitly call orchestratia-agent.exe.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$userPathEntries = if ($userPath) { $userPath.Split(";") | Where-Object { $_ } } else { @() }

# Remove any existing entries to rewrite cleanly with the right order.
$filtered = $userPathEntries | Where-Object { $_ -ne $BinDir -and $_ -ne $ConfigDir }

# Prepend $BinDir, then $ConfigDir, then everything else. $BinDir first
# ensures .cmd wrappers win resolution over the .exe files.
$newEntries = @($BinDir, $ConfigDir) + @($filtered)
$newPath = ($newEntries -join ";")

if ($newPath -ne $userPath) {
    try {
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        # Update current session so wrappers resolve immediately
        $sessionEntries = @($BinDir, $ConfigDir) + ($env:Path.Split(";") | Where-Object { $_ -and $_ -ne $BinDir -and $_ -ne $ConfigDir })
        $env:Path = ($sessionEntries -join ";")
        Write-Ok "PATH updated: $BinDir, $ConfigDir"
    } catch {
        Write-Warn "Could not update PATH: $_"
        Write-Info "Run manually: set Path to start with `"$BinDir;$ConfigDir;...`""
    }
} else {
    Write-Ok "PATH already ordered correctly"
}

# Verify that orchestratia-agent resolves to a wrapper (not the raw exe)
$resolvedCmd = Get-Command "orchestratia-agent" -ErrorAction SilentlyContinue
if ($resolvedCmd -and $resolvedCmd.Source -match [regex]::Escape($BinDir)) {
    Write-Ok "Verified: 'orchestratia-agent' resolves to wrapper"
} elseif ($resolvedCmd -and $resolvedCmd.Source -eq $AgentExePath) {
    Write-Info "Open a new PowerShell window for PATH changes to take effect"
} elseif ($resolvedCmd) {
    Write-Info "Open a new PowerShell window for PATH changes to take effect"
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
    Write-Info "Starting agent…"
    Start-Sleep -Seconds 5

    # Verify agent processes are running
    $agentProcs = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
    if ($agentProcs -and $agentProcs.Count -ge 2) {
        Write-Ok "Agent running"
    } elseif ($agentProcs) {
        Write-Ok "Agent running"
        Write-Warn "Session daemon may still be starting"
    } else {
        Write-Warn "Agent may not be running — check logs"
    }

    # Verify pty-host is listening on TCP
    $ptyHostUp = Test-NetConnection -ComputerName 127.0.0.1 -Port 19199 -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($ptyHostUp) {
        Write-Ok "Session daemon ready"
    } else {
        Write-Warn "Session daemon not yet ready — logs: $LogDir\pty-host.log"
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
            Write-Info "Starting agent…"
            Start-Sleep -Seconds 5
            $proc = Get-Process -Name "orchestratia-agent" -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Ok "Agent running"
            } else {
                Write-Warn "Agent may not be running — check logs"
            }
            $ptyHostUp = Test-NetConnection -ComputerName 127.0.0.1 -Port 19199 -InformationLevel Quiet -WarningAction SilentlyContinue
            if ($ptyHostUp) {
                Write-Ok "Session daemon ready"
            } else {
                Write-Warn "Session daemon not yet ready"
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

# Step 6: AI Agent integration (Claude Code, Gemini CLI, Codex CLI)
Write-Step 6 $TotalSteps "Setting up AI agent integrations"

# Download hook scripts (shared across all agents)
$HookDir = "$ConfigDir\agent-skills\hooks"
$RepoBase = "https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/agent-skills"
New-Item -ItemType Directory -Force -Path $HookDir | Out-Null

try {
    Invoke-WebRequest -Uri "$RepoBase/hooks/orchestratia-context.ps1" -OutFile "$HookDir\orchestratia-context.ps1" -UseBasicParsing -TimeoutSec 15
    Invoke-WebRequest -Uri "$RepoBase/hooks/orchestratia-pretooluse.ps1" -OutFile "$HookDir\orchestratia-pretooluse.ps1" -UseBasicParsing -TimeoutSec 15
    Write-Ok "Hook scripts downloaded to $HookDir"
} catch {
    Write-Warn "Could not download hook scripts: $_"
}

$ContextHookCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$HookDir\orchestratia-context.ps1`""
$PretoolHookCmd = "powershell -NoProfile -ExecutionPolicy Bypass -File `"$HookDir\orchestratia-pretooluse.ps1`""

# Python for reliable JSON merge
$PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $PythonExe) { $PythonExe = (Get-Command python3 -ErrorAction SilentlyContinue).Source }

# Helper: merge hooks into a JSON settings file
function Merge-JsonHooks($SettingsPath, $SessionEvent, $PretoolEvent, $ContextCmd, $PretoolCmd) {
    if (-not $PythonExe) {
        Write-Warn "Python not found — cannot merge hooks into $SettingsPath"
        return $false
    }
    $pyScript = @"
import json, os, sys
path = sys.argv[1]
session_event = sys.argv[2]
pretool_event = sys.argv[3]
context_cmd = sys.argv[4]
pretool_cmd = sys.argv[5]

settings = {}
if os.path.exists(path):
    try:
        with open(path, 'r', encoding='utf-8-sig') as f:
            settings = json.load(f)
    except: pass

hooks = settings.setdefault('hooks', {})

for event, cmd in [(session_event, context_cmd), (pretool_event, pretool_cmd)]:
    event_list = hooks.setdefault(event, [])
    if not any('orchestratia' in str(e) for e in event_list):
        event_list.append({'hooks': [{'type': 'command', 'command': cmd, 'timeout': 10000 if 'context' in cmd else 30000}]})

with open(path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
"@
    $pyTmp = "$env:TEMP\orc_merge_hooks.py"
    Set-Content -Path $pyTmp -Value $pyScript -Encoding ASCII
    try {
        & $PythonExe $pyTmp $SettingsPath $SessionEvent $PretoolEvent $ContextCmd $PretoolCmd 2>&1 | Out-Null
        Remove-Item $pyTmp -Force -ErrorAction SilentlyContinue
        return ($LASTEXITCODE -eq 0)
    } catch {
        Remove-Item $pyTmp -Force -ErrorAction SilentlyContinue
        return $false
    }
}

# ── Claude Code ──
$ClaudeDetected = $null -ne (Get-Command claude -ErrorAction SilentlyContinue)
if ($ClaudeDetected) {
    $ClaudeSkillDir = "$env:USERPROFILE\.claude\skills\orchestratia"
    New-Item -ItemType Directory -Force -Path $ClaudeSkillDir | Out-Null
    try {
        Invoke-WebRequest -Uri "$RepoBase/claude/SKILL.md" -OutFile "$ClaudeSkillDir\SKILL.md" -UseBasicParsing -TimeoutSec 15
        Write-Ok "Claude Code skill installed"
    } catch { Write-Warn "Could not download Claude SKILL.md" }

    $ClaudeSettings = "$env:USERPROFILE\.claude\settings.json"
    New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.claude" | Out-Null
    if (Merge-JsonHooks $ClaudeSettings "SessionStart" "PreToolUse" $ContextHookCmd $PretoolHookCmd) {
        Write-Ok "Claude Code hooks configured"
    } else { Write-Warn "Could not configure Claude Code hooks" }
}

# ── Gemini CLI ──
$GeminiDetected = $null -ne (Get-Command gemini -ErrorAction SilentlyContinue)
if ($GeminiDetected) {
    $GeminiSkillDir = "$env:USERPROFILE\.gemini\skills\orchestratia"
    $SharedSkillDir = "$env:USERPROFILE\.agents\skills\orchestratia"
    New-Item -ItemType Directory -Force -Path $GeminiSkillDir | Out-Null
    New-Item -ItemType Directory -Force -Path $SharedSkillDir | Out-Null
    try {
        Invoke-WebRequest -Uri "$RepoBase/gemini/SKILL.md" -OutFile "$GeminiSkillDir\SKILL.md" -UseBasicParsing -TimeoutSec 15
        Copy-Item "$GeminiSkillDir\SKILL.md" "$SharedSkillDir\SKILL.md" -Force -ErrorAction SilentlyContinue
        Write-Ok "Gemini CLI skill installed"
    } catch { Write-Warn "Could not download Gemini SKILL.md" }

    $GeminiSettings = "$env:USERPROFILE\.gemini\settings.json"
    New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.gemini" | Out-Null
    if (Merge-JsonHooks $GeminiSettings "SessionStart" "BeforeTool" $ContextHookCmd $PretoolHookCmd) {
        Write-Ok "Gemini CLI hooks configured"
    } else { Write-Warn "Could not configure Gemini CLI hooks" }
}

# ── Codex CLI ──
$CodexDetected = $null -ne (Get-Command codex -ErrorAction SilentlyContinue)
if ($CodexDetected) {
    $CodexSkillDir = "$env:USERPROFILE\.codex\skills\orchestratia"
    $SharedSkillDir = "$env:USERPROFILE\.agents\skills\orchestratia"
    New-Item -ItemType Directory -Force -Path $CodexSkillDir | Out-Null
    New-Item -ItemType Directory -Force -Path $SharedSkillDir | Out-Null
    try {
        Invoke-WebRequest -Uri "$RepoBase/codex/SKILL.md" -OutFile "$CodexSkillDir\SKILL.md" -UseBasicParsing -TimeoutSec 15
        if (-not (Test-Path "$SharedSkillDir\SKILL.md")) {
            Copy-Item "$CodexSkillDir\SKILL.md" "$SharedSkillDir\SKILL.md" -Force -ErrorAction SilentlyContinue
        }
        Write-Ok "Codex CLI skill installed"
    } catch { Write-Warn "Could not download Codex SKILL.md" }

    # Enable hooks feature flag in config.toml
    $CodexConfig = "$env:USERPROFILE\.codex\config.toml"
    New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.codex" | Out-Null
    if (Test-Path $CodexConfig) {
        $content = Get-Content $CodexConfig -Raw -ErrorAction SilentlyContinue
        if ($content -notmatch "codex_hooks") {
            Add-Content $CodexConfig "`n[features]`ncodex_hooks = true"
        }
    } else {
        Set-Content $CodexConfig "[features]`ncodex_hooks = true" -Encoding ASCII
    }

    # Configure hooks via hooks.json
    $CodexHooks = "$env:USERPROFILE\.codex\hooks.json"
    if ((Test-Path $CodexHooks) -and (Get-Content $CodexHooks -Raw -ErrorAction SilentlyContinue) -match "orchestratia") {
        Write-Ok "Codex CLI hooks already configured"
    } else {
        $hooksJson = @"
{
  "hooks": {
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "$($ContextHookCmd -replace '\\', '\\\\' -replace '"', '\\"')", "timeout": 10000}]}
    ],
    "PreToolUse": [
      {"matcher": ".*", "hooks": [{"type": "command", "command": "$($PretoolHookCmd -replace '\\', '\\\\' -replace '"', '\\"')", "timeout": 30000}]}
    ]
  }
}
"@
        Set-Content $CodexHooks $hooksJson -Encoding ASCII
        Write-Ok "Codex CLI hooks configured (feature flag enabled)"
    }
}

# ── Agent detection summary ──
Write-Host ""
$configured = @()
$available = @()
if ($ClaudeDetected) { $configured += "Claude Code" } else { $available += "Claude Code" }
if ($GeminiDetected) { $configured += "Gemini CLI" }  else { $available += "Gemini CLI" }
if ($CodexDetected)  { $configured += "Codex CLI" }   else { $available += "Codex CLI" }

if ($configured.Count -gt 0) {
    Write-Ok ("Configured: " + ($configured -join ", "))
}
if ($available.Count -gt 0) {
    Write-Note ("Also supported (install separately if needed): " + ($available -join ", "))
}

# ── Summary ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
if ($Errors -eq 0) {
    Write-Host "  Installation complete" -ForegroundColor Green
} else {
    Write-Host "  Installation finished with $Errors warning(s)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Next steps:" -ForegroundColor White
Write-Host "    1. Open your dashboard at " -NoNewline -ForegroundColor DarkGray
Write-Host "https://orchestratia.com" -ForegroundColor Cyan
Write-Host "    2. Your agent is running and sessions will auto-persist" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Commands:  " -NoNewline -ForegroundColor DarkGray
Write-Host "orchestratia status  |  orchestratia --help" -ForegroundColor Cyan
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
Write-Host ""

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
if ($env:ORC_TOKEN) { Remove-Item Env:\ORC_TOKEN -ErrorAction SilentlyContinue }
