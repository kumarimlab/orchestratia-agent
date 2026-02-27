# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Windows (Standalone .exe)
#
# Downloads the standalone orchestratia-agent.exe from GitHub Releases.
# No Python, pip, or git required.
#
# Usage — one-liner (paste into PowerShell as Administrator):
#   $env:ORC_TOKEN='orcreg_...'; irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex
#
# Or download and run directly:
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 <TOKEN>
#
# What this does:
#   1. Cleans up any existing installation
#   2. Downloads orchestratia-agent.exe from latest GitHub Release
#   3. Registers with the hub using the one-time token
#   4. Creates a Windows service (NSSM) or scheduled task (fallback)
# ──────────────────────────────────────────────────────────────────────

$Token = if ($args.Count -gt 0) { $args[0] } elseif ($env:ORC_TOKEN) { $env:ORC_TOKEN } else { $null }

if (-not $Token) {
    Write-Host ""
    Write-Host "  Usage:" -ForegroundColor White
    Write-Host ""
    Write-Host '  One-liner (paste into PowerShell as Administrator):' -ForegroundColor DarkGray
    Write-Host '    $env:ORC_TOKEN=''orcreg_...''; irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex' -ForegroundColor Cyan
    Write-Host ""
    Write-Host '  Or download and run:' -ForegroundColor DarkGray
    Write-Host '    .\install-windows.ps1 orcreg_...' -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

$ErrorActionPreference = "Continue"

# ── Logging ──────────────────────────────────────────────────────────
$ConfigDir = "$env:LOCALAPPDATA\Orchestratia"
$LogDir = "$env:LOCALAPPDATA\Orchestratia\logs"
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
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NssmDir = "$ConfigDir\nssm"
$ReleaseUrl = if ($env:ORCHESTRATIA_EXE_URL) {
    $env:ORCHESTRATIA_EXE_URL
} else {
    "https://github.com/kumarimlab/orchestratia-agent/releases/latest/download/orchestratia-agent.exe"
}
$Errors = 0
$TotalSteps = 4

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

if (-not $Token.StartsWith("orcreg_")) {
    Write-Fatal "Invalid token format (must start with orcreg_)"
}

# ── Main ─────────────────────────────────────────────────────────────

Write-Header

# Step 1: Cleanup
Write-Step 1 $TotalSteps "Removing existing installation (if any)"

$existing = $false

# Stop and remove existing service
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

# Remove existing scheduled task
$existingTask = Get-ScheduledTask -TaskName "OrchestratiAgent" -ErrorAction SilentlyContinue
if ($existingTask) {
    $existing = $true
    Unregister-ScheduledTask -TaskName "OrchestratiAgent" -Confirm:$false -ErrorAction SilentlyContinue
    Write-Ok "Removed existing scheduled task"
}

# Remove existing exe
if (Test-Path $AgentExePath) {
    $existing = $true
    Remove-Item $AgentExePath -Force -ErrorAction SilentlyContinue
    Write-Ok "Removed existing executable"
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
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $AgentExePath -UseBasicParsing -TimeoutSec 60
    $size = (Get-Item $AgentExePath).Length
    $sizeMB = [math]::Round($size / 1MB, 1)
    Write-Ok "Downloaded orchestratia-agent.exe ($sizeMB MB)"
} catch {
    Write-Fatal "Download failed: $_`n  URL: $ReleaseUrl"
}

# Verify it runs
try {
    $ver = & $AgentExePath --version 2>&1
    Write-Ok "Verified: $ver"
} catch {
    Write-Fatal "Downloaded exe failed to run: $_"
}

# Step 3: Register
Write-Step 3 $TotalSteps "Registering with Orchestratia hub"

Write-Info "Using one-time registration token..."
try {
    $regOutput = & $AgentExePath --register $Token --config "$ConfigDir\config.yaml" 2>&1
    Write-Ok "Registered successfully"
    $regOutput | ForEach-Object {
        if ($_ -match "api.key|orc_|registered|saved") {
            Write-Info $_
        }
    }
} catch {
    Write-Fail "Registration failed: $_"
}

if (Test-Path "$ConfigDir\config.yaml") {
    Write-Ok "Config: $ConfigDir\config.yaml"
} else {
    Write-Fatal "Registration did not create config. Cannot start service."
}

# Step 4: Auto-start setup
Write-Step 4 $TotalSteps "Setting up auto-start"

$ServiceInstalled = $false

# ── Try NSSM first (proper Windows service) ──
$nssmPath = $null
$nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
if ($nssmExe) {
    $nssmPath = $nssmExe.Source
    Write-Ok "NSSM found: $nssmPath"
} else {
    # Check if we already have a local copy from a previous install
    $localNssm = Get-ChildItem -Path $NssmDir -Recurse -Filter "nssm.exe" -ErrorAction SilentlyContinue |
        Where-Object { $_.DirectoryName -like "*win64*" } |
        Select-Object -First 1
    if ($localNssm) {
        $nssmPath = $localNssm.FullName
        Write-Ok "NSSM found (local): $nssmPath"
    } else {
        Write-Info "Downloading NSSM..."
        New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
        $zipPath = "$NssmDir\nssm.zip"

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $NssmUrl -OutFile $zipPath -UseBasicParsing -TimeoutSec 15
            Expand-Archive -Path $zipPath -DestinationPath $NssmDir -Force
            Remove-Item $zipPath

            $nssmBin = Get-ChildItem -Path $NssmDir -Recurse -Filter "nssm.exe" |
                Where-Object { $_.DirectoryName -like "*win64*" } |
                Select-Object -First 1
            if (-not $nssmBin) {
                $nssmBin = Get-ChildItem -Path $NssmDir -Recurse -Filter "nssm.exe" |
                    Select-Object -First 1
            }
            if ($nssmBin) {
                $nssmPath = $nssmBin.FullName
                Write-Ok "NSSM downloaded: $nssmPath"
            }
        } catch {
            Write-Warn "Could not download NSSM (site may be down)"
        }
    }
}

if ($nssmPath) {
    try {
        # No AppParameters needed — the exe defaults to %LOCALAPPDATA%\Orchestratia\config.yaml
        # which is exactly where we put the config. Avoids NSSM quoting issues with spaces in paths.
        & $nssmPath install $ServiceName $AgentExePath 2>&1 | Out-Null
        & $nssmPath set $ServiceName AppDirectory $ConfigDir 2>&1 | Out-Null
        & $nssmPath set $ServiceName DisplayName "Orchestratia Agent" 2>&1 | Out-Null
        & $nssmPath set $ServiceName Description "AI agent orchestration daemon" 2>&1 | Out-Null
        & $nssmPath set $ServiceName Start SERVICE_AUTO_START 2>&1 | Out-Null
        & $nssmPath set $ServiceName AppStdout "$LogDir\agent.log" 2>&1 | Out-Null
        & $nssmPath set $ServiceName AppStderr "$LogDir\agent.err" 2>&1 | Out-Null
        & $nssmPath set $ServiceName AppRotateFiles 1 2>&1 | Out-Null
        & $nssmPath set $ServiceName AppRotateBytes 10485760 2>&1 | Out-Null
        Write-Ok "Windows service installed (NSSM)"
        $ServiceInstalled = $true

        Start-Service $ServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq "Running") {
            Write-Ok "Service is running"
        } else {
            Write-Warn "Service may not be running — check: Get-Service $ServiceName"
        }
    } catch {
        Write-Fail "NSSM service setup failed: $_"
    }
}

# ── Fallback: Task Scheduler (built-in, zero dependencies) ──
if (-not $ServiceInstalled) {
    Write-Info "Falling back to Task Scheduler (built-in)..."

    $TaskName = "OrchestratiAgent"
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
            -Description "Orchestratia agent daemon" `
            -ErrorAction Stop | Out-Null

        Write-Ok "Scheduled task created (runs at logon)"
        $ServiceInstalled = $true

        Start-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($taskInfo -and $taskInfo.LastTaskResult -ne 267011) {
            Write-Ok "Agent started"
        } else {
            Write-Info "Task registered — will start at next logon"
        }
    } catch {
        Write-Fail "Could not create scheduled task: $_"
    }
}

if (-not $ServiceInstalled) {
    Write-Fail "Auto-start setup failed. Run the agent manually:"
    Write-Info "& `"$AgentExePath`" --config `"$ConfigDir\config.yaml`""
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
Write-Host "  Useful commands:" -ForegroundColor DarkGray
if ($nssmPath -and $ServiceInstalled) {
    Write-Host "    Status:   Get-Service $ServiceName"
    Write-Host "    Logs:     Get-Content $LogDir\agent.log -Wait"
    Write-Host "    Restart:  Restart-Service $ServiceName"
    Write-Host "    Stop:     Stop-Service $ServiceName"
} else {
    Write-Host "    Status:   schtasks /Query /TN OrchestratiAgent"
    Write-Host "    Logs:     Get-Content $LogDir\agent.log -Wait"
    Write-Host "    Start:    schtasks /Run /TN OrchestratiAgent"
    Write-Host "    Stop:     schtasks /End /TN OrchestratiAgent"
}
Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
Write-Host ""

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
if ($env:ORC_TOKEN) { Remove-Item Env:\ORC_TOKEN -ErrorAction SilentlyContinue }
