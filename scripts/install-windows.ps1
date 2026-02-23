# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Windows (pip + NSSM service)
#
# Installs the agent daemon via pip and registers with the hub.
#
# Usage (run as Administrator):
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 <TOKEN>
#
# What this does:
#   1. Checks prerequisites (Python 3.10+)
#   2. Installs orchestratia-agent via pip (includes pywinpty)
#   3. Registers with the hub
#   4. Installs NSSM and creates a Windows service
# ──────────────────────────────────────────────────────────────────────

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Token
)

$ErrorActionPreference = "Stop"

# ── Constants ────────────────────────────────────────────────────────

$ServiceName = "OrchestratiAgent"
$ConfigDir = "$env:LOCALAPPDATA\Orchestratia"
$LogDir = "$env:LOCALAPPDATA\Orchestratia\logs"
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NssmDir = "$env:LOCALAPPDATA\Orchestratia\nssm"
$Errors = 0

$InstallSource = if ($env:ORCHESTRATIA_INSTALL_SOURCE) { $env:ORCHESTRATIA_INSTALL_SOURCE } else { "orchestratia-agent" }

# ── Helper functions ─────────────────────────────────────────────────

function Write-Header {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor White
    Write-Host "║      Orchestratia Agent Installer (Windows)      ║" -ForegroundColor White
    Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor White
    Write-Host ""
}

function Write-Step($Num, $Total, $Title) {
    Write-Host ""
    Write-Host "[$Num/$Total] " -ForegroundColor Blue -NoNewline
    Write-Host $Title -ForegroundColor White
}

function Write-Ok($Msg) {
    Write-Host "     ✓ " -ForegroundColor Green -NoNewline
    Write-Host $Msg
}

function Write-Warn($Msg) {
    Write-Host "     ! " -ForegroundColor Yellow -NoNewline
    Write-Host $Msg -ForegroundColor Yellow
    $script:Errors++
}

function Write-Fail($Msg) {
    Write-Host "     ✗ " -ForegroundColor Red -NoNewline
    Write-Host $Msg -ForegroundColor Red
    $script:Errors++
}

function Write-Info($Msg) {
    Write-Host "     → " -ForegroundColor Cyan -NoNewline
    Write-Host $Msg
}

function Write-Fatal($Msg) {
    Write-Host ""
    Write-Host "  ✗ FATAL: $Msg" -ForegroundColor Red
    Write-Host "     Installation aborted." -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}

$TotalSteps = 5

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
    # Try NSSM remove, fall back to sc.exe
    $nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
    if ($nssmExe) {
        & nssm remove $ServiceName confirm 2>$null
    } else {
        sc.exe delete $ServiceName 2>$null
    }
    Write-Ok "Removed existing service"
}

# Uninstall pip package
$pipShow = pip show orchestratia-agent 2>$null
if ($pipShow) {
    $existing = $true
    pip uninstall -y orchestratia-agent 2>$null
    Write-Ok "Uninstalled pip package"
}

if (-not $existing) { Write-Ok "No existing installation found" }

# Step 2: Prerequisites
Write-Step 2 $TotalSteps "Checking prerequisites"

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $pythonCmd) {
    Write-Fatal "Python not found. Download from https://www.python.org/downloads/"
}

$pyVer = & $pythonCmd.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pyMinor = & $pythonCmd.Source -c "import sys; print(sys.version_info.minor)"
if ([int]$pyMinor -ge 10) {
    Write-Ok "Python $pyVer"
} else {
    Write-Fatal "Python 3.10+ required, found $pyVer"
}

$pipCmd = Get-Command pip -ErrorAction SilentlyContinue
if (-not $pipCmd) {
    $pipCmd = Get-Command pip3 -ErrorAction SilentlyContinue
}
if ($pipCmd) {
    Write-Ok "pip available"
} else {
    Write-Fatal "pip not found. Reinstall Python with 'Add to PATH' checked."
}

# Check Windows version for ConPTY
$build = [System.Environment]::OSVersion.Version.Build
if ($build -ge 17763) {
    Write-Ok "Windows build $build (ConPTY supported)"
} else {
    Write-Warn "Windows build $build — ConPTY requires build 17763+ (Windows 10 1809)"
}

$claudeCmd = Get-Command claude -ErrorAction SilentlyContinue
if ($claudeCmd) {
    Write-Ok "Claude Code CLI found"
} else {
    Write-Warn "Claude Code CLI not found"
    Write-Info "Install: npm install -g @anthropic-ai/claude-code"
}

# Step 3: Install package
Write-Step 3 $TotalSteps "Installing orchestratia-agent"

Write-Info "Installing via pip (includes pywinpty)..."
try {
    & $pipCmd.Source install -q $InstallSource 2>&1 | Out-Null
    Write-Ok "Package installed"
} catch {
    Write-Fail "pip install failed: $_"
    Write-Fatal "Cannot proceed without the agent package."
}

$agentBin = Get-Command orchestratia-agent -ErrorAction SilentlyContinue
if ($agentBin) {
    Write-Ok "Binary: $($agentBin.Source)"
} else {
    Write-Fail "orchestratia-agent not found in PATH"
    Write-Info "You may need to add Python Scripts to PATH"
}

# Step 4: Register
Write-Step 4 $TotalSteps "Registering with Orchestratia hub"

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Write-Info "Using one-time registration token..."
try {
    $regOutput = & orchestratia-agent --register $Token --config "$ConfigDir\config.yaml" 2>&1
    Write-Ok "Registered successfully"
    $regOutput | ForEach-Object {
        if ($_ -match "api.key|orc_|registered|saved") {
            Write-Info $_
        }
    }
} catch {
    Write-Fail "Registration failed: $_"
}

# Step 5: NSSM service
Write-Step 5 $TotalSteps "Setting up Windows service (NSSM)"

# Download NSSM if not present
$nssmExe = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssmExe) {
    Write-Info "Downloading NSSM..."
    New-Item -ItemType Directory -Force -Path $NssmDir | Out-Null
    $zipPath = "$NssmDir\nssm.zip"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $NssmUrl -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $NssmDir -Force
        Remove-Item $zipPath

        # Find the 64-bit binary
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
        } else {
            Write-Fatal "Could not find nssm.exe after extraction"
        }
    } catch {
        Write-Fail "Could not download NSSM: $_"
        Write-Info "Download manually from https://nssm.cc and place nssm.exe in PATH"
        Write-Fatal "Cannot create service without NSSM"
    }
} else {
    $nssmPath = $nssmExe.Source
    Write-Ok "NSSM found: $nssmPath"
}

$agentExe = (Get-Command orchestratia-agent -ErrorAction SilentlyContinue).Source
if (-not $agentExe) {
    Write-Fatal "Cannot find orchestratia-agent binary for service"
}

try {
    & $nssmPath install $ServiceName $agentExe "--config" "$ConfigDir\config.yaml" 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppDirectory $ConfigDir 2>&1 | Out-Null
    & $nssmPath set $ServiceName DisplayName "Orchestratia Agent" 2>&1 | Out-Null
    & $nssmPath set $ServiceName Description "AI agent orchestration daemon" 2>&1 | Out-Null
    & $nssmPath set $ServiceName Start SERVICE_AUTO_START 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppStdout "$LogDir\agent.log" 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppStderr "$LogDir\agent.err" 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppRotateFiles 1 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppRotateBytes 10485760 2>&1 | Out-Null
    & $nssmPath set $ServiceName AppEnvironmentExtra "PYTHONUNBUFFERED=1" 2>&1 | Out-Null
    Write-Ok "Service installed"
} catch {
    Write-Fail "Could not install service: $_"
}

try {
    Start-Service $ServiceName
    Write-Ok "Service started"
} catch {
    Write-Fail "Could not start service: $_"
    Write-Info "Start manually: Start-Service $ServiceName"
}

Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Ok "Service is running"
} else {
    Write-Warn "Service may not be running"
    Write-Info "Check: Get-Service $ServiceName"
}

# ── Summary ──────────────────────────────────────────────────────────

Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
if ($Errors -eq 0) {
    Write-Host "  ✓ Installation complete — no errors" -ForegroundColor Green
} else {
    Write-Host "  ! Installation finished with $Errors warning(s)" -ForegroundColor Yellow
}
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor DarkGray
Write-Host "    Status:   Get-Service $ServiceName"
Write-Host "    Logs:     Get-Content $LogDir\agent.log -Wait"
Write-Host "    Restart:  Restart-Service $ServiceName"
Write-Host "    Stop:     Stop-Service $ServiceName"
Write-Host ""
Write-Host "──────────────────────────────────────────────────" -ForegroundColor White
Write-Host ""
