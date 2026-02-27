# ──────────────────────────────────────────────────────────────────────
# Orchestratia Agent Installer — Windows (pip + NSSM service)
#
# Installs the agent daemon via pip and registers with the hub.
#
# Usage — one-liner (paste into PowerShell as Administrator):
#   $env:ORC_TOKEN='orcreg_...'; irm https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1 | iex
#
# Or download and run directly:
#   powershell -ExecutionPolicy Bypass -File install-windows.ps1 <TOKEN>
#
# What this does:
#   1. Checks prerequisites (Python 3.10+)
#   2. Installs orchestratia-agent via pip (includes pywinpty)
#   3. Registers with the hub
#   4. Installs NSSM and creates a Windows service
# ──────────────────────────────────────────────────────────────────────

# Support both: direct invocation with argument AND piped via irm|iex with env var
# param() blocks break when piped, so we use $args + $env:ORC_TOKEN fallback
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

$ErrorActionPreference = "Stop"

# ── Logging ──────────────────────────────────────────────────────────
# Log everything to a file so we can debug crashes
$InstallLog = "$env:LOCALAPPDATA\Orchestratia\install.log"
New-Item -ItemType Directory -Force -Path "$env:LOCALAPPDATA\Orchestratia" | Out-Null
Start-Transcript -Path $InstallLog -Force | Out-Null
trap {
    Write-Host ""
    Write-Host "  ✗ UNEXPECTED ERROR: $_" -ForegroundColor Red
    Write-Host "  Log saved to: $InstallLog" -ForegroundColor Yellow
    Write-Host ""
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
}

# ── Constants ────────────────────────────────────────────────────────

$ServiceName = "OrchestratiAgent"
$ConfigDir = "$env:LOCALAPPDATA\Orchestratia"
$LogDir = "$env:LOCALAPPDATA\Orchestratia\logs"
$NssmUrl = "https://nssm.cc/release/nssm-2.24.zip"
$NssmDir = "$env:LOCALAPPDATA\Orchestratia\nssm"
$Errors = 0

$InstallSource = if ($env:ORCHESTRATIA_INSTALL_SOURCE) {
    $env:ORCHESTRATIA_INSTALL_SOURCE
} else {
    "git+https://github.com/kumarimlab/orchestratia-agent.git"
}

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

# ── Resolve Python & pip ─────────────────────────────────────────────
# On Windows, 'pip' is often not in PATH even when Python is installed.
# The Python Launcher 'py' is more reliable. We resolve once and reuse.
# IMPORTANT: Windows ships a 'python.exe' stub that opens the Microsoft
# Store instead of running Python. We must verify the candidate actually
# executes before accepting it.

function Test-RealPython {
    param([string]$Candidate)
    try {
        # Temporarily allow errors — the MS Store stub writes to stderr which
        # becomes a terminating error under $ErrorActionPreference = "Stop"
        $prevPref = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        $out = & $Candidate -c "print('ok')" 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        return ($code -eq 0 -and "$out" -match 'ok')
    } catch {
        $ErrorActionPreference = $prevPref
        return $false
    }
}

function Find-Python {
    # Prefer 'py' launcher (always in PATH on standard Python installs)
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py -and (Test-RealPython $py.Source)) { return $py.Source }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python -and (Test-RealPython $python.Source)) { return $python.Source }

    $python3 = Get-Command python3 -ErrorAction SilentlyContinue
    if ($python3 -and (Test-RealPython $python3.Source)) { return $python3.Source }

    return $null
}

function Install-Python {
    # Try winget first (built into Windows 10 1709+ / Windows 11)
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Info "Installing Python 3.12 via winget (this may take a minute)..."
        try {
            $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
            & winget install Python.Python.3.12 --source winget --accept-package-agreements --accept-source-agreements 2>&1 | ForEach-Object { Write-Host "     $_" -ForegroundColor DarkGray }
            $wingetExit = $LASTEXITCODE
            $ErrorActionPreference = $prevPref
        } catch {
            $ErrorActionPreference = $prevPref
            $wingetExit = 1
        }
        # winget returns 0 on success, -1978335189 (0x8A150011) if already installed
        if ($wingetExit -eq 0 -or $wingetExit -eq -1978335189) {
            # Refresh PATH for this session
            $machPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
            $env:PATH = "$machPath;$userPath"
            $found = Find-Python
            if ($found) {
                Write-Ok "Python installed successfully"
                return $found
            }
        }
        Write-Fail "winget install completed but Python still not found in PATH"
        Write-Info "You may need to close and reopen PowerShell, then re-run this installer"
        return $null
    }

    # No winget — give manual instructions
    return $null
}

function Find-Pip {
    param([string]$PythonExe)

    # First try: python -m pip (most reliable, doesn't need pip in PATH)
    try {
        $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        $out = & $PythonExe -m pip --version 2>&1
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        if ($code -eq 0) { return @($PythonExe, "-m", "pip") }
    } catch { $ErrorActionPreference = $prevPref }

    # Fallback: bare pip/pip3 commands
    $pip = Get-Command pip -ErrorAction SilentlyContinue
    if ($pip) { return @($pip.Source) }

    $pip3 = Get-Command pip3 -ErrorAction SilentlyContinue
    if ($pip3) { return @($pip3.Source) }

    return $null
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

# Uninstall pip package (resolve python early just for cleanup)
$PythonExe = Find-Python
if ($PythonExe) {
    try {
        $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        $pipCheck = & $PythonExe -m pip show orchestratia-agent 2>$null
        $ErrorActionPreference = $prevPref
        if ($pipCheck) {
            $existing = $true
            & $PythonExe -m pip uninstall -y orchestratia-agent 2>$null
            Write-Ok "Uninstalled pip package"
        }
    } catch { $ErrorActionPreference = $prevPref }
}

if (-not $existing) { Write-Ok "No existing installation found" }

# Step 2: Prerequisites
Write-Step 2 $TotalSteps "Checking prerequisites"

if (-not $PythonExe) {
    Write-Warn "Python not found"
    Write-Host ""
    Write-Host "     Python 3.10+ is required. Install it now?" -ForegroundColor White
    Write-Host ""
    $choice = Read-Host "     [Y] Install via winget  [N] Abort  (Y/n)"
    if ($choice -eq '' -or $choice -match '^[Yy]') {
        $PythonExe = Install-Python
        if (-not $PythonExe) {
            Write-Fatal "Python installation failed. Install manually from https://www.python.org/downloads/ (check 'Add to PATH') then re-run this installer."
        }
    } else {
        Write-Fatal "Python is required. Install from https://www.python.org/downloads/ (check 'Add to PATH') then re-run."
    }
}

$pyVer = & $PythonExe -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$pyMinor = & $PythonExe -c "import sys; print(sys.version_info.minor)"
if ([int]$pyMinor -ge 10) {
    Write-Ok "Python $pyVer ($PythonExe)"
} else {
    Write-Fatal "Python 3.10+ required, found $pyVer"
}

$PipCmd = Find-Pip -PythonExe $PythonExe
if ($PipCmd) {
    Write-Ok "pip available ($(($PipCmd -join ' ')))"
} else {
    Write-Fatal "pip not found. Run: $PythonExe -m ensurepip --upgrade"
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
    & $PipCmd[0] $PipCmd[1..$PipCmd.Length] install -q $InstallSource 2>&1 | Out-Null
    Write-Ok "Package installed"
} catch {
    Write-Fail "pip install failed: $_"
    Write-Fatal "Cannot proceed without the agent package."
}

# Verify the binary is reachable
$agentBin = Get-Command orchestratia-agent -ErrorAction SilentlyContinue
if ($agentBin) {
    Write-Ok "Binary: $($agentBin.Source)"
} else {
    # Try refreshing PATH for the current session
    $scriptsDir = & $PythonExe -c "import sysconfig; print(sysconfig.get_path('scripts'))"
    if ($scriptsDir -and (Test-Path "$scriptsDir\orchestratia-agent.exe")) {
        $env:PATH = "$scriptsDir;$env:PATH"
        Write-Ok "Binary: $scriptsDir\orchestratia-agent.exe"
        Write-Info "Added $scriptsDir to PATH for this session"
    } else {
        Write-Fail "orchestratia-agent not found in PATH"
        Write-Info "You may need to add Python Scripts to PATH"
    }
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

# Verify config was created
if (Test-Path "$ConfigDir\config.yaml") {
    Write-Ok "Config: $ConfigDir\config.yaml"
} else {
    Write-Fatal "Registration did not create $ConfigDir\config.yaml. Cannot start service without config."
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

# Clean up
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
if ($env:ORC_TOKEN) { Remove-Item Env:\ORC_TOKEN -ErrorAction SilentlyContinue }
