# PowerShell wrapper for orchestratia-agent.exe
#
# The .exe is built as a windowed subsystem (console=False) so the
# scheduled task can run the daemon invisibly. As a side-effect,
# PowerShell cannot display stdout/stderr when invoking the exe
# directly via `& exe --args` — the child has no console attached
# and PowerShell doesn't pipe its output back to the prompt.
#
# This wrapper uses `Start-Process -RedirectStandardOutput` (the same
# pattern the installer uses for its verify step) to explicitly
# redirect stdout/stderr to temp files, then prints the contents to
# the parent shell. Exit code is propagated.
#
# Resolves the .exe relative to this script's location so it works
# regardless of where the dir is in PATH.

$ErrorActionPreference = 'Stop'

$exeCandidates = @(
    (Join-Path $PSScriptRoot '..\orchestratia-agent.exe'),
    (Join-Path $PSScriptRoot 'orchestratia-agent.exe'),
    (Join-Path $env:LOCALAPPDATA 'Orchestratia\orchestratia-agent.exe')
)

$exe = $null
foreach ($candidate in $exeCandidates) {
    if (Test-Path $candidate) { $exe = (Resolve-Path $candidate).Path; break }
}

if (-not $exe) {
    Write-Error "orchestratia-agent.exe not found. Checked: $($exeCandidates -join ', ')"
    exit 127
}

$out = [IO.Path]::GetTempFileName()
$err = [IO.Path]::GetTempFileName()
$exitCode = 1
try {
    $proc = Start-Process -FilePath $exe -ArgumentList $args `
        -NoNewWindow -Wait -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $exitCode = $proc.ExitCode

    $stdout = Get-Content $out -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content $err -Raw -ErrorAction SilentlyContinue

    if ($stdout) { [Console]::Out.Write($stdout) }
    if ($stderr) { [Console]::Error.Write($stderr) }
} finally {
    Remove-Item $out, $err -Force -ErrorAction SilentlyContinue
}
exit $exitCode
