# PowerShell wrapper for orchestratia.exe (the CLI tool).
#
# Same rationale as orchestratia-agent.ps1 — the .exe is windowed
# subsystem so PowerShell's `& exe ...` doesn't show output. This
# wrapper redirects stdout/stderr through temp files so `orchestratia
# status`, `orchestratia --version`, `orchestratia task check`, and
# every other subcommand produce visible output at the prompt.

$ErrorActionPreference = 'Stop'

$exeCandidates = @(
    (Join-Path $PSScriptRoot '..\orchestratia.exe'),
    (Join-Path $PSScriptRoot 'orchestratia.exe'),
    (Join-Path $env:LOCALAPPDATA 'Orchestratia\orchestratia.exe')
)

$exe = $null
foreach ($candidate in $exeCandidates) {
    if (Test-Path $candidate) { $exe = (Resolve-Path $candidate).Path; break }
}

if (-not $exe) {
    Write-Error "orchestratia.exe not found. Checked: $($exeCandidates -join ', ')"
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
