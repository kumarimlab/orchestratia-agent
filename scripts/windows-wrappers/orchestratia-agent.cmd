@echo off
REM CMD shim that hands off to the PowerShell wrapper. Lives in PATH so
REM `orchestratia-agent --version` at a PowerShell or cmd prompt
REM resolves here first (PATHEXT gives .CMD priority when dir is
REM earlier in PATH) and sees real output from the windowed-subsystem
REM exe. See orchestratia-agent.ps1 for why this wrapper exists.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0orchestratia-agent.ps1" %*
