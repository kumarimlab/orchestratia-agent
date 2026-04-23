@echo off
REM CMD shim that hands off to the PowerShell wrapper. Lives in PATH so
REM `orchestratia status` at a PowerShell or cmd prompt resolves here
REM first and sees real output from the windowed-subsystem exe.
REM See orchestratia.ps1 for why this wrapper exists.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0orchestratia.ps1" %*
