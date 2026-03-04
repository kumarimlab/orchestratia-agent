"""Auto-launch the pty-host background process on Windows.

``ensure_pty_host_running()`` checks for a live pty-host via PID file
and TCP probe, launching one if needed.  Returns True if pty-host is
available, False otherwise (caller should fall back to direct ConPTY).
"""

from __future__ import annotations

import logging
import os
import socket
import subprocess
import sys
import time

if sys.platform != "win32":
    raise ImportError("pty_host_launcher is only available on Windows")

from orchestratia_agent.pty_host import PTY_HOST_ADDR, PTY_HOST_PORT, pid_file_path

log = logging.getLogger("orchestratia-agent")

# Windows process creation flags
DETACHED_PROCESS = 0x00000008
CREATE_NO_WINDOW = 0x08000000


def _process_alive(pid: int) -> bool:
    """Check if a process with the given PID exists."""
    import ctypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        kernel32.CloseHandle(handle)
        return True
    return False


def _tcp_probe() -> bool:
    """Try to connect to the pty-host TCP port."""
    try:
        with socket.create_connection((PTY_HOST_ADDR, PTY_HOST_PORT), timeout=2):
            return True
    except (OSError, ConnectionRefusedError):
        return False


def _health_check() -> bool:
    """Connect, send ping, verify pong response.

    More reliable than a bare TCP probe — confirms the pty-host is
    actually processing commands, not just accepting connections.
    """
    try:
        with socket.create_connection((PTY_HOST_ADDR, PTY_HOST_PORT), timeout=3) as s:
            s.sendall(b'{"cmd":"ping"}\n')
            s.settimeout(3)
            data = s.recv(4096)
            return b'"pong"' in data
    except (OSError, ConnectionRefusedError, socket.timeout):
        return False


def _read_pid_file() -> int | None:
    """Read PID from the pid file. Returns None if missing or invalid."""
    path = pid_file_path()
    try:
        with open(path, "r") as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _kill_pid(pid: int) -> None:
    """Terminate a process by PID using Win32 API."""
    import ctypes

    PROCESS_TERMINATE = 0x0001
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if handle:
        kernel32.TerminateProcess(handle, 1)
        kernel32.CloseHandle(handle)
        log.info(f"Killed stale pty-host (PID {pid})")


def _kill_stale_pty_host() -> None:
    """Kill any process identified by the PID file and clean up."""
    pid = _read_pid_file()
    if pid and _process_alive(pid):
        _kill_pid(pid)
        time.sleep(1)
    try:
        os.remove(pid_file_path())
    except OSError:
        pass


def _launch_pty_host() -> bool:
    """Launch pty-host as a detached background process."""
    if getattr(sys, "frozen", False):
        # Running as PyInstaller exe — launch self with --pty-host flag
        exe = sys.executable
        args = [exe, "--pty-host"]
    else:
        # Development mode — use python -m
        args = [sys.executable, "-m", "orchestratia_agent.pty_host"]

    log.info(f"Launching pty-host: {' '.join(args)}")
    try:
        subprocess.Popen(
            args,
            creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
            close_fds=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception as e:
        log.error(f"Failed to launch pty-host: {e}")
        return False


def ensure_pty_host_running() -> bool:
    """Ensure the pty-host process is running and reachable.

    1. Check PID file -> verify process alive -> health check
    2. If not running, launch it and wait up to 5s for availability
    3. If launch fails (port conflict), kill stale process and retry
    4. Return True if pty-host is available, False to fall back
    """
    # Step 1: Check if already running via PID file
    pid = _read_pid_file()
    if pid and _process_alive(pid):
        if _health_check():
            log.info(f"pty-host already running (PID {pid})")
            return True
        # Process alive but not responding — give it a moment
        log.info(f"pty-host process alive (PID {pid}) but not responding, waiting...")
        for _ in range(10):
            time.sleep(0.5)
            if _health_check():
                log.info(f"pty-host became healthy")
                return True
        log.warning(f"pty-host process alive but unhealthy after 5s, killing")
        _kill_stale_pty_host()

    # Step 1b: No PID file, but pty-host might still be running
    if _health_check():
        log.info("pty-host already running (detected via health check, no PID file)")
        return True

    # Step 2: Clean up stale PID file
    if pid and not _process_alive(pid):
        try:
            os.remove(pid_file_path())
        except OSError:
            pass

    # Step 3: Launch pty-host
    if not _launch_pty_host():
        return False

    # Step 4: Wait for health check to pass (up to 5s)
    for _ in range(10):
        time.sleep(0.5)
        if _health_check():
            new_pid = _read_pid_file()
            log.info(f"pty-host started (PID {new_pid})")
            return True

    # Step 5: Launch failed — likely port conflict with stale pty-host
    log.warning("pty-host not responding, killing stale process and retrying")
    _kill_stale_pty_host()
    time.sleep(1)

    if not _launch_pty_host():
        return False

    for _ in range(10):
        time.sleep(0.5)
        if _health_check():
            new_pid = _read_pid_file()
            log.info(f"pty-host started on retry (PID {new_pid})")
            return True

    log.warning("pty-host unavailable after retry")
    return False
