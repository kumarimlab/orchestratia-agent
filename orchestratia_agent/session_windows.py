"""Windows session backend using native ConPTY via ctypes.

Uses the Windows Pseudo Console API directly (kernel32.dll) instead of
pywinpty, which fails in PyInstaller-bundled executables due to handle
lifecycle issues in the compiled .pyd extension.

Requires Windows 10 1809+ (Build 17763) for ConPTY support.
Sessions do NOT survive daemon restarts (no tmux equivalent).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys
import time

from orchestratia_agent.session_base import SessionHandle

if sys.platform != "win32":
    raise ImportError("session_windows is only available on Windows")

from orchestratia_agent.conpty import ConPtyProcess

log = logging.getLogger("orchestratia-agent")


def _detect_shell() -> str:
    """Detect the best available shell on Windows.

    Preference order: pwsh.exe (PowerShell 7), powershell.exe, cmd.exe
    """
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    powershell = shutil.which("powershell")
    if powershell:
        return powershell
    return os.environ.get("COMSPEC", "cmd.exe")


class WindowsSessionBackend:
    """Session backend using native ConPTY (Windows 10 1809+)."""

    def spawn(
        self,
        session_id: str,
        working_dir: str | None,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None,
        project_id: str | None,
    ) -> SessionHandle | None:
        shell = _detect_shell()

        cwd = working_dir or os.path.expanduser("~")
        if not os.path.isdir(cwd):
            log.warning(f"Working directory {cwd} doesn't exist, using home")
            cwd = os.path.expanduser("~")

        # Set custom env vars in parent process so child inherits them.
        # ConPTY child inherits the parent's environment automatically.
        if env_vars:
            for k, v in env_vars.items():
                os.environ[k] = v
        if project_id:
            os.environ["ORCHESTRATIA_PROJECT_ID"] = project_id

        try:
            proc = ConPtyProcess.spawn(shell, cwd=cwd, cols=cols, rows=rows)

            # Give the shell a moment to initialize, then verify it's alive.
            time.sleep(0.5)
            if not proc.isalive():
                exit_code = proc.exitstatus
                log.error(f"ConPTY session died immediately after spawn")
                if exit_code:
                    log.error(f"  Exit code: {exit_code} (0x{exit_code:08X})")
                else:
                    log.error(f"  Exit code: {exit_code}")
                log.error(f"  Shell: {shell}")
                log.error(f"  Working dir: {cwd}")
                log.error(f"  OS build: {sys.getwindowsversion().build}")
                proc.close()

                # Try fallback: cmd.exe (simpler, fewer DLL deps than PowerShell)
                if "powershell" in shell.lower():
                    fallback_shell = os.environ.get("COMSPEC", "cmd.exe")
                    log.info(f"Retrying with fallback shell: {fallback_shell}")
                    proc = ConPtyProcess.spawn(
                        fallback_shell, cwd=cwd, cols=cols, rows=rows
                    )
                    time.sleep(0.5)
                    if not proc.isalive():
                        exit_code2 = proc.exitstatus
                        log.error(f"Fallback shell also died: exit_code={exit_code2}")
                        proc.close()
                        return None
                    log.info(f"Fallback shell alive (PID {proc.pid})")
                else:
                    return None

            log.info(
                f"Spawned ConPTY session {session_id[:8]}: "
                f"shell={shell}, cwd={cwd}, pid={proc.pid}"
            )
            return SessionHandle(
                pid=proc.pid,
                fd=-1,
                pty_process=proc,
                cols=cols,
                rows=rows,
            )
        except Exception as e:
            log.error(f"Failed to spawn ConPTY session")
            log.error(f"  OS: Windows {sys.getwindowsversion().build}")
            log.error(f"  Shell: {shell}")
            log.error(f"  Working dir: {cwd} (exists: {os.path.isdir(cwd)})")
            log.error(f"  Error: {e}")
            if sys.getwindowsversion().build < 17763:
                log.error("  ConPTY requires Windows 10 build 17763+ (version 1809)")
            return None

    def reattach(
        self,
        session_id: str,
        session_name: str,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None = None,
    ) -> SessionHandle | None:
        # Windows has no tmux — sessions cannot be reattached
        return None

    def read_blocking(self, handle: SessionHandle) -> bytes | None:
        proc: ConPtyProcess = handle.pty_process
        try:
            data = proc.read(4096)
            if not data:
                return None
            return data.encode("utf-8", errors="replace")
        except EOFError:
            return None
        except Exception as e:
            if not proc.isalive():
                return None
            raise

    def write(self, handle: SessionHandle, data: bytes) -> None:
        proc: ConPtyProcess = handle.pty_process
        try:
            text = data.decode("utf-8", errors="replace")
            proc.write(text)
        except Exception as e:
            log.warning(f"Write error (pid={handle.pid}): {e}")

    def write_notification(self, handle: SessionHandle, text: str) -> None:
        proc: ConPtyProcess = handle.pty_process
        try:
            proc.write(text)
        except Exception:
            pass

    def resize(self, handle: SessionHandle, cols: int, rows: int) -> None:
        proc: ConPtyProcess = handle.pty_process
        try:
            proc.setwinsize(rows, cols)
        except Exception as e:
            log.warning(f"Resize error (pid={handle.pid}): {e}")

    def close_graceful(self, handle: SessionHandle) -> None:
        proc: ConPtyProcess = handle.pty_process
        try:
            proc.write("exit\r")
        except Exception:
            pass

    def kill_force(self, handle: SessionHandle) -> None:
        proc: ConPtyProcess = handle.pty_process
        try:
            proc.terminate(force=True)
        except Exception:
            pass

    def is_alive(self, handle: SessionHandle) -> bool:
        proc: ConPtyProcess = handle.pty_process
        try:
            return proc.isalive()
        except Exception:
            return False

    def wait_exit(self, handle: SessionHandle) -> int | None:
        proc: ConPtyProcess = handle.pty_process
        try:
            return proc.exitstatus
        except Exception:
            return None

    def close_handle(self, handle: SessionHandle) -> None:
        proc: ConPtyProcess = handle.pty_process
        if proc:
            proc.close()

    def discover_surviving_sessions(self) -> list[str]:
        return []

    def supports_persistence(self) -> bool:
        return False

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        return None

    def capture_scrollback(self, handle: SessionHandle) -> list[str] | None:
        return None

    def send_sigwinch(self, handle: SessionHandle) -> None:
        pass
