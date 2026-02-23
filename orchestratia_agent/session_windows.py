"""Windows session backend using pywinpty ConPTY.

Requires Windows 10 1809+ (Build 17763) for ConPTY support.
Sessions do NOT survive daemon restarts (no tmux equivalent).
"""

from __future__ import annotations

import logging
import os
import shutil
import sys

from orchestratia_agent.session_base import SessionHandle

if sys.platform != "win32":
    raise ImportError("session_windows is only available on Windows")

try:
    from winpty import PtyProcess  # type: ignore[import-untyped]
except ImportError:
    raise ImportError(
        "pywinpty is required on Windows. Install with: pip install pywinpty>=2.0.10"
    )

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
    """Session backend using pywinpty ConPTY (Windows 10 1809+)."""

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

        # Build environment
        env = os.environ.copy()
        if env_vars:
            env.update(env_vars)
        if project_id:
            env["ORCHESTRATIA_PROJECT_ID"] = project_id

        try:
            # pywinpty takes (rows, cols) — opposite of the (cols, rows) convention
            proc = PtyProcess.spawn(
                shell,
                cwd=cwd,
                dimensions=(rows, cols),
                env=env,
            )
            log.info(f"Spawned ConPTY session {session_id[:8]}: shell={shell}, cwd={cwd}")
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
    ) -> SessionHandle | None:
        # Windows has no tmux — sessions cannot be reattached
        return None

    def read_blocking(self, handle: SessionHandle) -> bytes | None:
        proc: PtyProcess = handle.pty_process
        try:
            # pywinpty read() returns str
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
        proc: PtyProcess = handle.pty_process
        try:
            text = data.decode("utf-8", errors="replace")
            # Debug: log control characters to diagnose Enter key issues
            if any(c in text for c in "\r\n"):
                log.info(f"Write (pid={handle.pid}): {repr(text)} ({len(data)} bytes, alive={proc.isalive()})")
            proc.write(text)
            # ConPTY workaround: some TUI apps (e.g. Codex CLI) don't register
            # bare \r as Enter when written via pipe. Send \n as well — apps that
            # already handled \r will treat \n as a no-op line feed, while apps
            # that need \n for Enter will pick it up.
            if text == "\r":
                log.info(f"ConPTY workaround: also writing \\n after \\r (pid={handle.pid})")
                proc.write("\n")
        except Exception as e:
            log.warning(f"Write error (pid={handle.pid}): {e}")

    def write_notification(self, handle: SessionHandle, text: str) -> None:
        proc: PtyProcess = handle.pty_process
        try:
            proc.write(text)
        except Exception:
            pass

    def resize(self, handle: SessionHandle, cols: int, rows: int) -> None:
        proc: PtyProcess = handle.pty_process
        try:
            proc.setwinsize(rows, cols)
        except Exception as e:
            log.warning(f"Resize error (pid={handle.pid}): {e}")

    def close_graceful(self, handle: SessionHandle) -> None:
        proc: PtyProcess = handle.pty_process
        try:
            # Send "exit" command to shell — Ctrl+C alone doesn't close PowerShell/cmd
            proc.write("exit\r")
        except Exception:
            pass

    def kill_force(self, handle: SessionHandle) -> None:
        proc: PtyProcess = handle.pty_process
        try:
            proc.terminate(force=True)
        except Exception:
            pass

    def is_alive(self, handle: SessionHandle) -> bool:
        proc: PtyProcess = handle.pty_process
        try:
            return proc.isalive()
        except Exception:
            return False

    def wait_exit(self, handle: SessionHandle) -> int | None:
        proc: PtyProcess = handle.pty_process
        try:
            return proc.exitstatus
        except Exception:
            return None

    def close_handle(self, handle: SessionHandle) -> None:
        # pywinpty handles cleanup internally
        pass

    def discover_surviving_sessions(self) -> list[str]:
        return []

    def supports_persistence(self) -> bool:
        return False

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        return None

    def send_sigwinch(self, handle: SessionHandle) -> None:
        # No SIGWINCH on Windows
        pass
