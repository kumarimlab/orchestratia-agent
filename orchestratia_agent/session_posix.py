"""POSIX session backend — Linux + macOS PTY management with optional tmux."""

from __future__ import annotations

import errno
import fcntl
import logging
import os
import pty
import signal
import struct
import subprocess
import sys
import termios

from orchestratia_agent.session_base import SessionBackend, SessionHandle
from orchestratia_agent.tmux import discover_tmux_sessions, has_tmux

if sys.platform == "win32":
    raise ImportError("session_posix is not available on Windows")

log = logging.getLogger("orchestratia-agent")


class PosixSessionBackend:
    """Session backend using fork + pty + optional tmux (Linux and macOS)."""

    def spawn(
        self,
        session_id: str,
        working_dir: str | None,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None,
        project_id: str | None,
    ) -> SessionHandle | None:
        use_tmux = has_tmux()
        tmux_name = f"orc-{session_id[:12]}" if use_tmux else ""

        # Platform-aware shell selection
        if sys.platform == "darwin":
            default_shell = "/bin/zsh"
        else:
            default_shell = "/bin/bash"
        user_shell = os.environ.get("SHELL", default_shell)
        if not os.path.isfile(user_shell):
            user_shell = default_shell
            if not os.path.isfile(user_shell):
                user_shell = "/bin/sh"

        # Resolve working directory
        cwd = working_dir or os.path.expanduser("~")
        if not os.path.isdir(cwd):
            log.warning(f"Working directory {cwd} doesn't exist, using home")
            cwd = os.path.expanduser("~")

        try:
            master_fd, slave_fd = pty.openpty()
            fcntl.ioctl(
                slave_fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", rows, cols, 0, 0),
            )

            pid = os.fork()
            if pid == 0:
                # Child process
                try:
                    os.setsid()
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                    os.dup2(slave_fd, 0)
                    os.dup2(slave_fd, 1)
                    os.dup2(slave_fd, 2)
                    os.close(master_fd)
                    os.close(slave_fd)
                    os.chdir(cwd)
                    os.environ["TERM"] = "xterm-256color"
                    os.environ["COLORTERM"] = "truecolor"

                    # Set Orchestratia env vars for the CLI tool
                    if env_vars:
                        for k, v in env_vars.items():
                            os.environ[k] = v
                    if project_id:
                        os.environ["ORCHESTRATIA_PROJECT_ID"] = project_id

                    if use_tmux:
                        os.execvp("tmux", [
                            "tmux", "new-session", "-s", tmux_name,
                            "-x", str(cols), "-y", str(rows),
                        ])
                    else:
                        os.execvp(user_shell, [f"-{os.path.basename(user_shell)}"])
                except Exception as e:
                    os.write(2, f"Failed to exec: {e}\n".encode())
                    os._exit(1)
            else:
                # Parent process
                os.close(slave_fd)
                mode = f"tmux={tmux_name}" if use_tmux else "plain"
                log.info(f"Spawned PTY session {session_id[:8]}: pid={pid}, cwd={cwd}, mode={mode}")
                return SessionHandle(pid=pid, fd=master_fd, tmux_name=tmux_name, cols=cols, rows=rows)

        except Exception as e:
            log.error(f"Failed to spawn PTY session")
            log.error(f"  OS: {sys.platform} {os.uname().release}")
            log.error(f"  Shell: {user_shell} (exists: {os.path.isfile(user_shell)})")
            log.error(f"  Working dir: {cwd} (exists: {os.path.isdir(cwd)})")
            log.error(f"  Error: {e}")
            return None

    def reattach(
        self,
        session_id: str,
        session_name: str,
        cols: int,
        rows: int,
    ) -> SessionHandle | None:
        try:
            master_fd, slave_fd = pty.openpty()
            fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

            pid = os.fork()
            if pid == 0:
                try:
                    os.setsid()
                    fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                    os.dup2(slave_fd, 0)
                    os.dup2(slave_fd, 1)
                    os.dup2(slave_fd, 2)
                    os.close(master_fd)
                    os.close(slave_fd)
                    os.environ["TERM"] = "xterm-256color"
                    os.execvp("tmux", ["tmux", "attach-session", "-t", session_name])
                except Exception as e:
                    os.write(2, f"Failed to attach tmux: {e}\n".encode())
                    os._exit(1)
            else:
                os.close(slave_fd)
                log.info(f"Reattached to tmux session {session_name}: pid={pid}")
                return SessionHandle(pid=pid, fd=master_fd, tmux_name=session_name, cols=cols, rows=rows)
        except Exception as e:
            log.error(f"Failed to reattach tmux session {session_name}: {e}")
            return None

    def read_blocking(self, handle: SessionHandle) -> bytes | None:
        try:
            data = os.read(handle.fd, 4096)
            if not data:
                return None
            return data
        except OSError as e:
            if e.errno == errno.EIO:
                return None
            raise

    def write(self, handle: SessionHandle, data: bytes) -> None:
        try:
            os.write(handle.fd, data)
        except OSError as e:
            log.warning(f"Write error (pid={handle.pid}): {e}")

    def write_notification(self, handle: SessionHandle, text: str) -> None:
        try:
            os.write(handle.fd, text.encode())
        except OSError:
            pass

    def resize(self, handle: SessionHandle, cols: int, rows: int) -> None:
        try:
            fcntl.ioctl(
                handle.fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", rows, cols, 0, 0),
            )
            os.killpg(os.getpgid(handle.pid), signal.SIGWINCH)
        except (OSError, ProcessLookupError) as e:
            log.warning(f"Resize error (pid={handle.pid}): {e}")
        if handle.tmux_name:
            subprocess.run(
                ["tmux", "resize-window", "-t", handle.tmux_name, "-x", str(cols), "-y", str(rows)],
                capture_output=True, timeout=2,
            )

    def close_graceful(self, handle: SessionHandle) -> None:
        try:
            os.killpg(os.getpgid(handle.pid), signal.SIGHUP)
        except (OSError, ProcessLookupError):
            pass
        if handle.tmux_name:
            subprocess.run(
                ["tmux", "kill-session", "-t", handle.tmux_name],
                capture_output=True, timeout=2,
            )

    def kill_force(self, handle: SessionHandle) -> None:
        try:
            os.killpg(os.getpgid(handle.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    def is_alive(self, handle: SessionHandle) -> bool:
        try:
            os.kill(handle.pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def wait_exit(self, handle: SessionHandle) -> int | None:
        try:
            _, status = os.waitpid(handle.pid, os.WNOHANG)
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return -os.WTERMSIG(status)
        except ChildProcessError:
            pass
        return None

    def close_handle(self, handle: SessionHandle) -> None:
        try:
            os.close(handle.fd)
        except OSError:
            pass

    def discover_surviving_sessions(self) -> list[str]:
        return discover_tmux_sessions()

    def supports_persistence(self) -> bool:
        return has_tmux()

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        if not handle.tmux_name:
            return None
        try:
            result = subprocess.run(
                ["tmux", "capture-pane", "-t", handle.tmux_name, "-p"],
                capture_output=True, text=True, timeout=3,
            )
            if result.returncode != 0:
                return None
            lines = result.stdout.split("\n")
            while lines and not lines[-1].strip():
                lines.pop()
            return lines
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def send_sigwinch(self, handle: SessionHandle) -> None:
        try:
            os.killpg(os.getpgid(handle.pid), signal.SIGWINCH)
        except (OSError, ProcessLookupError):
            pass
