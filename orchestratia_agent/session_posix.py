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
import time

from orchestratia_agent.session_base import SessionBackend, SessionHandle
from orchestratia_agent.tmux import discover_tmux_sessions, has_tmux

if sys.platform == "win32":
    raise ImportError("session_posix is not available on Windows")

log = logging.getLogger("orchestratia-agent")


def _run_as(handle: SessionHandle) -> str | None:
    return (handle.extra or {}).get("run_as")


def _tmux_argv(run_as: str | None, args: list[str], tmux_path: str = "tmux") -> list[str]:
    """Build a tmux argv, dropping privilege when the session belongs to another user.

    A tmux server is per-user: its socket lives in /tmp/tmux-<uid>/ and is mode
    0700. The daemon cannot reach a restricted session's tmux without sudo, so
    EVERY out-of-band call has to go through here.

    -H rather than -i: -i runs the command through a login shell, which
    re-parses argv and would corrupt any path or env value containing a space.
    """
    if run_as is None:
        return [tmux_path] + args
    return ["sudo", "-n", "-u", run_as, "-H", tmux_path] + args


def _tmux(handle: SessionHandle, args: list[str], timeout: int = 2, **kw):
    """Run a tmux command against `handle`'s session, as whoever owns it."""
    return subprocess.run(
        _tmux_argv(_run_as(handle), args),
        capture_output=True, timeout=timeout, **kw,
    )


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
        privilege_tier: str = "standard",
        tier_config=None,
    ) -> SessionHandle | None:
        from orchestratia_agent import privilege as _priv

        # Resolve the tier BEFORE forking, so a refusal is a clean "no session"
        # rather than a half-built one.
        tc = tier_config or getattr(self, "tier_config", None) or _priv.load_tier_config({})
        try:
            run_as = _priv.resolve_user(privilege_tier, tc)
            cwd = _priv.verify_workspace(privilege_tier, working_dir, tc)
        except _priv.PrivilegeError as e:
            # Fail closed. Never downgrade to standard, never fall back to $HOME:
            # either would be a privilege decision taken by an error branch.
            log.error(f"Refusing session {session_id[:8]}: {e}")
            return None

        use_tmux = has_tmux()
        if run_as is not None and not use_tmux:
            log.error(
                f"Refusing session {session_id[:8]}: tier {privilege_tier!r} "
                f"requires tmux, which is not installed"
            )
            return None
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

        if not os.path.isdir(cwd):
            if run_as is not None:
                log.error(
                    f"Refusing session {session_id[:8]}: granted workspace "
                    f"{cwd} does not exist"
                )
                return None
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
                        tmux_cmd = [
                            "tmux", "new-session", "-s", tmux_name,
                            "-x", str(cols), "-y", str(rows),
                        ]
                        # Pass env vars into tmux session via -e flags
                        # (tmux server spawns its own shell, so os.environ
                        # set above doesn't propagate — must use -e)
                        if env_vars:
                            for k, v in env_vars.items():
                                tmux_cmd.extend(["-e", f"{k}={v}"])
                        if project_id:
                            tmux_cmd.extend(["-e", f"ORCHESTRATIA_PROJECT_ID={project_id}"])
                        # Drop privilege here, in the child, so the tmux server
                        # and every process under it belong to the tier's user.
                        argv = _tmux_argv(run_as, tmux_cmd[1:], tc.tmux_path)
                        os.execvp(argv[0], argv)
                    else:
                        os.execvp(user_shell, [f"-{os.path.basename(user_shell)}"])
                except Exception as e:
                    os.write(2, f"Failed to exec: {e}\n".encode())
                    os._exit(1)
            else:
                # Parent process
                os.close(slave_fd)
                mode = f"tmux={tmux_name}" if use_tmux else "plain"
                log.info(
                    f"Spawned PTY session {session_id[:8]}: pid={pid}, cwd={cwd}, "
                    f"mode={mode}, tier={privilege_tier}, user={run_as or 'daemon'}"
                )

                handle = SessionHandle(
                    pid=pid, fd=master_fd, tmux_name=tmux_name,
                    cols=cols, rows=rows,
                    extra={"run_as": run_as, "cwd": cwd},
                )

                # Enable mouse mode so scroll wheel works in dashboards
                if use_tmux:
                    time.sleep(0.3)  # wait for tmux server to be ready
                    _tmux(handle, ["set-option", "-t", tmux_name, "mouse", "on"])
                    # OSC 52 clipboard passthrough: a mouse-drag selection
                    # (tmux copy-mode) is copied to the dashboard's system
                    # clipboard via OSC 52, not just tmux's own paste buffer.
                    _tmux(handle, ["set-option", "-t", tmux_name, "set-clipboard", "on"])
                    # Disable tmux's right-click context menu (split/select pane etc.)
                    # — it interferes with browser paste in the dashboard terminal
                    _tmux(handle, ["unbind-key", "-T", "root", "MouseDown3Pane"])

                return handle

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
        env_vars: dict[str, str] | None = None,
        run_as: str | None = None,
    ) -> SessionHandle | None:
        # A recovered restricted session must come back RESTRICTED. Resolving
        # the owner here (rather than trusting a caller) means recovery cannot
        # silently promote a session to the daemon's privilege.
        if run_as is None:
            run_as = self.owner_of(session_name)
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
                    argv = _tmux_argv(run_as, ["attach-session", "-t", session_name],
                                      self._tier_config().tmux_path)
                    os.execvp(argv[0], argv)
                except Exception as e:
                    os.write(2, f"Failed to attach tmux: {e}\n".encode())
                    os._exit(1)
            else:
                os.close(slave_fd)
                log.info(
                    f"Reattached to tmux session {session_name}: pid={pid}, "
                    f"user={run_as or 'daemon'}"
                )

                handle = SessionHandle(
                    pid=pid, fd=master_fd, tmux_name=session_name,
                    cols=cols, rows=rows, extra={"run_as": run_as},
                )

                # Ensure mouse mode is on for reattached sessions
                _tmux(handle, ["set-option", "-t", session_name, "mouse", "on"])
                # OSC 52 clipboard passthrough (see spawn path)
                _tmux(handle, ["set-option", "-t", session_name, "set-clipboard", "on"])
                # Disable tmux's right-click context menu
                _tmux(handle, ["unbind-key", "-T", "root", "MouseDown3Pane"])

                # Update env vars in recovered session (API key may have
                # changed after re-registration / reinstall).
                # tmux setenv updates the session-level env (affects new panes).
                # The CLI itself always reads config.yaml for the fresh key,
                # so stale env vars in the running shell are harmless.
                if env_vars:
                    for k, v in env_vars.items():
                        _tmux(handle, ["setenv", "-t", session_name, k, v])

                return handle
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
            _tmux(handle, ["resize-window", "-t", handle.tmux_name,
                           "-x", str(cols), "-y", str(rows)])

    def close_graceful(self, handle: SessionHandle) -> None:
        try:
            os.killpg(os.getpgid(handle.pid), signal.SIGHUP)
        except (OSError, ProcessLookupError):
            pass
        if handle.tmux_name:
            _tmux(handle, ["kill-session", "-t", handle.tmux_name])

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

    def _tier_config(self):
        from orchestratia_agent import privilege as _priv
        return getattr(self, "tier_config", None) or _priv.load_tier_config({})

    def discover_surviving_sessions(self) -> list[str]:
        """Find orphaned tmux sessions across every user we may have spawned as.

        Restricted sessions live on a DIFFERENT tmux server. Scanning only our
        own would silently abandon them on every daemon restart: the hub is
        told they died while the tmux keeps running unsupervised.
        """
        names = list(discover_tmux_sessions())
        tc = self._tier_config()
        if tc.restricted_user:
            for n in discover_tmux_sessions(run_as=tc.restricted_user):
                if n not in names:
                    names.append(n)
        return names

    def owner_of(self, session_name: str) -> str | None:
        """Which user's tmux server holds this session; None for the daemon's own."""
        if session_name in discover_tmux_sessions():
            return None
        tc = self._tier_config()
        if tc.restricted_user and session_name in discover_tmux_sessions(
                run_as=tc.restricted_user):
            return tc.restricted_user
        return None

    def supports_persistence(self) -> bool:
        return has_tmux()

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        if not handle.tmux_name:
            return None
        try:
            result = _tmux(handle, ["capture-pane", "-t", handle.tmux_name, "-p"],
                           timeout=3, text=True)
            if result.returncode != 0:
                return None
            lines = result.stdout.split("\n")
            while lines and not lines[-1].strip():
                lines.pop()
            return lines
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def is_alt_screen(self, handle: SessionHandle) -> bool:
        """True if the tmux pane is in the alternate screen (full-screen TUI).

        Lets the dashboard pick the right mobile scroll behavior: a full-screen
        TUI (e.g. newer Claude Code) owns its own scrollback and scrolls on
        PageUp, while a normal-buffer pane (shell, older inline-rendering Claude
        Code) keeps its history in the terminal scrollback instead.
        """
        if not handle.tmux_name:
            return False
        try:
            result = _tmux(handle, ["display-message", "-p", "-t", handle.tmux_name,
                                    "#{alternate_on}"], timeout=3, text=True)
            return result.returncode == 0 and result.stdout.strip() == "1"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def capture_scrollback(self, handle: SessionHandle) -> list[str] | None:
        """Capture full tmux scrollback history (from start to current cursor)."""
        if not handle.tmux_name:
            return None
        try:
            result = _tmux(handle, ["capture-pane", "-t", handle.tmux_name,
                                    "-p", "-S", "-"], timeout=5, text=True)
            if result.returncode != 0:
                return None
            lines = result.stdout.split("\n")
            while lines and not lines[-1].strip():
                lines.pop()
            return lines
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    def exit_copy_mode(self, handle: SessionHandle) -> None:
        """Exit tmux copy-mode if active (no-op if not in copy-mode)."""
        if not handle.tmux_name:
            return
        try:
            _tmux(handle, ["send-keys", "-X", "cancel", "-t", handle.tmux_name])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def send_sigwinch(self, handle: SessionHandle) -> None:
        try:
            os.killpg(os.getpgid(handle.pid), signal.SIGWINCH)
        except (OSError, ProcessLookupError):
            pass
