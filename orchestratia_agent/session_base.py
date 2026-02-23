"""Session backend protocol and shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


@dataclass
class SessionHandle:
    """Opaque handle returned by a SessionBackend after spawning."""
    pid: int
    fd: int = -1                  # master fd (POSIX) or -1 (Windows)
    tmux_name: str = ""           # tmux session name, empty if not using tmux
    pty_process: object = None    # pywinpty PtyProcess (Windows only)
    cols: int = 120               # terminal width for pyte virtual screen
    rows: int = 40                # terminal height for pyte virtual screen
    extra: dict = field(default_factory=dict)


@runtime_checkable
class SessionBackend(Protocol):
    """Platform-specific session lifecycle management.

    Implementations:
    - PosixSessionBackend (Linux + macOS): fork + pty + tmux
    - WindowsSessionBackend (Windows): pywinpty ConPTY
    """

    def spawn(
        self,
        session_id: str,
        working_dir: str | None,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None,
        project_id: str | None,
    ) -> SessionHandle | None:
        """Spawn a new interactive session. Returns handle or None on failure."""
        ...

    def reattach(
        self,
        session_id: str,
        session_name: str,
        cols: int,
        rows: int,
    ) -> SessionHandle | None:
        """Reattach to a surviving session (e.g., tmux). Returns None if unsupported."""
        ...

    def read_blocking(self, handle: SessionHandle) -> bytes | None:
        """Blocking read from the session PTY. Returns None on EOF. Run in executor."""
        ...

    def write(self, handle: SessionHandle, data: bytes) -> None:
        """Write input data to the session PTY."""
        ...

    def write_notification(self, handle: SessionHandle, text: str) -> None:
        """Write a notification string directly to the PTY output (visible to user)."""
        ...

    def resize(self, handle: SessionHandle, cols: int, rows: int) -> None:
        """Resize the terminal."""
        ...

    def close_graceful(self, handle: SessionHandle) -> None:
        """Gracefully close the session (SIGHUP on POSIX, Ctrl+C on Windows)."""
        ...

    def kill_force(self, handle: SessionHandle) -> None:
        """Forcefully kill the session (SIGKILL on POSIX, TerminateProcess on Windows)."""
        ...

    def is_alive(self, handle: SessionHandle) -> bool:
        """Check if the session process is still running."""
        ...

    def wait_exit(self, handle: SessionHandle) -> int | None:
        """Non-blocking check for exit code. Returns None if still running."""
        ...

    def close_handle(self, handle: SessionHandle) -> None:
        """Release resources (close fds, etc.)."""
        ...

    def discover_surviving_sessions(self) -> list[str]:
        """Find sessions that survived a daemon restart (e.g., tmux sessions)."""
        ...

    def supports_persistence(self) -> bool:
        """Whether sessions survive daemon restarts."""
        ...

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        """Capture the current screen content (tmux capture-pane). None if unsupported."""
        ...

    def send_sigwinch(self, handle: SessionHandle) -> None:
        """Send SIGWINCH to trigger terminal redraw. No-op on platforms that don't support it."""
        ...
