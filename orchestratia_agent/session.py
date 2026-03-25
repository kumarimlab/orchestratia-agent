"""ManagedSession wraps a SessionHandle + SessionBackend.

Contains the async reader loop, capture loop, and WebSocket relay logic.
All platform-specific behavior is delegated to the SessionBackend.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import sys
import time
from typing import TYPE_CHECKING, Callable, Awaitable

import pyte

from orchestratia_agent.session_base import SessionBackend, SessionHandle

if TYPE_CHECKING:
    pass

log = logging.getLogger("orchestratia-agent")


class VirtualScreen:
    """Virtual terminal emulator using pyte.

    Feeds raw PTY bytes into a pyte Screen+ByteStream to maintain
    rendered terminal state. Produces clean screen snapshots identical
    to tmux capture-pane output.
    """

    def __init__(self, cols: int = 120, rows: int = 40):
        self._screen = pyte.HistoryScreen(cols, rows, history=5000)
        self._stream = pyte.ByteStream(self._screen)
        self._last_snapshot: list[str] | None = None

    def feed(self, data: bytes) -> None:
        """Feed raw PTY output bytes (with all ANSI sequences intact)."""
        self._stream.feed(data)

    def resize(self, cols: int, rows: int) -> None:
        """Resize the virtual terminal."""
        self._screen.resize(rows, cols)  # pyte takes (lines, columns)

    def snapshot(self) -> list[str] | None:
        """Return current screen lines if changed since last snapshot.

        Returns None if screen hasn't changed (same as tmux capture
        returning identical content — the capture loop skips sending).
        """
        # pyte pads each line to screen width — rstrip for clean output
        lines = [line.rstrip() for line in self._screen.display]

        # Strip trailing empty lines for cleaner output
        while lines and not lines[-1]:
            lines.pop()

        if lines == self._last_snapshot:
            return None

        self._last_snapshot = list(lines)
        return lines

    def scrollback(self) -> list[str]:
        """Return all history + current screen as plain strings."""
        lines = []
        cols = self._screen.columns
        for row in self._screen.history.top:
            chars = []
            for col in range(cols):
                c = row[col]
                chars.append(c.data if hasattr(c, 'data') else ' ')
            lines.append(''.join(chars).rstrip())
        for display_line in self._screen.display:
            lines.append(display_line.rstrip())
        # Strip trailing empty lines
        while lines and not lines[-1]:
            lines.pop()
        return lines


class ManagedSession:
    """A running session with its async reader/capture loops.

    Platform-agnostic: delegates all PTY ops to the backend.
    """

    def __init__(
        self,
        session_id: str,
        handle: SessionHandle,
        backend: SessionBackend,
        ws_send: Callable[[dict], Awaitable[bool]],
        on_close: Callable[[str], None] | None = None,
    ):
        self.session_id = session_id
        self.handle = handle
        self.backend = backend
        self._ws_send = ws_send
        self._on_close = on_close
        self.reader_task: asyncio.Task | None = None
        self.capture_task: asyncio.Task | None = None
        self._last_screen: list[str] = []
        self.closed = False
        self._last_output_time: float = 0.0
        # pyte virtual screen for non-tmux platforms (Windows, Linux without tmux)
        self._vscreen = VirtualScreen(cols=handle.cols, rows=handle.rows)
        self._vscreen_lock = asyncio.Lock()

    @property
    def pid(self) -> int:
        return self.handle.pid

    @property
    def tmux_name(self) -> str:
        return self.handle.tmux_name

    @property
    def is_idle(self) -> bool:
        """True if no output received for >5 seconds."""
        if self._last_output_time == 0.0:
            return True
        return (time.monotonic() - self._last_output_time) > 5.0

    async def start_reader(self):
        """Start (or restart) the async reader that relays PTY output via WebSocket."""
        if self.reader_task and not self.reader_task.done():
            self.reader_task.cancel()
            try:
                await self.reader_task
            except (asyncio.CancelledError, Exception):
                pass
        self.reader_task = asyncio.create_task(self._read_loop())
        self._start_capture()

    def _start_capture(self):
        """Start the capture loop.

        Uses tmux capture-pane when available (clean rendered output).
        Falls back to pyte virtual terminal (Windows, Linux without tmux)
        which provides equivalent rendered screen snapshots.
        """
        if self.capture_task and not self.capture_task.done():
            self.capture_task.cancel()
        if self.handle.tmux_name:
            self.capture_task = asyncio.create_task(self._tmux_capture_loop())
        else:
            self.capture_task = asyncio.create_task(self._pyte_capture_loop())

    async def _tmux_capture_loop(self):
        """Periodically capture tmux pane content and send diffs to the hub."""
        loop = asyncio.get_event_loop()
        try:
            while not self.closed:
                await asyncio.sleep(5)
                if self.closed:
                    break
                try:
                    lines = await loop.run_in_executor(
                        None, self.backend.capture_screen, self.handle
                    )
                    if lines is None or lines == self._last_screen:
                        continue
                    await self._ws_send({
                        "type": "session_screen",
                        "session_id": self.session_id,
                        "lines": lines,
                    })
                    self._last_screen = lines
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    log.debug(f"Session {self.session_id[:8]} capture error: {e}")
        except asyncio.CancelledError:
            pass

    async def _pyte_capture_loop(self):
        """Periodically snapshot the pyte virtual screen and send to hub.

        pyte maintains a rendered character grid identical to what tmux
        capture-pane produces. snapshot() returns None if unchanged.
        """
        try:
            while not self.closed:
                await asyncio.sleep(5)
                if self.closed:
                    break
                try:
                    async with self._vscreen_lock:
                        lines = self._vscreen.snapshot()

                    if lines is None:
                        continue

                    await self._ws_send({
                        "type": "session_screen",
                        "session_id": self.session_id,
                        "lines": lines,
                    })
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    log.debug(f"Session {self.session_id[:8]} pyte capture error: {e}")
        except asyncio.CancelledError:
            pass

    async def _read_loop(self):
        """Read from the session and relay to the hub as base64.

        Also feeds the pyte virtual screen for non-tmux capture.
        """
        loop = asyncio.get_event_loop()
        use_pyte = not self.handle.tmux_name
        try:
            while not self.closed:
                try:
                    data = await loop.run_in_executor(
                        None, self.backend.read_blocking, self.handle
                    )
                    if data is None:
                        break
                    if data:
                        self._last_output_time = time.monotonic()
                        b64 = base64.b64encode(data).decode("ascii")
                        await self._ws_send({
                            "type": "session_output",
                            "session_id": self.session_id,
                            "data": b64,
                        })
                        # Feed pyte virtual screen (non-tmux platforms)
                        if use_pyte:
                            async with self._vscreen_lock:
                                self._vscreen.feed(data)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not self.closed:
                        log.error(f"Session {self.session_id[:8]} read error: {e}")
                    break
        finally:
            exit_code = self.backend.wait_exit(self.handle)
            self.closed = True
            if self.capture_task and not self.capture_task.done():
                self.capture_task.cancel()
            self.backend.close_handle(self.handle)
            await self._ws_send({
                "type": "session_closed",
                "session_id": self.session_id,
                "exit_code": exit_code,
            })
            if self._on_close:
                self._on_close(self.session_id)
            log.info(f"Session {self.session_id[:8]} closed (exit_code={exit_code})")

    # Terminal DA responses from xterm.js that leak as visible text
    _DA_RESPONSE_RE = re.compile(rb"\x1b\[\??[\d;]*c")

    def write_input(self, data: bytes):
        # Filter out Device Attributes responses from xterm.js — they leak
        # as visible text (e.g. "1;2c0;276;0c") when tmux queries the terminal
        data = self._DA_RESPONSE_RE.sub(b"", data)
        if data:
            self.backend.write(self.handle, data)

    def resize(self, cols: int, rows: int):
        self.backend.resize(self.handle, cols, rows)
        # Keep pyte virtual screen in sync with actual terminal size
        self.handle.cols = cols
        self.handle.rows = rows
        try:
            self._vscreen.resize(cols, rows)
        except Exception:
            pass

    def close_graceful(self):
        self.backend.close_graceful(self.handle)

    def kill_force(self):
        self.backend.kill_force(self.handle)

    def is_alive(self) -> bool:
        if self.closed:
            return False
        return self.backend.is_alive(self.handle)

    def write_notification(self, text: str):
        self.backend.write_notification(self.handle, text)

    def capture_scrollback(self) -> list[str] | None:
        lines = self.backend.capture_scrollback(self.handle)
        if lines is not None:
            return lines
        # Fallback for Windows/non-tmux: use pyte history
        return self._vscreen.scrollback()

    def exit_copy_mode(self):
        """Exit tmux copy-mode if active."""
        if hasattr(self.backend, 'exit_copy_mode'):
            self.backend.exit_copy_mode(self.handle)

    def send_sigwinch(self):
        self.backend.send_sigwinch(self.handle)


def get_session_backend() -> SessionBackend:
    """Factory: return the appropriate session backend for this platform."""
    if sys.platform == "win32":
        from orchestratia_agent.pty_host_launcher import ensure_pty_host_running
        if ensure_pty_host_running():
            from orchestratia_agent.session_pty_host import PtyHostSessionBackend
            return PtyHostSessionBackend()
        log.warning("pty-host unavailable, using direct ConPTY (no persistence)")
        from orchestratia_agent.session_windows import WindowsSessionBackend
        return WindowsSessionBackend()
    else:
        from orchestratia_agent.session_posix import PosixSessionBackend
        return PosixSessionBackend()
