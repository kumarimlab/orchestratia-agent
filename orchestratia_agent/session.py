"""ManagedSession wraps a SessionHandle + SessionBackend.

Contains the async reader loop, capture loop, and WebSocket relay logic.
All platform-specific behavior is delegated to the SessionBackend.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import re
import sys
from typing import TYPE_CHECKING, Callable, Awaitable

from orchestratia_agent.session_base import SessionBackend, SessionHandle

if TYPE_CHECKING:
    pass

log = logging.getLogger("orchestratia-agent")

# Regex to strip ANSI escape sequences (colors, cursor movement, etc.)
_ANSI_RE = re.compile(
    r"\x1b\[[0-9;]*[A-Za-z]"    # CSI sequences: ESC[...X
    r"|\x1b\][^\x07]*\x07"       # OSC sequences: ESC]...BEL
    r"|\x1b\[[\?0-9;]*[a-z]"     # Private mode: ESC[?...x
    r"|\x1b[\(\)][AB012]"         # Character set: ESC(B etc
    r"|\x1b[=>]"                  # Keypad mode
    r"|\x0f"                      # SI (shift in)
    r"|\x1b\[[\d;]*m"             # SGR (redundant with first, but explicit)
)

# Detect screen-clear/cursor-home sequences that indicate a full redraw.
# ESC[H = cursor home, ESC[2J = erase display, ESC[1;1H = cursor to 1,1
_SCREEN_CLEAR_RE = re.compile(r"\x1b\[H|\x1b\[2J|\x1b\[1;1H")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from terminal output."""
    return _ANSI_RE.sub("", text)


def _has_screen_clear(raw: str) -> bool:
    """Check if raw output contains a screen clear/redraw sequence."""
    return bool(_SCREEN_CLEAR_RE.search(raw))


class ScreenBuffer:
    """Rolling line buffer that simulates a terminal screen.

    Maintains the last `max_lines` of output. New output is appended,
    split by newlines, and old lines are trimmed. This produces a stable
    screen snapshot similar to tmux capture-pane.
    """

    def __init__(self, max_lines: int = 50):
        self._lines: list[str] = []
        self._partial: str = ""  # Incomplete line (no trailing newline yet)
        self._max = max_lines
        self._hash: str = ""

    def clear(self) -> None:
        """Reset the buffer (called when a screen-clear sequence is detected)."""
        self._lines.clear()
        self._partial = ""

    def feed(self, raw: str) -> None:
        """Feed raw terminal output (already ANSI-stripped)."""
        text = self._partial + raw
        # Normalize \r\n to \n first, then handle bare \r (overwrites)
        text = text.replace("\r\n", "\n")
        parts = text.split("\n")
        # Last element is the partial (incomplete) line
        self._partial = parts[-1]
        # All preceding elements are complete lines
        for line in parts[:-1]:
            # Bare \r means overwrite current line (progress bars, etc.)
            if "\r" in line:
                line = line.rsplit("\r", 1)[-1]
            self._lines.append(line)

        # Trim to max
        if len(self._lines) > self._max * 2:
            self._lines = self._lines[-self._max:]

    def snapshot(self) -> tuple[list[str], str]:
        """Return (lines, hash). Hash changes only when content changes."""
        # Include partial line if non-empty
        lines = list(self._lines[-self._max:])
        if self._partial.strip():
            partial = self._partial
            if "\r" in partial:
                partial = partial.rsplit("\r", 1)[-1]
            lines.append(partial)

        # Strip trailing empty lines
        while lines and not lines[-1].strip():
            lines.pop()

        h = hashlib.md5("\n".join(lines).encode()).hexdigest()
        return lines, h

    def has_changed(self) -> bool:
        """Check if content changed since last call."""
        _, h = self.snapshot()
        if h == self._hash:
            return False
        self._hash = h
        return True


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
        # Screen buffer for synthesizing session_screen (non-tmux)
        self._screen = ScreenBuffer(max_lines=50)
        self._screen_lock = asyncio.Lock()

    @property
    def pid(self) -> int:
        return self.handle.pid

    @property
    def tmux_name(self) -> str:
        return self.handle.tmux_name

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
        Falls back to synthesizing screen lines from a rolling buffer
        (Windows, Linux without tmux) so Telegram bots still receive
        session_screen messages.
        """
        if self.capture_task and not self.capture_task.done():
            self.capture_task.cancel()
        if self.handle.tmux_name:
            self.capture_task = asyncio.create_task(self._tmux_capture_loop())
        else:
            self.capture_task = asyncio.create_task(self._synthetic_capture_loop())

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

    async def _synthetic_capture_loop(self):
        """Send screen snapshots from the rolling buffer when content changes.

        The ScreenBuffer maintains a rendered view of the last ~50 lines.
        We only send when the content hash changes, avoiding duplicate
        messages from terminal redraws (e.g., resize events).
        """
        try:
            while not self.closed:
                await asyncio.sleep(5)
                if self.closed:
                    break
                try:
                    async with self._screen_lock:
                        if not self._screen.has_changed():
                            continue
                        lines, _ = self._screen.snapshot()

                    if not lines:
                        continue

                    await self._ws_send({
                        "type": "session_screen",
                        "session_id": self.session_id,
                        "lines": lines,
                    })
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    log.debug(f"Session {self.session_id[:8]} synthetic capture error: {e}")
        except asyncio.CancelledError:
            pass

    async def _read_loop(self):
        """Read from the session and relay to the hub as base64.

        Also feeds the screen buffer for synthetic capture when
        tmux is not available.
        """
        loop = asyncio.get_event_loop()
        use_synthetic = not self.handle.tmux_name
        try:
            while not self.closed:
                try:
                    data = await loop.run_in_executor(
                        None, self.backend.read_blocking, self.handle
                    )
                    if data is None:
                        break
                    if data:
                        b64 = base64.b64encode(data).decode("ascii")
                        await self._ws_send({
                            "type": "session_output",
                            "session_id": self.session_id,
                            "data": b64,
                        })
                        # Feed screen buffer for synthetic capture (non-tmux)
                        if use_synthetic:
                            text = data.decode("utf-8", errors="replace")
                            async with self._screen_lock:
                                # Detect screen clear/redraw before stripping
                                if _has_screen_clear(text):
                                    self._screen.clear()
                                clean = _strip_ansi(text)
                                self._screen.feed(clean)
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

    def write_input(self, data: bytes):
        self.backend.write(self.handle, data)

    def resize(self, cols: int, rows: int):
        self.backend.resize(self.handle, cols, rows)

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

    def send_sigwinch(self):
        self.backend.send_sigwinch(self.handle)


def get_session_backend() -> SessionBackend:
    """Factory: return the appropriate session backend for this platform."""
    if sys.platform == "win32":
        from orchestratia_agent.session_windows import WindowsSessionBackend
        return WindowsSessionBackend()
    else:
        from orchestratia_agent.session_posix import PosixSessionBackend
        return PosixSessionBackend()
