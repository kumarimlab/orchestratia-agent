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
from typing import TYPE_CHECKING, Callable, Awaitable

from orchestratia_agent.session_base import SessionBackend, SessionHandle

if TYPE_CHECKING:
    pass

log = logging.getLogger("orchestratia-agent")

# Regex to strip ANSI escape sequences (colors, cursor movement, etc.)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\].*?\x07|\x1b\[[\?0-9;]*[a-z]|\x1b\(B|\x1b=|\x1b>|\x0f")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from terminal output."""
    return _ANSI_RE.sub("", text)


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
        # Buffer for synthesizing session_screen from raw output (non-tmux)
        self._raw_buffer: list[str] = []
        self._raw_buffer_lock = asyncio.Lock()

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
        Falls back to synthesizing screen lines from raw output buffer
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
        """Synthesize session_screen from raw output when tmux is unavailable.

        Collects raw terminal output, strips ANSI escapes, splits into lines,
        and sends periodically. This enables Telegram bots to receive output
        on Windows and non-tmux Linux/macOS systems.
        """
        try:
            while not self.closed:
                await asyncio.sleep(5)
                if self.closed:
                    break
                try:
                    async with self._raw_buffer_lock:
                        if not self._raw_buffer:
                            continue
                        raw_text = "".join(self._raw_buffer)
                        self._raw_buffer.clear()

                    # Strip ANSI escapes and normalize line endings
                    clean = _strip_ansi(raw_text)
                    clean = clean.replace("\r\n", "\n").replace("\r", "\n")
                    lines = clean.split("\n")

                    # Strip trailing empty lines
                    while lines and not lines[-1].strip():
                        lines.pop()

                    if not lines or lines == self._last_screen:
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
                    log.debug(f"Session {self.session_id[:8]} synthetic capture error: {e}")
        except asyncio.CancelledError:
            pass

    async def _read_loop(self):
        """Read from the session and relay to the hub as base64.

        Also feeds the raw buffer for synthetic screen capture when
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
                        # Feed raw buffer for synthetic capture (non-tmux)
                        if use_synthetic:
                            text = data.decode("utf-8", errors="replace")
                            async with self._raw_buffer_lock:
                                self._raw_buffer.append(text)
                                # Cap buffer at 64KB to prevent memory growth
                                total = sum(len(s) for s in self._raw_buffer)
                                while total > 65536 and len(self._raw_buffer) > 1:
                                    removed = self._raw_buffer.pop(0)
                                    total -= len(removed)
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
