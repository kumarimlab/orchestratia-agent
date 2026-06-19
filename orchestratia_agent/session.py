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

# ── Output coalescing (see ManagedSession._flush_loop) ──────────────────────
# The read loop used to emit one base64+JSON `session_output` frame per PTY read.
# A high-output session (build, log tail, Claude Code spew) then produces a very
# high frame rate, and since all of a server's sessions share ONE agent→hub
# WebSocket, the per-frame json.dumps+base64+WS-framing CPU saturates the agent
# event loop — delaying both output AND input for every session on that server.
# Instead we batch PTY output into small time windows and send far fewer, larger
# frames. Interactive echo latency stays ≤ _OUTPUT_COALESCE_S (imperceptible).
_OUTPUT_COALESCE_S = 0.012            # batch window (12 ms)
_OUTPUT_MAX_FRAME = 256 * 1024        # max raw bytes per frame; b64 (~341 KB) stays < hub's 1 MB cap
_OUTPUT_HIGH_WATER = 4 * 1024 * 1024  # pause PTY reads above this → backpressure, bounds memory


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
        working_dir: str | None = None,
    ):
        self.session_id = session_id
        self.handle = handle
        self.backend = backend
        self._ws_send = ws_send
        self._on_close = on_close
        # Filesystem root for this session. Used by fs_handler to sandbox
        # editor read/write operations. Falls back to home dir on recovery
        # when the original cwd wasn't preserved through the daemon restart.
        self.working_dir: str = working_dir or ""
        self.reader_task: asyncio.Task | None = None
        self.capture_task: asyncio.Task | None = None
        self.flush_task: asyncio.Task | None = None
        self._last_screen: list[str] = []
        self.closed = False
        self._last_output_time: float = 0.0
        # Output coalescing buffer: the read loop appends here (never blocks on the
        # WS); _flush_loop drains it in batched frames. See _OUTPUT_* constants.
        self._out_buf = bytearray()
        self._out_lock = asyncio.Lock()
        self._out_event = asyncio.Event()
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
        if self.flush_task and not self.flush_task.done():
            self.flush_task.cancel()
        self.flush_task = asyncio.create_task(self._flush_loop())
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
                    # Report alternate-screen (full-screen TUI) state. The dashboard
                    # can't reliably detect it on a mid-session connect (xterm never
                    # saw the alt-screen-enter sequence), but tmux can. Drives mobile
                    # scroll: alt-screen -> PageUp to the app; normal buffer -> scroll
                    # the dashboard's own scrollback.
                    alt_fn = getattr(self.backend, "is_alt_screen", None)
                    if alt_fn is not None:
                        try:
                            alt = await loop.run_in_executor(None, alt_fn, self.handle)
                            await self._ws_send({
                                "type": "session_mode",
                                "session_id": self.session_id,
                                "alt_screen": alt,
                            })
                        except Exception:
                            pass

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

    async def _send_output_frame(self, chunk: bytes):
        """Encode + send one coalesced session_output frame."""
        await self._ws_send({
            "type": "session_output",
            "session_id": self.session_id,
            "data": base64.b64encode(chunk).decode("ascii"),
        })

    async def _flush_loop(self):
        """Drain the output buffer in batched frames.

        Blocks while idle (on _out_event), then accumulates a short window so a
        burst of PTY reads collapses into one frame. This is what bounds the
        agent's per-frame CPU under heavy output. Frames are capped at
        _OUTPUT_MAX_FRAME so a single send never exceeds the hub's size limit.
        """
        try:
            while not self.closed:
                await self._out_event.wait()
                # Let more output accumulate so we send fewer, larger frames.
                await asyncio.sleep(_OUTPUT_COALESCE_S)
                while True:
                    async with self._out_lock:
                        if not self._out_buf:
                            self._out_event.clear()
                            break
                        take = min(len(self._out_buf), _OUTPUT_MAX_FRAME)
                        chunk = bytes(self._out_buf[:take])
                        del self._out_buf[:take]
                        if not self._out_buf:
                            self._out_event.clear()
                    # Send outside the lock so the read loop can keep appending.
                    await self._send_output_frame(chunk)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            if not self.closed:
                log.error(f"Session {self.session_id[:8]} flush error: {e}")

    async def _final_flush(self):
        """Send any buffered output that hasn't been flushed yet (on close)."""
        try:
            async with self._out_lock:
                if not self._out_buf:
                    return
                pending = bytes(self._out_buf)
                self._out_buf.clear()
            for i in range(0, len(pending), _OUTPUT_MAX_FRAME):
                await self._send_output_frame(pending[i:i + _OUTPUT_MAX_FRAME])
        except Exception:
            pass

    async def _read_loop(self):
        """Read from the session and queue output for the coalescing flusher.

        Appending to the buffer never blocks on the WebSocket, so the PTY is
        drained promptly (and input handling on the shared WS isn't starved).
        Backpressure: if the buffer exceeds _OUTPUT_HIGH_WATER (producer
        outrunning the WS), pause reads until the flusher drains it — this
        restores the natural backpressure the old per-read `await ws_send` gave.
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
                        # Feed pyte first (order-preserving) for non-tmux capture.
                        if use_pyte:
                            async with self._vscreen_lock:
                                self._vscreen.feed(data)
                        async with self._out_lock:
                            self._out_buf.extend(data)
                            over = len(self._out_buf) >= _OUTPUT_HIGH_WATER
                        self._out_event.set()
                        # Backpressure: wait for the flusher to drain below the
                        # high-water mark before reading more (bounds memory).
                        while over and not self.closed:
                            await asyncio.sleep(_OUTPUT_COALESCE_S)
                            async with self._out_lock:
                                over = len(self._out_buf) >= _OUTPUT_HIGH_WATER
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
            # Stop the flusher and send any output still buffered before closing.
            if self.flush_task and not self.flush_task.done():
                self.flush_task.cancel()
            await self._final_flush()
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
