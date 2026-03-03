"""PTY Host — long-lived process that owns ConPTY sessions on Windows.

Exposes sessions over localhost TCP so the agent can disconnect/reconnect
freely (same pattern as tmux on Linux). Runs as a background process
launched by the agent, or directly via ``--pty-host`` / ``python -m
orchestratia_agent.pty_host``.

Protocol: newline-delimited JSON over a single TCP connection on
127.0.0.1:19199.  Session data is base64-encoded (matches the hub
WebSocket protocol).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

if sys.platform != "win32":
    raise ImportError("pty_host is only available on Windows")

from orchestratia_agent.conpty import ConPtyProcess

log = logging.getLogger("orchestratia-pty-host")

PTY_HOST_PORT = 19199
PTY_HOST_ADDR = "127.0.0.1"
RING_BUFFER_SIZE = 256 * 1024  # 256 KB per session
IDLE_SHUTDOWN_SECS = 30 * 60  # 30 minutes with no sessions and no client

# Where PID file lives: %LOCALAPPDATA%\Orchestratia\pty-host.pid
_DATA_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
    "Orchestratia",
)


def pid_file_path() -> str:
    return os.path.join(_DATA_DIR, "pty-host.pid")


# ── Ring Buffer ──────────────────────────────────────────────────────

class RingBuffer:
    """Fixed-size circular byte buffer.  Old data silently overwritten."""

    def __init__(self, capacity: int = RING_BUFFER_SIZE):
        self._buf = bytearray(capacity)
        self._cap = capacity
        self._write_pos = 0  # next write offset (mod capacity)
        self._readable = 0   # how many valid bytes are in the buffer
        self._total_dropped = 0

    def write(self, data: bytes) -> None:
        n = len(data)
        if n == 0:
            return
        if n >= self._cap:
            # Data larger than buffer — keep only the tail
            self._total_dropped += n - self._cap + self._readable
            self._buf[:] = data[-self._cap:]
            self._write_pos = 0
            self._readable = self._cap
            return
        overflow = max(0, self._readable + n - self._cap)
        if overflow:
            self._total_dropped += overflow
            self._readable -= overflow
        end = self._write_pos + n
        if end <= self._cap:
            self._buf[self._write_pos:end] = data
        else:
            first = self._cap - self._write_pos
            self._buf[self._write_pos:self._cap] = data[:first]
            self._buf[:n - first] = data[first:]
        self._write_pos = end % self._cap
        self._readable += n

    def drain(self) -> tuple[bytes, int]:
        """Return (buffered_data, bytes_dropped) and clear the buffer."""
        if self._readable == 0:
            dropped = self._total_dropped
            self._total_dropped = 0
            return b"", dropped
        start = (self._write_pos - self._readable) % self._cap
        if start + self._readable <= self._cap:
            data = bytes(self._buf[start:start + self._readable])
        else:
            first = self._cap - start
            data = bytes(self._buf[start:self._cap]) + bytes(self._buf[:self._readable - first])
        dropped = self._total_dropped
        self._readable = 0
        self._total_dropped = 0
        return data, dropped


# ── Hosted Session ───────────────────────────────────────────────────

@dataclass
class HostedSession:
    """A ConPTY session owned by the pty-host."""
    session_id: str
    proc: ConPtyProcess
    ring: RingBuffer = field(default_factory=RingBuffer)
    cols: int = 120
    rows: int = 40
    cwd: str = ""
    created_at: float = field(default_factory=time.time)
    exit_code: int | None = None
    reader_task: asyncio.Task | None = None

    @property
    def alive(self) -> bool:
        if self.exit_code is not None:
            return False
        return self.proc.isalive()

    @property
    def pid(self) -> int:
        return self.proc.pid


# ── PTY Host Server ─────────────────────────────────────────────────

class PtyHost:
    """TCP server that owns ConPTY sessions and multiplexes I/O."""

    def __init__(self):
        self.sessions: dict[str, HostedSession] = {}
        self._writer: asyncio.StreamWriter | None = None
        self._writer_lock = asyncio.Lock()
        self._executor = ThreadPoolExecutor(max_workers=8)
        self._server: asyncio.Server | None = None
        self._running = True
        self._last_activity = time.monotonic()

    async def start(self):
        os.makedirs(_DATA_DIR, exist_ok=True)
        self._server = await asyncio.start_server(
            self._handle_client, PTY_HOST_ADDR, PTY_HOST_PORT,
        )
        # Write PID file
        with open(pid_file_path(), "w") as f:
            f.write(str(os.getpid()))
        log.info(f"PTY Host listening on {PTY_HOST_ADDR}:{PTY_HOST_PORT} (PID {os.getpid()})")

    async def run_forever(self):
        await self.start()
        try:
            while self._running:
                await asyncio.sleep(5)
                # Idle shutdown check
                if not self.sessions and self._writer is None:
                    idle = time.monotonic() - self._last_activity
                    if idle > IDLE_SHUTDOWN_SECS:
                        log.info(f"No sessions and no client for {IDLE_SHUTDOWN_SECS}s, shutting down")
                        break
        finally:
            await self.shutdown()

    async def shutdown(self):
        self._running = False
        # Close all sessions
        for hs in list(self.sessions.values()):
            if hs.reader_task:
                hs.reader_task.cancel()
            try:
                hs.proc.terminate(force=True)
            except Exception:
                pass
            hs.proc.close()
        self.sessions.clear()
        # Close server
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Remove PID file
        try:
            os.remove(pid_file_path())
        except OSError:
            pass
        self._executor.shutdown(wait=False)
        log.info("PTY Host shut down")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a new TCP client.  One client at a time — new replaces old."""
        addr = writer.get_extra_info("peername")
        log.info(f"Client connected from {addr}")
        self._last_activity = time.monotonic()

        # Replace previous client
        old_writer = self._writer
        async with self._writer_lock:
            self._writer = writer
        if old_writer:
            try:
                old_writer.close()
                await old_writer.wait_closed()
            except Exception:
                pass

        # Send buffered output for all alive sessions
        for hs in self.sessions.values():
            if hs.alive or hs.ring._readable > 0:
                data, dropped = hs.ring.drain()
                if data:
                    await self._send({
                        "type": "buffered_output",
                        "session_id": hs.session_id,
                        "data": base64.b64encode(data).decode("ascii"),
                        "bytes_dropped": dropped,
                    })
            # Also report exited sessions
            if not hs.alive and hs.exit_code is not None:
                await self._send({
                    "type": "exited",
                    "session_id": hs.session_id,
                    "exit_code": hs.exit_code,
                })

        # Read loop
        try:
            while self._running:
                line = await reader.readline()
                if not line:
                    break
                self._last_activity = time.monotonic()
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue
                await self._dispatch(msg)
        except (asyncio.CancelledError, ConnectionError):
            pass
        finally:
            log.info(f"Client disconnected from {addr}")
            async with self._writer_lock:
                if self._writer is writer:
                    self._writer = None
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, msg: dict):
        cmd = msg.get("cmd", "")

        if cmd == "spawn":
            await self._cmd_spawn(msg)
        elif cmd == "write":
            self._cmd_write(msg)
        elif cmd == "resize":
            self._cmd_resize(msg)
        elif cmd == "close_graceful":
            self._cmd_close_graceful(msg)
        elif cmd == "kill_force":
            self._cmd_kill_force(msg)
        elif cmd == "list_sessions":
            await self._cmd_list_sessions(msg)
        elif cmd == "ping":
            await self._send({"type": "pong"})

    async def _cmd_spawn(self, msg: dict):
        req_id = msg.get("req_id", "")
        session_id = msg.get("session_id", "")
        command = msg.get("command", "pwsh.exe")
        cwd = msg.get("cwd")
        cols = msg.get("cols", 120)
        rows = msg.get("rows", 40)
        env_vars = msg.get("env")

        # Set env vars in parent so child inherits
        if env_vars and isinstance(env_vars, dict):
            for k, v in env_vars.items():
                os.environ[k] = str(v)

        try:
            proc = ConPtyProcess.spawn(command, cwd=cwd, cols=cols, rows=rows)
            # Brief check that it didn't die immediately
            await asyncio.sleep(0.3)
            if not proc.isalive():
                exit_code = proc.exitstatus
                proc.close()
                await self._send({
                    "type": "spawn_error",
                    "req_id": req_id,
                    "session_id": session_id,
                    "error": f"Process exited immediately (code={exit_code})",
                })
                return

            hs = HostedSession(
                session_id=session_id,
                proc=proc,
                cols=cols,
                rows=rows,
                cwd=cwd or "",
            )
            self.sessions[session_id] = hs
            hs.reader_task = asyncio.create_task(self._session_reader(hs))

            await self._send({
                "type": "spawn_ok",
                "req_id": req_id,
                "session_id": session_id,
                "pid": proc.pid,
            })
            log.info(f"Spawned session {session_id[:8]}: pid={proc.pid}, cmd={command}")
        except Exception as e:
            await self._send({
                "type": "spawn_error",
                "req_id": req_id,
                "session_id": session_id,
                "error": str(e),
            })
            log.error(f"Failed to spawn session {session_id[:8]}: {e}")

    def _cmd_write(self, msg: dict):
        session_id = msg.get("session_id", "")
        hs = self.sessions.get(session_id)
        if hs and hs.alive:
            try:
                raw = base64.b64decode(msg.get("data", ""))
                hs.proc.write(raw)
            except Exception as e:
                log.debug(f"Write error for {session_id[:8]}: {e}")

    def _cmd_resize(self, msg: dict):
        session_id = msg.get("session_id", "")
        cols = msg.get("cols", 120)
        rows = msg.get("rows", 40)
        hs = self.sessions.get(session_id)
        if hs and hs.alive:
            try:
                hs.proc.setwinsize(rows, cols)
                hs.cols = cols
                hs.rows = rows
            except Exception as e:
                log.debug(f"Resize error for {session_id[:8]}: {e}")

    def _cmd_close_graceful(self, msg: dict):
        session_id = msg.get("session_id", "")
        hs = self.sessions.get(session_id)
        if hs and hs.alive:
            try:
                hs.proc.write("exit\r")
            except Exception:
                pass

    def _cmd_kill_force(self, msg: dict):
        session_id = msg.get("session_id", "")
        hs = self.sessions.get(session_id)
        if hs:
            try:
                hs.proc.terminate(force=True)
            except Exception:
                pass

    async def _cmd_list_sessions(self, msg: dict):
        req_id = msg.get("req_id", "")
        result = {}
        for sid, hs in self.sessions.items():
            result[sid] = {
                "pid": hs.pid,
                "alive": hs.alive,
                "cols": hs.cols,
                "rows": hs.rows,
                "cwd": hs.cwd,
                "created_at": hs.created_at,
                "exit_code": hs.exit_code,
            }
        await self._send({
            "type": "sessions",
            "req_id": req_id,
            "sessions": result,
        })

    async def _session_reader(self, hs: HostedSession):
        """Read ConPTY output in a thread and relay to client or ring buffer."""
        loop = asyncio.get_event_loop()
        try:
            while self._running and hs.alive:
                try:
                    data_str = await loop.run_in_executor(
                        self._executor, hs.proc.read, 4096,
                    )
                    if not data_str:
                        break
                    raw = data_str.encode("utf-8", errors="replace")
                except EOFError:
                    break
                except Exception as e:
                    if hs.alive:
                        log.debug(f"Reader error for {hs.session_id[:8]}: {e}")
                    break

                # Send to client or buffer
                async with self._writer_lock:
                    has_client = self._writer is not None
                if has_client:
                    await self._send({
                        "type": "output",
                        "session_id": hs.session_id,
                        "data": base64.b64encode(raw).decode("ascii"),
                    })
                else:
                    hs.ring.write(raw)
        finally:
            # Session exited
            hs.exit_code = hs.proc.exitstatus
            log.info(f"Session {hs.session_id[:8]} exited (code={hs.exit_code})")
            await self._send({
                "type": "exited",
                "session_id": hs.session_id,
                "exit_code": hs.exit_code,
            })
            # Clean up dead sessions after a while (keep for list_sessions)

    async def _send(self, msg: dict):
        """Send a JSON-lines message to the connected client."""
        async with self._writer_lock:
            writer = self._writer
        if not writer:
            return
        try:
            line = json.dumps(msg, separators=(",", ":")) + "\n"
            writer.write(line.encode("utf-8"))
            await writer.drain()
        except (ConnectionError, OSError):
            pass


# ── Entry point ──────────────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    host = PtyHost()

    def handle_signal(sig, frame):
        log.info("Shutdown signal received")
        host._running = False

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGBREAK, handle_signal)

    asyncio.run(host.run_forever())


if __name__ == "__main__":
    main()
