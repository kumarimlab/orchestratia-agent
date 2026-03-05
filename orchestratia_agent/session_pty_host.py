"""Session backend that connects to a running pty-host over localhost TCP.

Implements the full SessionBackend protocol.  ``read_blocking()`` blocks on
a ``queue.Queue`` fed by a background recv loop — the caller in
``session.py`` runs it in an executor, so no changes needed to the
ManagedSession reader.

Falls back to direct ConPTY (WindowsSessionBackend) if the pty-host is
unreachable.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import queue
import shutil
import socket as socket_mod
import sys
import threading
import time
import uuid
from typing import Any

from orchestratia_agent.session_base import SessionHandle

if sys.platform != "win32":
    raise ImportError("session_pty_host is only available on Windows")

from orchestratia_agent.pty_host import PTY_HOST_ADDR, PTY_HOST_PORT

log = logging.getLogger("orchestratia-agent")


def _detect_shell() -> str:
    pwsh = shutil.which("pwsh")
    if pwsh:
        return pwsh
    powershell = shutil.which("powershell")
    if powershell:
        return powershell
    return os.environ.get("COMSPEC", "cmd.exe")


class PtyHostSessionBackend:
    """SessionBackend that delegates ConPTY ownership to pty-host."""

    def __init__(self):
        self._connected = False
        self._recv_thread: threading.Thread | None = None
        self._recv_running = False

        # Per-session output queues (fed by the recv loop)
        self._output_queues: dict[str, queue.Queue[bytes | None]] = {}

        # req_id -> (threading.Event, result_dict) for request-reply commands
        self._pending_requests: dict[str, tuple[threading.Event, dict[str, Any]]] = {}

        # Lock for socket send access from any thread
        self._send_lock = threading.Lock()
        # Plain blocking socket — NOT asyncio.  asyncio.open_connection()
        # creates a transport that starts IOCP reads on the socket,
        # competing with our recv thread's sock.recv().  On Windows this
        # causes the recv thread to miss responses, making every spawn
        # time out.
        self._raw_sock: socket_mod.socket | None = None

    async def connect(self) -> bool:
        """Connect to the pty-host TCP server. Returns True on success."""
        return self._connect_sync()

    def _connect_sync(self) -> bool:
        """Internal connect (can be called for initial connect or reconnect)."""
        # Clean up old connection if any
        if self._raw_sock:
            try:
                self._raw_sock.close()
            except OSError:
                pass
            self._raw_sock = None
        self._recv_running = False
        if self._recv_thread and self._recv_thread.is_alive():
            self._recv_thread.join(timeout=2)

        try:
            sock = socket_mod.create_connection(
                (PTY_HOST_ADDR, PTY_HOST_PORT), timeout=5,
            )
            sock.setblocking(True)
            self._raw_sock = sock
            self._connected = True
            # Start background recv thread
            self._recv_running = True
            self._recv_thread = threading.Thread(
                target=self._recv_loop, daemon=True, name="pty-host-recv",
            )
            self._recv_thread.start()
            log.info(f"Connected to pty-host at {PTY_HOST_ADDR}:{PTY_HOST_PORT}")
            # Request buffered output — pty-host no longer auto-drains on connect
            self._send_sync({"cmd": "drain"})
            return True
        except (OSError, ConnectionRefusedError) as e:
            log.warning(f"Cannot connect to pty-host: {e}")
            self._connected = False
            return False

    def _ensure_connected(self) -> bool:
        """Reconnect to pty-host if the connection was lost."""
        if self._connected:
            return True
        log.info("pty-host connection lost, attempting reconnect...")
        return self._connect_sync()

    def _recv_loop(self):
        """Background thread: read JSON-lines from pty-host and dispatch."""
        sock = self._raw_sock
        if not sock:
            return
        buf = b""
        try:
            while self._recv_running:
                try:
                    chunk = sock.recv(65536)
                except (socket_mod.timeout, BlockingIOError):
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        msg = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._handle_message(msg)
        except Exception as e:
            log.debug(f"pty-host recv loop error: {e}")
        finally:
            self._connected = False
            self._recv_running = False
            # Do NOT signal EOF to output queues here.  The TCP connection
            # dropping does NOT mean sessions are dead — they live in
            # pty-host.  read_blocking() will detect _connected=False and
            # trigger a reconnect instead of returning None (EOF).
            log.info("pty-host recv loop exited (sessions preserved in pty-host)")

    def _get_or_create_queue(self, session_id: str) -> queue.Queue:
        """Get or auto-create an output queue for a session.

        Auto-creation is essential for reconnect: when the agent connects
        to a running pty-host, buffered_output messages arrive immediately
        — before discover_surviving_sessions() / reattach() set up queues.
        Without auto-creation, that buffered data would be silently dropped.
        """
        q = self._output_queues.get(session_id)
        if q is None:
            q = queue.Queue(maxsize=4096)
            self._output_queues[session_id] = q
        return q

    def _handle_message(self, msg: dict):
        msg_type = msg.get("type", "")

        if msg_type == "output":
            sid = msg.get("session_id", "")
            q = self._get_or_create_queue(sid)
            raw = base64.b64decode(msg.get("data", ""))
            try:
                q.put_nowait(raw)
            except queue.Full:
                pass

        elif msg_type == "buffered_output":
            sid = msg.get("session_id", "")
            q = self._get_or_create_queue(sid)
            raw = base64.b64decode(msg.get("data", ""))
            if raw:
                try:
                    q.put_nowait(raw)
                except queue.Full:
                    pass

        elif msg_type == "exited":
            sid = msg.get("session_id", "")
            q = self._output_queues.get(sid)
            if q:
                try:
                    q.put_nowait(None)  # EOF
                except queue.Full:
                    pass

        elif msg_type in ("spawn_ok", "spawn_error", "sessions", "pong"):
            req_id = msg.get("req_id", "")
            pending = self._pending_requests.get(req_id)
            if pending:
                event, _ = pending
                self._pending_requests[req_id] = (event, msg)
                event.set()

    def _send_sync(self, msg: dict) -> None:
        """Send a JSON message synchronously via the raw socket."""
        if not self._raw_sock:
            return
        line = json.dumps(msg, separators=(",", ":")) + "\n"
        data = line.encode("utf-8")
        with self._send_lock:
            try:
                self._raw_sock.sendall(data)
            except OSError as e:
                log.debug(f"pty-host send error: {e}")

    def _request_sync(self, msg: dict, timeout: float = 10.0) -> dict | None:
        """Send a request and wait for the reply (blocking)."""
        req_id = msg.get("req_id", str(uuid.uuid4())[:8])
        msg["req_id"] = req_id
        event = threading.Event()
        self._pending_requests[req_id] = (event, {})
        self._send_sync(msg)
        if event.wait(timeout=timeout):
            _, result = self._pending_requests.pop(req_id, (None, {}))
            return result
        self._pending_requests.pop(req_id, None)
        return None

    # ── SessionBackend protocol ──────────────────────────────────────

    def spawn(
        self,
        session_id: str,
        working_dir: str | None,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None,
        project_id: str | None,
    ) -> SessionHandle | None:
        if not self._ensure_connected():
            return None

        shell = _detect_shell()
        cwd = working_dir or os.path.expanduser("~")
        if not os.path.isdir(cwd):
            cwd = os.path.expanduser("~")

        env = dict(env_vars or {})
        if project_id:
            env["ORCHESTRATIA_PROJECT_ID"] = project_id

        # Create output queue before spawning
        self._output_queues[session_id] = queue.Queue(maxsize=4096)

        resp = self._request_sync({
            "cmd": "spawn",
            "session_id": session_id,
            "command": shell,
            "cwd": cwd,
            "cols": cols,
            "rows": rows,
            "env": env,
        })

        if not resp or resp.get("type") != "spawn_ok":
            error = resp.get("error", "Unknown error") if resp else "No response from pty-host"
            log.error(f"pty-host spawn failed: {error}")
            self._output_queues.pop(session_id, None)
            return None

        pid = resp.get("pid", 0)
        log.info(f"Spawned via pty-host: session={session_id[:8]}, pid={pid}")
        return SessionHandle(
            pid=pid,
            fd=-1,
            pty_process=None,
            cols=cols,
            rows=rows,
            extra={"pty_host": True, "session_id": session_id},
        )

    def reattach(
        self,
        session_id: str,
        session_name: str,
        cols: int,
        rows: int,
        env_vars: dict[str, str] | None = None,
    ) -> SessionHandle | None:
        """Reattach to a surviving pty-host session."""
        if not self._connected:
            return None

        # The session already exists in pty-host — just set up the queue
        self._output_queues[session_id] = queue.Queue(maxsize=4096)

        # Resize to requested dimensions
        self._send_sync({
            "cmd": "resize",
            "session_id": session_id,
            "cols": cols,
            "rows": rows,
        })

        # We need the PID — get it from list_sessions
        resp = self._request_sync({
            "cmd": "list_sessions",
        })
        pid = 0
        if resp and resp.get("type") == "sessions":
            sessions = resp.get("sessions", {})
            info = sessions.get(session_id, {})
            pid = info.get("pid", 0)

        log.info(f"Reattached via pty-host: session={session_id[:8]}, pid={pid}")
        return SessionHandle(
            pid=pid,
            fd=-1,
            pty_process=None,
            cols=cols,
            rows=rows,
            extra={"pty_host": True, "session_id": session_id},
        )

    def read_blocking(self, handle: SessionHandle) -> bytes | None:
        """Block until output is available. Returns None on EOF.

        When the TCP connection to pty-host drops, this tries to reconnect
        (up to 3 attempts) instead of immediately returning None.  Sessions
        live in pty-host and survive agent TCP disconnects.
        """
        sid = handle.extra.get("session_id", "")
        q = self._output_queues.get(sid)
        if not q:
            return None
        try:
            data = q.get(timeout=2.0)
            return data  # None means the session actually exited (from "exited" message)
        except queue.Empty:
            if self._connected:
                return b""  # No data yet, still connected
            # TCP connection lost — try to reconnect to pty-host.
            # Sessions are still alive in pty-host, so don't return None.
            for attempt in range(3):
                log.info(f"read_blocking: reconnecting to pty-host (attempt {attempt + 1}/3)")
                if self._connect_sync():
                    # _connect_sync already sends drain command
                    return b""  # Reconnected — caller will retry read
                time.sleep(1)
            log.error("read_blocking: failed to reconnect to pty-host after 3 attempts")
            return None

    def write(self, handle: SessionHandle, data: bytes) -> None:
        sid = handle.extra.get("session_id", "")
        self._send_sync({
            "cmd": "write",
            "session_id": sid,
            "data": base64.b64encode(data).decode("ascii"),
        })

    def write_notification(self, handle: SessionHandle, text: str) -> None:
        self.write(handle, text.encode("utf-8"))

    def resize(self, handle: SessionHandle, cols: int, rows: int) -> None:
        sid = handle.extra.get("session_id", "")
        self._send_sync({
            "cmd": "resize",
            "session_id": sid,
            "cols": cols,
            "rows": rows,
        })

    def close_graceful(self, handle: SessionHandle) -> None:
        sid = handle.extra.get("session_id", "")
        self._send_sync({
            "cmd": "close_graceful",
            "session_id": sid,
        })

    def kill_force(self, handle: SessionHandle) -> None:
        sid = handle.extra.get("session_id", "")
        self._send_sync({
            "cmd": "kill_force",
            "session_id": sid,
        })

    def is_alive(self, handle: SessionHandle) -> bool:
        if not self._ensure_connected():
            return False
        # Check via list_sessions (lightweight — pty-host checks process)
        sid = handle.extra.get("session_id", "")
        resp = self._request_sync({"cmd": "list_sessions"}, timeout=3.0)
        if resp and resp.get("type") == "sessions":
            info = resp.get("sessions", {}).get(sid, {})
            return info.get("alive", False)
        return False

    def wait_exit(self, handle: SessionHandle) -> int | None:
        sid = handle.extra.get("session_id", "")
        resp = self._request_sync({"cmd": "list_sessions"}, timeout=3.0)
        if resp and resp.get("type") == "sessions":
            info = resp.get("sessions", {}).get(sid, {})
            return info.get("exit_code")
        return None

    def close_handle(self, handle: SessionHandle) -> None:
        sid = handle.extra.get("session_id", "")
        self._output_queues.pop(sid, None)

    def discover_surviving_sessions(self) -> list[str]:
        if not self._ensure_connected():
            return []
        resp = self._request_sync({"cmd": "list_sessions"}, timeout=5.0)
        if resp and resp.get("type") == "sessions":
            sessions = resp.get("sessions", {})
            return [sid for sid, info in sessions.items() if info.get("alive", False)]
        return []

    def supports_persistence(self) -> bool:
        return True

    def capture_screen(self, handle: SessionHandle) -> list[str] | None:
        # pty-host doesn't maintain a screen buffer — use pyte in ManagedSession
        return None

    def capture_scrollback(self, handle: SessionHandle) -> list[str] | None:
        return None

    def send_sigwinch(self, handle: SessionHandle) -> None:
        # Trigger a resize to the same dimensions to force redraw
        sid = handle.extra.get("session_id", "")
        self._send_sync({
            "cmd": "resize",
            "session_id": sid,
            "cols": handle.cols,
            "rows": handle.rows,
        })
