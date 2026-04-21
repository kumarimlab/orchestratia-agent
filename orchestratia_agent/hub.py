"""Hub communication — HTTP registration, heartbeats, and WebSocket messaging."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import platform
import ssl
import subprocess
import sys
import uuid
from typing import TYPE_CHECKING

import httpx
import websockets

from orchestratia_agent.config import persist_api_key
from orchestratia_agent.session import ManagedSession, get_session_backend
from orchestratia_agent.session_base import SessionBackend
from orchestratia_agent.system import get_repos_info, get_system_info

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent")


def get_machine_id() -> str:
    """Get a stable OS-level machine identifier.

    - Linux: /etc/machine-id (32 hex chars, unique per OS install)
    - macOS: IOPlatformUUID from IORegistry
    - Windows: MachineGuid from registry
    - Fallback: empty string (will always create a new server record)
    """
    if sys.platform == "linux":
        try:
            return open("/etc/machine-id").read().strip()
        except OSError:
            return ""
    elif sys.platform == "darwin":
        try:
            out = subprocess.check_output(
                ["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                text=True, timeout=5,
            )
            for line in out.splitlines():
                if "IOPlatformUUID" in line:
                    # Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-..."
                    return line.split("=", 1)[1].strip().strip('"')
        except Exception:
            pass
        return ""
    elif sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            value, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            return value
        except Exception:
            return ""
    return ""


def get_mac_address() -> str:
    """Get the primary MAC address as colon-separated hex."""
    node = uuid.getnode()
    return ":".join(f"{(node >> (8 * i)) & 0xFF:02x}" for i in reversed(range(6)))


async def ws_send(state: DaemonState, msg: dict) -> bool:
    """Send a message on the current WebSocket, silently dropping if disconnected."""
    ws = state.ws_connection
    if ws and not getattr(ws, "close_code", None):
        try:
            await ws.send(json.dumps(msg))
            return True
        except Exception:
            return False
    return False


async def register_with_hub(
    client: httpx.AsyncClient,
    state: DaemonState,
) -> str | None:
    """Register this server with the hub. Returns API key or None."""
    if state.config.get("api_key"):
        state.api_key = state.config["api_key"]
        log.info(f"Using configured API key: {state.api_key[:8]}...")
        return state.api_key

    reg_token = state.config.get("registration_token", "")
    if not reg_token:
        log.error(
            "No api_key and no registration_token in config. "
            "Get a registration token from the Orchestratia dashboard: "
            "Servers -> Register Server"
        )
        return None

    try:
        payload = {
            "name": state.config.get("server_name", platform.node()),
            "hostname": platform.node(),
            "ip": "0.0.0.0",
            "os": platform.system().lower(),
            "repos": get_repos_info(state.config),
            "system_info": get_system_info(),
            "registration_token": reg_token,
            "machine_id": get_machine_id(),
            "mac_address": get_mac_address(),
        }

        resp = await client.post(
            f"{state.hub_url}/api/v1/servers/register",
            json=payload,
        )
        if resp.status_code == 401:
            detail = resp.json().get("detail", "Unknown error")
            log.error(f"Failed to register with hub at {state.hub_url}/api/v1/servers/register")
            log.error(f"  HTTP 401: {detail}")
            log.error(f"  Remediation:")
            log.error(f"    1. Check hub_url in config.yaml")
            log.error(f"    2. Verify network: curl -k {state.hub_url}/api/v1/health")
            log.error(f"    3. Ensure the registration token hasn't expired or been used")
            return None
        resp.raise_for_status()
        data = resp.json()
        state.api_key = data["api_key"]
        server_id = data.get("id")
        log.info(f"Registered with hub. Server ID: {server_id}, Key: {state.api_key[:8]}...")

        if state.config_path:
            persist_api_key(state.config_path, state.api_key)
        else:
            log.warning(f"SAVE THIS API KEY to your config.yaml: {state.api_key}")

        return state.api_key
    except httpx.HTTPStatusError as e:
        log.error(f"Failed to register with hub at {state.hub_url}/api/v1/servers/register")
        log.error(f"  HTTP {e.response.status_code}: {e.response.text[:200]}")
        return None
    except httpx.HTTPError as e:
        log.error(f"Failed to register with hub at {state.hub_url}/api/v1/servers/register")
        log.error(f"  Error: {e}")
        log.error(f"  Remediation:")
        log.error(f"    1. Check hub_url in config.yaml")
        log.error(f"    2. Verify network: curl -k {state.hub_url}/api/v1/health")
        return None


async def send_heartbeat(client: httpx.AsyncClient, state: DaemonState) -> bool:
    """Send a heartbeat with system stats to the hub."""
    try:
        resp = await client.post(
            f"{state.hub_url}/api/v1/servers/heartbeat",
            json={"system_info": get_system_info()},
            headers={"X-API-Key": state.api_key},
        )
        resp.raise_for_status()
        return True
    except httpx.HTTPError as e:
        log.warning(f"Heartbeat failed: {e}")
        return False


async def connect_ws(state: DaemonState):
    """Connect to the hub's agent WebSocket."""
    ws_url = state.hub_url.replace("https://", "wss://").replace("http://", "ws://")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    target = f"{ws_url}/ws/server"
    log.debug(f"WebSocket connecting to {target}")

    try:
        ws = await websockets.connect(
            target,
            ssl=ssl_ctx if ws_url.startswith("wss") else None,
            ping_interval=30,
            ping_timeout=10,
            max_size=2**20,
        )
        await ws.send(json.dumps({"type": "auth", "api_key": state.api_key}))
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        if resp.get("type") == "auth_ok":
            log.info("WebSocket connected and authenticated")
            return ws
        else:
            log.error(f"WebSocket auth failed: {resp}")
            await ws.close()
            return None
    except Exception as e:
        log.warning(f"WebSocket connect failed to {target}")
        log.warning(f"  Error: {e.__class__.__name__}: {e}")
        log.debug(f"  SSL verify: disabled, event loop: {type(asyncio.get_event_loop()).__name__}")
        return None


async def heartbeat_loop(client: httpx.AsyncClient, state: DaemonState):
    """Send heartbeats every 30 seconds."""
    while state.running:
        await send_heartbeat(client, state)
        # Sleep in 1s increments so we can exit promptly
        for _ in range(30):
            if not state.running:
                return
            await asyncio.sleep(1)


def _upload_dest_dir() -> "Path":
    """Return the per-OS directory for browser-initiated uploads.

    Uses tempfile.gettempdir() so we get the right root on every OS:
    - Linux: /tmp
    - macOS: /var/folders/... (user-scoped)
    - Windows: C:\\Users\\<user>\\AppData\\Local\\Temp
    """
    import tempfile
    from pathlib import Path
    return Path(tempfile.gettempdir()) / "orchestratia-uploads"


async def _process_pending_upload(
    client: httpx.AsyncClient, state: DaemonState, item: dict
) -> None:
    """Download one queued upload to local disk and ack back to the hub."""
    import hashlib
    from pathlib import Path

    upload_id = item.get("upload_id")
    filename = item.get("filename") or "file"
    download_url = item.get("download_url") or ""
    expected_sha = item.get("sha256")

    if not upload_id or not download_url:
        return

    # Always compute dest locally — never trust hub's hint (hub sends a
    # /tmp/... path that doesn't exist on Windows).
    dest = _upload_dest_dir() / filename
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        await _ack_upload(client, state, upload_id, success=False, error=f"mkdir failed: {e}")
        return

    url = download_url
    if url.startswith("/"):
        url = f"{state.hub_url}{url}"

    try:
        sha = hashlib.sha256()
        size = 0
        tmp_path = dest.with_suffix(dest.suffix + ".part")
        async with client.stream("GET", url, headers={"X-API-Key": state.api_key}) as resp:
            resp.raise_for_status()
            with open(tmp_path, "wb") as f:
                async for chunk in resp.aiter_bytes(64 * 1024):
                    f.write(chunk)
                    sha.update(chunk)
                    size += len(chunk)

        if expected_sha and sha.hexdigest() != expected_sha:
            tmp_path.unlink(missing_ok=True)
            await _ack_upload(client, state, upload_id, success=False, error="sha256 mismatch")
            return

        tmp_path.replace(dest)
        log.info(f"Direct upload delivered: {filename} ({size} B) → {dest}")
        await _ack_upload(client, state, upload_id, success=True, path=str(dest))

    except httpx.HTTPError as e:
        await _ack_upload(client, state, upload_id, success=False, error=f"download failed: {e}")
    except OSError as e:
        await _ack_upload(client, state, upload_id, success=False, error=f"write failed: {e}")


async def _ack_upload(
    client: httpx.AsyncClient,
    state: DaemonState,
    upload_id: str,
    success: bool,
    path: str | None = None,
    error: str | None = None,
) -> None:
    try:
        body: dict = {"success": success}
        if path:
            body["path"] = path
        if error:
            body["error"] = error
        resp = await client.post(
            f"{state.hub_url}/api/v1/server/files/{upload_id}/ack",
            json=body,
            headers={"X-API-Key": state.api_key},
        )
        resp.raise_for_status()
    except httpx.HTTPError as e:
        log.warning(f"Ack failed for upload {upload_id[:8]}: {e}")


async def pending_uploads_loop(client: httpx.AsyncClient, state: DaemonState):
    """Poll the hub for pending direct uploads and download them to disk.

    Uses a 3s interval — fast enough for responsive UX, slow enough that
    load stays trivial. Each iteration fetches the pending list and
    processes entries serially (preserves order, avoids concurrent writes
    to the same destination).
    """
    url = f"{state.hub_url}/api/v1/server/files/pending"
    headers = {"X-API-Key": state.api_key}

    while state.running:
        try:
            resp = await client.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                items = resp.json() or []
                for item in items:
                    if not state.running:
                        return
                    await _process_pending_upload(client, state, item)
        except httpx.HTTPError as e:
            log.debug(f"pending_uploads poll failed: {e}")
        except Exception as e:
            log.warning(f"pending_uploads loop error: {e}")

        # Sleep in 1s increments so we can exit promptly
        for _ in range(3):
            if not state.running:
                return
            await asyncio.sleep(1)


def _get_tmux_name(session: "ManagedSession") -> str | None:
    """Extract tmux session name from a ManagedSession."""
    tmux_name = getattr(session.handle, "tmux_name", None) if hasattr(session, "handle") else None
    if not tmux_name:
        tmux_name = getattr(session, "tmux_name", None)
    return tmux_name


def _inject_text(session: "ManagedSession", text: str, send_enter: bool = True):
    """Inject text into a session reliably.

    For tmux: uses send-keys -l (literal) for the text, then a separate
    send-keys Enter command. This prevents special character interpretation.
    For non-tmux: uses direct PTY write with \\r (not \\n).
    """
    import subprocess

    tmux_name = _get_tmux_name(session)

    if tmux_name and sys.platform != "win32":
        try:
            # Send text literally (no key interpretation)
            subprocess.run(
                ["tmux", "send-keys", "-t", tmux_name, "-l", text],
                capture_output=True, timeout=5,
            )
            if send_enter:
                # Send Enter separately (as a named key, not literal)
                subprocess.run(
                    ["tmux", "send-keys", "-t", tmux_name, "Enter"],
                    capture_output=True, timeout=5,
                )
            log.debug(f"Injected text via tmux send-keys -l to {tmux_name}")
        except Exception as e:
            log.warning(f"tmux send-keys failed ({e}), falling back to PTY write")
            data = text.encode()
            if send_enter:
                data += b"\r"
            session.write_input(data)
    else:
        # Fallback: direct PTY write — use \r not \n
        data = text.encode()
        if send_enter:
            data += b"\r"
        session.write_input(data)


def _inject_escape(session: "ManagedSession"):
    """Send Escape key to a session."""
    import subprocess

    tmux_name = _get_tmux_name(session)

    if tmux_name and sys.platform != "win32":
        try:
            subprocess.run(
                ["tmux", "send-keys", "-t", tmux_name, "Escape"],
                capture_output=True, timeout=5,
            )
        except Exception as e:
            log.warning(f"tmux Escape failed ({e}), falling back to PTY write")
            session.write_input(b"\x1b")
    else:
        session.write_input(b"\x1b")


def _inject_task_trigger(state: "DaemonState", session: "ManagedSession", task_id: str):
    """Inject a user prompt into the session to trigger task pickup."""
    message = (
        "A new task has been assigned to you via Orchestratia. "
        "Please run `orchestratia task check` to see the details "
        "and begin working on it."
    )
    _inject_text(session, message, send_enter=True)
    log.info(f"Injected task trigger for task #{task_id[:8]}")


async def ws_receive_loop(ws, state: DaemonState):
    """Receive messages from hub and dispatch to session handlers."""
    backend = state.backend

    def _make_ws_sender(st: DaemonState):
        async def sender(msg: dict) -> bool:
            return await ws_send(st, msg)
        return sender

    def _on_session_close(session_id: str):
        state.active_sessions.pop(session_id, None)

    sender = _make_ws_sender(state)

    try:
        while state.running:
            raw = await ws.recv()
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "session_start":
                session_id = msg.get("session_id")
                working_dir = msg.get("working_directory")
                cols = msg.get("cols", 120)
                rows = msg.get("rows", 40)
                project_id = msg.get("project_id")
                log.info(f"Hub requests session start: {session_id[:8]}")

                try:
                    env_vars = {
                        "ORCHESTRATIA_HUB_URL": state.hub_url,
                        "ORCHESTRATIA_API_KEY": state.api_key,
                        "ORCHESTRATIA_SESSION_ID": session_id,
                    }

                    handle = backend.spawn(
                        session_id, working_dir, cols, rows,
                        env_vars=env_vars, project_id=project_id,
                    )
                    if handle:
                        session = ManagedSession(
                            session_id, handle, backend, sender,
                            on_close=_on_session_close,
                        )
                        state.active_sessions[session_id] = session
                        await session.start_reader()
                        await ws_send(state, {
                            "type": "session_started",
                            "session_id": session_id,
                            "pid": handle.pid,
                            "tmux_name": handle.tmux_name or "",
                        })
                    else:
                        await ws_send(state, {
                            "type": "session_error",
                            "session_id": session_id,
                            "error": "Failed to spawn session",
                        })
                except Exception as e:
                    log.error(f"Session spawn crashed for {session_id[:8]}: {e}", exc_info=True)
                    await ws_send(state, {
                        "type": "session_error",
                        "session_id": session_id,
                        "error": f"Spawn exception: {e}",
                    })

            elif msg_type == "session_input":
                session_id = msg.get("session_id")
                b64_data = msg.get("data", "")
                session = state.active_sessions.get(session_id)
                if session and not session.closed and b64_data:
                    raw_bytes = base64.b64decode(b64_data)
                    log.debug(f"session_input: session={session_id[:8]}, bytes={repr(raw_bytes)}, closed={session.closed}")
                    session.write_input(raw_bytes)
                elif not session:
                    log.warning(f"session_input: session {session_id[:8]} not found in active_sessions")
                elif session.closed:
                    log.warning(f"session_input: session {session_id[:8]} is closed")

            elif msg_type == "session_resize":
                session_id = msg.get("session_id")
                cols = msg.get("cols", 120)
                rows = msg.get("rows", 40)
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    session.resize(cols, rows)

            elif msg_type == "session_close":
                session_id = msg.get("session_id")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    log.info(f"Graceful close requested for session {session_id[:8]}")
                    session.close_graceful()

            elif msg_type == "session_kill":
                session_id = msg.get("session_id")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    log.info(f"Force kill requested for session {session_id[:8]}")
                    session.kill_force()

            elif msg_type == "session_recovered_ack":
                # Hub tells us the real UUID for an orphaned tmux session.
                # Re-key active_sessions so hub→daemon messages (session_input etc.) work.
                tmux_name = msg.get("tmux_name", "")
                real_id = msg.get("session_id", "")
                if tmux_name and real_id and tmux_name in state.active_sessions:
                    session = state.active_sessions.pop(tmux_name)
                    session.session_id = real_id
                    state.active_sessions[real_id] = session
                    log.info(f"Re-keyed orphaned session {tmux_name} → {real_id[:8]}")
                    # Now that the session has a real UUID, start the reader
                    # so output is tagged with the correct session_id.
                    if session.reader_task is None or session.reader_task.done():
                        await session.start_reader()
                        session.send_sigwinch()
                        log.info(f"Started reader for recovered session {real_id[:8]}")

            elif msg_type == "session_exit_copy_mode":
                session_id = msg.get("session_id")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    session.exit_copy_mode()

            elif msg_type == "capture_scrollback":
                session_id = msg.get("session_id")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    lines = session.capture_scrollback()
                    if lines is not None:
                        await ws_send(state, {
                            "type": "scrollback_captured",
                            "session_id": session_id,
                            "lines": lines,
                        })
                    else:
                        await ws_send(state, {
                            "type": "scrollback_captured",
                            "session_id": session_id,
                            "lines": [],
                            "error": "Could not capture scrollback",
                        })

            elif msg_type == "task_assigned":
                target_session_id = msg.get("session_id")
                task_id = msg.get("task_id", "")
                title = msg.get("title", "")
                from_name = msg.get("from_session_name", "Unknown")
                priority = msg.get("priority", "normal")
                pending_approval = msg.get("pending_approval", False)
                require_plan = msg.get("require_plan", False)

                session = state.active_sessions.get(target_session_id)
                if session and not session.closed:
                    if pending_approval:
                        # Show notification only — wait for admin approval
                        notification = (
                            f"\r\n\033[38;2;212;114;47m"
                            f"\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\r\n"
                            f"\u2551  ORCHESTRATIA: Task pending approval                 \u2551\r\n"
                            f"\u2551  #{task_id[:8]}: \"{title[:40]}\"                     \r\n"
                            f"\u2551  Waiting for admin to approve before starting...      \r\n"
                            f"\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
                            f"\033[0m\r\n"
                        )
                        session.write_notification(notification)
                        log.info(f"Task #{task_id[:8]} pending approval, notification shown in session {target_session_id[:8]}")
                    elif require_plan:
                        # Plan mode: tell the worker to analyze before executing
                        message = (
                            "A new task has been assigned to you via Orchestratia in PLAN MODE. "
                            "You must analyze the task and submit a plan before executing. "
                            "Please run `orchestratia task check` to see the details."
                        )
                        _inject_text(session, message, send_enter=True)
                        log.info(f"Task #{task_id[:8]} assigned in plan mode to session {target_session_id[:8]}")
                    else:
                        # Auto-trigger: inject user message into Claude session
                        _inject_task_trigger(state, session, task_id)
                        log.info(f"Auto-triggered task #{task_id[:8]} in session {target_session_id[:8]}")

            elif msg_type == "task_approved":
                session_id = msg.get("session_id")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    _inject_task_trigger(state, session, task_id)
                    log.info(f"Task #{task_id[:8]} approved, triggered in session {session_id[:8]}")

            elif msg_type == "task_rejected":
                session_id = msg.get("session_id")  # orchestrator's session
                reason = msg.get("reason", "No reason given")
                title = msg.get("title", "Unknown")
                session = state.active_sessions.get(session_id)
                if session and not session.closed:
                    notification = (
                        f"\r\n\033[38;2;220;50;50m"
                        f"\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557\r\n"
                        f"\u2551  ORCHESTRATIA: Task rejected by admin                 \u2551\r\n"
                        f"\u2551  \"{title[:45]}\"                                       \r\n"
                        f"\u2551  Reason: {reason[:40]}                                \r\n"
                        f"\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d"
                        f"\033[0m\r\n"
                    )
                    session.write_notification(notification)
                    log.info(f"Task '{title}' rejected, notification sent to session {session_id[:8]}")

            elif msg_type == "intervention_response":
                session_id = msg.get("session_id")
                response = msg.get("response", "")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    _inject_text(session, response, send_enter=True)
                    log.info(f"Injected intervention response into session {session_id[:8]}")

            elif msg_type == "task_note":
                session_id = msg.get("session_id")
                content = msg.get("content", "")
                urgent = msg.get("urgent", False)
                author = msg.get("author", "")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    if urgent:
                        # Urgent: Esc + delay + inject
                        async def _urgent_note(s, c, a):
                            _inject_escape(s)
                            await asyncio.sleep(2)
                            message = f"URGENT NOTE from {a}: {c}"
                            _inject_text(s, message, send_enter=True)
                        asyncio.create_task(_urgent_note(session, content, author))
                        log.info(f"Urgent note injected into session {session_id[:8]}")
                    else:
                        # Non-urgent: queue for idle delivery
                        pending = state.pending_notes.setdefault(session_id, [])
                        pending.append({"content": content, "author": author})
                        log.info(f"Non-urgent note queued for session {session_id[:8]}")

            elif msg_type == "task_updated":
                session_id = msg.get("session_id")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    async def _task_update_inject(s):
                        _inject_escape(s)
                        await asyncio.sleep(2)
                        message = (
                            "The task spec has been updated by the orchestrator. "
                            "Please run `orchestratia task check` to see the latest details."
                        )
                        _inject_text(s, message, send_enter=True)
                    asyncio.create_task(_task_update_inject(session))
                    log.info(f"Task update notification injected into session {session_id[:8]}")

            elif msg_type == "plan_approved":
                session_id = msg.get("session_id")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    message = (
                        "Your plan has been approved. Proceed with execution. "
                        "Run `orchestratia task check` for the full task details."
                    )
                    _inject_text(session, message, send_enter=True)
                    log.info(f"Plan approved, injected into session {session_id[:8]}")

            elif msg_type == "plan_revision":
                session_id = msg.get("session_id")
                feedback = msg.get("feedback", "")
                task_id = msg.get("task_id", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    async def _plan_revision_inject(s, fb):
                        _inject_escape(s)
                        await asyncio.sleep(2)
                        message = (
                            f"Plan revision requested. Feedback: {fb} "
                            "Please run `orchestratia task check` to review and resubmit."
                        )
                        _inject_text(s, message, send_enter=True)
                    asyncio.create_task(_plan_revision_inject(session, feedback))
                    log.info(f"Plan revision injected into session {session_id[:8]}")

            elif msg_type == "task_status_update":
                session_id = msg.get("session_id")
                task_id = msg.get("task_id", "")
                title = msg.get("title", "")
                status_label = msg.get("status_label", msg.get("status", ""))
                summary = msg.get("summary", "")
                session = state.active_sessions.get(session_id) if session_id else None
                if session and not session.closed:
                    parts = [f"Task '{title}' (#{task_id[:8]}) {status_label}."]
                    if summary:
                        parts.append(f"Summary: {summary}")
                    parts.append("Run `orchestratia task list` to see current status.")
                    message = " ".join(parts)

                    async def _status_update_inject(s, m):
                        _inject_escape(s)
                        await asyncio.sleep(2)
                        _inject_text(s, m, send_enter=True)
                    asyncio.create_task(_status_update_inject(session, message))
                    log.info(f"Task status update ({msg.get('status')}) injected into orchestrator session {session_id[:8]}")

            elif msg_type == "tunnel_open":
                from orchestratia_agent.tunnel import open_tunnel
                tunnel_id = msg.get("tunnel_id")
                target_host = msg.get("target_host", "127.0.0.1")
                target_port = msg.get("target_port", 22)
                if tunnel_id:
                    asyncio.create_task(open_tunnel(tunnel_id, target_host, target_port, sender))

            elif msg_type == "tunnel_data":
                tunnel_id = msg.get("tunnel_id")
                b64_data = msg.get("data", "")
                if tunnel_id and b64_data:
                    from orchestratia_agent import s2s_tunnel
                    if tunnel_id in s2s_tunnel._writers:
                        # S2S: data from hub → local TCP socket (source role)
                        await s2s_tunnel.write_data(tunnel_id, b64_data)
                    else:
                        # Regular tunnel (target role)
                        from orchestratia_agent.tunnel import write_tunnel_data
                        await write_tunnel_data(tunnel_id, b64_data)

            elif msg_type == "tunnel_ready":
                # Target confirmed TCP connection — unblock source relay
                tunnel_id = msg.get("tunnel_id")
                if tunnel_id:
                    from orchestratia_agent import s2s_tunnel
                    s2s_tunnel.mark_ready(tunnel_id)

            elif msg_type == "tunnel_close":
                tunnel_id = msg.get("tunnel_id")
                if tunnel_id:
                    from orchestratia_agent import s2s_tunnel
                    if tunnel_id in s2s_tunnel._writers:
                        s2s_tunnel.close_tunnel(tunnel_id)
                    else:
                        from orchestratia_agent.tunnel import close_tunnel
                        close_tunnel(tunnel_id)

            elif msg_type == "tunnel_closed":
                # Hub relays close from peer
                tunnel_id = msg.get("tunnel_id")
                if tunnel_id:
                    from orchestratia_agent import s2s_tunnel
                    if tunnel_id in s2s_tunnel._writers:
                        s2s_tunnel.close_tunnel(tunnel_id)
                    else:
                        from orchestratia_agent.tunnel import close_tunnel
                        close_tunnel(tunnel_id)

            # ── SSH Access Grant Messages ──
            elif msg_type == "setup_ssh_access":
                # Target role: add public key to orchestratia user
                from orchestratia_agent.ssh_setup import setup_authorized_key, setup_sudoers
                grant_id = msg.get("grant_id", "")
                pub_key = msg.get("ssh_public_key", "")
                priv_level = msg.get("privilege_level", "standard")
                if grant_id and pub_key:
                    setup_authorized_key(pub_key, grant_id, priv_level)
                    if priv_level == "elevated":
                        setup_sudoers(priv_level)

            elif msg_type == "revoke_ssh_access":
                # Target role: remove public key
                from orchestratia_agent.ssh_setup import remove_authorized_key, remove_sudoers
                grant_id = msg.get("grant_id", "")
                if grant_id:
                    remove_authorized_key(grant_id)
                    # Check if any elevated grants remain before removing sudoers
                    remove_sudoers()

            elif msg_type == "grant_ssh_access":
                # Source role: store private key + start TCP listener
                from orchestratia_agent.ssh_setup import store_private_key, clean_known_hosts
                from orchestratia_agent import s2s_tunnel
                grant_id = msg.get("grant_id", "")
                priv_key = msg.get("ssh_private_key", "")
                bind_port = msg.get("local_bind_port", 0)
                target_port = msg.get("target_port", 22)
                if grant_id and priv_key and bind_port:
                    store_private_key(grant_id, priv_key)
                    clean_known_hosts(bind_port)
                    asyncio.create_task(
                        s2s_tunnel.setup_grant(grant_id, bind_port, target_port, sender)
                    )

            elif msg_type == "revoke_grant_access":
                # Source role: remove private key + stop listener
                from orchestratia_agent.ssh_setup import remove_private_key
                from orchestratia_agent import s2s_tunnel
                grant_id = msg.get("grant_id", "")
                if grant_id:
                    remove_private_key(grant_id)
                    asyncio.create_task(s2s_tunnel.teardown_grant(grant_id))

            elif msg_type == "remote_exec":
                request_id = msg.get("request_id")
                command = msg.get("command", "")
                if request_id and command:
                    asyncio.create_task(_handle_remote_exec(sender, request_id, command))

            # ── File Transfer Messages ──
            elif msg_type == "file_offer":
                from orchestratia_agent.file_transfer import handle_file_offer
                asyncio.create_task(handle_file_offer(msg, sender))

            elif msg_type == "file_send_start":
                from orchestratia_agent.file_transfer import send_file
                transfer_id = msg.get("transfer_id", "")
                file_path = msg.get("file_path", "")
                if transfer_id and file_path:
                    asyncio.create_task(send_file(file_path, transfer_id, sender))

            elif msg_type == "file_accepted":
                from orchestratia_agent.file_transfer import resolve_outbound
                transfer_id = msg.get("transfer_id", "")
                if transfer_id:
                    resolve_outbound(transfer_id, {"status": "accepted"})

            elif msg_type == "file_rejected":
                from orchestratia_agent.file_transfer import resolve_outbound
                transfer_id = msg.get("transfer_id", "")
                if transfer_id:
                    resolve_outbound(transfer_id, {
                        "status": "rejected",
                        "reason": msg.get("reason", ""),
                    })

            elif msg_type == "file_chunk":
                from orchestratia_agent.file_transfer import handle_file_chunk
                handle_file_chunk(msg)

            elif msg_type == "file_complete":
                from orchestratia_agent.file_transfer import handle_file_complete
                asyncio.create_task(handle_file_complete(msg, sender))

            elif msg_type == "file_ack":
                from orchestratia_agent.file_transfer import resolve_outbound
                transfer_id = msg.get("transfer_id", "")
                if transfer_id:
                    resolve_outbound(transfer_id, {
                        "status": "completed",
                        "sha256_verified": msg.get("sha256_verified", False),
                    })

            elif msg_type == "file_error":
                from orchestratia_agent.file_transfer import (
                    resolve_outbound,
                    _cleanup_incoming,
                )
                transfer_id = msg.get("transfer_id", "")
                if transfer_id:
                    resolve_outbound(transfer_id, {
                        "status": "failed",
                        "error": msg.get("error", "Unknown error"),
                    })
                    _cleanup_incoming(transfer_id)

            elif msg_type == "approval_rules_updated":
                log.info("Approval rules updated by hub, refreshing cache")
                asyncio.create_task(_refresh_rules_cache(state))

            elif msg_type == "pong":
                pass

    except websockets.exceptions.ConnectionClosed:
        log.warning("WebSocket connection closed by hub")
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error(f"WebSocket receive error: {e}")


async def report_alive_sessions(state: DaemonState):
    """After WS reconnect, report alive sessions and discover orphaned sessions.

    Handles both tmux (Linux) and pty-host (Windows) session persistence.
    For tmux: orphaned sessions use tmux names (not UUIDs), so they go through
    session_recovered -> session_recovered_ack flow to get real UUIDs.
    For pty-host: session IDs are already UUIDs, so they can be reattached
    and reported directly.
    """
    backend = state.backend

    def _make_ws_sender(st: DaemonState):
        async def sender(msg: dict) -> bool:
            return await ws_send(st, msg)
        return sender

    def _on_session_close(session_id: str):
        state.active_sessions.pop(session_id, None)

    sender = _make_ws_sender(state)

    # 1. Check existing tracked sessions — try to reattach dead ones
    dead = []
    surviving_ids = backend.discover_surviving_sessions()
    is_pty_host = hasattr(backend, "_connected")  # PtyHostSessionBackend

    # Env vars to inject into recovered sessions (API key may have changed)
    recovery_env = {
        "ORCHESTRATIA_HUB_URL": state.hub_url,
        "ORCHESTRATIA_API_KEY": state.api_key,
    }

    for sid, s in list(state.active_sessions.items()):
        if not s.is_alive():
            if s.tmux_name and s.tmux_name in surviving_ids:
                handle = backend.reattach(sid, s.tmux_name, 120, 40, env_vars=recovery_env)
                if handle:
                    new_session = ManagedSession(
                        sid, handle, backend, sender,
                        on_close=_on_session_close,
                    )
                    state.active_sessions[sid] = new_session
                    await new_session.start_reader()
                    log.info(f"Reattached to surviving tmux session {s.tmux_name} for {sid[:8]}")
                    continue
            elif is_pty_host and sid in surviving_ids:
                handle = backend.reattach(sid, sid, 120, 40, env_vars=recovery_env)
                if handle:
                    new_session = ManagedSession(
                        sid, handle, backend, sender,
                        on_close=_on_session_close,
                    )
                    state.active_sessions[sid] = new_session
                    await new_session.start_reader()
                    log.info(f"Reattached to surviving pty-host session {sid[:8]}")
                    continue
            dead.append(sid)

    for sid in dead:
        session = state.active_sessions.pop(sid)
        session.closed = True
        backend.close_handle(session.handle)
        log.info(f"Cleaned up dead session {sid[:8]}")

    # 2. Discover orphaned sessions not tracked by us
    orphaned: set[str] = set()  # track keys reported via session_recovered
    tracked_ids = set(state.active_sessions.keys())
    tracked_tmux = {s.tmux_name for s in state.active_sessions.values() if s.tmux_name}

    for surviving_id in surviving_ids:
        if is_pty_host:
            # pty-host: session IDs are UUIDs — can reattach and report directly
            if surviving_id not in tracked_ids:
                log.info(f"Found orphaned pty-host session: {surviving_id[:8]}")
                handle = backend.reattach(surviving_id, surviving_id, 120, 40, env_vars=recovery_env)
                if handle:
                    new_session = ManagedSession(
                        surviving_id, handle, backend, sender,
                        on_close=_on_session_close,
                    )
                    state.active_sessions[surviving_id] = new_session
                    # pty-host sessions already have UUID IDs — start reader immediately
                    await new_session.start_reader()
                    await ws_send(state, {
                        "type": "session_started",
                        "session_id": surviving_id,
                        "pid": handle.pid,
                        "recovered": True,
                        "tmux_name": "",
                    })
                    orphaned.add(surviving_id)
        else:
            # tmux: surviving_id is a tmux session name, not a UUID
            if surviving_id not in tracked_tmux:
                log.info(f"Found orphaned tmux session: {surviving_id}")
                handle = backend.reattach(surviving_id, surviving_id, 120, 40, env_vars=recovery_env)
                if handle:
                    new_session = ManagedSession(
                        surviving_id, handle, backend, sender,
                        on_close=_on_session_close,
                    )
                    state.active_sessions[surviving_id] = new_session
                    # Don't start reader yet — it would send output with tmux_name
                    # as session_id, which isn't a valid UUID.  The reader will be
                    # started in the session_recovered_ack handler after the hub
                    # tells us the real UUID.
                    await ws_send(state, {
                        "type": "session_recovered",
                        "tmux_name": surviving_id,
                        "pid": handle.pid,
                    })
                    orphaned.add(surviving_id)

    # 3. Report alive sessions (skip orphans — already reported above)
    alive = [sid for sid in state.active_sessions if sid not in orphaned]
    if alive:
        log.info(f"Reporting {len(alive)} alive session(s) to hub")
        for sid in alive:
            session = state.active_sessions[sid]
            await ws_send(state, {
                "type": "session_started",
                "session_id": sid,
                "pid": session.pid,
                "recovered": True,
                "tmux_name": session.tmux_name or "",
            })
    # Ensure readers are running and trigger redraw for all recovered sessions.
    # Skip tmux orphans — their reader will start when session_recovered_ack
    # arrives with the real UUID.  pty-host orphans already have readers started.
    for sid, session in state.active_sessions.items():
        if sid in orphaned and not is_pty_host:
            continue
        if session.reader_task is None or session.reader_task.done():
            log.info(f"Restarting reader for session {sid[:8]}")
            await session.start_reader()
        session.send_sigwinch()

    # Restore SSH access grants after reconnect
    await _restore_grants(state, sender)


async def _restore_grants(state: DaemonState, sender):
    """Poll hub for active grants and restore SSH keys + listeners."""
    try:
        import httpx

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        async with httpx.AsyncClient(verify=ssl_ctx) as client:
            resp = await client.get(
                f"{state.hub_url}/api/v1/server/access-grants",
                headers={"X-API-Key": state.api_key},
                timeout=10,
            )
            if resp.status_code != 200:
                log.warning(f"Failed to fetch grants: HTTP {resp.status_code}")
                return

            grants = resp.json()
            if not grants:
                return

            from orchestratia_agent.ssh_setup import (
                setup_authorized_key, setup_sudoers,
                store_private_key,
            )
            from orchestratia_agent import s2s_tunnel

            source_count = target_count = 0
            for g in grants:
                grant_id = g["grant_id"]
                role = g["role"]

                if role == "source":
                    priv_key = g.get("ssh_private_key", "")
                    bind_port = g.get("local_bind_port", 0)
                    target_port = g.get("target_port", 22)
                    if priv_key and bind_port:
                        store_private_key(grant_id, priv_key)
                        await s2s_tunnel.setup_grant(grant_id, bind_port, target_port, sender)
                        source_count += 1

                elif role == "target":
                    pub_key = g.get("ssh_public_key", "")
                    priv_level = g.get("privilege_level", "standard")
                    if pub_key:
                        setup_authorized_key(pub_key, grant_id, priv_level)
                        if priv_level == "elevated":
                            setup_sudoers(priv_level)
                        target_count += 1

            if source_count or target_count:
                log.info(f"Restored {source_count} source + {target_count} target SSH grants")

    except Exception as e:
        log.warning(f"Failed to restore grants: {e}")


# ── Approval rules cache + permission log flush ──────────────────


def _get_rules_cache_path(state: DaemonState) -> str:
    """Return path to the local rules cache file."""
    import hashlib
    api_hash = hashlib.md5(state.api_key.encode()).hexdigest()[:12]
    tmp_dir = os.environ.get("TMPDIR", os.environ.get("TEMP", os.environ.get("TMP", "/tmp")))
    return os.path.join(tmp_dir, f"orchestratia-rules-{api_hash}.json")


def _get_permlog_path(state: DaemonState) -> str:
    """Return path to the local permission log file."""
    import hashlib
    api_hash = hashlib.md5(state.api_key.encode()).hexdigest()[:12]
    tmp_dir = os.environ.get("TMPDIR", os.environ.get("TEMP", os.environ.get("TMP", "/tmp")))
    return os.path.join(tmp_dir, f"orchestratia-permlog-{api_hash}.jsonl")


async def _refresh_rules_cache(state: DaemonState):
    """Fetch approval rules from hub and write to local cache file."""
    try:
        import httpx
        hub_url = state.hub_url.replace("wss://", "https://").replace("ws://", "http://")
        if hub_url.endswith("/ws/server"):
            hub_url = hub_url[: -len("/ws/server")]
        url = f"{hub_url}/api/v1/server/approval-rules"

        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers={"X-API-Key": state.api_key})
            if resp.status_code == 200:
                rules = resp.json()
                cache_path = _get_rules_cache_path(state)
                with open(cache_path, "w") as f:
                    json.dump(rules, f)
                log.info(f"Refreshed approval rules cache: {len(rules)} rules → {cache_path}")
            else:
                log.warning(f"Failed to fetch approval rules: HTTP {resp.status_code}")
    except Exception as e:
        log.warning(f"Failed to refresh approval rules cache: {e}")


async def permlog_flush_loop(state: DaemonState):
    """Periodically flush permission log entries to the hub API."""
    while state.running:
        await asyncio.sleep(5)
        log_path = _get_permlog_path(state)
        try:
            if not os.path.exists(log_path):
                continue
            with open(log_path, "r") as f:
                lines = f.readlines()
            if not lines:
                continue

            # Truncate the file immediately to avoid re-sending
            with open(log_path, "w") as f:
                pass

            # Parse log entries
            entries = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            if not entries:
                continue

            # POST to hub
            import httpx
            hub_url = state.hub_url.replace("wss://", "https://").replace("ws://", "http://")
            if hub_url.endswith("/ws/server"):
                hub_url = hub_url[: -len("/ws/server")]
            url = f"{hub_url}/api/v1/server/permissions/log"

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    url,
                    headers={"X-API-Key": state.api_key, "Content-Type": "application/json"},
                    json={"entries": entries},
                )
                if resp.status_code == 201:
                    log.debug(f"Flushed {len(entries)} permission log entries to hub")
                else:
                    log.warning(f"Permission log flush failed: HTTP {resp.status_code}")
        except Exception as e:
            log.debug(f"Permission log flush error: {e}")


async def ws_connection_loop(state: DaemonState):
    """Maintain the WebSocket connection with automatic reconnection."""
    backoff = 1

    while state.running:
        ws = await connect_ws(state)
        if ws:
            state.ws_connection = ws
            backoff = 1
            await report_alive_sessions(state)
            # Fetch approval rules on connect (non-blocking)
            asyncio.create_task(_refresh_rules_cache(state))
            await ws_receive_loop(ws, state)
            state.ws_connection = None
            log.info("WebSocket disconnected, will reconnect...")
        else:
            log.warning(f"WebSocket connect failed, retrying in {backoff}s...")

        if not state.running:
            break

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30)


async def _handle_remote_exec(sender, request_id: str, command: str):
    """Execute a command locally and return the result via WS."""
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        await sender({
            "type": "remote_exec_result",
            "request_id": request_id,
            "exit_code": proc.returncode,
            "stdout": stdout.decode(errors="replace"),
            "stderr": stderr.decode(errors="replace"),
        })
    except asyncio.TimeoutError:
        await sender({
            "type": "remote_exec_result",
            "request_id": request_id,
            "exit_code": -1,
            "stdout": "",
            "stderr": "Command timed out (120s)",
        })
    except Exception as e:
        await sender({
            "type": "remote_exec_result",
            "request_id": request_id,
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
        })


async def cleanup_sessions(state: DaemonState):
    """Cleanup on daemon shutdown.

    Persistent sessions (tmux on Linux, pty-host on Windows) are
    intentionally LEFT ALIVE so they survive daemon restarts.  On next
    startup, report_alive_sessions() will discover and reattach to them.
    Only non-persistent (plain PTY / direct ConPTY) sessions are
    terminated, since they cannot outlive the daemon anyway.
    """
    # Close all active tunnels (regular + S2S)
    from orchestratia_agent.tunnel import close_all_tunnels
    close_all_tunnels()
    from orchestratia_agent import s2s_tunnel
    await s2s_tunnel.close_all()

    backend = state.backend
    persistent = backend.supports_persistence()
    for session_id, session in list(state.active_sessions.items()):
        if session.reader_task:
            session.reader_task.cancel()
        if session.tmux_name:
            log.info(f"Detaching from tmux session {session.tmux_name} ({session_id[:8]})")
            backend.close_handle(session.handle)
            # Do NOT kill the tmux session — let it survive for recovery
        elif persistent and session.handle.extra.get("pty_host"):
            log.info(f"Detaching from pty-host session ({session_id[:8]})")
            backend.close_handle(session.handle)
            # Do NOT kill the pty-host session — let it survive for recovery
        else:
            log.info(f"Closing plain session {session_id[:8]}")
            session.close_graceful()
    state.active_sessions.clear()
