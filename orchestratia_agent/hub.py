"""Hub communication — HTTP registration, heartbeats, and WebSocket messaging."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import platform
import ssl
import sys
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
        resp = await client.post(
            f"{state.hub_url}/api/v1/servers/register",
            json={
                "name": state.config.get("server_name", platform.node()),
                "hostname": platform.node(),
                "ip": "0.0.0.0",
                "os": platform.system().lower(),
                "repos": get_repos_info(state.config),
                "system_info": get_system_info(),
                "registration_token": reg_token,
            },
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
        log.info(f"Registered with hub. Server ID: {data['id']}, Key: {state.api_key[:8]}...")

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


async def ws_connection_loop(state: DaemonState):
    """Maintain the WebSocket connection with automatic reconnection."""
    backoff = 1

    while state.running:
        ws = await connect_ws(state)
        if ws:
            state.ws_connection = ws
            backoff = 1
            await report_alive_sessions(state)
            await ws_receive_loop(ws, state)
            state.ws_connection = None
            log.info("WebSocket disconnected, will reconnect...")
        else:
            log.warning(f"WebSocket connect failed, retrying in {backoff}s...")

        if not state.running:
            break

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30)


async def cleanup_sessions(state: DaemonState):
    """Cleanup on daemon shutdown.

    Persistent sessions (tmux on Linux, pty-host on Windows) are
    intentionally LEFT ALIVE so they survive daemon restarts.  On next
    startup, report_alive_sessions() will discover and reattach to them.
    Only non-persistent (plain PTY / direct ConPTY) sessions are
    terminated, since they cannot outlive the daemon anyway.
    """
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
