"""Second outbound connection: agent -> relay tier, for code-server traffic.

The agent's primary WebSocket is owned by the realtime singleton, which must not
carry VS Code's chatty traffic (file watchers, language servers, search). So on
`code_server_start` the agent dials a SEPARATE WebSocket to the relay tier and
bridges it to the local code-server over the existing TCP tunnel primitive.

The relay speaks HTTP+WS to the browser and raw-bytes-over-WS to the agent; the
agent detunnels those bytes to code-server on loopback. The relay↔agent framing
reuses tunnel_open/tunnel_data/tunnel_close.

SECURITY: the target port is PINNED to the port code-server actually bound. It is
NEVER read from a relay message — otherwise this link would be a general
loopback-SSRF primitive able to reach any local service.
"""

from __future__ import annotations

import asyncio
import json
import logging

import websockets

from orchestratia_agent.tunnel import open_tunnel, write_tunnel_data, close_tunnel

log = logging.getLogger("orchestratia-agent.relay_client")

# session_id -> {"ws": ws, "task": task}
_relays: dict[str, dict] = {}


async def handle_relay_message(msg: dict, *, pinned_port: int, ws_send, on_activity) -> None:
    """Route one relay message to the local code-server tunnel.

    `pinned_port` is authoritative — the message's target_host/target_port are
    ignored on purpose (finding #3)."""
    mt = msg.get("type")
    tid = msg.get("tunnel_id")
    if not tid:
        return
    if mt == "tunnel_open":
        on_activity()
        await open_tunnel(tid, "127.0.0.1", pinned_port, ws_send)
    elif mt == "tunnel_data":
        on_activity()
        data = msg.get("data", "")
        if data:
            await write_tunnel_data(tid, data)
    elif mt == "tunnel_close":
        close_tunnel(tid)


async def _run(session_id: str, relay_url: str, api_key: str, pinned_port: int,
               on_activity, ssl_ctx=None) -> None:
    """Hold the relay WS and pump messages until it closes."""
    target = f"{relay_url.rstrip('/')}/ws/relay"
    try:
        ws = await websockets.connect(
            target, ssl=ssl_ctx if target.startswith("wss") else None,
            ping_interval=30, ping_timeout=10, max_size=2 ** 22,
        )
    except Exception as e:  # noqa: BLE001
        log.error("relay connect failed for session %s: %s", session_id[:8], e)
        return

    async def ws_send(m: dict) -> bool:
        try:
            await ws.send(json.dumps(m))
            return True
        except Exception:  # noqa: BLE001
            return False

    try:
        # Auth: the relay verifies the API key AND that this server owns the
        # editor session (T7). Nothing routes before auth_ok.
        await ws.send(json.dumps({"type": "auth", "api_key": api_key,
                                  "session_id": session_id}))
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except (ValueError, TypeError):
                continue
            await handle_relay_message(msg, pinned_port=pinned_port,
                                       ws_send=ws_send, on_activity=on_activity)
    except websockets.exceptions.ConnectionClosed:
        log.info("relay connection closed for session %s", session_id[:8])
    except Exception as e:  # noqa: BLE001
        log.error("relay loop error for session %s: %s", session_id[:8], e)
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


def connect(session_id: str, relay_url: str, api_key: str, pinned_port: int,
            on_activity, ssl_ctx=None) -> None:
    """Start (idempotently) the relay bridge for an editor session."""
    if session_id in _relays and not _relays[session_id]["task"].done():
        return
    task = asyncio.create_task(
        _run(session_id, relay_url, api_key, pinned_port, on_activity, ssl_ctx))
    _relays[session_id] = {"task": task}


async def disconnect(session_id: str) -> None:
    """Tear down the relay bridge for an editor session."""
    entry = _relays.pop(session_id, None)
    if entry and not entry["task"].done():
        entry["task"].cancel()
        try:
            await entry["task"]
        except (asyncio.CancelledError, Exception):  # noqa: BLE001
            pass
