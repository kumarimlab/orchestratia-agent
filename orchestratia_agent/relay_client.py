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
import random

import websockets

from orchestratia_agent.tunnel import open_tunnel, write_tunnel_data, close_tunnel

log = logging.getLogger("orchestratia-agent.relay_client")

# session_id -> {"ws": ws, "task": task}
_relays: dict[str, dict] = {}


# Reconnection policy. A relay restart (deploy, autoheal) must not orphan a live
# editor: without a retry the browser gets "502 editor is not connected" forever,
# because nothing re-establishes the link until a new code_server_start.
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

# Closes the relay uses to say "this session is not yours / is gone". Retrying
# those is a pointless login storm — and honouring them is what lets this loop
# terminate by itself once the editor session ends.
PERMANENT_CLOSE_CODES = frozenset({4401, 4403})


def backoff_for(attempt: int) -> float:
    """Exponential backoff with jitter.

    The jitter is not decoration: every agent loses its relay socket at the same
    instant when the relay redeploys, so identical timers would have them all
    reconnect in lockstep and hammer the tier as it comes back.
    """
    capped = min(BASE_BACKOFF_SECONDS * (2 ** max(0, attempt)), MAX_BACKOFF_SECONDS)
    return capped * (0.5 + random.random() * 0.5)


class RetryState:
    """Backoff that resets once a connection actually succeeds.

    Tracked separately from the loop so "we got through" is an explicit event:
    an attempt counter that only grows leaves a recovered link crawling at the
    ceiling for every later blip, which is slowest precisely when things are
    working again.
    """

    def __init__(self) -> None:
        self._attempt = 0

    def failed(self) -> None:
        self._attempt += 1

    def connected(self) -> None:
        self._attempt = 0

    def next_delay(self) -> float:
        return backoff_for(max(0, self._attempt - 1))


def should_retry(close_code) -> bool:
    """False only for closes that mean the session itself is no longer valid."""
    return close_code not in PERMANENT_CLOSE_CODES


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


async def _attempt(session_id: str, relay_url: str, api_key: str, pinned_port: int,
                   on_activity, ssl_ctx=None):
    """One connect+pump cycle -> (connected, close_code).

    `connected` distinguishes "the relay was unreachable" from "we were attached
    and the link later dropped" — only the latter should reset the backoff."""
    target = f"{relay_url.rstrip('/')}/ws/relay"
    try:
        ws = await websockets.connect(
            target, ssl=ssl_ctx if target.startswith("wss") else None,
            ping_interval=30, ping_timeout=10, max_size=2 ** 22,
        )
    except Exception as e:  # noqa: BLE001
        log.warning("relay connect failed for session %s: %s", session_id[:8], e)
        return False, None

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
        return True, None
    except websockets.exceptions.ConnectionClosed as e:
        code = getattr(e, "code", None) or getattr(getattr(e, "rcvd", None), "code", None)
        log.info("relay connection closed for session %s (code=%s)", session_id[:8], code)
        return True, code
    except Exception as e:  # noqa: BLE001
        log.error("relay loop error for session %s: %s", session_id[:8], e)
        return True, None
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass


async def _run(session_id: str, relay_url: str, api_key: str, pinned_port: int,
               on_activity, ssl_ctx=None) -> None:
    """Keep the relay link up for as long as this editor session is valid.

    Ends only on a permanent rejection (the relay saying the session is not ours
    or is gone) or on cancellation from disconnect().
    """
    state = RetryState()
    while True:
        connected, code = await _attempt(session_id, relay_url, api_key,
                                         pinned_port, on_activity, ssl_ctx)
        if not should_retry(code):
            log.info("relay: session %s rejected (code=%s) — not retrying",
                     session_id[:8], code)
            return
        if connected:
            state.connected()
        else:
            state.failed()
        delay = state.next_delay()
        log.info("relay: reconnecting session %s in %.1fs", session_id[:8], delay)
        try:
            await asyncio.sleep(delay)
        except asyncio.CancelledError:
            raise


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
