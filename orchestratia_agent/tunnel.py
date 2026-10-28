"""TCP tunnel relay — agent side.

Opens TCP connections to local ports and relays data bidirectionally
over the hub WebSocket. Used for SSH tunneling and port forwarding.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Callable, Coroutine, Any

log = logging.getLogger("orchestratia-agent.tunnel")

# tunnel_id -> (reader_task, writer)
active_tunnels: dict[str, tuple[asyncio.Task, asyncio.StreamWriter]] = {}

# Type for the WS send function
WsSender = Callable[[dict], Coroutine[Any, Any, bool]]

# Credit-based flow control (relay editor tunnels, only once the relay announces it):
# stop reading the local socket at WINDOW unacknowledged bytes; the relay acks as the
# browser drains.
WINDOW = 1024 * 1024

# tunnel_id -> {"unacked": int, "event": asyncio.Event}
_credit: dict[str, dict] = {}

# Tunnels whose local TCP connect is still in progress (data for them is dropped
# as before, not answered with a close — they're about to exist).
_opening: set[str] = set()

# Opening tunnels the far end closed before our connect finished: close the
# socket as soon as it connects instead of reporting it ready.
_cancelled: set[str] = set()

# tunnel_id -> monotonic time we last answered its data with tunnel_closed, so a
# burst of orphan data (an scp) costs one reply, not one per chunk.
_close_replied: dict[str, float] = {}
_CLOSE_REPLY_TTL = 60.0


def ack(tunnel_id: str, n: int) -> None:
    c = _credit.get(tunnel_id)
    if not c:
        return
    c["unacked"] = max(0, c["unacked"] - int(n or 0))
    if c["unacked"] < WINDOW:
        c["event"].set()


async def open_tunnel(
    tunnel_id: str,
    target_host: str,
    target_port: int,
    ws_send: WsSender,
    flow_control: bool = False,
):
    """Open TCP connection to target and start reader task for TCP→WS relay."""
    _opening.add(tunnel_id)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port),
            timeout=10,
        )
    except asyncio.TimeoutError:
        _opening.discard(tunnel_id)
        log.error(f"Tunnel {tunnel_id[:8]}: TCP connect timeout to {target_host}:{target_port}")
        await ws_send({
            "type": "tunnel_error",
            "tunnel_id": tunnel_id,
            "error": f"Connection timeout to {target_host}:{target_port}",
        })
        return
    except Exception as e:
        _opening.discard(tunnel_id)
        log.error(f"Tunnel {tunnel_id[:8]}: TCP connect failed to {target_host}:{target_port}: {e}")
        await ws_send({
            "type": "tunnel_error",
            "tunnel_id": tunnel_id,
            "error": str(e),
        })
        return

    if tunnel_id in _cancelled:
        _cancelled.discard(tunnel_id)
        _opening.discard(tunnel_id)
        writer.close()
        log.info(f"Tunnel {tunnel_id[:8]}: closed by the far end while connecting")
        return

    log.info(f"Tunnel {tunnel_id[:8]}: TCP connected to {target_host}:{target_port}")

    if flow_control:
        ev = asyncio.Event()
        ev.set()
        _credit[tunnel_id] = {"unacked": 0, "event": ev}

    # Start reader task
    task = asyncio.create_task(_tcp_to_ws(tunnel_id, reader, ws_send))
    active_tunnels[tunnel_id] = (task, writer)
    _opening.discard(tunnel_id)

    # Notify hub that target TCP connection is established
    await ws_send({
        "type": "tunnel_ready",
        "tunnel_id": tunnel_id,
    })


async def _tcp_to_ws(
    tunnel_id: str,
    reader: asyncio.StreamReader,
    ws_send: WsSender,
):
    """Read from TCP socket and forward to WebSocket as base64."""
    try:
        while True:
            c = _credit.get(tunnel_id)
            if c is not None:
                while c["unacked"] >= WINDOW:
                    c["event"].clear()
                    await c["event"].wait()
            data = await reader.read(16384)  # 16KB chunks
            if not data:
                # TCP EOF
                log.info(f"Tunnel {tunnel_id[:8]}: TCP EOF")
                await ws_send({
                    "type": "tunnel_closed",
                    "tunnel_id": tunnel_id,
                    "reason": "eof",
                })
                break

            b64 = base64.b64encode(data).decode("ascii")
            await ws_send({
                "type": "tunnel_data",
                "tunnel_id": tunnel_id,
                "data": b64,
            })
            if c is not None:
                c["unacked"] += len(data)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning(f"Tunnel {tunnel_id[:8]}: TCP read error: {e}")
        try:
            await ws_send({
                "type": "tunnel_closed",
                "tunnel_id": tunnel_id,
                "reason": str(e),
            })
        except Exception:
            pass
    finally:
        _cleanup_tunnel(tunnel_id)


async def write_tunnel_data(tunnel_id: str, b64_data: str, ws_send: WsSender | None = None):
    """Decode base64 and write to TCP socket, flushing to ensure delivery.

    With ws_send (the hub connection), data for a tunnel we don't have is
    answered with tunnel_closed so the far end stops instead of being an orphan.
    """
    entry = active_tunnels.get(tunnel_id)
    if not entry:
        if ws_send is None or tunnel_id in _opening:
            log.warning(f"Tunnel {tunnel_id[:8]}: write to unknown tunnel")
            return
        now = time.monotonic()
        if now - _close_replied.get(tunnel_id, -_CLOSE_REPLY_TTL) < _CLOSE_REPLY_TTL:
            return
        if len(_close_replied) > 256:
            for tid, t in list(_close_replied.items()):
                if now - t >= _CLOSE_REPLY_TTL:
                    del _close_replied[tid]
        _close_replied[tunnel_id] = now
        log.warning(f"Tunnel {tunnel_id[:8]}: write to unknown tunnel, closing it")
        try:
            await asyncio.wait_for(ws_send({
                "type": "tunnel_closed",
                "tunnel_id": tunnel_id,
                "reason": "unknown tunnel",
            }), timeout=2)
        except Exception:
            pass
        return

    _, writer = entry
    try:
        raw = base64.b64decode(b64_data)
        writer.write(raw)
        await writer.drain()
    except Exception as e:
        log.warning(f"Tunnel {tunnel_id[:8]}: write error: {e}")


def close_tunnel(tunnel_id: str):
    """Cancel reader task and close TCP socket."""
    _credit.pop(tunnel_id, None)
    if tunnel_id in _opening:
        _cancelled.add(tunnel_id)
    entry = active_tunnels.pop(tunnel_id, None)
    if not entry:
        return

    task, writer = entry
    task.cancel()
    try:
        writer.close()
    except Exception:
        pass
    log.info(f"Tunnel {tunnel_id[:8]}: closed")


def _cleanup_tunnel(tunnel_id: str):
    """Clean up tunnel state after reader task exits."""
    _credit.pop(tunnel_id, None)
    entry = active_tunnels.pop(tunnel_id, None)
    if entry:
        _, writer = entry
        try:
            writer.close()
        except Exception:
            pass


def close_all_tunnels():
    """Shutdown hook — close all active tunnels."""
    for tunnel_id in list(active_tunnels.keys()):
        close_tunnel(tunnel_id)
    log.info("All tunnels closed")
