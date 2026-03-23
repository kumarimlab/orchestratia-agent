"""Source-side local TCP listener and WS relay for S2S SSH tunnels.

For each active grant where this agent is the *source*, we open a local TCP
listener on 127.0.0.1:{bind_port}. When a local process (e.g. ssh) connects,
we generate a tunnel_id and relay data bidirectionally through the hub to the
target agent.

Data flow:
  ssh client → TCP listener (localhost:30xxx) → base64 → WS → hub → WS → target agent → TCP → sshd
"""

from __future__ import annotations

import asyncio
import base64
import logging
import uuid
from typing import Callable, Coroutine, Any

log = logging.getLogger("orchestratia-agent.s2s_tunnel")

WsSender = Callable[[dict], Coroutine[Any, Any, bool]]

# grant_id -> (server, grant_info)
_active_grants: dict[str, tuple[asyncio.AbstractServer, dict]] = {}

# tunnel_id -> (reader_task, writer, grant_id)
_active_tunnels: dict[str, tuple[asyncio.Task, asyncio.StreamWriter, str]] = {}

# For hub.py to route incoming tunnel_data from hub
_writers: dict[str, asyncio.StreamWriter] = {}

# Tunnel ready events — source waits for target to confirm TCP connection
_ready_events: dict[str, asyncio.Event] = {}

# Module-level ws_send reference (set during setup)
_ws_send: WsSender | None = None


async def setup_grant(
    grant_id: str,
    bind_port: int,
    target_port: int,
    ws_send: WsSender,
) -> bool:
    """Start a local TCP listener for an access grant."""
    global _ws_send
    _ws_send = ws_send

    if grant_id in _active_grants:
        log.warning(f"Grant {grant_id[:8]}: listener already active on port {bind_port}")
        return True

    try:
        server = await asyncio.start_server(
            lambda r, w: _handle_connection(r, w, grant_id, target_port, ws_send),
            "127.0.0.1",
            bind_port,
        )
        _active_grants[grant_id] = (server, {
            "bind_port": bind_port,
            "target_port": target_port,
        })
        log.info(f"Grant {grant_id[:8]}: TCP listener started on 127.0.0.1:{bind_port}")
        return True
    except Exception as e:
        log.error(f"Grant {grant_id[:8]}: failed to start listener on port {bind_port}: {e}")
        return False


async def teardown_grant(grant_id: str):
    """Stop listener and close all tunnels for a grant."""
    entry = _active_grants.pop(grant_id, None)
    if entry:
        server, _ = entry
        server.close()
        await server.wait_closed()
        log.info(f"Grant {grant_id[:8]}: listener stopped")

    # Close any active tunnels for this grant
    to_close = [tid for tid, (_, _, gid) in _active_tunnels.items() if gid == grant_id]
    for tid in to_close:
        close_tunnel(tid)


def mark_ready(tunnel_id: str):
    """Called by hub.py when target confirms tunnel is connected."""
    ev = _ready_events.get(tunnel_id)
    if ev:
        ev.set()
        log.info(f"S2S tunnel {tunnel_id[:8]}: target ready")


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    grant_id: str,
    target_port: int,
    ws_send: WsSender,
):
    """Handle incoming TCP connection: generate tunnel_id, start relay."""
    tunnel_id = str(uuid.uuid4())
    _writers[tunnel_id] = writer

    log.info(f"S2S tunnel {tunnel_id[:8]}: new TCP connection (grant {grant_id[:8]})")

    # Create ready event and tell hub to open tunnel to target
    ready = asyncio.Event()
    _ready_events[tunnel_id] = ready

    await ws_send({
        "type": "s2s_tunnel_open",
        "tunnel_id": tunnel_id,
        "grant_id": grant_id,
    })

    # Wait for target to confirm TCP connection (up to 10s)
    try:
        await asyncio.wait_for(ready.wait(), timeout=10.0)
    except asyncio.TimeoutError:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: target not ready after 10s, aborting")
        _ready_events.pop(tunnel_id, None)
        _writers.pop(tunnel_id, None)
        writer.close()
        return
    finally:
        _ready_events.pop(tunnel_id, None)

    # Start TCP→WS reader only after target is connected
    task = asyncio.create_task(_tcp_to_ws(tunnel_id, reader, ws_send))
    _active_tunnels[tunnel_id] = (task, writer, grant_id)


async def _tcp_to_ws(
    tunnel_id: str,
    reader: asyncio.StreamReader,
    ws_send: WsSender,
):
    """Read from local TCP socket and forward to hub as base64."""
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                log.info(f"S2S tunnel {tunnel_id[:8]}: TCP EOF")
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
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: TCP read error: {e}")
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


async def write_data(tunnel_id: str, b64_data: str):
    """WS→TCP: decode base64 and write to local TCP socket."""
    writer = _writers.get(tunnel_id)
    if not writer:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: write to unknown tunnel")
        return

    try:
        raw = base64.b64decode(b64_data)
        writer.write(raw)
        await writer.drain()
    except Exception as e:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: write error: {e}")


def close_tunnel(tunnel_id: str):
    """Close a specific S2S tunnel."""
    entry = _active_tunnels.pop(tunnel_id, None)
    if entry:
        task, writer, _ = entry
        task.cancel()
        try:
            writer.close()
        except Exception:
            pass

    _writers.pop(tunnel_id, None)
    log.info(f"S2S tunnel {tunnel_id[:8]}: closed")


def _cleanup_tunnel(tunnel_id: str):
    """Clean up after reader task exits."""
    entry = _active_tunnels.pop(tunnel_id, None)
    if entry:
        _, writer, _ = entry
        try:
            writer.close()
        except Exception:
            pass
    _writers.pop(tunnel_id, None)


async def close_all():
    """Shutdown all listeners and tunnels."""
    for grant_id in list(_active_grants):
        await teardown_grant(grant_id)

    for tunnel_id in list(_active_tunnels):
        close_tunnel(tunnel_id)

    log.info("All S2S tunnels and listeners closed")
