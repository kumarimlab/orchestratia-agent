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

# bind_port -> grant_id (reverse index for fast "what's on this port?" lookup
# during setup-with-conflict and reconciliation). Kept consistent with
# _active_grants on every mutate.
_port_to_grant: dict[int, str] = {}

# tunnel_id -> (reader_task, writer, grant_id)
_active_tunnels: dict[str, tuple[asyncio.Task, asyncio.StreamWriter, str]] = {}

# For hub.py to route incoming tunnel_data from hub
_writers: dict[str, asyncio.StreamWriter] = {}

# Tunnel ready events — source waits for target to confirm TCP connection
_ready_events: dict[str, asyncio.Event] = {}

# tunnel_id -> grant_id for every tunnel we hold a socket for, including ones
# still waiting for the target (those aren't in _active_tunnels yet).
_tunnel_grant: dict[str, str] = {}

# tunnel_id -> reason, for a tunnel the hub or target refused before it was ready
_refused: dict[str, str] = {}

# How long a new connection waits for the target agent to confirm its end.
READY_TIMEOUT = 10.0

# tunnel_id -> reason for closes we couldn't send (WS down mid-reconnect).
# Flushed on the next reconcile, which also runs right after a reconnect —
# otherwise the target keeps that session open for days.
_unsent_closes: dict[str, str] = {}
_UNSENT_CLOSES_MAX = 500

# Set by close_all(): no listener may be (re)started once shutdown has begun.
_shutting_down = False

# Module-level ws_send reference (set during setup)
_ws_send: WsSender | None = None


def active_grant_ids() -> set[str]:
    """Snapshot of grant IDs currently held in source-side tunnel state.

    Consumed by hub.py::_reconcile_grants to compute the diff against the
    hub's authoritative list. Returns a copy so callers can mutate during
    iteration.
    """
    return set(_active_grants.keys())


def active_grants_snapshot() -> list[dict]:
    """Human-readable snapshot of current grant→port mapping. For diagnostics
    (logged by reconcile loop; future `orchestratia tunnels` CLI)."""
    return [
        {"grant_id": gid, "bind_port": info["bind_port"], "target_port": info["target_port"]}
        for gid, (_, info) in _active_grants.items()
    ]


async def setup_grant(
    grant_id: str,
    bind_port: int,
    target_port: int,
    ws_send: WsSender,
) -> bool:
    """Start a local TCP listener for an access grant.

    Idempotent + conflict-tolerant: an unchanged re-broadcast (the 60s
    reconcile calls this every cycle) keeps the running listener and its
    open tunnels; a listener for the same grant on a different port/target,
    or for a different grant on the same port, is torn down first. The
    latter covers a missed `revoke_grant_access` push leaving a stale
    listener whose closure routes to a grant the target no longer knows
    ('target not ready after 10s' on every SSH attempt — staging.kritis.io,
    2026-05-24).

    Recreating on every reconcile was itself a bug: on Python >= 3.12.1
    `Server.wait_closed()` waits for every open connection, so one long SSH
    session left the port refusing all new connections, and the reconcile
    loop stalled, until that session ended (kritis-ipp, 2026-10).
    """
    global _ws_send
    _ws_send = ws_send
    if _shutting_down:
        return False

    existing = _active_grants.get(grant_id)
    if existing:
        server, info = existing
        if (info["bind_port"] == bind_port and info["target_port"] == target_port
                and server.is_serving()):
            return True
        log.info(
            f"Grant {grant_id[:8]}: listener changed "
            f"({info['bind_port']}→{bind_port}, target port {info['target_port']}→{target_port}"
            f"{'' if server.is_serving() else ', not serving'}), recreating"
        )
        await teardown_grant(grant_id)

    # Conflict 2: a *different* grant holds this port. Standard cause is a
    # missed revoke push (grant rotated on target; we never got told to
    # release the port). Tear it down — the hub-issued port is now claimed
    # by the new grant_id.
    if bind_port in _port_to_grant and _port_to_grant[bind_port] != grant_id:
        stale_gid = _port_to_grant[bind_port]
        log.warning(
            f"Port {bind_port} held by stale grant {stale_gid[:8]} "
            f"(reassigning to {grant_id[:8]}). Likely a missed revoke push — "
            f"reconciliation should prevent recurrence."
        )
        await teardown_grant(stale_gid)

    try:
        server = await asyncio.start_server(
            lambda r, w: _handle_connection(r, w, grant_id),
            "127.0.0.1",
            bind_port,
        )
        _active_grants[grant_id] = (server, {
            "bind_port": bind_port,
            "target_port": target_port,
        })
        _port_to_grant[bind_port] = grant_id
        log.info(f"Grant {grant_id[:8]}: TCP listener started on 127.0.0.1:{bind_port}")
        return True
    except Exception as e:
        log.error(f"Grant {grant_id[:8]}: failed to start listener on port {bind_port}: {e}")
        return False


async def teardown_grant(grant_id: str):
    """Stop listener and close all tunnels for a grant, telling the hub about
    each so the target closes its end too. Idempotent — calling for a grant
    we don't have is a no-op, not an error (this is the `revoke_grant_access`
    push arriving after the grant was already cleaned up by reconciliation,
    for example)."""
    entry = _active_grants.pop(grant_id, None)
    if entry:
        server, info = entry
        # Keep the port index consistent — only release if it still points
        # at this grant (it could have been overwritten by a concurrent
        # setup_grant for a different grant on the same port).
        port = info.get("bind_port")
        if port is not None and _port_to_grant.get(port) == grant_id:
            _port_to_grant.pop(port, None)
        server.close()

    # Close the tunnels BEFORE waiting on the server: wait_closed() waits for
    # every connection to drop, so waiting first deadlocks on a live session.
    for tid in [t for t, gid in _tunnel_grant.items() if gid == grant_id]:
        await _notify_closed(tid, "grant listener stopped")
        close_tunnel(tid)

    if entry:
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            log.warning(f"Grant {grant_id[:8]}: connections still draining after 5s")
        log.info(f"Grant {grant_id[:8]}: listener stopped")


def owns(tunnel_id: str) -> bool:
    """True if this module holds a socket for the tunnel (pending or live)."""
    return tunnel_id in _writers


def mark_ready(tunnel_id: str):
    """Called by hub.py when target confirms tunnel is connected."""
    ev = _ready_events.get(tunnel_id)
    if ev:
        ev.set()
        log.info(f"S2S tunnel {tunnel_id[:8]}: target ready")


def handle_remote_close(tunnel_id: str, reason: str):
    """The hub or target closed/refused the tunnel (tunnel_close, tunnel_closed,
    tunnel_error). A tunnel still waiting for the target fails right away with
    the reason instead of timing out; a live one is closed. Never echoed back."""
    ev = _ready_events.get(tunnel_id)
    if ev:
        _refused[tunnel_id] = reason
        ev.set()
        return
    close_tunnel(tunnel_id)


async def _send(msg: dict, timeout: float | None = 2) -> bool:
    """Send on the hub WS. Control messages get a timeout so a stuck hub can't
    hold up teardown; data frames pass timeout=None to keep backpressure."""
    if _ws_send is None:
        return False
    try:
        if timeout is None:
            return await _ws_send(msg)
        return await asyncio.wait_for(_ws_send(msg), timeout=timeout)
    except Exception:
        return False


async def _notify_closed(tunnel_id: str, reason: str):
    """Tell the hub (and through it the target) that our end is gone. If the WS
    is down, keep it for flush_unsent_closes()."""
    sent = await _send({"type": "tunnel_closed", "tunnel_id": tunnel_id, "reason": reason})
    if not sent and len(_unsent_closes) < _UNSENT_CLOSES_MAX:
        _unsent_closes[tunnel_id] = reason


async def flush_unsent_closes():
    """Resend closes that failed while the WS was down (called on reconcile)."""
    for tid, reason in list(_unsent_closes.items()):
        if not await _send({"type": "tunnel_closed", "tunnel_id": tid, "reason": reason}):
            return  # still down — try again next cycle
        _unsent_closes.pop(tid, None)


async def _handle_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    grant_id: str,
):
    """Handle incoming TCP connection: generate tunnel_id, start relay."""
    tunnel_id = str(uuid.uuid4())
    _writers[tunnel_id] = writer
    _tunnel_grant[tunnel_id] = grant_id

    log.info(f"S2S tunnel {tunnel_id[:8]}: new TCP connection (grant {grant_id[:8]})")

    # Create ready event and tell hub to open tunnel to target
    ready = asyncio.Event()
    _ready_events[tunnel_id] = ready

    await _send({
        "type": "s2s_tunnel_open",
        "tunnel_id": tunnel_id,
        "grant_id": grant_id,
    })

    # Wait for target to confirm TCP connection
    try:
        await asyncio.wait_for(ready.wait(), timeout=READY_TIMEOUT)
    except asyncio.TimeoutError:
        log.warning(
            f"S2S tunnel {tunnel_id[:8]}: target not ready after {READY_TIMEOUT:g}s "
            f"(no reply from the hub or the target agent), aborting"
        )
        _ready_events.pop(tunnel_id, None)
        # The target may still connect late — make sure its end is closed too.
        await _notify_closed(tunnel_id, "source timed out waiting for target")
        close_tunnel(tunnel_id)
        return
    finally:
        _ready_events.pop(tunnel_id, None)
        refused = _refused.pop(tunnel_id, None)

    if refused is not None:
        if tunnel_id in _writers:
            log.warning(f"S2S tunnel {tunnel_id[:8]}: refused before ready: {refused}")
            close_tunnel(tunnel_id)
        return
    if tunnel_id not in _writers:
        return  # closed (grant torn down) while waiting

    # Start TCP→WS reader only after target is connected
    task = asyncio.create_task(_tcp_to_ws(tunnel_id, reader))
    _active_tunnels[tunnel_id] = (task, writer, grant_id)


async def _tcp_to_ws(
    tunnel_id: str,
    reader: asyncio.StreamReader,
):
    """Read from local TCP socket and forward to hub as base64."""
    try:
        while True:
            data = await reader.read(16384)
            if not data:
                log.info(f"S2S tunnel {tunnel_id[:8]}: TCP EOF")
                await _notify_closed(tunnel_id, "eof")
                break

            b64 = base64.b64encode(data).decode("ascii")
            await _send({
                "type": "tunnel_data",
                "tunnel_id": tunnel_id,
                "data": b64,
            }, timeout=None)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: TCP read error: {e}")
        await _notify_closed(tunnel_id, str(e))
    finally:
        _cleanup_tunnel(tunnel_id)


async def write_data(tunnel_id: str, b64_data: str):
    """WS→TCP: decode base64 and write to local TCP socket."""
    writer = _writers.get(tunnel_id)
    if not writer:
        # hub.py only routes here when owns() — an orphan id goes to
        # tunnel.write_tunnel_data, which answers it with tunnel_closed.
        return

    try:
        raw = base64.b64decode(b64_data)
        writer.write(raw)
        await writer.drain()
    except Exception as e:
        log.warning(f"S2S tunnel {tunnel_id[:8]}: write error: {e}")


def close_tunnel(tunnel_id: str):
    """Close a specific S2S tunnel (no message to the hub — callers that end it
    on our side send tunnel_closed first)."""
    if tunnel_id not in _writers and tunnel_id not in _active_tunnels:
        return
    ev = _ready_events.get(tunnel_id)
    if ev:  # still waiting for the target: wake the handler so it stops now
        _refused.setdefault(tunnel_id, "closed locally")
        ev.set()
    entry = _active_tunnels.pop(tunnel_id, None)
    if entry:
        task, writer, _ = entry
        task.cancel()
        try:
            writer.close()
        except Exception:
            pass

    writer = _writers.pop(tunnel_id, None)
    if writer and not entry:
        try:
            writer.close()  # still waiting for the target — no reader task yet
        except Exception:
            pass
    _tunnel_grant.pop(tunnel_id, None)
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
    _tunnel_grant.pop(tunnel_id, None)


async def close_all():
    """Shutdown all listeners and tunnels, telling the hub about each tunnel."""
    global _shutting_down
    _shutting_down = True
    for grant_id in list(_active_grants):
        await teardown_grant(grant_id)

    for tunnel_id in list(_tunnel_grant):
        await _notify_closed(tunnel_id, "source agent shutting down")
        close_tunnel(tunnel_id)

    log.info("All S2S tunnels and listeners closed")
