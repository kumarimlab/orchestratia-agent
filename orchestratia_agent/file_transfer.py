"""Agent-to-agent file transfer — sender and receiver logic.

Sender: reads file in 64KB chunks, base64-encodes, sends via hub WS.
Receiver: reassembles chunks into temp file, verifies SHA-256, moves to destination.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Coroutine, Any

log = logging.getLogger("orchestratia-agent.file_transfer")

CHUNK_SIZE = 65_536  # 64 KB raw

# Type for the WS send function (same as tunnel.py)
WsSender = Callable[[dict], Coroutine[Any, Any, bool]]

# Active incoming transfers: transfer_id -> IncomingTransfer
_incoming_transfers: dict[str, "IncomingTransfer"] = {}

# Pending outbound transfer completion events: transfer_id -> asyncio.Event
_outbound_events: dict[str, asyncio.Event] = {}
_outbound_results: dict[str, dict] = {}


@dataclass
class IncomingTransfer:
    transfer_id: str
    filename: str
    file_size: int
    sha256: str
    sender_session: str
    temp_path: str
    dest_dir: str
    chunks_received: int = 0
    total_chunks: int = 0
    temp_file: Any = field(default=None, repr=False)


def get_download_dir() -> str:
    """Get or create the file transfer download directory."""
    d = os.environ.get(
        "ORCHESTRATIA_TRANSFER_DIR",
        os.path.expanduser("~/.orchestratia/transfers"),
    )
    os.makedirs(d, exist_ok=True)
    return d


# ── Sender ──────────────────────────────────────────────────────────


async def send_file(
    file_path: str,
    transfer_id: str,
    ws_send: WsSender,
) -> None:
    """Read file and stream chunks to hub. Called when daemon receives file_send_start."""
    path = Path(file_path)
    if not path.is_file():
        log.error(f"Transfer {transfer_id[:8]}: file not found: {file_path}")
        await ws_send({
            "type": "file_error",
            "transfer_id": transfer_id,
            "error": f"File not found: {file_path}",
        })
        return

    file_size = path.stat().st_size
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE if file_size > 0 else 1
    hasher = hashlib.sha256()

    log.info(
        f"Transfer {transfer_id[:8]}: sending {path.name} "
        f"({file_size} bytes, {total_chunks} chunks)"
    )

    try:
        with open(path, "rb") as f:
            index = 0
            while True:
                raw = f.read(CHUNK_SIZE)
                if not raw:
                    break
                hasher.update(raw)
                b64 = base64.b64encode(raw).decode("ascii")
                await ws_send({
                    "type": "file_chunk",
                    "transfer_id": transfer_id,
                    "index": index,
                    "data": b64,
                    "total_chunks": total_chunks,
                })
                index += 1
                # Yield to event loop every chunk to avoid blocking
                await asyncio.sleep(0)

        sha256 = hasher.hexdigest()
        await ws_send({
            "type": "file_complete",
            "transfer_id": transfer_id,
            "total_chunks": index,
            "sha256": sha256,
        })
        log.info(f"Transfer {transfer_id[:8]}: all {index} chunks sent, sha256={sha256[:16]}...")

    except Exception as e:
        log.error(f"Transfer {transfer_id[:8]}: send error: {e}")
        await ws_send({
            "type": "file_error",
            "transfer_id": transfer_id,
            "error": str(e),
        })


# ── Receiver ────────────────────────────────────────────────────────


async def handle_file_offer(
    msg: dict,
    ws_send: WsSender,
) -> None:
    """Received file_offer from hub — auto-accept and prepare for receiving."""
    transfer_id = msg.get("transfer_id", "")
    filename = msg.get("filename", "unknown")
    file_size = msg.get("file_size", 0)
    sha256 = msg.get("sha256", "")
    sender_session = msg.get("sender_session", "")

    dest_dir = get_download_dir()

    # Create temp file for assembly
    fd, temp_path = tempfile.mkstemp(
        prefix=f"orc_transfer_{transfer_id[:8]}_",
        dir=dest_dir,
    )
    os.close(fd)

    incoming = IncomingTransfer(
        transfer_id=transfer_id,
        filename=filename,
        file_size=file_size,
        sha256=sha256,
        sender_session=sender_session,
        temp_path=temp_path,
        dest_dir=dest_dir,
    )
    # Open for writing
    incoming.temp_file = open(temp_path, "wb")
    _incoming_transfers[transfer_id] = incoming

    log.info(
        f"Transfer {transfer_id[:8]}: accepting '{filename}' "
        f"({file_size} bytes) from session {sender_session}"
    )

    # Auto-accept
    await ws_send({
        "type": "file_accept",
        "transfer_id": transfer_id,
    })


def handle_file_chunk(msg: dict) -> None:
    """Received a chunk — decode and append to temp file."""
    transfer_id = msg.get("transfer_id", "")
    incoming = _incoming_transfers.get(transfer_id)
    if not incoming or not incoming.temp_file:
        log.warning(f"Transfer {transfer_id[:8]}: chunk for unknown transfer")
        return

    b64_data = msg.get("data", "")
    if not b64_data:
        return

    try:
        raw = base64.b64decode(b64_data)
        incoming.temp_file.write(raw)
        incoming.chunks_received = msg.get("index", incoming.chunks_received) + 1
        incoming.total_chunks = msg.get("total_chunks", incoming.total_chunks)
    except Exception as e:
        log.warning(f"Transfer {transfer_id[:8]}: chunk decode error: {e}")


async def handle_file_complete(msg: dict, ws_send: WsSender) -> None:
    """All chunks received — verify SHA-256 and finalize."""
    transfer_id = msg.get("transfer_id", "")
    incoming = _incoming_transfers.get(transfer_id)
    if not incoming:
        log.warning(f"Transfer {transfer_id[:8]}: complete for unknown transfer")
        return

    expected_sha256 = msg.get("sha256", incoming.sha256)

    # Close temp file
    if incoming.temp_file:
        incoming.temp_file.close()
        incoming.temp_file = None

    # Verify SHA-256
    hasher = hashlib.sha256()
    try:
        with open(incoming.temp_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
    except Exception as e:
        log.error(f"Transfer {transfer_id[:8]}: hash verification read error: {e}")
        await ws_send({
            "type": "file_error",
            "transfer_id": transfer_id,
            "error": f"Hash verification failed: {e}",
        })
        _cleanup_incoming(transfer_id)
        return

    actual_sha256 = hasher.hexdigest()
    verified = actual_sha256 == expected_sha256

    if verified:
        # Move temp file to final destination
        dest_path = os.path.join(incoming.dest_dir, incoming.filename)
        # Handle name collisions
        if os.path.exists(dest_path):
            base, ext = os.path.splitext(incoming.filename)
            counter = 1
            while os.path.exists(dest_path):
                dest_path = os.path.join(incoming.dest_dir, f"{base}_{counter}{ext}")
                counter += 1
        try:
            os.rename(incoming.temp_path, dest_path)
            log.info(
                f"Transfer {transfer_id[:8]}: completed — "
                f"saved as {dest_path} (hash verified)"
            )
        except OSError:
            # Cross-device rename — fall back to copy
            import shutil
            shutil.move(incoming.temp_path, dest_path)
            log.info(
                f"Transfer {transfer_id[:8]}: completed — "
                f"saved as {dest_path} (hash verified, cross-device move)"
            )
    else:
        log.warning(
            f"Transfer {transfer_id[:8]}: SHA-256 MISMATCH — "
            f"expected {expected_sha256[:16]}..., got {actual_sha256[:16]}..."
        )
        # Clean up bad file
        try:
            os.unlink(incoming.temp_path)
        except OSError:
            pass

    await ws_send({
        "type": "file_ack",
        "transfer_id": transfer_id,
        "sha256_verified": verified,
    })

    _incoming_transfers.pop(transfer_id, None)


def _cleanup_incoming(transfer_id: str):
    """Clean up an incoming transfer on error."""
    incoming = _incoming_transfers.pop(transfer_id, None)
    if not incoming:
        return
    if incoming.temp_file:
        try:
            incoming.temp_file.close()
        except Exception:
            pass
    try:
        os.unlink(incoming.temp_path)
    except OSError:
        pass


# ── Outbound event tracking (for CLI polling) ──


def register_outbound(transfer_id: str) -> asyncio.Event:
    """Register an event for an outbound transfer so CLI can wait."""
    event = asyncio.Event()
    _outbound_events[transfer_id] = event
    return event


def resolve_outbound(transfer_id: str, result: dict):
    """Signal that an outbound transfer completed (ack/error received)."""
    _outbound_results[transfer_id] = result
    event = _outbound_events.pop(transfer_id, None)
    if event:
        event.set()


def get_outbound_result(transfer_id: str) -> dict | None:
    """Get the result of a completed outbound transfer."""
    return _outbound_results.pop(transfer_id, None)


def cleanup_all_incoming():
    """Shutdown hook — close all temp files and clean up."""
    for transfer_id in list(_incoming_transfers.keys()):
        _cleanup_incoming(transfer_id)
    log.info("All incoming transfers cleaned up")
