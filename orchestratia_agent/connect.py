"""orchestratia-connect — SSH tunnel client tool.

Two modes:
  1. Listen mode (default): orchestratia-connect <token>
     Opens a local TCP listener, prints SSH command, relays to hub WS.

  2. Proxy mode: orchestratia-connect --proxy <token>
     SSH ProxyCommand: relays stdin/stdout to hub WS tunnel.
     Usage: ssh -o ProxyCommand="orchestratia-connect --proxy <token>" user@anything
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import signal
import ssl
import sys


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification (client-side, hub validates)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid token format")
    # Add padding
    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    raw = base64.urlsafe_b64decode(payload_b64)
    return json.loads(raw)


async def _listen_mode(token: str):
    """Listen mode: open local TCP port, relay to hub WS."""
    import websockets

    payload = _decode_jwt_payload(token)
    hub_url = payload.get("hub_url", "")
    mode = payload.get("mode", "ssh")
    session_id = payload.get("session_id", "")[:8]

    if not hub_url:
        print("Error: token does not contain hub_url", file=sys.stderr)
        sys.exit(1)

    ws_url = hub_url.replace("https://", "wss://").replace("http://", "ws://")
    target = f"{ws_url}/ws/tunnel"

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    print(f"\033[38;2;212;114;47m")
    print(f"  Orchestratia Connect")
    print(f"  Mode: {mode} | Session: {session_id}...")
    print(f"  Connecting to {hub_url}...")
    print(f"\033[0m")

    ws = await websockets.connect(
        target,
        ssl=ssl_ctx if ws_url.startswith("wss") else None,
        ping_interval=30,
        ping_timeout=10,
        max_size=2**20,
    )

    # Authenticate
    await ws.send(json.dumps({"type": "auth", "token": token}))
    resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
    if resp.get("type") != "auth_ok":
        print(f"Error: authentication failed: {resp}", file=sys.stderr)
        await ws.close()
        sys.exit(1)

    tunnel_id = resp.get("tunnel_id", "")

    # Open local TCP listener
    local_conn: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        nonlocal local_conn
        if local_conn is not None:
            # Only one connection at a time
            writer.close()
            return
        local_conn = (reader, writer)

        # TCP → WS relay
        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                b64 = base64.b64encode(data).decode("ascii")
                await ws.send(json.dumps({
                    "type": "tunnel_data",
                    "data": b64,
                }))
        except Exception:
            pass
        finally:
            writer.close()
            local_conn = None

    tcp_server = await asyncio.start_server(handle_client, "127.0.0.1", 0)
    port = tcp_server.sockets[0].getsockname()[1]

    print(f"\033[38;2;212;114;47m")
    print(f"  Tunnel ready! Local port: {port}")
    print(f"  Connect with:")
    print(f"\033[0m")
    print(f"  ssh -p {port} user@127.0.0.1")
    print()
    print("  Press Ctrl+C to disconnect.")
    print()

    # WS → TCP relay
    try:
        async for raw in ws:
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "tunnel_data":
                if local_conn:
                    _, writer = local_conn
                    raw_data = base64.b64decode(msg["data"])
                    writer.write(raw_data)
                    await writer.drain()

            elif msg_type == "tunnel_close":
                reason = msg.get("reason", "")
                print(f"\n  Tunnel closed: {reason}")
                break

            elif msg_type == "pong":
                pass
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(f"\n  Connection lost: {e}", file=sys.stderr)
    finally:
        tcp_server.close()
        await tcp_server.wait_closed()
        try:
            await ws.close()
        except Exception:
            pass


async def _proxy_mode(token: str):
    """Proxy mode: relay stdin/stdout to hub WS tunnel (SSH ProxyCommand)."""
    import websockets

    payload = _decode_jwt_payload(token)
    hub_url = payload.get("hub_url", "")

    if not hub_url:
        print("Error: token does not contain hub_url", file=sys.stderr)
        sys.exit(1)

    ws_url = hub_url.replace("https://", "wss://").replace("http://", "ws://")
    target = f"{ws_url}/ws/tunnel"

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    ws = await websockets.connect(
        target,
        ssl=ssl_ctx if ws_url.startswith("wss") else None,
        ping_interval=30,
        ping_timeout=10,
        max_size=2**20,
    )

    # Authenticate
    await ws.send(json.dumps({"type": "auth", "token": token}))
    resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
    if resp.get("type") != "auth_ok":
        print(f"Error: auth failed: {resp}", file=sys.stderr)
        await ws.close()
        sys.exit(1)

    loop = asyncio.get_event_loop()

    # stdin → WS
    async def stdin_to_ws():
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        try:
            while True:
                data = await reader.read(16384)
                if not data:
                    break
                b64 = base64.b64encode(data).decode("ascii")
                await ws.send(json.dumps({"type": "tunnel_data", "data": b64}))
        except Exception:
            pass

    # WS → stdout
    async def ws_to_stdout():
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "tunnel_data":
                    raw_data = base64.b64decode(msg["data"])
                    sys.stdout.buffer.write(raw_data)
                    sys.stdout.buffer.flush()
                elif msg.get("type") == "tunnel_close":
                    break
        except Exception:
            pass

    # Run both tasks, exit when either finishes
    done, pending = await asyncio.wait(
        [asyncio.create_task(stdin_to_ws()), asyncio.create_task(ws_to_stdout())],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for task in pending:
        task.cancel()

    try:
        await ws.close()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(
        prog="orchestratia-connect",
        description="SSH tunnel client for Orchestratia",
    )
    parser.add_argument("token", help="Tunnel token from dashboard")
    parser.add_argument(
        "--proxy", action="store_true",
        help="ProxyCommand mode: relay stdin/stdout (for ssh -o ProxyCommand=...)",
    )
    args = parser.parse_args()

    if args.proxy:
        asyncio.run(_proxy_mode(args.token))
    else:
        try:
            asyncio.run(_listen_mode(args.token))
        except KeyboardInterrupt:
            print("\n  Disconnected.")


if __name__ == "__main__":
    main()
