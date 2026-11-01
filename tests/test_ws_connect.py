#!/usr/bin/env python3
"""connect_ws never leaves a socket open behind a failed attempt.

An attempt whose auth reply is late used to be dropped without closing it. The hub
had already authenticated it, so it stayed registered next to the retry; the hub
now copes with that, but the socket still lingered, kept alive by our own pings.

Run:  python3 tests/test_ws_connect.py
"""
import asyncio
import base64
import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import websockets  # noqa: E402

from orchestratia_agent import hub  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class State:
    def __init__(self, port):
        self.hub_url = f"http://127.0.0.1:{port}"
        self.api_key = "orc_test"
        self.insecure = True


async def main():
    mode = {"reply": "late"}
    closed = []

    async def handler(ws):
        await ws.recv()
        if mode["reply"] == "late":
            # Answer only after the agent's wait — if it is still connected by then.
            try:
                await asyncio.wait_for(ws.wait_closed(), hub.AUTH_REPLY_TIMEOUT + 3)
                closed.append(time.monotonic())
            except asyncio.TimeoutError:
                await ws.send(json.dumps({"type": "auth_ok"}))
            return
        elif mode["reply"] == "ok":
            await ws.send(json.dumps({"type": "auth_ok"}))
        else:
            await ws.send(json.dumps({"type": "auth_error"}))
        try:
            await ws.wait_closed()
        finally:
            closed.append(time.monotonic())

    default_wait = getattr(hub, "AUTH_REPLY_TIMEOUT", 5)
    hub.AUTH_REPLY_TIMEOUT = 0.5
    async with websockets.serve(handler, "127.0.0.1", 0) as srv:
        port = srv.sockets[0].getsockname()[1]
        state = State(port)

        # Late auth reply: the attempt fails AND its socket is closed.
        t0 = time.monotonic()
        ws = await hub.connect_ws(state)
        ok("a late auth reply fails the attempt", ws is None)
        await asyncio.sleep(0.3)
        ok("...and the abandoned socket is closed, not left open", len(closed) == 1 and closed[0] - t0 < 2,
           closed)

        # Refused auth: closed too (this path already closed).
        mode["reply"] = "refused"
        closed.clear()
        ok("a refused auth fails the attempt", await hub.connect_ws(state) is None)
        await asyncio.sleep(0.3)
        ok("...and its socket is closed", len(closed) == 1)

        # Normal auth still returns a live socket.
        mode["reply"] = "ok"
        closed.clear()
        ws = await hub.connect_ws(state)
        ok("a prompt auth_ok returns the socket", ws is not None)
        await asyncio.sleep(0.2)
        ok("...left open", not closed)
        await ws.close()

    ok("the default auth wait leaves room for a slow hub", default_wait >= 15, default_wait)

    # A hub that never answers the close: _discard is bounded AND really drops the socket
    # (cancelling websockets' close() alone leaves it open until the next ping).
    peer_eof = asyncio.Event()

    async def mute(reader, writer):
        req = b""
        while b"\r\n\r\n" not in req:
            req += await reader.read(4096)
        key = [ln.split(b": ")[1] for ln in req.split(b"\r\n")
               if ln.lower().startswith(b"sec-websocket-key")][0]
        accept = base64.b64encode(hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
        writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n")
        while await reader.read(4096):   # swallow everything, never answer
            pass
        peer_eof.set()

    srv = await asyncio.start_server(mute, "127.0.0.1", 0)
    ws = await websockets.connect(f"ws://127.0.0.1:{srv.sockets[0].getsockname()[1]}", ping_interval=30)
    t0 = time.monotonic()
    await hub._discard(ws)
    took = time.monotonic() - t0
    ok("discarding against a hub that never answers the close is bounded", took < 2.5, f"{took:.2f}s")
    try:
        await asyncio.wait_for(peer_eof.wait(), 1)
        dropped = True
    except asyncio.TimeoutError:
        dropped = False
    ok("...and the socket is really dropped", dropped)
    srv.close()

    print(f"\n{sum(results)}/{len(results)} passed")
    return all(results)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
