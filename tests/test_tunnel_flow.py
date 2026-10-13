#!/usr/bin/env python3
"""Editor tunnels: credits only after the relay says hello; window enforced; acks resume.

Run:  python3 tests/test_tunnel_flow.py
"""
import asyncio
import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import relay_client, tunnel  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


async def main():
    payload = b"z" * (4 * 1024 * 1024)

    async def serve(reader, writer):
        writer.write(payload)
        await writer.drain()
        writer.close()

    srv = await asyncio.start_server(serve, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    sent = []

    async def ws_send(m):
        sent.append(m)
        return True

    def got():
        return sum(len(base64.b64decode(m["data"])) for m in sent if m["type"] == "tunnel_data")

    fc = {"on": False}
    await relay_client.handle_relay_message({"type": "tunnel_open", "tunnel_id": "t0"}, pinned_port=port,
                                            ws_send=ws_send, on_activity=lambda: None, fc=fc)
    await asyncio.sleep(0.5)
    ok("before relay_hello: no flow control (old relay can't stall us)", got() == len(payload), got())
    tunnel.close_tunnel("t0")

    sent.clear()
    await relay_client.handle_relay_message({"type": "relay_hello", "flow_control": 1}, pinned_port=port,
                                            ws_send=ws_send, on_activity=lambda: None, fc=fc)
    ok("relay_hello enables flow control", fc["on"] is True)
    await relay_client.handle_relay_message({"type": "tunnel_open", "tunnel_id": "t1"}, pinned_port=port,
                                            ws_send=ws_send, on_activity=lambda: None, fc=fc)
    await asyncio.sleep(0.5)
    first = got()
    ok("stops at the 1 MiB window", tunnel.WINDOW <= first < tunnel.WINDOW + 64 * 1024, first)
    await relay_client.handle_relay_message({"type": "tunnel_ack", "tunnel_id": "t1", "bytes": first},
                                            pinned_port=port, ws_send=ws_send, on_activity=lambda: None, fc=fc)
    await asyncio.sleep(0.5)
    ok("resumes after an ack", got() > first, (first, got()))
    tunnel.close_tunnel("t1")
    srv.close()


asyncio.run(main())
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
