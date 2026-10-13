#!/usr/bin/env python3
"""Agent download streaming against a local fake relay (real websockets server).

Run:  python3 tests/test_downloads.py   (needs `websockets`, an agent dependency)
"""
import asyncio
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import websockets  # noqa: E402

from orchestratia_agent import downloads as dl  # noqa: E402
from orchestratia_agent.privilege import TierConfig  # noqa: E402

results = []
TC = TierConfig(projects={}, tmux_path="/usr/bin/tmux", git_path="/usr/bin/git")


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def test_argv():
    a = dl.helper_argv(None, TC, ["stat", "--cwd", "/w"], "-x")
    ok("standard: this python, isolated, the package's helper file",
       a[:3] == [sys.executable, "-I", dl.HELPER_SOURCE], a[:3])
    ok("path goes after --", a[-2:] == ["--", "-x"], a[-2:])
    r = dl.helper_argv("orcp-abc", TC, ["stat", "--cwd", "/w"], "x")
    ok("restricted: sudo -n -u <user> -H <installed helper>",
       r[:6] == ["sudo", "-n", "-u", "orcp-abc", "-H", dl.HELPER_INSTALL_PATH], r[:6])


async def fake_relay(handler, port):
    return await websockets.serve(handler, "127.0.0.1", port, max_size=None, compression=None)


async def test_stream():
    frames, done = [], asyncio.Event()
    credit_mode = {"grant": True}

    async def relay(ws):
        async for m in ws:
            frames.append(m)
            if isinstance(m, bytes) and credit_mode["grant"]:
                await ws.send(json.dumps({"type": "credit", "bytes": len(m)}))
            if isinstance(m, str) and json.loads(m)["type"] in ("end", "error"):
                done.set()

    srv = await fake_relay(relay, 18767)
    try:
        with tempfile.TemporaryDirectory() as d:
            data = os.urandom(6 * 1024 * 1024)
            open(os.path.join(d, "f.bin"), "wb").write(data)
            st = await dl.stat_request({"path": "f.bin", "working_dir": d, "privilege_tier": "standard",
                                        "project_id": None}, TC)
            ok("stat_request", st.get("ok") and st["size"] == len(data), st)
            msg = {"download_id": "D", "request_id": "R", "relay_url": "ws://127.0.0.1:18767", "path": "f.bin",
                   "kind": "file", "privilege_tier": "standard", "project_id": None, "working_dir": d,
                   "method": "GET", "range": "bytes=100-", "if_range": None}
            await asyncio.wait_for(dl.open_download(msg, TC, api_key="orc_k"), 30)
            await asyncio.wait_for(done.wait(), 10)
            ok("auth first", json.loads(frames[0]) == {"type": "auth", "api_key": "orc_k", "download_id": "D",
                                                       "request_id": "R"})
            head = json.loads(frames[1])
            ok("head is structured (no headers field)", head["type"] == "head" and "headers" not in head
               and head["status"] == 206 and head["offset"] == 100 and head["size"] == len(data), head)
            body = b"".join(f for f in frames[2:-1] if isinstance(f, bytes))
            ok("exact range delivered", body == data[100:], len(body))
            ok("end reports bytes", json.loads(frames[-1]) == {"type": "end", "bytes": len(data) - 100})

            # Without credit the agent must stop at the window.
            frames.clear(); done.clear(); credit_mode["grant"] = False
            task = asyncio.create_task(dl.open_download(dict(msg, range=None), TC, api_key="orc_k"))
            await asyncio.sleep(2.0)
            sent = sum(len(f) for f in frames if isinstance(f, bytes))
            ok("stops at the 4 MiB credit window", dl.WINDOW - 256 * 1024 <= sent <= dl.WINDOW, sent)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            credit_mode["grant"] = True

            frames.clear(); done.clear()
            await dl.open_download(dict(msg, path="nope", range=None), TC, api_key="orc_k")
            await asyncio.wait_for(done.wait(), 10)
            err = json.loads(frames[1])
            ok("missing file -> error frame", err["type"] == "error" and err["code"] == "not_found", err)

            st = await dl.stat_request({"path": "f.bin", "working_dir": d, "privilege_tier": "restricted",
                                        "project_id": "00000000-0000-0000-0000-000000000001"}, TC)
            ok("restricted + unprovisioned -> privilege, never a fallback", st.get("error") == "privilege", st)
    finally:
        srv.close()
        await srv.wait_closed()


async def test_teardown_does_not_hang():
    # A child that ignores its stdout and keeps the pipe open (like a sudo'd helper
    # after its parent is killed) must not hang teardown.
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", "import time,sys; sys.stdout.write('x'*10); sys.stdout.flush(); time.sleep(60)",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    t0 = asyncio.get_running_loop().time()
    await dl._stop(proc)
    ok("teardown finishes promptly", asyncio.get_running_loop().time() - t0 < 8 and proc.returncode is not None)


test_argv()
asyncio.run(test_stream())
asyncio.run(test_teardown_does_not_hang())
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
