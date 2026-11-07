#!/usr/bin/env python3
"""Agent upload link against a local fake relay (a real websockets server) driving the
REAL helper as a subprocess (standard tier) in a temp folder.

Run:  python3 tests/test_uploads.py   (needs `websockets`, an agent dependency)
"""
import asyncio
import hashlib
import json
import os
import random
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import websockets  # noqa: E402

from orchestratia_agent import uploads as ul  # noqa: E402
from orchestratia_agent.privilege import TierConfig  # noqa: E402

results = []
TC = TierConfig(projects={}, tmux_path="/usr/bin/tmux", git_path="/usr/bin/git")
PORT = 18793
CS = 1024 * 1024
PIECE = 256 * 1024
FOLDER = tempfile.mkdtemp(prefix="ul-link-")
ul._folder = lambda run_as: FOLDER          # never the real /tmp/orchestratia-uploads
ul.REOPEN_WAIT = 1


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def published():
    return sorted(n for n in os.listdir(FOLDER) if not n.startswith(".orchestratia-"))


class Peer:
    """The relay's side of one /ws/relay-ul socket."""

    def __init__(self, ws):
        self.ws, self.credit, self.more = ws, 0, asyncio.Event()
        self.grants: list = []
        self.inbox: asyncio.Queue = asyncio.Queue()
        self.auth = None

    async def start(self):
        self.auth = json.loads(await self.ws.recv())
        asyncio.ensure_future(self._read())

    async def _read(self):
        try:
            async for m in self.ws:
                f = json.loads(m)
                if f["type"] == "credit":
                    self.grants.append(f["bytes"])
                    self.credit += f["bytes"]
                    self.more.set()
                else:
                    if f["type"] == "ready":
                        self.credit = ul.WINDOW         # implicit, as the real relay does
                        self.more.set()
                    await self.inbox.put(f)
        except websockets.exceptions.ConnectionClosed:
            pass
        await self.inbox.put(None)

    async def next(self, timeout=30):
        return await asyncio.wait_for(self.inbox.get(), timeout)

    async def chunk(self, offset, data, index, final, upto=None):
        await self.ws.send(json.dumps({"type": "chunk", "offset": offset, "length": len(data), "index": index,
                                       "sha256": sha(data), "final": final}))
        stop, pos = (len(data) if upto is None else upto), 0
        while pos < stop:
            piece = data[pos:min(pos + PIECE, stop)]
            while self.credit < len(piece):
                self.more.clear()
                await asyncio.wait_for(self.more.wait(), 30)
            self.credit -= len(piece)
            await self.ws.send(piece)
            pos += len(piece)


class Relay:
    def __init__(self):
        self.peers: asyncio.Queue = asyncio.Queue()

    async def handler(self, ws):
        p = Peer(ws)
        await p.start()
        await self.peers.put(p)
        await ws.wait_closed()

    async def link(self, msg, timeout=30):
        """upload_open as the relay would cause it; returns (task, peer)."""
        task = asyncio.create_task(ul.open_upload(msg, TC, api_key="orc_k"))
        return task, await asyncio.wait_for(self.peers.get(), timeout)


def open_msg(uid, name, size):
    return {"type": "upload_open", "upload_id": uid, "request_id": "R-" + uid[:4],
            "relay_url": f"ws://127.0.0.1:{PORT}", "name": name, "size": size, "chunk_size": CS,
            "privilege_tier": "standard", "project_id": None}


async def send_all(peer, data, start=0):
    """Chunks from `start` to the end; returns every frame the agent sent back."""
    out, off, i = [], start, start // CS
    while off < len(data) or (not data and not out):
        piece = data[off:off + CS]
        final = off + len(piece) == len(data)
        await peer.chunk(off, piece, i, final)
        f = await peer.next()
        out.append(f)
        if f["type"] != "ack":
            return out
        off, i = f["offset"], i + 1
        if final:
            out.append(await peer.next())
            return out
    return out


async def test_link(relay):
    # helper_argv: nothing about the upload in argv
    a = ul.helper_argv(None, TC, "ul-write", "/f")
    ok("standard argv: isolated python, op, --base only", a == [sys.executable, "-I", ul.HELPER_SOURCE,
                                                               "ul-write", "--base", "/f"], a)
    r = ul.helper_argv("orcp-abc", TC, "ul-prepare", "/f")
    ok("restricted argv: sudo -n -u <user> -H <installed helper>",
       r == ["sudo", "-n", "-u", "orcp-abc", "-H", ul.HELPER_INSTALL_PATH, "ul-prepare", "--base", "/f"], r)

    # prepare
    uid = str(uuid.uuid4())
    data = random.Random(1).randbytes(2 * CS + 12345)
    pre = await ul.prepare_request({"upload_id": uid, "name": "three.bin", "size": len(data), "chunk_size": CS,
                                    "reservation": 0, "privilege_tier": "standard", "project_id": None}, TC)
    ok("prepare: ok with folder, free space and offset 0", pre.get("ok") and pre["dir"] == FOLDER
       and pre["offset"] == 0 and pre["free_bytes"] > 0 and pre["protocol"] == 2, pre)
    bad = await ul.prepare_request({"upload_id": uid, "name": "a\u202eb", "size": 1, "chunk_size": CS,
                                    "privilege_tier": "standard"}, TC)
    ok("prepare: bidi override in the name -> invalid_name", bad.get("ok") is False
       and bad.get("error") == "invalid_name", bad)
    priv = await ul.prepare_request({"upload_id": uid, "name": "x", "size": 1, "chunk_size": CS,
                                     "privilege_tier": "restricted",
                                     "project_id": "00000000-0000-0000-0000-000000000001"}, TC)
    ok("prepare: restricted + unprovisioned -> privilege, never a fallback", priv == {"ok": False, "error": "privilege"},
       priv)

    # 3-chunk upload over one link
    task, peer = await relay.link(open_msg(uid, "three.bin", len(data)))
    ok("auth is the first frame", peer.auth == {"type": "auth", "api_key": "orc_k", "upload_id": uid,
                                                "request_id": "R-" + uid[:4]}, peer.auth)
    ready = await peer.next()
    ok("ready{offset 0, protocol 2}", ready == {"type": "ready", "offset": 0, "finalizing": False, "done": None,
                                               "protocol": 2}, ready)
    await asyncio.sleep(0.2)
    ok("no initial credit frame (the relay's window is implicit)", peer.grants == [], peer.grants)
    ok("link registered while live", uid in ul.live_links)
    frames = await send_all(peer, data)
    acks = [f for f in frames if f["type"] == "ack"]
    done = frames[-1]
    ok("grants are per link: every one 0 < n <= 4 MiB, all bytes covered", peer.grants
       and all(isinstance(n, int) and 0 < n <= ul.WINDOW for n in peer.grants)
       and len(data) - sum(peer.grants) < ul.GRANT_EVERY, (len(peer.grants), sum(peer.grants), len(data)))
    ok("three acks with the relay's digests", [a["index"] for a in acks] == [0, 1, 2]
       and acks[-1]["offset"] == len(data) and acks[0]["sha256"] == sha(data[:CS]), acks)
    ok("done with path and whole-file sha256", done["type"] == "done" and done["sha256"] == sha(data)
       and done["path"] == os.path.join(FOLDER, "three.bin"), done)
    await asyncio.wait_for(task, 15)
    ok("link ends after done and unregisters", uid not in ul.live_links)
    ok("bytes on disk are exact", open(os.path.join(FOLDER, "three.bin"), "rb").read() == data)

    # relay drops mid-chunk
    uid = str(uuid.uuid4())
    data = random.Random(2).randbytes(3 * CS)
    task, peer = await relay.link(open_msg(uid, "drop.bin", len(data)))
    await peer.next()
    await peer.chunk(0, data[:CS], 0, False)
    ok("first chunk acked", (await peer.next())["offset"] == CS)
    await peer.chunk(CS, data[CS:2 * CS], 1, False, upto=CS // 2)
    await asyncio.sleep(0.3)
    helper = ul.live_links[uid]
    await peer.ws.close()
    await asyncio.wait_for(task, 15)
    ok("relay drop -> helper killed and link unregistered", helper.returncode is not None and uid not in ul.live_links)
    task, peer = await relay.link(open_msg(uid, "drop.bin", len(data)))
    ready = await peer.next()
    part = os.path.join(FOLDER, f".orchestratia-{uid}.part")
    ok("next link resumes at the journal offset", ready["offset"] == CS, ready)
    ok("…with the half chunk rolled back", os.path.getsize(part) == CS)
    frames = await send_all(peer, data, start=CS)
    ok("…and completes exactly", frames[-1]["type"] == "done" and frames[-1]["sha256"] == sha(data), frames[-1])
    await asyncio.wait_for(task, 15)

    # relay drops during finalize (Review Focus 5, agent half)
    uid = str(uuid.uuid4())
    data = random.Random(3).randbytes(8 * CS)
    task, peer = await relay.link(open_msg(uid, "final.bin", len(data)))
    await peer.next()
    off = 0
    for i in range(8):
        await peer.chunk(off, data[off:off + CS], i, i == 7)
        a = await peer.next()
        off = a["offset"]
    await peer.ws.close()                     # right after the final ack: before (or while) finalizing
    await asyncio.wait_for(task, 15)
    task, peer = await relay.link(open_msg(uid, "final.bin", len(data)))
    ready = await peer.next()
    if ready["done"]:
        result = ready["done"]
        tail = await peer.next()
        ok("finalize had finished: ready carries done, then a done frame", tail["type"] == "done", tail)
    else:
        ok("finalize was interrupted: ready says finalizing", ready["finalizing"] is True, ready)
        result = await peer.next()
    await asyncio.wait_for(task, 15)
    ok("completed exactly once with the right hash", result["sha256"] == sha(data), result)
    ok("one published file, no duplicate", published().count("final.bin") == 1
       and not any(n.startswith("final (") for n in published()), published())
    task, peer = await relay.link(open_msg(uid, "final.bin", len(data)))
    ready = await peer.next()
    tail = await peer.next()
    ok("a third link (lost response) re-hashes and reports done, no copy", ready["finalizing"] is True
       and tail["type"] == "done" and tail["sha256"] == sha(data) and published().count("final.bin") == 1,
       (ready, tail))
    await asyncio.wait_for(task, 15)

    # duplicate open while one is live
    uid = str(uuid.uuid4())
    data = random.Random(4).randbytes(2 * CS)
    task1, peer1 = await relay.link(open_msg(uid, "dup.bin", len(data)))
    await peer1.next()
    task2, peer2 = await relay.link(open_msg(uid, "dup.bin", len(data)))
    e = await peer2.next()
    ok("second link for a live upload -> busy", e["type"] == "error" and e["code"] == "busy", e)
    await asyncio.wait_for(task2, 15)
    ok("the first link is untouched", uid in ul.live_links and ul.live_links[uid].returncode is None)

    # cancel during a live link
    await peer1.chunk(0, data[:CS], 0, False)
    await peer1.next()
    await ul.cancel({"upload_id": uid, "privilege_tier": "standard", "project_id": None}, TC)
    await asyncio.wait_for(task1, 15)
    left = [n for n in os.listdir(FOLDER) if n.startswith(f".orchestratia-{uid}")]
    ok("cancel kills the live helper and removes part + journal", left == [] and uid not in ul.live_links, left)

    # an outdated (protocol-1) helper -> helper_outdated, not a crash
    old_src = ul.HELPER_SOURCE
    fake = os.path.join(tempfile.mkdtemp(), "old_helper.py")
    with open(fake, "w") as fh:
        fh.write("import sys\nsys.stderr.write(\"dl-helper: error: argument op: invalid choice: 'ul-write'\\n\")\n"
                 "sys.exit(2)\n")
    ul.HELPER_SOURCE = fake
    try:
        uid = str(uuid.uuid4())
        task, peer = await relay.link(open_msg(uid, "old.bin", 10))
        e = await peer.next()
        ok("old helper -> error helper_outdated on the link", e["type"] == "error" and e["code"] == "helper_outdated", e)
        await asyncio.wait_for(task, 15)
        pre = await ul.prepare_request({"upload_id": uid, "name": "old.bin", "size": 10, "chunk_size": CS,
                                        "privilege_tier": "standard"}, TC)
        ok("old helper -> prepare says helper_outdated", pre == {"ok": False, "error": "helper_outdated"}, pre)
    finally:
        ul.HELPER_SOURCE = old_src

    # sweep: runs, reports nothing to remove for fresh files
    await ul.sweep_all(TC)
    ok("sweep_all leaves recent files and published uploads alone", "three.bin" in published())


async def main():
    relay = Relay()
    srv = await websockets.serve(relay.handler, "127.0.0.1", PORT, max_size=None, compression=None)
    try:
        await test_link(relay)
    finally:
        srv.close()
        await srv.wait_closed()


asyncio.run(main())
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
