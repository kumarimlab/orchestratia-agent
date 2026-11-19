#!/usr/bin/env python3
"""Adversarial review M3: a restricted session could hijack its own snapshot helper (SIGSTOP it, open
/proc/<pid>/fd/1, write any stream) — 2.25 GiB went past the 2 GiB cap into the host's /var, and a
stopped helper held a scan slot for ~17 minutes. Every layer now bounds it:

  helper   non-dumpable from the start (its /proc/<pid>/fd is no longer openable by its own uid)
  runner   caps the bytes it forwards, fails a body that stops arriving, fails a helper that
           didn't exit cleanly
  shim     caps member count and total member bytes while unpacking; a 000-mode directory in
           the stream can't hide the files under it

Run:  python3 tests/test_scan_stream_caps.py
"""
import asyncio
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import runner  # noqa: E402

runner._SWEEP_DONE.set()
HELPER = os.path.join(HERE, "orchestratia_agent", "dl_helper.py")
SHIM = os.path.join(HERE, "orchestratia_agent", "scanning", "shim.py")
_RD = tempfile.mkdtemp()
open(os.path.join(_RD, "shim.py"), "w").write("")
for _f in runner.pack.RUNNER_FILES:
    open(os.path.join(_RD, _f), "w").write("")
    os.chmod(os.path.join(_RD, _f), 0o644)            # the runner refuses a group-writable scanner tree (L3)
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


# ---------------------------------------------------------------- helper: stdout can't be re-opened
# Raced like the reviewer's PoC: a sibling of the helper's uid polls /proc, SIGSTOPs the helper the
# moment it appears (before any of its own code runs) and tries to open its stdout for writing.
import signal  # noqa: E402
import threading  # noqa: E402


def hijack_attempt(marker, outcome):
    me, deadline = os.getuid(), time.time() + 30
    while time.time() < deadline:
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                cmd = open(f"/proc/{pid}/cmdline", "rb").read()
                if os.stat(f"/proc/{pid}").st_uid != me or marker.encode() not in cmd or b"snap" not in cmd:
                    continue
                os.kill(int(pid), signal.SIGSTOP)
                try:
                    open(f"/proc/{pid}/fd/1", "wb", buffering=0).close()
                    outcome.append("opened")
                except OSError as e:
                    outcome.append(__import__("errno").errorcode.get(e.errno, str(e.errno)))
                finally:
                    os.kill(int(pid), signal.SIGCONT)
                return
            except (OSError, ValueError):
                continue
    outcome.append("helper not seen")


with tempfile.TemporaryDirectory() as td:
    repo = os.path.join(td, "hijack-target")
    os.makedirs(repo)
    for i in range(200):
        with open(os.path.join(repo, f"f{i}"), "w") as f:
            f.write("x" * 100)
    outcome = []
    t = threading.Thread(target=hijack_attempt, args=(repo, outcome))
    t.start()

    async def snap_once():
        hdr, body, rc, stop = await runner._default_snapshot({"working_directory": repo, "privilege_tier": "standard"},
                                                            None, False)
        n = 0
        async for b in body:
            n += len(b)
        await stop()
        return hdr, n
    hdr, n = asyncio.run(snap_once())
    t.join()
    ok("M3 the snapshot helper's stdout can't be re-opened through /proc, even stopped right at exec",
       outcome and outcome[0] not in ("opened", "helper not seen") and hdr.get("ok") and n > 0, (outcome, hdr, n))


# ---------------------------------------------------------------- runner: cap, stall, helper exit
class FakeHub:
    def __init__(self):
        self.calls = []

    async def post(self, path, body):
        self.calls.append((path, body))
        return 200


class FakeProc:
    """A sandbox that reads stdin until EOF (like the shim's unpack), then ends with `status`."""

    def __init__(self, status="done"):
        self.returncode, self.got, self.closed = None, 0, asyncio.Event()
        outer = self

        class W:
            def write(s, b):
                outer.got += len(b)

            async def drain(s):
                await asyncio.sleep(0)

            def close(s):
                outer.closed.set()
        self.stdin = W()
        self.status = status

        class R:
            def __init__(s):
                s.sent = False

            async def readline(s):
                if s.sent:
                    return b""
                await outer.closed.wait()
                s.sent = True
                return json.dumps({"type": "end", "status": outer.status, "error": None}).encode() + b"\n"
        self.stdout = R()

    async def wait(self):
        self.returncode = 0
        return 0


async def _stop_true(rid):
    return True


MSG = {"type": "scan_run", "run_id": "11111111-2222-3333-4444-555555555555", "scan_id": "code.agent",
       "catalog_version": "1", "session_id": "s1", "project_id": "p1", "privilege_tier": "standard",
       "working_directory": "/srv/app", "params": {"since": None}}


async def go(snapshot, **kw):
    hub, procs = FakeHub(), []

    async def launch(argv):
        procs.append(FakeProc())
        return procs[-1]
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snapshot, support=lambda: (True, "ok"),
                          stop=_stop_true, runner_dir=_RD, trusted_uids=(0, os.getuid()), run_grace=5, **kw)
    await r.handle(dict(MSG))
    return hub.calls[-1][1], procs


def snap_of(chunks, rc=0, stall=False):
    async def snapshot(*a, **k):
        async def gen():
            for c in chunks:
                yield c
            if stall:
                await asyncio.sleep(3600)
        return {"ok": True}, gen(), (lambda: rc)
    return snapshot


old_max = runner.STREAM_MAX if hasattr(runner, "STREAM_MAX") else None
runner.STREAM_MAX = 10_000
done, procs = asyncio.run(go(snap_of([b"x" * 4096] * 10)))
ok("M3 the runner stops forwarding past the stream cap and fails the run",
   done["status"] == "failed" and "too large" in (done["error"] or "") and procs and procs[0].got <= 10_000 + 4096 + 512,
   (done, procs and procs[0].got))
runner.STREAM_MAX = old_max if old_max is not None else runner.STREAM_MAX

runner.BODY_STALL_S = 0.5
t0 = time.monotonic()
done, procs = asyncio.run(go(snap_of([b"x" * 100], stall=True)))
ok("M3 a snapshot body that stops arriving fails the run promptly (no slot held)",
   done["status"] == "failed" and "stopped arriving" in (done["error"] or "") and time.monotonic() - t0 < 5,
   (done, time.monotonic() - t0))

# N4: SIGSTOP/SIGCONT (a chunk every so often) resets the stall timer; an overall deadline still ends it
def trickle():
    async def snapshot(*a, **k):
        async def gen():
            while True:
                yield b"x"
                await asyncio.sleep(0.2)
        return {"ok": True}, gen(), (lambda: None)
    return snapshot


runner.SNAPSHOT_DEADLINE_S = 1.5
t0 = time.monotonic()
done, procs = asyncio.run(go(trickle()))
ok("N4 a snapshot trickling in under the stall timer still ends at the overall deadline",
   done["status"] == "failed" and "took too long" in (done["error"] or "") and time.monotonic() - t0 < 6,
   (done, round(time.monotonic() - t0, 2)))
runner.SNAPSHOT_DEADLINE_S = None

done, procs = asyncio.run(go(snap_of([b"x" * 100], rc=-9)))
ok("M3 a helper that didn't exit cleanly (killed) fails the run", done["status"] == "failed", done)
done, procs = asyncio.run(go(snap_of([b"x" * 100], rc=0)))
ok("M3 control: a complete stream from a clean helper keeps the sandbox's result", done["status"] == "done", done)


# ---------------------------------------------------------------- shim: unpack caps, dir modes
def tar_bytes(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|", format=tarfile.PAX_FORMAT) as tf:
        for ti, data in members:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return buf.getvalue()


def file_ti(name, size):
    ti = tarfile.TarInfo(name)
    ti.size = size
    return ti


def run_shim(body, env_extra=None):
    with tempfile.TemporaryDirectory() as tmp:
        env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "TMPDIR": tmp, **(env_extra or {})}
        hdr = {"scan_id": "code.agent", "since": None, "tools": {}, "osv_db": None, "data_as_of": None, "known": []}
        p = subprocess.run([sys.executable, "-I", SHIM], input=json.dumps(hdr).encode() + b"\n" + body,
                           capture_output=True, timeout=120, env=env)
        return [json.loads(x) for x in p.stdout.splitlines() if x.strip()]


sys.path.insert(0, os.path.join(HERE, "orchestratia_agent", "scanning"))
import shim  # noqa: E402
ok("M3 the shim's unpack caps mirror the snapshot caps", getattr(shim, "UNPACK_MAX_ENTRIES", None) == 200_000
   and getattr(shim, "UNPACK_MAX_BYTES", None) == 2 * 1024 ** 3)
many = tar_bytes([(file_ti(f"f{i}", 0), b"") for i in range(30)])
lines = run_shim(many, {"ORC_UNPACK_MAX_ENTRIES_FOR_TEST": "20"})
ok("M3 more members than the cap → the run fails 'too large'",
   lines and lines[-1]["status"] == "failed" and "too large" in (lines[-1]["error"] or ""), lines[-1:])
big = tar_bytes([(file_ti("a", 6000), b"a" * 6000), (file_ti("b", 6000), b"b" * 6000)])
lines = run_shim(big, {"ORC_UNPACK_MAX_BYTES_FOR_TEST": "10000"})
ok("M3 more member bytes than the cap → the run fails 'too large'",
   lines and lines[-1]["status"] == "failed" and "too large" in (lines[-1]["error"] or ""), lines[-1:])
d = tarfile.TarInfo("locked")
d.type, d.mode = tarfile.DIRTYPE, 0o000
body = tar_bytes([(d, None), (file_ti("locked/notes.py", 22), b"x = 1  # noqa\n12345678")])
lines = run_shim(body)
fs = [x["finding"]["location"]["path"] for x in lines if x.get("type") == "finding"]
ok("M3 a 000-mode directory in the stream doesn't hide the files under it", "locked/notes.py" in fs, (fs, lines[-1:]))


# ---------------------------------------------------------------- round 4: a snapshot cut off at a file boundary
# (root E2E: the session SIGSTOPs its helper; sudo stops itself; the helper is killed. The stream ends at a
# member boundary with no end-of-archive marker and the helper's exit code stays None.)
def cut_tar(n_files):
    """Members only — no end-of-archive blocks — like a stream cut off between two files."""
    out = b""
    for i in range(n_files):
        data = b"x = 1  # noqa\n"
        ti = file_ti(f"f{i}.py", len(data))
        out += ti.tobuf(format=tarfile.PAX_FORMAT) + data + b"\0" * (-len(data) % 512)
    return out


lines = run_shim(cut_tar(5))
fs = [x for x in lines if x.get("type") == "finding"]
ok("R4 a tar stream cut at a member boundary (no end-of-archive marker) fails, before any finding",
   lines and lines[-1]["status"] == "failed" and not fs, (len(fs), lines[-1:]))
lines = run_shim(cut_tar(5) + b"\0" * 512)
ok("R4 one zero block is not an end-of-archive marker (two are)", lines and lines[-1]["status"] == "failed",
   lines[-1:])
lines = run_shim(cut_tar(5) + b"\0" * 1024)
fs = [x for x in lines if x.get("type") == "finding"]
ok("R4 control: the same members with the two-block marker scan normally", lines and lines[-1]["status"] == "done"
   and len(fs) == 5, (len(fs), lines[-1:]))


class FindingsProc(FakeProc):
    """A sandbox that, once stdin closes, reports 3 findings and done."""

    def __init__(self):
        super().__init__()
        outer = self
        F = {"scan_id": "code.agent", "rule_id": "agent:x", "severity": "low", "title": "t", "description": "",
             "location": {"kind": "file", "path": "a.py", "line": 1}, "evidence": "",
             "references": {"cwe": [], "cve": [], "urls": []}, "tool": "orchestratia", "tool_version": "1"}
        items = [json.dumps({"type": "finding", "finding": F}).encode() + b"\n"] * 3 + [
            json.dumps({"type": "end", "status": "done", "error": None}).encode() + b"\n"]

        class R:
            async def readline(s):
                await outer.closed.wait()
                return items.pop(0) if items else b""
        self.stdout = R()


async def go_findings(rc):
    hub = FakeHub()

    async def launch(argv):
        return FindingsProc()
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snap_of([b"x" * 100], rc=rc), support=lambda: (True, "ok"),
                          stop=_stop_true, runner_dir=_RD, trusted_uids=(0, os.getuid()), run_grace=5, feed_grace=0.3)
    await r.handle(dict(MSG))
    return hub.calls


calls = asyncio.run(go_findings(None))
done = calls[-1][1]
ok("R4 a helper that never exited (rc None) fails the run, and no finding is uploaded",
   done["status"] == "failed" and "didn't finish" in (done["error"] or "")
   and not [c for c in calls if c[0].endswith("/findings")], (done, [c[0] for c in calls]))
calls = asyncio.run(go_findings(0))
ok("R4 control: a helper that exited 0 → findings uploaded, done",
   calls[-1][1]["status"] == "done" and [c for c in calls if c[0].endswith("/findings")], calls[-1][1])
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
