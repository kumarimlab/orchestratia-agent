#!/usr/bin/env python3
"""The runner: ack, snapshot as the session user, sandbox, validate, upload, complete —
with a fake hub, a fake snapshot and a fake sandbox, so it runs without root.

Run:  python3 tests/test_scan_runner.py
"""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import privilege_surface  # noqa: E402
from orchestratia_agent.scanning import runner  # noqa: E402
runner._SWEEP_DONE.set()
import tempfile  # noqa: E402
_RD = tempfile.mkdtemp()
open(os.path.join(_RD, 'shim.py'), 'w').write('')
for _f in runner.pack.RUNNER_FILES:
    open(os.path.join(_RD, _f), "w").write("")
    os.chmod(os.path.join(_RD, _f), 0o644)            # the runner refuses a group-writable scanner tree (L3)

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class FakeHub:
    def __init__(self, ack=200):
        self.calls, self.ack = [], ack

    async def post(self, path, body):
        self.calls.append((path, body))
        return self.ack if path.endswith("/ack") else 200


class FakeProc:
    def __init__(self, lines, rc=0, block=False):
        self.lines, self.returncode, self._rc, self.block = lines, None, rc, block
        self.stdin_data = b""

        class W:
            def __init__(s):
                s.buf = []

            def write(s, b):
                self.stdin_data += b

            async def drain(s):
                pass

            def close(s):
                pass

            async def wait_closed(s):
                pass
        self.stdin = W()

        class R:
            def __init__(s, items):
                s.items = list(items)

            async def readline(s):
                if self.block:
                    await asyncio.sleep(3600)
                return (s.items.pop(0) + b"\n") if s.items else b""
        self.stdout = R([json.dumps(x).encode() for x in lines])

    async def wait(self):
        self.returncode = self._rc
        return self._rc


async def snapshot_ok(*a, **k):
    async def gen():
        yield b"TARBYTES"
    return {"ok": True}, gen(), (lambda: 0)


MSG = {"type": "scan_run", "run_id": "11111111-2222-3333-4444-555555555555", "scan_id": "code.secrets",
       "catalog_version": "1", "session_id": "s1", "project_id": "p1", "privilege_tier": "standard",
       "working_directory": "/srv/app", "params": {"since": None, "exclude": ["vendor"]}}
F = {"scan_id": "code.secrets", "rule_id": "gitleaks:k", "severity": "high", "title": "Key",
     "description": "", "location": {"kind": "file", "path": "a.py", "line": 1}, "evidence": "Cookie: a=b",
     "references": {"cwe": [], "cve": [], "urls": []}, "tool": "gitleaks", "tool_version": "8"}


async def _stop_true(rid):
    return True


async def go(hub, lines, rc=0, msg=MSG, support=(True, "ok"), snapshot=snapshot_ok, stop=None, **kw):
    procs = []

    async def launch(argv):
        p = FakeProc(lines, rc, block=kw.pop('block', False)) if False else FakeProc(lines, rc)
        procs.append((argv, p))
        return p
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snapshot, support=lambda: support,
                          stop=stop or _stop_true,
                          runner_dir=_RD, trusted_uids=(0, os.getuid()), **kw)
    await r.handle(dict(msg))
    return procs


hub = FakeHub()
procs = asyncio.run(go(hub, [{"type": "meta", "tool_version": "8", "data_as_of": None, "manifests_scanned": []},
                             {"type": "finding", "finding": F}, {"type": "end", "status": "done", "error": None}]))
paths = [c[0] for c in hub.calls]
ok("acks, uploads findings, completes — in that order",
   paths == [f"/server/security/runs/{MSG['run_id']}/{x}" for x in ("ack", "findings", "complete")], paths)
up = hub.calls[1][1]["findings"]
ok("findings are re-masked by the daemon", up and "a=b" not in json.dumps(up), up)
done = hub.calls[-1][1]
ok("complete says done, isolation systemd, tool version", done["status"] == "done" and done["isolation"] == "systemd"
   and done["tool_version"] == "8", done)
sent = procs[0][1].stdin_data
hdr = json.loads(sent.split(b"\n", 1)[0])
ok("the sandbox gets a header line then the snapshot bytes", hdr["scan_id"] == "code.secrets"
   and sent.endswith(b"TARBYTES"), sent[:120])
ok("the header carries no hub credentials", "api_key" not in json.dumps(hdr).lower())
ok("the runner launches what sandbox.launch_argv says (sudo + launcher when not root)",
   procs[0][0] == runner.sandbox.launch_argv(MSG["run_id"], runner.catalog.CATALOG["code.secrets"]), procs[0][0])

# The launcher's own exits (a non-root daemon runs it through sudo) never read as "out of memory".
_saved_lo, _saved_ar = runner.sandbox.launcher_ok, runner.sandbox.as_root
try:
    runner.sandbox.as_root = lambda: False
    for _rc, _word in ((64, "out of date"), (77, "root-owned")):
        hub = FakeHub()
        asyncio.run(go(hub, [], rc=_rc))
        _c = hub.calls[-1][1]
        ok(f"launcher exit {_rc} -> a plain launcher message, not out of memory",
           _c["status"] == "failed" and "launcher" in _c["error"] and _word in _c["error"]
           and "memory" not in _c["error"] and "scanners install" in _c["error"], _c)
    _lo_kw = []
    runner.sandbox.launcher_ok = lambda *a, **k: _lo_kw.append(k) or (False, "sudo doesn't let the agent run the scan launcher; run: sudo orchestratia scanners install")
    hub = FakeHub()
    asyncio.run(go(hub, [], rc=1))
    _c = hub.calls[-1][1]
    ok("sudo refusing the launcher (rc 1, no output) -> the launcher's reason",
       "sudo doesn't let" in _c["error"] and "memory" not in _c["error"], _c)
    ok("a launcher failure re-checks sudo, bypassing the cached answer (fresh=True)",
       _lo_kw and _lo_kw[-1].get("fresh") is True, _lo_kw)
    runner.sandbox.launcher_ok = lambda *a, **k: (True, "ok")
    hub = FakeHub()
    asyncio.run(go(hub, [], rc=1))
    ok("rc 1 while sudo still allows the launcher -> the sandbox's own failure text",
       "memory" in hub.calls[-1][1]["error"], hub.calls[-1][1])
    runner.sandbox.as_root = lambda: True
    hub = FakeHub()
    asyncio.run(go(hub, [], rc=64))
    ok("a root daemon (no launcher) keeps the sandbox's own failure text for any rc",
       "memory" in hub.calls[-1][1]["error"], hub.calls[-1][1])
finally:
    runner.sandbox.launcher_ok, runner.sandbox.as_root = _saved_lo, _saved_ar

hub = FakeHub(ack=409)
asyncio.run(go(hub, []))
ok("a refused ack stops the run without completing", [c[0].rsplit("/", 1)[1] for c in hub.calls] == ["ack"])

hub = FakeHub()
asyncio.run(go(hub, [], support=(False, "systemd 249 is older than 250")))
ok("no sandbox → failed with the reason, nothing launched",
   hub.calls[-1][1]["status"] == "failed" and "can't sandbox" in hub.calls[-1][1]["error"], hub.calls[-1])

hub = FakeHub()
asyncio.run(go(hub, [], msg=dict(MSG, scan_id="web.active")))
ok("an unknown scan → failed", hub.calls[-1][1]["status"] == "failed" and "unknown scan" in hub.calls[-1][1]["error"])

hub = FakeHub()
asyncio.run(go(hub, [], msg=dict(MSG, params={"since": "HEAD; rm -rf /"})))
ok("a non-sha base → failed before anything runs", hub.calls[-1][1]["status"] == "failed")


async def snapshot_refused(*a, **k):
    return {"ok": False, "error": "refused_home"}, None, (lambda: 2)


hub = FakeHub()
asyncio.run(go(hub, [], snapshot=snapshot_refused))
ok("a refused snapshot → failed with a plain reason",
   hub.calls[-1][1]["status"] == "failed" and "home" in hub.calls[-1][1]["error"].lower(), hub.calls[-1])


async def snapshot_too_big(*a, **k):
    async def gen():
        yield b"x"
    return {"ok": True}, gen(), (lambda: 3)


hub = FakeHub()
asyncio.run(go(hub, [{"type": "end", "status": "failed", "error": "could not read the snapshot"}], snapshot=snapshot_too_big))
ok("snapshot cap exceeded → 'repository too large to scan'",
   hub.calls[-1][1]["error"] == "repository too large to scan", hub.calls[-1])

hub = FakeHub()
asyncio.run(go(hub, ["not json", {"type": "finding", "finding": {"evil": 1}}, {"type": "end", "status": "done"}]))
ok("garbage lines and malformed findings are dropped, run still completes",
   hub.calls[-1][1]["status"] == "done" and not any(c[0].endswith("/findings") for c in hub.calls))

hub = FakeHub()
asyncio.run(go(hub, [{"type": "meta", "tool_version": "8"}], rc=1))
ok("a sandbox that dies without an end line → failed", hub.calls[-1][1]["status"] == "failed", hub.calls[-1])

ok("validate_finding enforces caps",
   len(runner.validate_finding(dict(F, evidence="e" * 5000))["evidence"]) == 2048
   and runner.validate_finding(dict(F, severity="apocalyptic")) is None)

ok("scan_run and scan_cancel are classified SANDBOXED",
   privilege_surface.PRIVILEGE_CLASSIFICATION.get("scan_run") == privilege_surface.SANDBOXED
   and privilege_surface.PRIVILEGE_CLASSIFICATION.get("scan_cancel") == privilege_surface.SANDBOXED)


async def snapshot_cred(*a, **k):
    return {"ok": False, "error": "refused_cred"}, None, (lambda: 2)


hub = FakeHub()
asyncio.run(go(hub, [], snapshot=snapshot_cred))
ok("a credentials folder → plain refusal", hub.calls[-1][1]["status"] == "failed"
   and "credentials folder" in hub.calls[-1][1]["error"], hub.calls[-1])

stopped = []


async def stop_false(rid):
    stopped.append(rid)
    return False


hub = FakeHub()
import logging  # noqa: E402


class H(logging.Handler):
    def __init__(s):
        super().__init__()
        s.msgs = []

    def emit(s, r):
        s.msgs.append((r.levelno, r.getMessage()))


h = H()
logging.getLogger("orchestratia.scan").addHandler(h)
try:
    asyncio.run(go(hub, [{"type": "end", "status": "done", "error": None}], stop=stop_false))
    raised = False
except Exception:
    raised = True
ok("M7 stop() returning False → logged, complete failed 'sandbox couldn't be cleaned up'",
   not raised and stopped == [MSG["run_id"]] and hub.calls[-1][1]["status"] == "failed"
   and hub.calls[-1][1]["error"] == "the scan sandbox couldn't be cleaned up"
   and any(lv >= logging.ERROR and MSG["run_id"][:8] in m for lv, m in h.msgs), (hub.calls[-1], h.msgs))


# ---- fix round 1 ----
hub = FakeHub()
many = [{"type": "finding", "finding": F}] * 12000 + [{"type": "end", "status": "done", "error": None}]
asyncio.run(go(hub, many))
ups = [c[1]["findings"] for c in hub.calls if c[0].endswith("/findings")]
ok("12,000 findings → exactly 5,000 uploaded, ≤500 per POST, truncated",
   sum(map(len, ups)) == 5000 and max(map(len, ups)) <= 500 and hub.calls[-1][1]["status"] == "truncated",
   (sum(map(len, ups)), hub.calls[-1][1]["status"]))


async def snapshot_stall_body(*a, **k):
    async def gen():
        yield b"x"
        await asyncio.sleep(3600)
        yield b"y"
    return {"ok": True}, gen(), (lambda: 0), _hook("stall")


hooks = []


def _hook(name):
    async def h():
        hooks.append(name)
    return h


import time  # noqa: E402
hub = FakeHub()
t0 = time.monotonic()
asyncio.run(go(hub, [{"type": "end", "status": "done"}], snapshot=snapshot_stall_body, header_timeout=1, run_grace=1, feed_grace=0.3))
ok("stalled snapshot body after sandbox EOF → returns promptly; helper stopped",
   time.monotonic() - t0 < 2 and hub.calls[-1][1]["status"] == "done" and "stall" in hooks, time.monotonic() - t0)


async def snapshot_stall_header(*a, **k):
    await asyncio.sleep(3600)


hub = FakeHub()
asyncio.run(go(hub, [], snapshot=snapshot_stall_header, header_timeout=0.2))
ok("stalled header → failed 'couldn't be read in time'",
   hub.calls[-1][1]["status"] == "failed" and "in time" in hub.calls[-1][1]["error"], hub.calls[-1])


async def snapshot_hook_ok(*a, **k):
    async def gen():
        yield b"x"
    return {"ok": True}, gen(), (lambda: 0), _hook("ok")


async def snapshot_hook_refused(*a, **k):
    return {"ok": False, "error": "not_found"}, None, (lambda: 2), _hook("refused")


hooks.clear()
asyncio.run(go(FakeHub(), [{"type": "end", "status": "done"}], snapshot=snapshot_hook_ok))
asyncio.run(go(FakeHub(), [], snapshot=snapshot_hook_refused))
ok("helper-stop hook runs on success and failure", hooks == ["ok", "refused"], hooks)


class SlowProc(FakeProc):
    pass


async def go_block(hub):
    async def launch(argv):
        return FakeProc([], 0, block=True)
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snapshot_hook_ok, support=lambda: (True, "ok"),
                          stop=_stop_true, runner_dir=_RD, trusted_uids=(0, os.getuid()), run_grace=0.2)
    import orchestratia_agent.scanning.catalog as cat
    spec = cat.get("code.secrets")
    object.__setattr__(spec, "timeout_s", 0) if hasattr(spec, "__dataclass_fields__") else None
    await r.handle(dict(MSG))


import orchestratia_agent.scanning.catalog as _cat  # noqa: E402
_old = _cat.get("code.secrets").timeout_s
hooks.clear()
hub = FakeHub()
try:
    asyncio.run(go_block(hub))
finally:
    object.__setattr__(_cat.get("code.secrets"), "timeout_s", _old)
ok("M8 whole-run timeout → timed_out 'ran out of time', helper stopped",
   hub.calls[-1][1]["status"] == "timed_out" and "out of time" in hub.calls[-1][1]["error"] and "ok" in hooks, hub.calls[-1])


class Hub500(FakeHub):
    async def post(self, path, body):
        self.calls.append((path, body))
        if path.endswith("/findings"):
            return 500
        return 200


hub = Hub500()
asyncio.run(go(hub, [{"type": "finding", "finding": F}, {"type": "end", "status": "done"}], post_backoff=0))
n500 = sum(1 for c in hub.calls if c[0].endswith("/findings"))
ok("findings 500 ×3 → complete failed", n500 == 3 and hub.calls[-1][1]["status"] == "failed"
   and "upload findings" in hub.calls[-1][1]["error"], (n500, hub.calls[-1]))


class HubRaise(FakeHub):
    def __init__(self, where):
        super().__init__()
        self.where = where

    async def post(self, path, body):
        if path.endswith("/" + self.where):
            raise ConnectionError("down")
        return await super().post(path, body)


for where in ("ack", "complete"):
    try:
        asyncio.run(go(HubRaise(where), [{"type": "end", "status": "done"}]))
        good = True
    except Exception as e:
        good = False
    ok(f"hub.post raising on {where} → handle returns cleanly", good)

# 4: waits for the sweep
runner._SWEEP_DONE.clear()


async def gated():
    hub = FakeHub()
    t = asyncio.ensure_future(go(hub, [{"type": "end", "status": "done"}]))
    await asyncio.sleep(0.2)
    before = [c[0].rsplit("/", 1)[1] for c in hub.calls]
    runner._SWEEP_DONE.set()
    await t
    return before, [c[0].rsplit("/", 1)[1] for c in hub.calls]


b4, af = asyncio.run(gated())
ok("no sandbox launch until the sweep is done", "complete" not in b4 and af[-1] == "complete", (b4, af))
runner._SWEEP_DONE.set()

# 5: duplicate run id
async def dup():
    hub = FakeHub()

    async def launch(argv):
        return FakeProc([], 0, block=True)
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snapshot_ok, support=lambda: (True, "ok"),
                          stop=_stop_true, runner_dir=_RD, trusted_uids=(0, os.getuid()))
    t1 = asyncio.ensure_future(r.handle(dict(MSG)))
    await asyncio.sleep(0.2)
    await r.handle(dict(MSG))
    acks = sum(1 for c in hub.calls if c[0].endswith("/ack"))
    await r.cancel(MSG["run_id"])
    await t1
    return acks
ok("duplicate run id is ignored without a second ack", asyncio.run(dup()) == 1)

# 6: option-like values
a = runner.helper_args(dict(MSG, params={"exclude": ["--deps-only"] + ["e" * 300] + ["x"] * 80}), False)
ok("exclude '--deps-only' reaches argv as --exclude=--deps-only; capped",
   "--exclude=--deps-only" in a and "--deps-only" not in a and a[1] == "--cwd=/srv/app"
   and len([x for x in a if x.startswith("--exclude=")]) == 50 and max(map(len, a)) <= 128 + 10, len(a))

# 7: meta validation
m = runner._clean_meta({"tool_version": "v" * 99, "data_as_of": 5, "manifests_scanned": ["a", 3, "b" * 600] + ["c"] * 300})
ok("meta validated", m["tool_version"] == "" and m["data_as_of"] is None and len(m["manifests_scanned"]) == 200
   and "a" in m["manifests_scanned"], m["tool_version"])

# 9: pack not installed
hub = FakeHub()


async def nopack():
    r = runner.ScanRunner(hub, tc=None, snapshot=snapshot_ok, support=lambda: (True, "ok"), stop=_stop_true,
                          runner_dir="/nonexistent-dir")
    await r.handle(dict(MSG))
asyncio.run(nopack())
ok("missing runner files → failed 'pack isn't installed'", "isn't installed" in hub.calls[-1][1]["error"])

# 11: validate_finding bool line / string references
v = runner.validate_finding(dict(F, location={"kind": "file", "path": "a", "line": True},
                                 references={"cwe": "CWE-79", "cve": [], "urls": []}))
ok("bool line → None; string references → []", v["location"]["line"] is None and v["references"]["cwe"] == [], v)


# ---------------------------------------------------------------- final fix wave
RID = MSG["run_id"]
END = {"type": "end", "status": "done", "error": None}


class DelayProc(FakeProc):
    """Returns its lines only after `delay` seconds (a sandbox that is busy scanning)."""
    def __init__(self, lines, delay):
        super().__init__(lines, 0)
        inner, outer = self.stdout, self

        class R:
            async def readline(s):
                if outer.delay > 0:
                    await asyncio.sleep(outer.delay)
                    outer.delay = 0
                return await inner.readline()
        self.delay = delay
        self.stdout = R()


async def go2(hub, lines, *, delay=0, msg=MSG, **kw):
    async def launch(argv):
        return DelayProc(lines, delay)
    kw.setdefault("stop", _stop_true)
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=kw.pop("snapshot", snapshot_ok),
                          support=lambda: (True, "ok"), runner_dir=_RD, trusted_uids=(0, os.getuid()), **kw)
    await r.handle(dict(msg))
    return r


# I1: scan_progress
sent = []


async def send(m):
    sent.append(m)
    return True


hub = FakeHub()
asyncio.run(go2(hub, [{"type": "finding", "finding": F}, END], delay=0.35, send=send, keepalive_s=0.05))
phases = [m.get("phase") for m in sent]
ok("I1 progress for snapshot, scanning and uploading, in that order",
   phases and phases[0] == "snapshot" and "scanning" in phases and "uploading" in phases
   and phases.index("snapshot") < phases.index("scanning") < phases.index("uploading"), phases)
ok("I1 keepalives while the sandbox runs", phases.count("scanning") >= 4, phases.count("scanning"))
ok("I1 progress messages are well-formed and short",
   all(m.get("type") == "scan_progress" and m.get("run_id") == RID and isinstance(m.get("message"), str)
       and len(m["message"]) <= 200 for m in sent), sent[:2])
ok("I1 the run still completes after progress", hub.calls[-1][1]["status"] == "done")


async def send_boom(m):
    raise ConnectionError("ws gone")


hub = FakeHub()
asyncio.run(go2(hub, [END], delay=0.12, send=send_boom, keepalive_s=0.03))
ok("I1 a failing send never fails the run", hub.calls[-1][1]["status"] == "done", hub.calls[-1])
sent.clear()
asyncio.run(go2(FakeHub(), [END], send=send, keepalive_s=0.05))
ok("I1 progress messages are masked", all("a=b" not in json.dumps(m) for m in sent))

# I2: scope forwarded and validated
for label, scope, want in (("change/true", {"mode": "change", "history": True}, {"mode": "change", "history": True}),
                           ("tool/false", {"mode": "tool", "history": False}, {"mode": "tool", "history": False}),
                           ("nothing_to_compare", {"mode": "nothing_to_compare", "history": True},
                            {"mode": "nothing_to_compare", "history": True}),
                           ("bad mode", {"mode": "everything", "history": True}, None),
                           ("non-bool history", {"mode": "full", "history": "yes"}, None),
                           ("missing", None, None)):
    hub = FakeHub()
    meta = {"type": "meta", "tool_version": "8"}
    if scope is not None:
        meta["scope"] = scope
    asyncio.run(go2(hub, [meta, END]))
    ok(f"I2 complete carries scope ({label})", hub.calls[-1][1].get("scope", "absent") == want, hub.calls[-1][1].get("scope", "absent"))

# I3: batches stay under the 4 MB request cap with large non-ASCII evidence
big = dict(F, evidence="中é\U0001F600" * 682, title="Ünïcödé " * 60)
hub = FakeHub()
asyncio.run(go2(hub, [{"type": "finding", "finding": big}] * 1200 + [END]))
ups = [c[1] for c in hub.calls if c[0].endswith("/findings")]
sizes = [len(json.dumps(b).encode()) for b in ups]
ok("I3 every findings POST is ≤ 3.5 MB however it is encoded",
   ups and max(sizes) <= 3.5 * 1024 * 1024 and max(len(json.dumps(b, ensure_ascii=False).encode()) for b in ups) <= 3.5 * 1024 * 1024,
   [round(x / 1048576, 2) for x in sizes])
ok("I3 all 1,200 findings still uploaded", sum(len(b["findings"]) for b in ups) == 1200, sum(len(b["findings"]) for b in ups))

# M1: a non-string end.error still completes
for err in ({"x": 1}, 5, ["a"]):
    hub = FakeHub()
    asyncio.run(go2(hub, [{"type": "end", "status": "failed", "error": err}]))
    ok(f"M1 end.error={err!r} still completes", hub.calls[-1][0].endswith("/complete")
       and isinstance(hub.calls[-1][1]["error"], str), hub.calls[-1])

# M2: validate_finding masks before it cuts
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
v = runner.validate_finding(dict(F, evidence="x" * 2030 + JWT, title="t" * 500 + JWT))
ok("M2 validate_finding: a JWT at the cap is masked, not cut", "eyJhbGciOiJI" not in json.dumps(v), (v["evidence"][-30:], v["title"][-30:]))

# M3: manifests are masked
GHP = "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
m = runner._clean_meta({"manifests_scanned": [f"/{GHP}/requirements.txt", "a/" + "b" * 600]})
ok("M3 manifests_scanned entries are masked (and long ones cut, not dropped)",
   "a1B2c3D4" not in json.dumps(m) and len(m["manifests_scanned"]) == 2, m)

# M7: the sandbox is stopped BEFORE complete; an unclean id is never run again
events = []


class OrderHub(FakeHub):
    async def post(self, path, body):
        events.append(path.rsplit("/", 1)[1])
        return await super().post(path, body)


async def stop_rec(rid):
    events.append("stop")
    return True


asyncio.run(go2(OrderHub(), [END], stop=stop_rec))
ok("M7 stop happens before complete", events[-2:] == ["stop", "complete"], events)


async def stop_bad(rid):
    return False


async def unclean_twice():
    hub = FakeHub()

    async def launch(argv):
        return DelayProc([END], 0)
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snapshot_ok, support=lambda: (True, "ok"),
                          stop=stop_bad, runner_dir=_RD, trusted_uids=(0, os.getuid()))
    await r.handle(dict(MSG))
    first = list(hub.calls)
    await r.handle(dict(MSG))
    return first, hub.calls
first, after = asyncio.run(unclean_twice())
ok("M7 a run whose sandbox couldn't be cleaned up is refused if it comes again",
   first[-1][1]["error"] == "the scan sandbox couldn't be cleaned up" and len(after) == len(first), (len(first), len(after)))

# M8: statuses
hub = FakeHub()
asyncio.run(go2(hub, [{"type": "end", "status": "timed_out", "error": "the scan ran out of time"}]))
ok("M8 the shim's timed_out is forwarded", hub.calls[-1][1]["status"] == "timed_out", hub.calls[-1])
ticks = iter([0.0] + [10_000.0] * 50)
hub = FakeHub()
asyncio.run(go2(hub, [{"type": "meta", "tool_version": "8"}], clock=lambda: next(ticks)))
ok("M8 no end line after RuntimeMaxSec → timed_out", hub.calls[-1][1]["status"] == "timed_out"
   and hub.calls[-1][1]["error"], hub.calls[-1])
ticks2 = iter([0.0] + [3.0] * 50)
hub = FakeHub()
asyncio.run(go2(hub, [{"type": "meta", "tool_version": "8"}], clock=lambda: next(ticks2)))
ok("M8 no end line well before the limit → failed", hub.calls[-1][1]["status"] == "failed", hub.calls[-1])

# M9: plain reasons
from orchestratia_agent import privilege  # noqa: E402


async def snapshot_priv(*a, **k):
    raise privilege.PrivilegeError("tier 'restricted' requested for project 'p1', which is not provisioned")


async def snapshot_boom(*a, **k):
    raise ValueError("boom")


hub = FakeHub()
asyncio.run(go2(hub, [], snapshot=snapshot_priv))
ok("M9 PrivilegeError → plain reason", hub.calls[-1][1]["error"] == "this project's restricted user isn't set up on this server",
   hub.calls[-1])
hub = FakeHub()
asyncio.run(go2(hub, [], snapshot=snapshot_boom))
ok("M9 other errors are not a bare exception name",
   hub.calls[-1][1]["error"] != "ValueError" and not hub.calls[-1][1]["error"].startswith("runner error:")
   and "internal error" in hub.calls[-1][1]["error"], hub.calls[-1])

# hub wiring: the runner's progress goes out on the daemon's websocket; capability off the loop
from orchestratia_agent import hub as hubmod  # noqa: E402


class WS:
    close_code = None

    def __init__(self):
        self.out = []

    async def send(self, data):
        self.out.append(json.loads(data))


class St:
    hub_url = "wss://h.example/ws/server"
    api_key = "orc_x"
    insecure = False
    tier_config = None
    config = {}

    def __init__(self):
        self.ws_connection = WS()


st = St()
hubmod._SCAN_RUNNER = None
sr = hubmod._scan_runner(st)
asyncio.run(sr._progress(RID, "scanning", "x"))
ok("hub wires the runner's progress to ws_send", st.ws_connection.out and st.ws_connection.out[0]["type"] == "scan_progress",
   st.ws_connection.out)
hubmod._SCAN_RUNNER = None

import threading  # noqa: E402
seen = []
_orig_cap = hubmod._scanners_capability
hubmod._scanners_capability = lambda: seen.append(threading.current_thread() is threading.main_thread()) or {"scans": []}


class Resp:
    status_code = 200

    def raise_for_status(self):
        pass


class Client:
    async def post(self, *a, **k):
        return Resp()


class HSt:
    hub_url, api_key, config, tier_config = "https://h", "k", {}, None


try:
    asyncio.run(hubmod.send_heartbeat(Client(), HSt()))
finally:
    hubmod._scanners_capability = _orig_cap
ok("M12 heartbeat computes the scanner capability off the event loop thread", seen == [False], seen)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
