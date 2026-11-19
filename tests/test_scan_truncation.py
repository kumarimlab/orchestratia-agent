#!/usr/bin/env python3
"""Adversarial review L2: when findings are capped, the most severe survive — repo content
can't push a high finding out with thousands of low ones — and the drop is counted per severity.

Run:  python3 tests/test_scan_truncation.py
"""
import asyncio
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import code_agent, runner  # noqa: E402

runner._SWEEP_DONE.set()
SHIM = os.path.join(HERE, "orchestratia_agent", "scanning", "shim.py")
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


FLOOD = "".join("x = 1  # noqa\n" for _ in range(6000)) + "name = 'ad‮min'\n"
with tempfile.TemporaryDirectory() as td:
    with open(os.path.join(td, "flood.py"), "w") as f:
        f.write(FLOOD)
    fs, meta = code_agent.run(td, None)
    sev = [f["severity"] for f in fs]
    ok("L2 code.agent: a high finding after 6000 low ones survives the cap", "high" in sev, (len(fs), sev[-3:]))
    ok("L2 code.agent: findings come out most severe first", sev == sorted(sev, key=["critical", "high", "medium",
                                                                                     "low", "info"].index))
    ok("L2 code.agent: the dropped findings are counted per severity",
       (meta.get("dropped") or {}).get("low", 0) >= 6000 - 5001, meta.get("dropped"))

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w|") as tf:
        data = FLOOD.encode()
        ti = tarfile.TarInfo("flood.py")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    hdr = {"scan_id": "code.agent", "since": None, "tools": {}, "osv_db": None, "data_as_of": None, "known": []}
    p = subprocess.run([sys.executable, "-I", SHIM], input=json.dumps(hdr).encode() + b"\n" + buf.getvalue(),
                       capture_output=True, timeout=120, env={"PATH": "/usr/bin:/bin", "HOME": td, "TMPDIR": td})
    lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    out = [x["finding"]["severity"] for x in lines if x.get("type") == "finding"]
    m = next((x for x in lines if x.get("type") == "meta"), {})
    ok("L2 shim: the high finding is emitted first and the run says truncated",
       out[:1] == ["high"] and len(out) == 5000 and lines[-1]["status"] == "truncated", (out[:2], len(out), lines[-1:]))
    ok("L2 shim: meta reports how many of each severity were dropped",
       isinstance(m.get("dropped"), dict) and m["dropped"].get("low", 0) == 6000 - 4999, m.get("dropped"))


class FakeHub:
    def __init__(self):
        self.calls = []

    async def post(self, path, body):
        self.calls.append((path, body))
        return 200


F = {"scan_id": "code.agent", "rule_id": "agent:x", "severity": "low", "title": "t", "description": "",
     "location": {"kind": "file", "path": "a.py", "line": 1}, "evidence": "", "references": {"cwe": [], "cve": [], "urls": []},
     "tool": "orchestratia", "tool_version": "1"}


class Proc:
    def __init__(self, lines):
        self.returncode = None
        items = [json.dumps(x).encode() + b"\n" for x in lines]

        class W:
            def write(s, b):
                pass

            async def drain(s):
                pass

            def close(s):
                pass
        self.stdin = W()

        class R:
            async def readline(s):
                return items.pop(0) if items else b""
        self.stdout = R()

    async def wait(self):
        self.returncode = 0
        return 0


async def go():
    hub = FakeHub()
    lines = ([{"type": "meta", "tool_version": "1", "data_as_of": None, "manifests_scanned": [],
               "scope": {"mode": "full", "history": False}, "dropped": {"low": 7, "bogus": 3, "high": "x"}}]
             + [{"type": "finding", "finding": F}] * 5003 + [{"type": "end", "status": "truncated", "error": None}])

    async def launch(argv):
        return Proc(lines)

    async def snap(*a):
        async def gen():
            yield b"x"
        return {"ok": True}, gen(), (lambda: 0)

    async def stop(rid):
        return True
    rd = tempfile.mkdtemp()
    for f in runner.pack.RUNNER_FILES:
        open(os.path.join(rd, f), "w").write("")
        os.chmod(os.path.join(rd, f), 0o644)
    r = runner.ScanRunner(hub, tc=None, launch=launch, snapshot=snap, support=lambda: (True, "ok"), stop=stop, runner_dir=rd, trusted_uids=(0, os.getuid()))
    await r.handle({"run_id": "11111111-2222-3333-4444-555555555555", "scan_id": "code.agent", "session_id": "s",
                    "working_directory": "/srv/x", "params": {}})
    return hub.calls[-1][1]


done = asyncio.run(go())
ok("L2 runner: /complete carries the per-severity drop count (sandbox's + its own cap), validated",
   done.get("dropped") == {"low": 10}, done.get("dropped"))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
