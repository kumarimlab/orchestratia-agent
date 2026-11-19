#!/usr/bin/env python3
"""Runner hardening from the adversarial review (fake hub / snapshot / sandbox, no root).

L4  the snapshot identity (OS user, directory) comes from the daemon's live session, never a
    less restricted one from the hub message.

Run:  python3 tests/test_scan_runner_hardening.py
"""
import asyncio
import json
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning import runner  # noqa: E402

runner._SWEEP_DONE.set()
_RD = tempfile.mkdtemp()
open(os.path.join(_RD, "shim.py"), "w").write("")
for _f in runner.pack.RUNNER_FILES:
    open(os.path.join(_RD, _f), "w").write("")
    os.chmod(os.path.join(_RD, _f), 0o644)            # the runner refuses a group-writable scanner tree (L3)
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class FakeHub:
    def __init__(self):
        self.calls = []

    async def post(self, path, body):
        self.calls.append((path, body))
        return 200


async def _stop_true(rid):
    return True


MSG = {"type": "scan_run", "run_id": "11111111-2222-3333-4444-555555555555", "scan_id": "code.agent",
       "catalog_version": "1", "session_id": "s1", "project_id": "p1", "privilege_tier": "standard",
       "working_directory": "/etc", "params": {"since": None}}


def live(run_as, cwd):
    return types.SimpleNamespace(working_dir=cwd, handle=types.SimpleNamespace(extra={"run_as": run_as, "cwd": cwd}))


async def capture(msg, sessions):
    seen = []

    async def snap(m, tc, deps_only):
        seen.append(m)

        async def gen():
            if False:
                yield b""
        return {"ok": False, "error": "not_found"}, gen(), (lambda: 0)
    kw = {"sessions": sessions} if sessions is not None else {}
    r = runner.ScanRunner(FakeHub(), tc=None, snapshot=snap, support=lambda: (True, "ok"), stop=_stop_true,
                          runner_dir=_RD, trusted_uids=(0, os.getuid()), **kw)
    await r.handle(dict(msg))
    return seen


try:
    seen = asyncio.run(capture(MSG, lambda sid: live("orcp-p1", "/srv/app") if sid == "s1" else None))
    m = seen[0] if seen else {}
    ok("L4 a live restricted session: the snapshot runs as that session's user, in its directory",
       m.get("working_directory") == "/srv/app" and runner.snapshot_run_as(m, None) == "orcp-p1", m)
    seen = asyncio.run(capture(dict(MSG, privilege_tier="restricted", working_directory="/srv/app"),
                               lambda sid: live(None, "/srv/app")))
    m = seen[0] if seen else {}
    resolved = []
    ok("L4 a live standard session never upgrades a restricted request to the daemon user",
       runner.snapshot_run_as(m, None, resolve=lambda t, p, tc: resolved.append((t, p)) or "orcp-p1") == "orcp-p1", m)
    seen = asyncio.run(capture(dict(MSG, _session_run_as=None, _live=True, privilege_tier="restricted"),
                               lambda sid: None))
    m = seen[0] if seen else {}
    ok("L4 a hub message can't set the private identity fields", "_live" not in m and "_session_run_as" not in m, m)
    ok("L4 no live session, restricted tier: the message's directory is used (as the project user)",
       m.get("working_directory") == "/etc", m)
    hub_calls = []

    async def capture_done(msg, sessions):
        seen = []

        class Hub(FakeHub):
            async def post(self, path, body):
                hub_calls.append((path, body))
                return 200

        async def snap(m, tc, deps_only):
            seen.append(m)
            raise AssertionError("must not snapshot")
        r = runner.ScanRunner(Hub(), tc=None, snapshot=snap, support=lambda: (True, "ok"), stop=_stop_true,
                              runner_dir=_RD, trusted_uids=(0, os.getuid()), sessions=sessions)
        await r.handle(dict(msg))
        return seen
    seen = asyncio.run(capture_done(MSG, lambda sid: None))
    done = hub_calls[-1][1] if hub_calls else {}
    ok("L4 no live session, standard tier: refused before any snapshot (never read as root from the hub's path)",
       not seen and done.get("status") == "failed" and "isn't running" in (done.get("error") or ""), done)
except TypeError as e:
    ok("L4 ScanRunner takes a live-session lookup", False, e)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
