#!/usr/bin/env python3
"""Adversarial review L3: the scanner tree (runner files, tools, OSV data) runs in EVERY tenant's
scan sandbox, so it must be root-owned and writable by nobody else, all the way up — checked at
install and before every launch — and it can never be granted to a restricted project user.

Unprivileged here: "trusted" uids are (0, this user) where a test needs a clean tree it owns.

Run:  python3 tests/test_scan_integrity.py
"""
import asyncio
import os
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import provision  # noqa: E402
from orchestratia_agent.scanning import pack, runner  # noqa: E402

runner._SWEEP_DONE.set()
ME = (0, os.getuid())
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


for path in ("/opt/orchestratia", "/opt/orchestratia/scanners/runner", "/var/lib/orchestratia/scan-data"):
    try:
        provision.validate_workspace(path)
        ok(f"L3 {path} can't be granted to a project user", False)
    except provision.ProvisionError as e:
        ok(f"L3 {path} can't be granted to a project user", True, str(e)[:80])

check = getattr(pack, "integrity_problem", None)
if check is None:
    ok("L3 pack has an integrity check", False)
else:
    with tempfile.TemporaryDirectory() as td:
        os.chmod(td, 0o755)
        root = os.path.join(td, "scanners")
        rd = os.path.join(root, "runner")
        os.makedirs(rd)
        os.chmod(root, 0o755)
        os.chmod(rd, 0o755)
        for f in pack.RUNNER_FILES:
            p = os.path.join(rd, f)
            with open(p, "w") as fh:
                fh.write("x")
            os.chmod(p, 0o644)
        tool = os.path.join(root, "gitleaks")
        with open(tool, "w") as fh:
            fh.write("x")
        os.chmod(tool, 0o755)
        ok("L3 a clean tree owned by a trusted uid passes", check(rd, [tool], None, uids=ME) is None,
           check(rd, [tool], None, uids=ME))
        ok("L3 a tree not owned by root fails (the production setting)", check(rd, [tool], None, uids=(0,)) is not None)
        os.chmod(os.path.join(rd, "shim.py"), 0o664)
        ok("L3 a group-writable runner file fails", check(rd, [tool], None, uids=ME) is not None)
        os.chmod(os.path.join(rd, "shim.py"), 0o644)
        os.chmod(root, 0o777)
        ok("L3 a world-writable directory on the way fails", check(rd, [tool], None, uids=ME) is not None)
        os.chmod(root, 0o755)
        os.unlink(os.path.join(rd, "masking.py"))
        os.symlink(os.path.join(td, "elsewhere.py"), os.path.join(rd, "masking.py"))
        ok("L3 a symlinked runner file fails", check(rd, [tool], None, uids=ME) is not None)
        os.unlink(os.path.join(rd, "masking.py"))
        ok("L3 a missing runner file fails", check(rd, [tool], None, uids=ME) is not None)
        with open(os.path.join(rd, "masking.py"), "w") as fh:
            fh.write("x")
        os.chmod(os.path.join(rd, "masking.py"), 0o644)
        db = os.path.join(td, "osv", "d1")
        os.makedirs(os.path.join(db, "osv-scalibr", "PyPI"))
        for d in (os.path.join(td, "osv"), db, os.path.join(db, "osv-scalibr"), os.path.join(db, "osv-scalibr", "PyPI")):
            os.chmod(d, 0o755)
        z = os.path.join(db, "osv-scalibr", "PyPI", "all.zip")
        with open(z, "w") as fh:
            fh.write("x")
        os.chmod(z, 0o666)
        ok("L3 a world-writable OSV data file fails", check(rd, [tool], db, uids=ME) is not None)
        os.chmod(z, 0o644)
        ok("L3 clean OSV data passes", check(rd, [tool], db, uids=ME) is None, check(rd, [tool], db, uids=ME))

        # pack._mkdir enforces modes on directories that already exist, not only ones it creates
        pre = os.path.join(td, "pre")
        os.makedirs(os.path.join(pre, "scanners"))
        os.chmod(os.path.join(pre, "scanners"), 0o777)
        pack._mkdir(os.path.join(pre, "scanners", "x"))
        ok("L3 _mkdir tightens an existing group/world-writable directory",
           stat.S_IMODE(os.stat(os.path.join(pre, "scanners")).st_mode) == 0o755,
           oct(stat.S_IMODE(os.stat(os.path.join(pre, "scanners")).st_mode)))

        # the runner refuses to launch on a tree that fails the check
        class Hub:
            calls = []

            async def post(self, path, body):
                Hub.calls.append((path, body))
                return 200
        launched = []

        async def launch(argv):
            launched.append(argv)
            raise RuntimeError("must not launch")

        async def snap(*a):
            async def gen():
                yield b""
            return {"ok": True}, gen(), (lambda: 0)

        async def stop(rid):
            return True
        os.chmod(os.path.join(rd, "shim.py"), 0o666)
        try:
            r = runner.ScanRunner(Hub(), tc=None, launch=launch, snapshot=snap, support=lambda: (True, "ok"), stop=stop,
                                  runner_dir=rd, trusted_uids=ME)
            asyncio.run(r.handle({"run_id": "11111111-2222-3333-4444-555555555555", "scan_id": "code.agent",
                                  "session_id": "s", "working_directory": "/srv/x", "params": {}}))
            done = Hub.calls[-1][1]
            ok("L3 the runner refuses a tampered scanner tree before launching anything",
               not launched and done["status"] == "failed" and "scanner pack" in (done["error"] or ""), done)
        except TypeError as e:
            ok("L3 the runner checks the scanner tree", False, e)

# ---- round 2: every UNRESOLVED path component is checked — a symlink anywhere on the way is refused
if check is not None:
    with tempfile.TemporaryDirectory() as td:
        os.chmod(td, 0o755)
        real = os.path.join(td, "real")
        rd = os.path.join(real, "runner")
        os.makedirs(rd)
        for x in (real, rd):
            os.chmod(x, 0o755)
        for f in pack.RUNNER_FILES:
            with open(os.path.join(rd, f), "w") as fh:
                fh.write("x")
            os.chmod(os.path.join(rd, f), 0o644)
        os.symlink(real, os.path.join(td, "via"))
        ok("L3 a clean real path passes", check(rd, [], None, uids=ME) is None, check(rd, [], None, uids=ME))
        why = check(os.path.join(td, "via", "runner"), [], None, uids=ME)
        ok("L3 a symlinked directory on the way to the runner is refused", why is not None and "symlink" in why, why)
        # the OSV data's own `current` link (relative, to a sibling) stays allowed; any other link is not
        osv = os.path.join(td, "osv")
        os.makedirs(os.path.join(osv, "2026-11-16-x", "osv-scalibr"))
        for x in (osv, os.path.join(osv, "2026-11-16-x"), os.path.join(osv, "2026-11-16-x", "osv-scalibr")):
            os.chmod(x, 0o755)
        os.symlink("2026-11-16-x", os.path.join(osv, "current"))
        ok("L3 the OSV `current` link to a sibling passes", check(rd, [], os.path.join(osv, "current"), uids=ME) is None,
           check(rd, [], os.path.join(osv, "current"), uids=ME))
        os.symlink(osv, os.path.join(td, "osvlink"))
        why = check(rd, [], os.path.join(td, "osvlink", "current"), uids=ME)
        ok("L3 a symlink above the OSV data is refused", why is not None and "symlink" in why, why)
        os.unlink(os.path.join(osv, "current"))
        os.symlink(os.path.join(td, "real"), os.path.join(osv, "current"))
        why = check(rd, [], os.path.join(osv, "current"), uids=ME)
        ok("L3 a `current` link that leaves its directory is refused", why is not None, why)
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
