#!/usr/bin/env python3
"""Root consumers of agent code refuse code that isn't root's (hardening plan Task 3): scanners install/refresh, the
runner-file copy, the download-helper copy; the scan-data timer runs the agent isolated; secure-install refreshes
the scanner pieces.

Dependency-free — run:  python3 tests/test_root_consumers.py
"""
import contextlib
import io
import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import cli, codetrust, provision, secure_install  # noqa: E402
from orchestratia_agent.scanning import pack  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def refuse(action, **kw):
    raise codetrust.CodeTrustError(f"refusing to {action}: test")


real_gate = codetrust.require_trusted

# ── the copies refuse before writing anything ──
codetrust.require_trusted = refuse
try:
    rr = os.path.join(tempfile.mkdtemp(), "scanners")
    try:
        pack.sync_runner_files(rr)
        res = "copied"
    except codetrust.CodeTrustError as e:
        res = str(e)
    ok("sync_runner_files refuses through the gate", res.startswith("refusing to copy the scanner runner"), res)
    ok("…and creates nothing", not os.path.exists(rr))
    target = os.path.join(tempfile.mkdtemp(), "libexec", "dl-helper")
    try:
        provision.install_dl_helper(target, python=sys.executable)
        res = "installed"
    except codetrust.CodeTrustError as e:
        res = str(e)
    ok("install_dl_helper refuses through the gate", res.startswith("refusing to install the download helper"), res)
    ok("…and writes nothing", not os.path.exists(target))

    # scanners install / refresh stop before doing anything
    calls = []
    saved = (pack.install, pack.refresh_osv, sys.argv, cli.os.geteuid)
    pack.install = lambda *a, **k: calls.append("install")
    pack.refresh_osv = lambda *a, **k: calls.append("refresh")
    try:
        for argv in (["orchestratia", "scanners", "install"], ["orchestratia", "scanners", "refresh"]):
            sys.argv = argv
            cli.os.geteuid = lambda: 0
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(io.StringIO()):
                try:
                    cli.main()
                    code = 0
                except SystemExit as e:
                    code = e.code
            ok(f"`{' '.join(argv[1:])}` refuses untrusted code (exit 1, says why)",
               code == 1 and "refusing to" in buf.getvalue() and calls == [], (code, buf.getvalue(), calls))
    finally:
        pack.install, pack.refresh_osv, sys.argv, cli.os.geteuid = saved
finally:
    codetrust.require_trusted = real_gate

# ── the timer: isolated interpreter, from /, an import probe first ──
ud = tempfile.mkdtemp()
pack.install_timer("/opt/py/bin/python3", unit_dir=ud, systemctl=False, probe=lambda py: "/x", euid=lambda: 1000)
svc = open(os.path.join(ud, "orchestratia-scan-data.service")).read()
ok("ExecStart: the interpreter isolated (-I), the agent's CLI as a module",
   'ExecStart="/opt/py/bin/python3" -I -m orchestratia_agent.cli scanners refresh\n' in svc, svc)
ok("WorkingDirectory=/ and UMask=0022", "WorkingDirectory=/\n" in svc and "UMask=0022\n" in svc, svc)


def bad_probe(py):
    raise pack.InstallError("can't import")


ud2 = tempfile.mkdtemp()
try:
    pack.install_timer("/opt/py/bin/python3", unit_dir=ud2, systemctl=False, probe=bad_probe, euid=lambda: 1000)
    res = "installed"
except pack.InstallError as e:
    res = str(e)
ok("a failing import probe -> no units written", "can't import" in res and os.listdir(ud2) == [], (res, os.listdir(ud2)))
try:
    pack._probe_import("/nonexistent/python3")
    res = "probed"
except pack.InstallError as e:
    res = str(e)
ok("the real probe reports an interpreter that can't import the agent", "can't import the agent" in res, res)
mine = tempfile.mkdtemp()
os.chmod(mine, 0o755)
py = os.path.join(mine, "python3")
os.symlink(sys.executable, py)
ud3 = tempfile.mkdtemp()
try:
    pack.install_timer(py, unit_dir=ud3, systemctl=False, probe=lambda p: "/x", euid=lambda: 0)
    res = "installed"
except pack.InstallError as e:
    res = str(e)
ok("as root: an interpreter in a directory root doesn't own is refused, nothing written",
   "isn't root-owned" in res and os.listdir(ud3) == [], (res, os.listdir(ud3)))

# ── secure-install refreshes the scanner pieces when the pack is installed ──
log = []
saved = (pack.SCANNERS_ROOT, pack.sync_runner_files, pack.install_timer, pack.install_launcher)
pack.sync_runner_files = lambda *a, **k: log.append(("sync",))
pack.install_timer = lambda python, **k: log.append(("timer", python))
pack.install_launcher = lambda user, **k: log.append(("launcher", user))
try:
    ctx = SimpleNamespace(layout=codetrust.Layout(venv="/opt/v"), uids=(0,), elevated=None)
    pack.SCANNERS_ROOT = os.path.join(tempfile.mkdtemp(), "absent")
    msg = secure_install.refresh_scanner_pieces("svc", ctx)
    ok("no scanner pack -> nothing touched", log == [] and "not installed" in msg, (log, msg))
    pack.SCANNERS_ROOT = tempfile.mkdtemp()
    msg = secure_install.refresh_scanner_pieces("svc", ctx)
    ok("scanner pack -> runner files, timer (venv python), launcher (daemon user), in that order",
       log == [("sync",), ("timer", "/opt/v/bin/python3"), ("launcher", "svc")], log)
    ok("refresh_scanner_pieces is a default secure-install step", secure_install.refresh_scanner_pieces
       in secure_install.DEFAULT_STEPS)
finally:
    pack.SCANNERS_ROOT, pack.sync_runner_files, pack.install_timer, pack.install_launcher = saved

# ── beyond the brief: the probe never runs an interpreter root would refuse; unit-breaking paths are refused ──
probed = []
ud4 = tempfile.mkdtemp()
try:
    pack.install_timer(py, unit_dir=ud4, systemctl=False, probe=lambda p: probed.append(p) or "/x", euid=lambda: 0)
    res = "installed"
except pack.InstallError as e:
    res = str(e)
ok("as root: an untrusted interpreter is refused BEFORE the import probe runs it", probed == [] and
   "isn't root-owned" in res, (probed, res))
for badpy in ("/opt/py/bin/python3\nExecStartPre=/bin/sh", "/opt/%h/bin/python3", "/opt/a\\b/python3"):
    ud5 = tempfile.mkdtemp()
    try:
        pack.install_timer(badpy, unit_dir=ud5, systemctl=False, probe=lambda p: "/x", euid=lambda: 1000)
        res = "installed"
    except pack.InstallError as e:
        res = str(e)
    ok(f"a python path that would break the unit ({badpy!r}) is refused, nothing written",
       "invalid python3 path" in res and os.listdir(ud5) == [], (res, os.listdir(ud5)))

# the timer's command really works from / under -I through a venv's site-packages (no PYTHONPATH, no cwd)
import subprocess  # noqa: E402
repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
vdir = os.path.join(tempfile.mkdtemp(), "v")
made = subprocess.run([sys.executable, "-m", "venv", "--without-pip", vdir], capture_output=True).returncode == 0
if made:
    vpy = os.path.join(vdir, "bin", "python3")
    site = subprocess.run([vpy, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                          capture_output=True, text=True).stdout.strip()
    with open(os.path.join(site, "agent.pth"), "w") as fh:
        fh.write(repo + "\n")
    got = pack._probe_import(vpy)
    ok("the real probe finds the agent package through the venv (-I, from /, clean env)",
       got == os.path.join(repo, "orchestratia_agent"), got)
    run = subprocess.run([vpy, "-I", "-m", "orchestratia_agent.cli", "scanners", "--help"], cwd="/",
                         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
                         capture_output=True, text=True)
    ok("`<venv python> -I -m orchestratia_agent.cli scanners …` runs from /", run.returncode == 0 and
       "refresh" in run.stdout, (run.returncode, run.stderr[-300:]))
    ud6 = tempfile.mkdtemp()
    pack.install_timer(vpy, unit_dir=ud6, systemctl=False, euid=lambda: 1000)
    ok("install_timer with the real probe writes both units for a working interpreter",
       sorted(os.listdir(ud6)) == ["orchestratia-scan-data.service", "orchestratia-scan-data.timer"], os.listdir(ud6))
else:
    print("SKIP  venv-based probe checks (python3 -m venv unavailable)")

# ══ Task 4 fold-ins (Task 3 review) ══
from orchestratia_agent import linux_update  # noqa: E402

# the import probe runs with the Global Constraints' root environment (HOME=/root), not a bespoke one
probe_kw = []
real_run = pack.subprocess.run
pack.subprocess.run = lambda argv, **kw: probe_kw.append(kw) or subprocess.CompletedProcess(argv, 0, "/x/pkg\n", "")
try:
    pack._probe_import("/usr/bin/python3")
finally:
    pack.subprocess.run = real_run
ok("the import probe runs from / with linux_update.safe_env() (HOME=/root)",
   probe_kw and probe_kw[0].get("env") == linux_update.safe_env() and probe_kw[0]["env"].get("HOME") == "/root"
   and probe_kw[0].get("cwd") == "/", probe_kw)

# the copies also check the directory they copy FROM: an editable (.pth) install's package lives outside the venv
seen_roots = []


def record(action, **kw):
    seen_roots.append(kw.get("roots"))
    raise codetrust.CodeTrustError(f"refusing to {action}: test")


codetrust.require_trusted = record
try:
    for call in (lambda: pack.sync_runner_files(os.path.join(tempfile.mkdtemp(), "scanners")),
                 lambda: provision.install_dl_helper(os.path.join(tempfile.mkdtemp(), "dl"), python=sys.executable)):
        try:
            call()
        except codetrust.CodeTrustError:
            pass
finally:
    codetrust.require_trusted = real_gate
scan_dir = os.path.dirname(os.path.abspath(pack.__file__))
pkg_dir = os.path.dirname(os.path.abspath(provision.__file__))
ok("sync_runner_files checks the code roots AND the runner files' source dir",
   len(seen_roots) == 2 and seen_roots[0] and scan_dir in seen_roots[0]
   and all(r in seen_roots[0] for r in codetrust.code_roots()), seen_roots)
ok("install_dl_helper checks the code roots AND the helper's source dir",
   len(seen_roots) == 2 and seen_roots[1] and pkg_dir in seen_roots[1]
   and all(r in seen_roots[1] for r in codetrust.code_roots()), seen_roots)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
