#!/usr/bin/env python3
"""The root-owned scan launcher (plan 1C Task 3): the daemon isn't root, so scans start through
`sudo -n /usr/local/libexec/orchestratia/scan-launch run <run_id> <scan_id>`, which builds the unit from
root-owned code. Nothing the caller passes becomes a unit property.

Dependency-free — run:  python3 tests/test_scan_launcher.py
"""
import asyncio
import os
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning import catalog, launch, pack, sandbox  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


RID = "12345678-1234-1234-1234-123456789abc"
execs = []
exec_paths = []


def fake_exec(path, argv):
    exec_paths.append(path)
    execs.append(argv)


ok("not root -> usage error, nothing executed",
   launch.main(["run", RID, "code.secrets"], execvp=fake_exec, euid=lambda: 1000) == 64 and execs == [])
ok("its own directory isn't root-owned here -> refused as unsafe (77)",
   launch.main(["run", RID, "code.secrets"], execvp=fake_exec, euid=lambda: 0) == 77 and execs == [])
real_safe = launch._safe_tree
launch._safe_tree = lambda paths: None
try:
    ok("a bad run id -> 64", launch.main(["run", "../../etc", "code.secrets"], execvp=fake_exec, euid=lambda: 0) == 64)
    ok("an unknown scan -> 64", launch.main(["run", RID, "web.evil"], execvp=fake_exec, euid=lambda: 0) == 64)
    ok("extra arguments -> 64",
       launch.main(["run", RID, "code.secrets", "-p", "User=root"], execvp=fake_exec, euid=lambda: 0) == 64)
    ok("no command -> 64", launch.main([], execvp=fake_exec, euid=lambda: 0) == 64 and execs == [])
    ok("an option where the command goes -> 64",
       launch.main(["--unit=x", RID, "code.secrets"], execvp=fake_exec, euid=lambda: 0) == 64 and execs == [])
    ok("a run id with a trailing newline -> 64",
       launch.main(["run", RID + "\n", "code.secrets"], execvp=fake_exec, euid=lambda: 0) == 64 and execs == [])
    launch.main(["run", RID, "code.secrets"], execvp=fake_exec, euid=lambda: 0)
    want = sandbox.argv(RID, catalog.CATALOG["code.secrets"], shim=os.path.join(launch.HERE, "shim.py"))
    ok("a valid run execs exactly sandbox.argv for that run and scan", execs == [want], execs)
    ok("…as a unit named after the run, with no network",
       f"--unit=orc-scan-{RID}" in want and "PrivateNetwork=yes" in want)
    ok("…through systemd-run's fixed absolute path, never a PATH lookup",
       exec_paths == [launch.SYSTEMD_RUN] and os.path.isabs(launch.SYSTEMD_RUN), exec_paths)

    # stop / sweep run as root inside the launcher: they touch only orc-scan-* units and the scan state dirs.
    ok("stop with a bad run id -> 64", launch.main(["stop", "x; rm -rf /"], execvp=fake_exec, euid=lambda: 0) == 64)
    ok("stop with extra arguments -> 64", launch.main(["stop", RID, "more"], execvp=fake_exec, euid=lambda: 0) == 64)
    ok("sweep with arguments -> 64", launch.main(["sweep", "now"], execvp=fake_exec, euid=lambda: 0) == 64)
    lsb = sys.modules["sandbox"]                         # the launcher's own (runner-dir) copy of sandbox.py
    calls = []

    async def fake_run(*cmd, capture=False):
        calls.append(cmd)
        return 0, "inactive\n" if "show" in cmd else ""
    saved = (lsb._run, lsb.as_root, lsb.STATE_ROOT, lsb.LINK_ROOT)
    tmp_state = tempfile.mkdtemp()
    lsb._run, lsb.as_root = fake_run, (lambda: True)
    lsb.STATE_ROOT = lsb.LINK_ROOT = tmp_state
    try:
        ok("stop <run id> -> 0 when the unit is gone", launch.main(["stop", RID], execvp=fake_exec, euid=lambda: 0) == 0)
        units = {c[-1] for c in calls if c[0].endswith("systemctl")}
        ok("…and it only ever names that run's orc-scan- unit", units == {f"orc-scan-{RID}"}, calls)
        ok("…with systemctl by its absolute path", all(c[0] == sandbox.SYSTEMCTL for c in calls), calls)
        calls.clear()
        ok("sweep -> 0", launch.main(["sweep"], execvp=fake_exec, euid=lambda: 0) == 0)
        ok("…lists only orc-scan-* units", any("orc-scan-*" in c for c in calls), calls)
    finally:
        lsb._run, lsb.as_root, lsb.STATE_ROOT, lsb.LINK_ROOT = saved
        os.rmdir(tmp_state)
finally:
    launch._safe_tree = real_safe

# The integrity rule: lstat every component as given; root-owned, not group/other-writable, no symlinks.
ok("a root-owned system file passes", launch._safe_tree(["/usr/bin/env"]) is None, launch._safe_tree(["/usr/bin/env"]))
if os.path.islink("/bin"):
    why = launch._safe_tree(["/bin/env"])
    ok("a symlink anywhere on the path is refused (never resolved)", why is not None and "/bin" in why, why)
ok("a world-writable directory on the path is refused", launch._safe_tree(["/tmp"]) is not None)
ok("a file under a user-owned directory is refused", launch._safe_tree([os.path.abspath(__file__)]) is not None)
ok("a missing file is refused", launch._safe_tree(["/usr/bin/no-such-orc-file"]) is not None)
ok("the launcher checks every file synced into the runner dir",
   set(pack.RUNNER_FILES) <= set(launch._CHECKED), (pack.RUNNER_FILES, launch._CHECKED))

# The default exec: a fixed path and a clean environment, nothing inherited.
seen = []
real_execve = os.execve
os.execve = lambda path, argv, env: seen.append((path, argv, env))
os.environ["ORC_TEST_LEAK"] = "1"
try:
    launch._exec(launch.SYSTEMD_RUN, ["systemd-run", "--version"])
finally:
    os.execve = real_execve
    del os.environ["ORC_TEST_LEAK"]
ok("the real exec passes a clean, fixed environment", seen and seen[0][2] == launch.CLEAN_ENV
   and "ORC_TEST_LEAK" not in seen[0][2] and seen[0][0] == launch.SYSTEMD_RUN, seen)

real_root = sandbox.as_root
sandbox.as_root = lambda: False
try:
    a = sandbox.launch_argv(RID, catalog.CATALOG["code.deps"])
    ok("non-root daemon: sudo -n launcher run <id> <scan>", a == ["sudo", "-n", sandbox.LAUNCHER, "run", RID, "code.deps"], a)
    try:
        sandbox.launch_argv("x; rm", catalog.CATALOG["code.deps"])
        ok("launch_argv rejects a bad run id", False)
    except ValueError:
        ok("launch_argv rejects a bad run id", True)
    real_ok = sandbox.launcher_ok
    sandbox.launcher_ok = lambda: (False, "the scan launcher isn't set up; run: sudo orchestratia scanners install")
    try:
        sup = sandbox.support()
        ok("support() without the launcher says what to run", sup[0] is False and "scanners install" in sup[1], sup)
    finally:
        sandbox.launcher_ok = real_ok

    # stop / sweep from a non-root daemon go through the launcher with only the run id.
    rec = []

    async def rec_run(*cmd, capture=False):
        rec.append(cmd)
        return 0, "3\n"
    real_run = sandbox._run
    sandbox._run = rec_run
    try:
        ok("non-root stop -> sudo -n launcher stop <id>", asyncio.run(sandbox.stop(RID)) is True
           and rec == [("sudo", "-n", sandbox.LAUNCHER, "stop", RID)], rec)
        try:
            asyncio.run(sandbox.stop("../x"))
            ok("non-root stop rejects a bad run id", False)
        except ValueError:
            ok("non-root stop rejects a bad run id", True)
        rec.clear()
        ok("non-root sweep -> sudo -n launcher sweep, count parsed", asyncio.run(sandbox.sweep()) == 3
           and rec == [("sudo", "-n", sandbox.LAUNCHER, "sweep")], rec)
    finally:
        sandbox._run = real_run

    # launcher_ok: the whole path, as given, must be root-owned and protected, then sudo must allow it.
    real_l = sandbox.LAUNCHER
    try:
        sandbox.LAUNCHER = os.path.abspath(__file__)
        r_ = sandbox.launcher_ok(run=lambda *a, **k: subprocess.CompletedProcess(a, 0))
        ok("launcher_ok refuses a launcher on a user-owned path", r_[0] is False and "scanners install" in r_[1], r_)
        if os.path.islink("/bin"):
            sandbox.LAUNCHER = "/bin/env"
            r_ = sandbox.launcher_ok(run=lambda *a, **k: subprocess.CompletedProcess(a, 0))
            ok("launcher_ok refuses a symlink on the path", r_[0] is False, r_)
        sandbox.LAUNCHER = "/usr/bin/env"
        asked = []
        r_ = sandbox.launcher_ok(run=lambda a, **k: asked.append(a) or subprocess.CompletedProcess(a, 0))
        ok("launcher_ok: protected + sudo allows it -> ok", r_ == (True, "ok") and asked == [["sudo", "-n", "-l", "/usr/bin/env"]], (r_, asked))
        r_ = sandbox.launcher_ok(run=lambda a, **k: subprocess.CompletedProcess(a, 1), fresh=True)
        ok("launcher_ok: sudo refuses -> says what to run", r_[0] is False and "sudo" in r_[1], r_)

        # A positive `sudo -n -l` is cached (every capability refresh asked it: ~1,440 auth.log lines a day per
        # scanner host); a refusal never is, and a launcher failure re-checks (fresh=True).
        sandbox._sudo_ok.clear()
        t = [1000.0]
        asked = []
        yes = lambda a, **k: asked.append(a) or subprocess.CompletedProcess(a, 0)
        no = lambda a, **k: asked.append(a) or subprocess.CompletedProcess(a, 1)
        r1 = sandbox.launcher_ok(run=yes, clock=lambda: t[0])
        t[0] += 600
        r2 = sandbox.launcher_ok(run=yes, clock=lambda: t[0])
        ok("launcher_ok: a positive sudo check is reused within the hour (one sudo -l)",
           r1 == r2 == (True, "ok") and len(asked) == 1, (r1, r2, asked))
        t[0] += sandbox.LAUNCHER_SUDO_TTL_S
        sandbox.launcher_ok(run=yes, clock=lambda: t[0])
        ok("launcher_ok: after the hour it asks sudo again", len(asked) == 2, asked)
        r3 = sandbox.launcher_ok(run=no, clock=lambda: t[0], fresh=True)
        ok("launcher_ok(fresh=True) re-checks inside the hour and sees the refusal", r3[0] is False and len(asked) == 3,
           (r3, asked))
        r4 = sandbox.launcher_ok(run=no, clock=lambda: t[0])
        ok("launcher_ok: a refusal is never cached (the next check asks again)", r4[0] is False and len(asked) == 4, asked)
        sandbox.launcher_ok(run=yes, clock=lambda: t[0])
        sandbox.LAUNCHER = os.path.abspath(__file__)
        r5 = sandbox.launcher_ok(run=yes, clock=lambda: t[0])
        ok("launcher_ok: the path checks still run every time, even with a cached sudo answer",
           r5[0] is False and "scanners install" in r5[1] and len(asked) == 5, (r5, asked))
        sandbox.LAUNCHER = "/usr/bin/env"
        sandbox._sudo_ok.clear()
    finally:
        sandbox.LAUNCHER = real_l
finally:
    sandbox.as_root = real_root
sandbox.as_root = lambda: True
try:
    ok("root daemon: systemd-run directly, as before",
       sandbox.launch_argv(RID, catalog.CATALOG["code.deps"]) == sandbox.argv(RID, catalog.CATALOG["code.deps"]))
finally:
    sandbox.as_root = real_root

ok("the launcher and the sandbox module are synced into the root-owned runner dir",
   {"launch.py", "sandbox.py"} <= set(pack.RUNNER_FILES), pack.RUNNER_FILES)

d = tempfile.mkdtemp()
target, sudoers = os.path.join(d, "libexec", "scan-launch"), os.path.join(d, "sudoers.d", "orchestratia-scan")
checked = []
pack.install_launcher("ubuntu", python="/usr/bin/python3", target=target, sudoers=sudoers, require_root=False,
                      visudo=lambda p: checked.append(p) or True)
body = open(target).read()
ok("wrapper: pinned python in isolated mode without site-packages, imports only from the runner dir",
   body.startswith("#!/usr/bin/python3 -IS\n") and repr(sandbox.RUNNER_DIR) in body and "launch.main" in body, body)
ok("wrapper is 0755", stat.S_IMODE(os.stat(target).st_mode) == 0o755)
ok("wrapper clears the environment and writes no bytecode before importing anything",
   body.index("environ.clear()") < body.index("import launch") and "dont_write_bytecode = True" in body)
rule = open(sudoers).read()
ok("sudoers: one rule, the launcher only, no wildcard",
   f"ubuntu ALL=(root) NOPASSWD: {target}\n" in rule and "*" not in rule.split("NOPASSWD:")[1], rule)
ok("sudoers: the launcher's Defaults force env_reset, no pty, no I/O log",
   f"Defaults!{target} env_reset, !use_pty, !log_input, !log_output\n" in rule, rule)
ok("sudoers: one user rule only", sum(1 for ln in rule.splitlines() if "NOPASSWD" in ln) == 1, rule)
ok("sudoers is 0440 and was validated by visudo", stat.S_IMODE(os.stat(sudoers).st_mode) == 0o440 and len(checked) == 1)
ok("the sudoers temp file has a dot in its name (sudo's includedir skips it)", "." in os.path.basename(checked[0]))
if os.path.exists("/usr/sbin/visudo"):
    ok("the real visudo accepts the rule", pack._visudo(sudoers), rule)

# The generated wrapper refuses an unprotected runner dir BEFORE importing launch.py from it.
rd = tempfile.mkdtemp()
with open(os.path.join(rd, "launch.py"), "w") as fh:
    fh.write("import sys\nprint('IMPORTED')\nsys.exit(0)\n")
w = os.path.join(d, "w")
with open(w, "w") as fh:
    fh.write(pack._wrapper_body("/usr/bin/python3", rd))
os.chmod(w, 0o755)
res = subprocess.run([w, "run", RID, "code.secrets"], capture_output=True, text=True, timeout=20)
ok("wrapper on a user-owned runner dir -> 77, launch.py never imported",
   res.returncode == 77 and "IMPORTED" not in res.stdout, (res.returncode, res.stdout, res.stderr))

os.unlink(sudoers)
pack.install_launcher("root", python="/usr/bin/python3", target=target, sudoers=sudoers, require_root=False,
                      visudo=lambda p: True)
ok("a root daemon needs no sudoers rule", not os.path.exists(sudoers))
try:
    pack.install_launcher("a b", python="/usr/bin/python3", target=target, sudoers=sudoers, require_root=False,
                          visudo=lambda p: True)
    ok("an invalid daemon user is refused", False)
except Exception as e:
    ok("an invalid daemon user is refused", "user" in str(e).lower(), str(e))
for bad_py in ("/usr/bin/python3 -c x", "python3", "/usr/bin/python3\nroot ALL=(ALL) ALL"):
    try:
        pack.install_launcher("ubuntu", python=bad_py, target=target, sudoers=sudoers, require_root=False,
                              visudo=lambda p: True)
        ok(f"an unsafe python path is refused: {bad_py!r}", False)
    except pack.InstallError:
        ok(f"an unsafe python path is refused: {bad_py!r}", True)
wd = tempfile.mkdtemp()
os.chmod(wd, 0o777)
open(os.path.join(wd, "python3"), "w").close()
os.chmod(os.path.join(wd, "python3"), 0o755)
for bad_py, label in ((os.path.join(wd, "python3"), "in a world-writable directory"),
                      ("/usr/bin/no-such-python3", "that doesn't exist")):
    try:
        pack.install_launcher("ubuntu", python=bad_py, target=target, sudoers=sudoers, require_root=False,
                              visudo=lambda p: True)
        ok(f"a python3 {label} is refused", False)
    except pack.InstallError as e:
        ok(f"a python3 {label} is refused", "python3" in str(e), str(e))
try:
    pack.install_launcher("ubuntu", python=os.path.abspath(__file__), target=target, sudoers=sudoers,
                          require_root=True, visudo=lambda p: True)
    ok("install_launcher refuses to run unprivileged when root is required", False)
except pack.InstallError as e:
    ok("install_launcher refuses to run unprivileged when root is required", "root" in str(e).lower(), str(e))
try:
    pack.install_launcher("ubuntu", python="/usr/bin/python3", target=target, sudoers=sudoers, require_root=False,
                          visudo=lambda p: False)
    ok("an invalid sudoers file never goes live", False)
except pack.InstallError:
    ok("an invalid sudoers file never goes live", not os.path.exists(sudoers)
       and not [f for f in os.listdir(os.path.dirname(sudoers)) if f.startswith(".")])

# sweep_at_start: a non-root daemon can't write /opt, so it never re-syncs the runner files (scanners install does).
from orchestratia_agent.scanning import runner  # noqa: E402
synced, swept = [], []


async def _sweep():
    swept.append(1)
    return 0
saved_r = (sandbox.support, sandbox.sweep, sandbox.as_root, pack.tool_paths, pack.sync_runner_files)
sandbox.support, sandbox.sweep = (lambda: (True, "ok")), _sweep
pack.tool_paths, pack.sync_runner_files = (lambda *a, **k: {"gitleaks": "/x"}), (lambda *a, **k: synced.append(1))
try:
    sandbox.as_root = lambda: False
    runner._SWEEP_DONE.clear()
    asyncio.run(runner.sweep_at_start())
    ok("non-root start: sweeps (through the launcher) but never syncs /opt", swept == [1] and synced == [], (swept, synced))
    sandbox.as_root = lambda: True
    asyncio.run(runner.sweep_at_start())
    ok("root start: sweeps and syncs as before", swept == [1, 1] and synced == [1], (swept, synced))
finally:
    sandbox.support, sandbox.sweep, sandbox.as_root, pack.tool_paths, pack.sync_runner_files = saved_r

# The root runner copy is stamped at install; a non-root daemon refuses scans when its own files differ
# (after `orchestratia update` the launcher would otherwise run an older shim/catalog than this runner).
rr = os.path.join(tempfile.mkdtemp(), "scanners")      # never let _mkdir tighten /tmp itself
pack.sync_runner_files(rr)
stamp = os.path.join(rr, "runner", os.path.basename(sandbox.RUNNER_STAMP))
ok("sync_runner_files stamps the runner dir with the hash of what it copied",
   open(stamp).read().strip() == sandbox.runner_hash(os.path.join(rr, "runner"))
   == sandbox.runner_hash(os.path.dirname(sandbox.__file__)), open(stamp).read())
ok("the stamp is 0644", stat.S_IMODE(os.stat(stamp).st_mode) == 0o644)
ok("the stamp is not one of the synced files", os.path.basename(stamp) not in pack.RUNNER_FILES)
saved_s = (sandbox.RUNNER_STAMP, sandbox.as_root, sandbox.launcher_ok, sandbox._python_ok)
try:
    sandbox.RUNNER_STAMP = stamp
    ok("runner_current: matching stamp -> ok", sandbox.runner_current() == (True, "ok"), sandbox.runner_current())
    with open(stamp, "w") as fh:
        fh.write("0" * 64 + "\n")
    r_ = sandbox.runner_current()
    ok("runner_current: a different stamp -> out of date, says what to run",
       r_ == (False, "the scanner runner is out of date — run: sudo orchestratia scanners install"), r_)
    os.unlink(stamp)
    ok("runner_current: no stamp (an install from before stamps) -> out of date", sandbox.runner_current()[0] is False)
    sandbox.RUNNER_STAMP = os.path.join(rr, "nope", "RUNNER_SHA256")
    r_ = sandbox.runner_current()
    ok("runner_current: no runner dir -> not installed", r_[0] is False and "isn't installed" in r_[1], r_)
    sandbox.RUNNER_STAMP = stamp
    sandbox.as_root, sandbox.launcher_ok = (lambda: False), (lambda *a, **k: (True, "ok"))
    sandbox._python_ok = lambda *a, **k: (True, "ok")
    if sys.platform.startswith("linux"):
        r_ = sandbox.support()
        ok("support() (not root) refuses an out-of-date runner with that reason",
           r_ == (False, "the scanner runner is out of date — run: sudo orchestratia scanners install"), r_)
        pack.sync_runner_files(rr)
        r_ = sandbox.support()
        ok("…and passes the stamp check once it's refreshed", "out of date" not in r_[1], r_)
finally:
    sandbox.RUNNER_STAMP, sandbox.as_root, sandbox.launcher_ok, sandbox._python_ok = saved_s

# service_user: the unit's User=; a loaded unit with no User= runs as root; else the sudo caller.
def fake_show(out, rc=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, rc, stdout=out, stderr="")


saved_su = os.environ.pop("SUDO_USER", None)
try:
    os.environ["SUDO_USER"] = "alice"
    ok("service_user: the unit's User=", pack.service_user(run=fake_show("LoadState=loaded\nUser=ubuntu\n")) == "ubuntu")
    ok("service_user: a loaded unit without User= is root, never the sudo caller",
       pack.service_user(run=fake_show("LoadState=loaded\nUser=\n")) == "root")
    ok("service_user: no unit -> the sudo caller",
       pack.service_user(run=fake_show("LoadState=not-found\nUser=\n")) == "alice")

    def boom(*a, **k):
        raise FileNotFoundError("systemctl")
    ok("service_user: no systemctl -> the sudo caller", pack.service_user(run=boom) == "alice")
    del os.environ["SUDO_USER"]
    ok("service_user: nothing known -> root", pack.service_user(run=boom) == "root")
finally:
    os.environ.pop("SUDO_USER", None)
    if saved_su is not None:
        os.environ["SUDO_USER"] = saved_su

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
