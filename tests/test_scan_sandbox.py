#!/usr/bin/env python3
"""The per-run sandbox (spec §7.3, D12). Unit part checks the argv; with root it really
runs units: fresh dynamic UID, no network, memory and time limits, nothing left behind.

Run:  python3 tests/test_scan_sandbox.py          (unit checks)
      sudo python3 tests/test_scan_sandbox.py     (+ integration)
"""
import asyncio
import dataclasses
import json
import os
import shutil
import socket
import stat
import subprocess
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import catalog, sandbox  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


a = sandbox.argv("11111111-2222-3333-4444-555555555555", catalog.get("code.secrets"))
props = {}
multi = {}
for x in a:
    if "=" in x and not x.startswith("--") and x[0].isupper():
        k, v = x.split("=", 1)
        props[k] = v
        multi.setdefault(k, []).append(v)
ok("runs through systemd-run --wait --pipe --collect", a[:4] == ["systemd-run", "--wait", "--pipe", "--collect"], a[:5])
for k, v in {"DynamicUser": "yes", "PrivateNetwork": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
             "PrivateTmp": "yes", "PrivateDevices": "yes", "NoNewPrivileges": "yes", "RestrictSUIDSGID": "yes",
             "CapabilityBoundingSet": "", "MemoryMax": "2G", "RuntimeMaxSec": "900", "TasksMax": "512", "PrivateIPC": "yes", "ProtectProc": "invisible",
             "ProcSubset": "pid", "ProtectKernelLogs": "yes", "RestrictAddressFamilies": "AF_UNIX",
             "SystemCallErrorNumber": "EPERM"}.items():
    ok(f"{k}={v}", props.get(k) == v, props.get(k))
ok("unit is named after the run", "--unit=orc-scan-11111111-2222-3333-4444-555555555555" in a)
ok("shim runs with python -I", a[-3:] == ["/usr/bin/python3", "-I", sandbox.RUNNER_DIR + "/shim.py"], a[-3:])

ok("syscall filter allows @system-service", "@system-service" in multi["SystemCallFilter"], multi["SystemCallFilter"])
ok("io_uring explicitly denied", any(v.startswith("~io_uring_setup") and "io_uring_enter" in v and "io_uring_register" in v
                                     for v in multi["SystemCallFilter"]), multi["SystemCallFilter"])
ok("/run and /dev/shm are private tmpfs", "/run:ro" in multi["TemporaryFileSystem"] and "/dev/shm" in multi["TemporaryFileSystem"], multi["TemporaryFileSystem"])
ok("/etc/orchestratia inaccessible (missing path tolerated)", props.get("InaccessiblePaths") == "-/etc/orchestratia", props.get("InaccessiblePaths"))
for bad in ("11111111-2222-3333-4444-555555555555\n", "../" + "a" * 33, "short", 5):
    try:
        sandbox.unit_name(bad)
        ok(f"bad run id rejected {bad!r}", False)
    except ValueError:
        ok(f"bad run id rejected {bad!r}", True)

# --- M5: support() refuses non-Linux / no geteuid; probes the sandbox python once ---
import platform as _platform  # noqa: E402
_saved_sys = _platform.system
_platform.system = lambda: "Darwin"
try:
    r_ = sandbox.support()
finally:
    _platform.system = _saved_sys
ok("support() is (False, reason) off Linux", r_[0] is False and "Linux" in r_[1], r_)
_saved_euid = os.geteuid
del os.geteuid
try:
    r_ = sandbox.support()
    raised = False
except Exception as e:
    raised = repr(e)
finally:
    os.geteuid = _saved_euid
ok("support() is (False, reason) without os.geteuid", not raised and r_[0] is False, raised or r_)

import tempfile  # noqa: E402
_pt = tempfile.mkdtemp()
_count = os.path.join(_pt, "count")
for name, rc in (("goodpy", 0), ("oldpy", 3)):
    with open(os.path.join(_pt, name), "w") as f:
        f.write(f"#!/bin/sh\necho x >> {_count}\nexit {rc}\n")
    os.chmod(os.path.join(_pt, name), 0o755)
r1 = sandbox._python_ok(os.path.join(_pt, "goodpy"))
r2 = sandbox._python_ok(os.path.join(_pt, "goodpy"))
r3 = sandbox._python_ok(os.path.join(_pt, "oldpy"))
calls = open(_count).read().count("x")
ok("python probe: a good interpreter passes, the result is cached (probed once)", r1[0] and r2[0] and calls == 2, (r1, calls))
ok("python probe: < 3.10 or no tarfile.data_filter → (False, reason)", r3[0] is False and "3.10" in r3[1], r3)
ok("python probe: a missing interpreter → (False, reason)", sandbox._python_ok(os.path.join(_pt, "nope"))[0] is False)
ok("python probe: the real /usr/bin/python3 passes", sandbox._python_ok("/usr/bin/python3")[0] is True,
   sandbox._python_ok("/usr/bin/python3"))
shutil.rmtree(_pt, ignore_errors=True)

# --- sweep() decision logic with faked systemctl helpers ---
import tempfile
_tmp = tempfile.mkdtemp()
_state, _links = os.path.join(_tmp, "state"), os.path.join(_tmp, "links")
os.makedirs(_state)
os.makedirs(_links)
ACT, DONE, DANG = ("cccccccc-0000-0000-0000-00000000000%d" % i for i in (1, 2, 3))
for rid in (ACT, DONE):
    os.makedirs(os.path.join(_state, rid))
    open(os.path.join(_state, rid, "f"), "w").write("x")
    os.symlink(os.path.join(_state, rid), os.path.join(_links, rid))
os.symlink(os.path.join(_state, "gone"), os.path.join(_links, DANG))
_saved = (sandbox.STATE_ROOT, sandbox.LINK_ROOT, sandbox._list_units, sandbox._stop_unit, sandbox._is_stopped,
          sandbox.as_root)


async def _fake_list():
    return [sandbox.unit_name(ACT) + ".service", sandbox.unit_name(DONE) + ".service"]


async def _fake_stop(u):
    pass


async def _fake_is_stopped(u):
    return ACT not in u


try:
    sandbox.STATE_ROOT, sandbox.LINK_ROOT = _state, _links
    sandbox._list_units, sandbox._stop_unit, sandbox._is_stopped = _fake_list, _fake_stop, _fake_is_stopped
    sandbox.as_root = lambda: True                 # the root branch: the one the launcher runs
    n = asyncio.run(sandbox.sweep())
    ok("sweep counts the units it stopped", n == 2, n)
    ok("sweep keeps state of a unit that is still active", os.path.isdir(os.path.join(_state, ACT))
       and os.path.islink(os.path.join(_links, ACT)))
    ok("sweep removes state and link of a stopped unit", not os.path.lexists(os.path.join(_state, DONE))
       and not os.path.lexists(os.path.join(_links, DONE)))
    ok("sweep removes a dangling link", not os.path.lexists(os.path.join(_links, DANG)))
finally:
    (sandbox.STATE_ROOT, sandbox.LINK_ROOT, sandbox._list_units, sandbox._stop_unit, sandbox._is_stopped,
     sandbox.as_root) = _saved
    shutil.rmtree(_tmp, ignore_errors=True)


async def _is_stopped_with(rc, out):
    saved = sandbox._run

    async def fake(*cmd, capture=False):
        return rc, out
    sandbox._run = fake
    try:
        return await sandbox._is_stopped("x")
    finally:
        sandbox._run = saved


for rc_, out_, want in ((0, "inactive\n", True), (0, "failed\n", True), (0, "", False), (1, "inactive\n", False),
                        (0, "active\n", False), (0, "deactivating\n", False)):
    ok(f"_is_stopped(rc={rc_}, {out_!r}) is {want}", asyncio.run(_is_stopped_with(rc_, out_)) is want)


if os.geteuid() != 0:
    print("(not root: skipping integration checks)")
else:
    import time
    shim_dir = sandbox.RUNNER_DIR
    os.makedirs(shim_dir, exist_ok=True)
    probe = os.path.join(shim_dir, "probe.py")
    bomb = os.path.join(shim_dir, "bomb.py")
    sleeper = os.path.join(shim_dir, "sleeper.py")
    marker = f"/tmp/orc-host-marker-{os.getpid()}"
    lst = socket.socket()
    lst.bind(("127.0.0.1", 0))
    lst.listen(5)
    port = lst.getsockname()[1]
    RID1 = "aaaaaaaa-0000-0000-0000-000000000001"
    try:
        with open(marker, "w") as f:
            f.write("host")
        with open(probe, "w") as f:
            f.write(f"""import os,sys,socket,json,ctypes,platform
d=sys.stdin.read()
r={{'uid':os.getuid(),'stdin':d}}
def conn(addr,fam=socket.AF_INET):
    try:
        s=socket.socket(fam,socket.SOCK_STREAM); s.settimeout(3); s.connect(addr); s.close(); return 'open'
    except Exception: return 'blocked'
r['net']=conn(('1.1.1.1',443))
r['loopback']=conn(('127.0.0.1',{port}))
try:
    socket.socket(socket.AF_INET); r['inet_socket']='ok'
except Exception: r['inet_socket']='denied'
r['dbus']=conn('/run/dbus/system_bus_socket',socket.AF_UNIX)
sd=os.environ['STATE_DIRECTORY']
r['left_before']=os.path.exists(os.path.join(sd,'left.txt'))
open(os.path.join(sd,'left.txt'),'w').write('x')
r['home_ok']=not os.path.exists('/root/.ssh')
try: r['home_list']=os.listdir('/home')
except Exception: r['home_list']='denied'
r['run_user']=os.path.exists('/run/user')
r['run_list']=os.listdir('/run') if os.path.isdir('/run') else None
def w(p):
    try: open(p,'w').write('x'); os.remove(p); return 'wrote'
    except Exception: return 'denied'
r['usr']=w('/usr/x'); r['etc']=w('/etc/x')
r['usr_rdonly']=bool(os.statvfs('/usr').f_flag & os.ST_RDONLY); r['etc_rdonly']=bool(os.statvfs('/etc').f_flag & os.ST_RDONLY)
r['foreign_pids']=[x for x in os.listdir('/proc') if x.isdigit() and os.stat('/proc/'+x).st_uid!=os.getuid()]
socks=[]
for root,dirs,files in os.walk('/run'):
    for n in dirs+files:
        try:
            import stat as _st
            if _st.S_ISSOCK(os.lstat(os.path.join(root,n)).st_mode): socks.append(os.path.join(root,n))
        except OSError: pass
r['run_socks']=socks
r['marker']=os.path.exists({marker!r})
r['pids']=len([x for x in os.listdir('/proc') if x.isdigit()])
try: open('/proc/1/cmdline').read(); r['proc1']='read'
except Exception: r['proc1']='denied'
try: r['orc_etc']=os.listdir('/etc/orchestratia')
except Exception: r['orc_etc']='denied'
r['shm']=os.listdir('/dev/shm')
if platform.machine()=='x86_64':
    libc=ctypes.CDLL(None,use_errno=True)
    rv=libc.syscall(425,1,0)
    r['uring']=(rv,ctypes.get_errno())
print(json.dumps(r))
""")
        with open(bomb, "w") as f:
            f.write("x=[]\nwhile True: x.append(bytearray(64*1024*1024))\n")
        with open(sleeper, "w") as f:
            f.write("import time\ntime.sleep(30)\n")

        async def run(rid, script, data=b"hi", spec=None, collect=True):
            av = sandbox.argv(rid, spec or catalog.get("code.agent"), shim=script)
            if not collect:
                av.remove("--collect")
            p = await asyncio.create_subprocess_exec(*av, stdin=asyncio.subprocess.PIPE,
                                                     stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            out, err = await p.communicate(data)
            return p.returncode, out.decode(), err.decode()

        async def run_stop(rid, script, **kw):
            res = await run(rid, script, **kw)
            stopped = await sandbox.stop(rid)
            return res, stopped

        (rc, out, err), stopped = asyncio.run(run_stop(RID1, probe))
        r = json.loads(out.strip().splitlines()[-1]) if out.strip() else {}
        print(err[-500:] if not r else "", end="")
        ok("runs as a dynamic UID, not root", r.get("uid", 0) >= 61184, r)
        ok("stdin reaches the unit", r.get("stdin") == "hi", r)
        ok("code scans have no network", r.get("net") == "blocked", r)
        ok("host loopback is unreachable", r.get("loopback") == "blocked", r)
        ok("AF_INET socket() is denied", r.get("inet_socket") == "denied", r.get("inet_socket"))
        ok("dbus system socket unreachable", r.get("dbus") == "blocked", r.get("dbus"))
        ok("/run holds no host sockets (only systemd's own)", set(r.get("run_list") or []) <= {"systemd"}, r.get("run_list"))
        ok("home directories are hidden", r.get("home_ok") is True and r.get("home_list") in ([], "denied"), (r.get("home_ok"), r.get("home_list")))
        ok("/run/user absent", r.get("run_user") is False)
        ok("/usr and /etc are read-only", r.get("usr") == "denied" and r.get("etc") == "denied", (r.get("usr"), r.get("etc")))
        ok("/usr and /etc mounted read-only (ST_RDONLY)", r.get("usr_rdonly") is True and r.get("etc_rdonly") is True,
           (r.get("usr_rdonly"), r.get("etc_rdonly")))
        ok("every visible process belongs to the probe's own uid", r.get("foreign_pids") == [], r.get("foreign_pids"))
        ok("no socket files under /run", r.get("run_socks") == [], r.get("run_socks"))
        ok("host /tmp is invisible", r.get("marker") is False)
        ok("only the unit's own processes are visible", r.get("pids", 99) < 10, r.get("pids"))
        ok("/proc/1/cmdline cannot be read", r.get("proc1") == "denied", r.get("proc1"))
        ok("/etc/orchestratia is inaccessible", r.get("orc_etc") == "denied", r.get("orc_etc"))
        ok("/dev/shm is empty and private", r.get("shm") == [], r.get("shm"))
        if platform_ok := (os.uname().machine == "x86_64"):
            ok("io_uring_setup is refused", r.get("uring", [0])[0] == -1 and r["uring"][1] == 1, r.get("uring"))
        ok("first run started with an empty state dir", r.get("left_before") is False, r.get("left_before"))
        ok("stop() reports success", stopped is True, stopped)
        ok("the state directory is gone after stop", not os.path.lexists(os.path.join(sandbox.STATE_ROOT, RID1)))
        ok("the /var/lib/orc-scan link is gone after stop", not os.path.lexists("/var/lib/orc-scan/" + RID1))
        (rc2, out2, _), _s = asyncio.run(run_stop(RID1, probe))
        r2 = json.loads(out2.strip().splitlines()[-1]) if out2.strip() else {}
        ok("a second run with the same id starts clean", rc2 == 0 and r2.get("left_before") is False, r2.get("left_before"))

        def result_of(unit):
            return subprocess.run(["systemctl", "show", "-p", "Result", "--value", unit],
                                  capture_output=True, text=True).stdout.strip()

        def cleanup(rid):
            asyncio.run(sandbox.stop(rid))
            subprocess.run(["systemctl", "reset-failed", sandbox.unit_name(rid)], capture_output=True)

        RID2 = "aaaaaaaa-0000-0000-0000-000000000002"
        try:
            rc, out, err = asyncio.run(run(RID2, bomb, collect=False))
            res = result_of(sandbox.unit_name(RID2))
            ok("MemoryMax kills an allocation bomb (oom-kill)", rc != 0 and res == "oom-kill", (rc, res))
        finally:
            cleanup(RID2)

        RID4 = "aaaaaaaa-0000-0000-0000-000000000004"
        try:
            t0 = time.time()
            rc, out, err = asyncio.run(run(RID4, sleeper, collect=False,
                                           spec=dataclasses.replace(catalog.get("code.agent"), timeout_s=3)))
            el = time.time() - t0
            res = result_of(sandbox.unit_name(RID4))
            ok("RuntimeMaxSec ends a runaway scan (Result=timeout after >=2.5s)",
               rc != 0 and 2.5 <= el < 15 and res == "timeout", (rc, round(el, 1), res))
        finally:
            cleanup(RID4)

        # M6: the pinned tools under the FULL sandbox argv via the real shim. (RestrictAddressFamilies=none
        # was tried: systemd-run rejects it for transient units, so the argv keeps AF_UNIX.)
        if os.path.exists("/tmp/orc-pin/gitleaks") and os.path.isdir("/tmp/orc-pin/db"):
            import io as _io
            import tarfile as _tarfile
            from orchestratia_agent.scanning import pack as _pack
            tools = os.path.join(os.path.dirname(shim_dir), f"m6-{os.getpid()}")
            try:
                os.makedirs(tools)
                os.chmod(tools, 0o755)
                for name in _pack.RUNNER_FILES:
                    shutil.copy(os.path.join(HERE, "orchestratia_agent", "scanning", name), tools)
                for name in ("gitleaks", "osv-scanner_linux_amd64"):
                    shutil.copy("/tmp/orc-pin/" + name, tools)
                shutil.copytree("/tmp/orc-pin/db", os.path.join(tools, "db"))
                for root_, dirs_, files_ in os.walk(tools):
                    os.chmod(root_, 0o755)
                    for fn in files_:
                        os.chmod(os.path.join(root_, fn), 0o755)
                buf = _io.BytesIO()
                with _tarfile.open(fileobj=buf, mode="w|") as tf:
                    for n_, d_ in (("k.py", ('aws = "' + "AKIA" + 'Z3MSJV4WZXQ7RT2P"\n').encode()),
                                   ("requirements.txt", b"django==2.2.0\n")):
                        ti = _tarfile.TarInfo(n_)
                        ti.size = len(d_)
                        tf.addfile(ti, _io.BytesIO(d_))
                for sid, tool, binary in (("code.secrets", "gitleaks", "gitleaks"),
                                          ("code.deps", "osv-scanner", "osv-scanner_linux_amd64")):
                    rid = "aaaaaaaa-0000-0000-0000-00000000000" + ("5" if sid == "code.secrets" else "6")
                    hdr = {"scan_id": sid, "since": None, "tools": {tool: os.path.join(tools, binary)},
                           "osv_db": os.path.join(tools, "db"), "data_as_of": "2026-11-16", "known": []}
                    try:
                        rc, out, err = asyncio.run(run(rid, os.path.join(tools, "shim.py"),
                                                       data=json.dumps(hdr).encode() + b"\n" + buf.getvalue(),
                                                       spec=catalog.get(sid)))
                    finally:
                        asyncio.run(sandbox.stop(rid))
                    lines = [json.loads(x) for x in out.splitlines() if x.strip().startswith("{")]
                    fs = [x["finding"] for x in lines if x.get("type") == "finding"]
                    ok(f"M6 {tool} works under the full sandbox argv (end done, findings)",
                       lines and lines[-1].get("status") == "done" and fs, (rc, lines[-1:], len(fs), err[-300:]))
            finally:
                shutil.rmtree(tools, ignore_errors=True)
        else:
            print("[SKIP] M6 real-tool sandbox check: /tmp/orc-pin missing")

        asyncio.run(asyncio.create_subprocess_exec("systemd-run", "--unit=orc-scan-aaaaaaaa-0000-0000-0000-000000000003",
                                                   "--collect", "-p", "DynamicUser=yes", "/bin/sleep", "300"))
        time.sleep(1)
        n = asyncio.run(sandbox.sweep())
        alive = subprocess.run(["systemctl", "is-active", "orc-scan-aaaaaaaa-0000-0000-0000-000000000003"],
                               capture_output=True, text=True).stdout.strip()
        ok("sweep stops leftover units", n >= 1 and alive != "active", (n, alive))
    finally:
        lst.close()
        for p in (probe, bomb, sleeper, marker):
            try:
                os.remove(p)
            except OSError:
                pass

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
