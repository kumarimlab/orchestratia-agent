#!/usr/bin/env python3
"""dl-helper snap hardening (adversarial review L1, L4, M11 note).

L1   the size counted against the cap must be the size streamed (one fstat of the open file).
M11  a directory swapped for a symlink after the walk saw it must not redirect the walk.
L4   system trees and Orchestratia's own directories are never snapshotted.

Races are made deterministic by a wrapper that runs the REAL helper in a subprocess with os.walk /
os.fwalk / os.lstat hooked to do the swap at the worst moment.

Run:  python3 tests/test_scan_snap_hardening.py
"""
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER = os.path.join(HERE, "orchestratia_agent", "dl_helper.py")
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def run_wrapped(prelude, repo):
    code = ("import os, runpy, sys\n" + prelude +
            f"\nsys.argv = [{HELPER!r}, 'snap', '--', {repo!r}]\nrunpy.run_path({HELPER!r}, run_name='__main__')\n")
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, timeout=120, cwd="/")
    head, _, body = p.stdout.partition(b"\n")
    return p.returncode, json.loads(head or b"{}"), body, p.stderr.decode(errors="replace")


def members(body):
    out = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r|") as tf:
            for m in tf:
                out[m.name] = tf.extractfile(m).read() if m.isfile() else None
    except tarfile.TarError:
        pass
    return out


with tempfile.TemporaryDirectory() as td:
    # ---- L1: counted from one lstat, streamed from another
    repo = os.path.join(td, "l1")
    os.makedirs(repo)
    big = os.path.join(repo, "big.bin")
    with open(big, "wb") as f:
        f.truncate(3 * 1024 ** 3)                     # sparse: 3 GiB apparent, nothing on disk
    small = os.path.join(td, "small")
    with open(small, "wb") as f:
        f.write(b"x")
    # The first lstat of big.bin sees a 1-byte file (the race the reviewer ran with a flipper);
    # stdout is counted and discarded so nothing large is held in memory.
    prelude = (f"_real = os.lstat\n_n = [0]\n"
               f"def _lstat(p, *a, **k):\n"
               f"    if str(p).endswith('big.bin') and _n[0] == 0:\n"
               f"        _n[0] += 1\n        return _real({small!r})\n"
               f"    return _real(p, *a, **k)\n"
               f"os.lstat = _lstat\n"
               f"import atexit, io\n"
               f"class _Count(io.RawIOBase):\n"
               f"    n = 0\n"
               f"    def writable(self):\n        return True\n"
               f"    def write(self, b):\n        _Count.n += len(b)\n        return len(b)\n"
               f"sys.stdout = io.TextIOWrapper(io.BufferedWriter(_Count()))\n"
               f"atexit.register(lambda: sys.stderr.write('STREAMED=%d\\n' % _Count.n))\n")
    rc, head, body, err = run_wrapped(prelude, repo)
    streamed = max([int(x.split("=")[1]) for x in err.split() if x.startswith("STREAMED=")] or [0])
    ok("L1 the size checked against the cap is the size streamed (3 GiB counted as 3 GiB → cap, rc 3)",
       rc == 3 and streamed < 2 * 1024 ** 3, (rc, streamed, err[-300:]))

    # ---- M11: a directory swapped for a symlink after the walk listed it
    repo = os.path.join(td, "m11")
    os.makedirs(os.path.join(repo, "sub"))
    with open(os.path.join(repo, "sub", "ok.txt"), "w") as f:
        f.write("fine")
    outside = os.path.join(td, "outside")
    os.makedirs(outside)
    with open(os.path.join(outside, "secret.txt"), "w") as f:
        f.write("OUTSIDE-SECRET")
    sub, real_sub = os.path.join(repo, "sub"), os.path.join(repo, "sub.real")
    prelude = (f"def _swap():\n"
               f"    if os.path.lexists({real_sub!r}):\n        return\n"
               f"    os.rename({sub!r}, {real_sub!r})\n"
               f"    os.symlink({outside!r}, {sub!r})\n"
               f"def _hook(orig):\n"
               f"    def gen(*a, **k):\n"
               f"        first = True\n"
               f"        for x in orig(*a, **k):\n"
               f"            yield x\n"
               f"            if first:\n"
               f"                first = False\n"
               f"                _swap()\n"
               f"    return gen\n"
               f"os.fwalk = _hook(os.fwalk)\n"
               # os.walk re-checks islink() right before it descends: swap inside that window too
               f"_islink = os.path.islink\n"
               f"def _il(p):\n"
               f"    r = _islink(p)\n"
               f"    if str(p).endswith('/sub'):\n        _swap()\n"
               f"    return r\n"
               f"os.path.islink = _il\n")
    rc, head, body, err = run_wrapped(prelude, repo)
    got = members(body)
    ok("M11 a dir swapped for a symlink mid-walk doesn't take the walk outside the repo",
       not any(v and b"OUTSIDE-SECRET" in v for v in got.values()), (rc, sorted(got), err[-300:]))

# ---- L4: system and Orchestratia trees are refused
spec = importlib.util.spec_from_file_location("dl_helper_mod", HELPER)
dl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dl)
refused = getattr(dl, "_is_system_path", None)
if refused is None:
    ok("L4 dl_helper has a system-tree refusal", False)
else:
    for path in ("/etc", "/etc/orchestratia", "/usr/local/libexec/orchestratia", "/var/lib/orchestratia",
                 "/var/lib/orchestratia/scan-data", "/opt/orchestratia", "/opt/orchestratia/scanners/runner",
                 "/opt/orchestratia-agent", "/opt/orchestratia-venv", "/var/lib/private", "/proc/self", "/sys", "/boot",
                 "/opt", "/var", "/var/lib", "/usr", "/run/user"):
        ok(f"L4 refuses {path}", refused(path))
    for path in ("/srv/app", "/opt/myapp", "/var/www/app", "/data/repo", "/tmp/x", "/opt/orchestratia-website"):
        ok(f"L4 allows {path}", not refused(path))
for path in ("/etc", "/usr/lib/python3"):
    p = subprocess.run([sys.executable, "-I", HELPER, "snap", "--", path], capture_output=True, timeout=60)
    head = json.loads(p.stdout.partition(b"\n")[0] or b"{}")
    ok(f"L4 snap {path} is refused with refused_system", head.get("ok") is False and head.get("error") == "refused_system",
       head)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
