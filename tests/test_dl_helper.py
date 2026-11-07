#!/usr/bin/env python3
"""dl_helper: Range decisions, isolation, stat/read/zip edge cases.

Dependency-free — run directly:  python3 tests/test_dl_helper.py
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from orchestratia_agent import dl_helper as h  # noqa: E402

HELPER = os.path.join(ROOT, "orchestratia_agent", "dl_helper.py")
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def run(op, path, cwd, *extra, timeout=20, env=None):
    p = subprocess.run([sys.executable, "-I", HELPER, op, "--cwd", cwd, *extra, "--", path],
                       capture_output=True, timeout=timeout, cwd="/", env=env)
    head, _, body = p.stdout.partition(b"\n")
    return p.returncode, json.loads(head or b"{}"), body


# ── Range decisions ─────────────────────────────────────────────────────────
E = h.etag(1000, 5)
ok("no Range -> 200 full", h.decide_range(None, None, 1000, E) == (200, 0, 1000))
ok("bytes=100- -> 206", h.decide_range("bytes=100-", None, 1000, E) == (206, 100, 900))
ok("bytes=0-99 -> 206", h.decide_range("bytes=0-99", None, 1000, E) == (206, 0, 100))
ok("suffix bytes=-100", h.decide_range("bytes=-100", None, 1000, E) == (206, 900, 100))
ok("end clamped", h.decide_range("bytes=900-5000", None, 1000, E) == (206, 900, 100))
ok("start >= size -> 416", h.decide_range("bytes=1000-", None, 1000, E)[0] == 416)
ok("multi-range ignored", h.decide_range("bytes=0-1,5-6", None, 1000, E) == (200, 0, 1000))
ok("garbage ignored", h.decide_range("lines=1-2", None, 1000, E) == (200, 0, 1000))
ok("If-Range match -> 206", h.decide_range("bytes=10-", E, 1000, E) == (206, 10, 990))
ok("If-Range mismatch -> full 200", h.decide_range("bytes=10-", '"x"', 1000, E) == (200, 0, 1000))
ok("empty file", h.decide_range(None, None, 0, h.etag(0, 1)) == (200, 0, 0))

# ── isolation + protocol ────────────────────────────────────────────────────
src = open(HELPER).read()
body_src = src.split('"""', 2)[-1]
for forbidden in ("orchestratia_agent", "websockets", "yaml", "requests"):
    ok(f"helper does not import {forbidden}", f"import {forbidden}" not in body_src
       and f"from {forbidden}" not in body_src)
ok("shebang runs python3 isolated", src.startswith("#!/usr/bin/python3 -I"))

with tempfile.TemporaryDirectory() as d:
    # A json.py in the caller's directory must not be imported (-I + cwd="/").
    open(os.path.join(d, "json.py"), "w").write("raise SystemExit('hijacked')\n")
    data = os.urandom(700_000)
    f = os.path.join(d, "a.bin")
    open(f, "wb").write(data)
    rc, head, _ = run("stat", "a.bin", d, env={"PYTHONPATH": d})
    ok("PYTHONPATH/cwd can't hijack the helper", rc == 0 and head.get("protocol") == h.PROTOCOL, head)
    ok("every header lists the ops (protocol 2)", head.get("protocol") == 2
       and head.get("ops") == ["stat", "read", "zip", "ul-prepare", "ul-write", "ul-cancel", "ul-sweep"], head)
    p = subprocess.run([sys.executable, "-I", HELPER, "stat", "--cwd", d], capture_output=True, timeout=20, cwd="/")
    ok("a download op still requires its path", p.returncode == 2 and not p.stdout)
    dash = os.path.join(d, "-rf")
    open(dash, "w").write("x")
    rc, head, _ = run("stat", "-rf", d)
    ok("a path starting with '-' is a path, not an option", rc == 0 and head["name"] == "-rf", head)

    # ── stat ───────────────────────────────────────────────────────────────
    rc, head, _ = run("stat", "a.bin", d)
    ok("stat relative via --cwd", rc == 0 and head["kind"] == "file" and head["size"] == 700_000)
    rc, head, _ = run("stat", "missing", d)
    ok("missing -> not_found exit 2", rc == 2 and head["error"] == "not_found")
    rc, head, _ = run("stat", "/dev/null", d)
    ok("device -> not_regular", rc == 2 and head["error"] == "not_regular")
    os.makedirs(os.path.join(d, "sub", "deep"))
    open(os.path.join(d, "sub", "x.txt"), "w").write("hello")
    rc, head, _ = run("stat", "sub", d)
    ok("dir -> entries + approx size", rc == 0 and head["kind"] == "dir" and head["entries"] >= 2)

    # ── read ───────────────────────────────────────────────────────────────
    rc, head, body = run("read", f, d)
    ok("read full", rc == 0 and head["status"] == 200 and body == data)
    rc, head, body = run("read", f, d, "--range", "bytes=1000-1999")
    ok("read range", head["status"] == 206 and body == data[1000:2000])
    rc, head, body = run("read", f, d, "--range", "bytes=1000-", "--if-range", head["etag"])
    ok("resume with matching etag", head["status"] == 206 and body == data[1000:])
    rc, head, _ = run("read", f, d, "--range", "bytes=999999999-")
    ok("unsatisfiable -> error with size", rc == 2 and head["error"] == "range_not_satisfiable"
       and head["size"] == 700_000)
    rc, head, _ = run("read", "/dev/zero", d)
    ok("read refuses a device (would never end)", rc == 2 and head["error"] == "not_regular")
    fifo = os.path.join(d, "pipe")
    os.mkfifo(fifo)
    rc, head, _ = run("read", fifo, d, timeout=10)
    ok("read refuses a FIFO without hanging", rc == 2 and head["error"] == "not_regular")
    if os.geteuid() != 0:
        locked = os.path.join(d, "locked")
        open(locked, "w").write("secret")
        os.chmod(locked, 0)
        rc, head, _ = run("read", locked, d)
        ok("unreadable -> permission_denied", rc == 2 and head["error"] == "permission_denied")

    # ── zip ────────────────────────────────────────────────────────────────
    os.symlink("/etc/passwd", os.path.join(d, "sub", "link"))
    old = os.path.join(d, "sub", "old.txt")
    open(old, "w").write("1970")
    os.utime(old, (0, 0))                                   # pre-1980 mtime
    os.mkfifo(os.path.join(d, "sub", "fifo"))
    weird = os.path.join(d.encode(), b"sub", b"\xff\xfe.txt")
    with open(weird, "wb") as fh:
        fh.write(b"bytes name")
    rc, head, body = run("zip", "sub", d, timeout=30)
    ok("zip header names <dir>.zip", rc == 0 and head["name"] == "sub.zip", head)
    zf = zipfile.ZipFile(io.BytesIO(body))
    ok("zip is valid", zf.testzip() is None)
    names = set(zf.namelist())
    ok("files under the dir name", "sub/x.txt" in names, names)
    ok("empty dirs kept", "sub/deep/" in names, names)
    ok("pre-1980 file included (no crash)", "sub/old.txt" in names, names)
    ok("FIFO skipped without hanging", "sub/fifo" not in names)
    info = zf.getinfo("sub/link")
    ok("symlink stored as a link", (info.external_attr >> 16) & 0o170000 == 0o120000
       and zf.read("sub/link") == b"/etc/passwd")
    skipped = zf.read("sub/ORCHESTRATIA-SKIPPED.txt").decode("utf-8", "replace") if \
        "sub/ORCHESTRATIA-SKIPPED.txt" in names else ""
    ok("non-UTF-8 name is either stored or listed as skipped — never a crash",
       any(n.endswith(".txt") and "x.txt" not in n and "old" not in n for n in names) or ".txt" in skipped)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
