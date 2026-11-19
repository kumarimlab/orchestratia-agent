#!/usr/bin/env python3
"""Scanner pack (spec §7.1–7.2): checksum before unpack, nothing half-installed, never on a
hub host, OSV data swapped atomically, runner files synced.

Run:  python3 tests/test_scan_pack.py
"""
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning import pack  # noqa: E402

_real_is_hub_host = pack.is_hub_host
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def tgz(name, data):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


GL = tgz("gitleaks", b"#!/bin/sh\necho gitleaks\n")
OSV = b"#!/bin/sh\necho osv\n"
blobs = {"https://x/gl.tgz": GL, "https://x/osv": OSV}
manifest = {"manifest_version": 1, "tools": {
    "gitleaks": {"version": "8.0.0", "license": "MIT", "binary": "gitleaks",
                 "assets": {"x86_64": {"url": "https://x/gl.tgz", "sha256": hashlib.sha256(GL).hexdigest(),
                                       "archive": "tar.gz"}}},
    "osv-scanner": {"version": "2.0.0", "license": "Apache-2.0", "binary": "osv-scanner",
                    "assets": {"x86_64": {"url": "https://x/osv", "sha256": hashlib.sha256(OSV).hexdigest(),
                                          "archive": "binary"}}}}}
fetch = lambda url: blobs[url]

with tempfile.TemporaryDirectory() as td:
    root = os.path.join(td, "scanners")
    pack.is_hub_host = lambda: False
    pack.sandbox.support = lambda: (True, "ok")
    info = pack.install(root=root, manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
    paths = pack.tool_paths(root, manifest)
    ok("installs both tools at name/version", paths.get("gitleaks", "").endswith("gitleaks/8.0.0/gitleaks")
       and paths.get("osv-scanner", "").endswith("osv-scanner/2.0.0/osv-scanner"), paths)
    ok("binaries are executable", all(os.access(p, os.X_OK) for p in paths.values()))
    ok("runner files are synced", all(os.path.isfile(os.path.join(root, "runner", f))
                                      for f in ("shim.py", "masking.py", "parsers.py", "code_agent.py", "catalog.py")))

    bad = json.loads(json.dumps(manifest))
    bad["tools"]["osv-scanner"]["version"] = "2.0.1"
    bad["tools"]["osv-scanner"]["assets"]["x86_64"]["sha256"] = "0" * 64
    try:
        pack.install(root=root, manifest=bad, arch="x86_64", fetch=fetch, require_root=False)
        ok("a checksum mismatch aborts", False)
    except pack.InstallError as e:
        ok("a checksum mismatch aborts with a clear error", "checksum" in str(e).lower(), str(e))
    ok("…and installs nothing of that version", not os.path.exists(os.path.join(root, "osv-scanner", "2.0.1")))

    pack.is_hub_host = lambda: True
    try:
        pack.install(root=root, manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
        ok("refuses on a hub host", False)
    except pack.InstallError as e:
        ok("refuses on a hub host", "hub" in str(e).lower(), str(e))
    pack.is_hub_host = lambda: False
    pack.sandbox.support = lambda: (False, "systemd 249 is older than 250")
    try:
        pack.install(root=root, manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
        ok("refuses without sandbox support", False)
    except pack.InstallError as e:
        ok("refuses without sandbox support, saying why", "249" in str(e), str(e))

    def zip_of(name):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(f"{name}.json", "{}")
        return buf.getvalue()
    osv_blobs = {f"https://osv-vulnerabilities.storage.googleapis.com/{e}/all.zip": zip_of(e) for e in ("PyPI", "npm")}
    data_root = os.path.join(td, "data")
    as_of = pack.refresh_osv(data_root=data_root, fetch=lambda u: osv_blobs[u], ecosystems=["PyPI", "npm"])
    path, got_as_of = pack.osv_db(data_root)
    ok("OSV refresh lands under current with an as-of date", path and os.path.isfile(
        os.path.join(path, "osv-scalibr", "PyPI", "all.zip")) and got_as_of == as_of, (path, got_as_of))
    first = os.path.realpath(path)

    def broken(u):
        raise OSError("network down")
    try:
        pack.refresh_osv(data_root=data_root, fetch=broken, ecosystems=["PyPI"])
    except Exception:
        pass
    ok("a failed refresh keeps the previous data", os.path.realpath(pack.osv_db(data_root)[0]) == first)

    # ruling 2: readable by an arbitrary UID, modes explicit (not umask-dependent)
    old_umask = os.umask(0o077)
    try:
        rroot = os.path.join(td, "scanners2")
        pack.is_hub_host = lambda: False
        pack.sandbox.support = lambda: (True, "ok")
        pack.install(root=rroot, manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
        ddata = os.path.join(td, "data2")
        pack.refresh_osv(data_root=ddata, fetch=lambda u: osv_blobs[u], ecosystems=["PyPI", "npm"])
    finally:
        os.umask(old_umask)

    def modes(top):
        bad = []
        for dp, dn, fn in os.walk(top):
            for n in dn:
                p = os.path.join(dp, n)
                if not os.path.islink(p) and (os.stat(p).st_mode & 0o777) != 0o755:
                    bad.append(p)
            for n in fn:
                p = os.path.join(dp, n)
                m = os.stat(p).st_mode & 0o777
                if m not in (0o644, 0o755):
                    bad.append(p)
        return bad
    ok("scan-data dirs 0755 / files 0644 under a 077 umask", not modes(ddata) and
       (os.stat(ddata).st_mode & 0o777) == 0o755, modes(ddata))
    ok("pack dirs/files world-readable under a 077 umask", not modes(rroot) and
       (os.stat(rroot).st_mode & 0o777) == 0o755, modes(rroot))
    ok("OSV zips are 0644", all((os.stat(os.path.join(ddata, "osv", "current", "osv-scalibr", e, "all.zip")).st_mode & 0o777) == 0o644
                                for e in ("PyPI", "npm")))
    ok("current symlink is relative", not os.path.isabs(os.readlink(os.path.join(ddata, "osv", "current"))))
    ok("binaries are 0755", all((os.stat(p).st_mode & 0o777) == 0o755 for p in pack.tool_paths(rroot, manifest).values()))

    # ---- review fixes ----
    def real_dirs(top):
        return sorted(x for x in os.listdir(top) if os.path.isdir(os.path.join(top, x)) and not os.path.islink(os.path.join(top, x)))
    d3 = os.path.join(td, "data3")
    osvr = os.path.join(d3, "osv")
    fz = lambda u: osv_blobs[u]
    pack.refresh_osv(data_root=d3, fetch=fz, ecosystems=["PyPI"])
    a = os.path.realpath(os.path.join(osvr, "current"))
    # force distinct dir names within the same day
    pack.refresh_osv(data_root=d3, fetch=fz, ecosystems=["PyPI"])
    b = os.path.realpath(os.path.join(osvr, "current"))
    ok("after two refreshes latest and previous both exist", a != b and os.path.isdir(a) and os.path.isdir(b), real_dirs(osvr))
    pack.refresh_osv(data_root=d3, fetch=fz, ecosystems=["PyPI"])
    c = os.path.realpath(os.path.join(osvr, "current"))
    ok("after a third only the last two remain", len(real_dirs(osvr)) == 2 and os.path.isdir(b)
       and os.path.isdir(c) and not os.path.exists(a), real_dirs(osvr))

    calls = []
    pack.sandbox.support = lambda: (calls.append(1), (True, "ok"))[1]
    pack._cap_cache.update(at=0.0, value=None)
    pack.capability(); pack.capability()
    ok("capability cached: support called once for two calls", len(calls) == 1, len(calls))
    pack.capability(force=True)
    ok("capability(force=True) bypasses the cache", len(calls) == 2, len(calls))
    pack.sandbox.support = lambda: (True, "ok")

    import subprocess as sp
    real_run = pack.subprocess.run
    class R:
        def __init__(s, rc, out=""):
            s.returncode, s.stdout = rc, out
    def fake(result):
        def run(*a, **k):
            if isinstance(result, Exception):
                raise result
            return result
        return run
    try:
        pack.subprocess.run = fake(R(1))
        ok("is_hub_host fails closed on docker non-zero rc", _real_is_hub_host() is True)
        pack.subprocess.run = fake(sp.TimeoutExpired("docker", 10))
        ok("is_hub_host fails closed on docker timeout", _real_is_hub_host() is True)
        pack.subprocess.run = fake(FileNotFoundError("docker"))
        ok("is_hub_host is False when docker is not installed", _real_is_hub_host() is False)
        pack.subprocess.run = fake(R(0, "web\ndb\n"))
        ok("is_hub_host False with unrelated containers", _real_is_hub_host() is False)
        pack.subprocess.run = fake(R(0, "web\norchestratia-postgres\n"))
        ok("is_hub_host True with a hub container", _real_is_hub_host() is True)
        pack.subprocess.run = fake(R(1))
        pack.is_hub_host = _real_is_hub_host
        try:
            pack.install(root=os.path.join(td, "s9"), manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
            ok("install refuses when docker can't be queried", False)
        except pack.InstallError as e:
            ok("install refuses when docker can't be queried, saying so", "could not check" in str(e), str(e))
    finally:
        pack.subprocess.run = real_run
        pack.is_hub_host = lambda: False

    # size caps
    old_cap = pack.TOOL_MAX_BYTES
    pack.TOOL_MAX_BYTES = 10
    try:
        pack.install(root=os.path.join(td, "s5"), manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
        ok("oversize tool download aborts", False)
    except pack.InstallError as e:
        ok("oversize tool download aborts", "limit" in str(e), str(e))
    finally:
        pack.TOOL_MAX_BYTES = old_cap
    ok("…and leaves no staging dirs", not [x for x in os.listdir(os.path.join(td, "s5")) if x.startswith(".")])
    old_cap = pack.OSV_MAX_BYTES
    pack.OSV_MAX_BYTES = 10
    d4 = os.path.join(td, "data4")
    try:
        pack.refresh_osv(data_root=d4, fetch=fz, ecosystems=["PyPI"])
        ok("oversize OSV zip aborts", False)
    except Exception as e:
        ok("oversize OSV zip aborts", "limit" in str(e), str(e))
    finally:
        pack.OSV_MAX_BYTES = old_cap if False else 2 * 1024 * 1024 * 1024
    ok("…and no OSV dir remains, no current link", not real_dirs(os.path.join(d4, "osv")) and pack.osv_db(d4)[0] is None)
    badzip = {"https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip": b"not a zip"}
    try:
        pack.refresh_osv(data_root=d4, fetch=lambda u: badzip[u], ecosystems=["PyPI"])
        ok("a corrupt OSV zip is rejected", False)
    except Exception:
        ok("a corrupt OSV zip is rejected", pack.osv_db(d4)[0] is None)

    # stale temp dirs
    s7 = os.path.join(td, "s7")
    os.makedirs(os.path.join(s7, ".gitleaks-crashed"))
    os.makedirs(os.path.join(s7, ".runner-crashed"))
    os.makedirs(os.path.join(s7, "keepme"))
    os.symlink(os.path.join(td, "scanners"), os.path.join(s7, ".gitleaks-link"))
    pack.install(root=s7, manifest=manifest, arch="x86_64", fetch=fetch, require_root=False)
    left = sorted(os.listdir(s7))
    ok("stale .name-*/.runner-* dirs removed; others and links untouched",
       ".gitleaks-crashed" not in left and ".runner-crashed" not in left and "keepme" in left
       and ".gitleaks-link" in left and os.path.isdir(os.path.join(td, "scanners")), left)

    # systemd units
    ud = os.path.join(td, "units")
    os.makedirs(ud)
    pack.install_timer("/opt/my python/bin/python3", unit_dir=ud, systemctl=False, probe=lambda py: "/x",
                       euid=lambda: 1000)
    svc = open(os.path.join(ud, "orchestratia-scan-data.service")).read()
    ok("ExecStart quotes the interpreter",
       'ExecStart="/opt/my python/bin/python3" -I -m orchestratia_agent.cli scanners refresh' in svc, svc)
    ok("unit files are 0644", all((os.stat(os.path.join(ud, f)).st_mode & 0o777) == 0o644 for f in os.listdir(ud)) and len(os.listdir(ud)) == 2)


# ---------------------------------------------------------------- final fix wave
import fcntl  # noqa: E402
with tempfile.TemporaryDirectory() as td:
    d = os.path.join(td, "data")
    os.makedirs(os.path.join(d, "osv"))
    fd = os.open(os.path.join(d, "osv", ".lock"), os.O_RDWR | os.O_CREAT, 0o644)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        pack.refresh_osv(data_root=d, fetch=lambda u: osv_blobs[u], ecosystems=["PyPI"])
        res = "ran"
    except pack.InstallError as e:
        res = str(e)
    except Exception as e:
        res = f"other: {e!r}"
    ok("refresh_osv refuses while another refresh holds the lock",
       "already running" in res and not os.path.lexists(os.path.join(d, "osv", "current")), res)
    fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
    pack.refresh_osv(data_root=d, fetch=lambda u: osv_blobs[u], ecosystems=["PyPI"])
    ok("refresh_osv runs once the lock is free, and keeps the lock file",
       os.path.isdir(os.path.join(d, "osv", "current")) and os.path.isfile(os.path.join(d, "osv", ".lock")))
    rr = os.path.join(td, "s")
    pack.sync_runner_files(rr)
    ok("sync_runner_files ships gitleaks.toml (flat layout)", os.path.isfile(os.path.join(rr, "runner", "gitleaks.toml")))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
