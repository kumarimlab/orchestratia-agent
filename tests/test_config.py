#!/usr/bin/env python3
"""config.yaml holds the server API key, so only its owner may read it.

It was written 0644 (and root-owned, because the installer registers as root). A
locked-down project user could `cat /etc/orchestratia/config.yaml`, take the key and
act as the server against the hub — the one boundary that tier exists to draw.
Found on staging, 2026-09-14.

Dependency-free — run directly:  python3 tests/test_config.py
"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import config as cfg  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_new_config_is_owner_only():
    old = os.umask(0o022)
    try:
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "config.yaml")
            cfg.save_config(p, {"api_key": "orc_secret"})
            ok("created 0600 under a permissive umask", _mode(p) == 0o600, oct(_mode(p)))
            ok("content written", cfg.load_config(p) == {"api_key": "orc_secret"})
    finally:
        os.umask(old)


def test_rewrite_tightens_a_world_readable_config_atomically():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "config.yaml")
        with open(p, "w") as f:
            f.write("api_key: orc_old\n")
        os.chmod(p, 0o644)
        cfg.save_config(p, {"api_key": "orc_new"})
        ok("tightened to 0600", _mode(p) == 0o600, oct(_mode(p)))
        ok("updated", cfg.load_config(p) == {"api_key": "orc_new"})
        ok("no temp file left behind", os.listdir(td) == ["config.yaml"], os.listdir(td))


def test_owner_rule():
    """Run as root (installer, provision-tier), the file belongs to the daemon user —
    which is who owns its directory — or stays with a non-root owner it already has.
    Root-owned 0600 would lock the daemon out of its own config."""
    class St:
        def __init__(self, uid, gid):
            self.st_uid, self.st_gid = uid, gid
    rule = cfg._config_owner
    ok("root-owned file in the daemon user's dir -> the daemon user",
       rule(St(0, 0), St(1001, 1001)) == (1001, 1001))
    ok("new file in the daemon user's dir -> the daemon user", rule(None, St(1001, 1001)) == (1001, 1001))
    ok("a non-root owner is kept even in a root dir", rule(St(1002, 1002), St(0, 0)) == (1002, 1002))
    ok("root everywhere stays root", rule(St(0, 0), St(0, 0)) == (0, 0))


def test_save_as_root_hands_the_file_to_that_owner():
    calls = []
    saved = (cfg.os.geteuid, getattr(cfg.os, "fchown", None))
    try:
        cfg.os.geteuid = lambda: 0
        cfg.os.fchown = lambda fd, uid, gid: calls.append((uid, gid))
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "config.yaml")
            cfg.save_config(p, {"a": 1})
            st = os.stat(td)
            ok("chowned to the directory's owner", calls == [(st.st_uid, st.st_gid)], calls)
    finally:
        cfg.os.geteuid = saved[0]
        if saved[1] is not None:
            cfg.os.fchown = saved[1]


def test_check_permissions_repairs_what_it_owns_and_reports_what_it_cannot():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "config.yaml")
        with open(p, "w") as f:
            f.write("api_key: orc_x\n")
        os.chmod(p, 0o644)
        ok("own world-readable file is fixed", cfg.secure_config_file(p) == "fixed" and _mode(p) == 0o600,
           oct(_mode(p)))
        ok("already private is ok", cfg.secure_config_file(p) == "ok")
        os.chmod(p, 0o640)
        saved = cfg.os.getuid
        try:
            cfg.os.getuid = lambda: os.stat(p).st_uid + 1
            ok("someone else's readable file is reported, not touched",
               cfg.secure_config_file(p) == "exposed" and _mode(p) == 0o640, oct(_mode(p)))
        finally:
            cfg.os.getuid = saved
        ok("a missing file is ok", cfg.secure_config_file(os.path.join(td, "nope.yaml")) == "ok")


def test_startup_warning_only_when_it_cannot_fix_it():
    with tempfile.TemporaryDirectory() as td:
        p = os.path.join(td, "config.yaml")
        with open(p, "w") as f:
            f.write("api_key: orc_x\n")
        os.chmod(p, 0o644)
        ok("own file: fixed silently", cfg.config_permission_warning(p, True) is None and _mode(p) == 0o600)
        os.chmod(p, 0o644)
        saved = cfg.os.getuid
        try:
            cfg.os.getuid = lambda: os.stat(p).st_uid + 1
            w = cfg.config_permission_warning(p, True)
            ok("not ours + locked-down tier: names the risk and the fix",
               w is not None and "locked-down" in w and "chmod 600" in w, w)
            w = cfg.config_permission_warning(p, False)
            ok("not ours, no tier: still warns", w is not None and "locked-down" not in w, w)
        finally:
            cfg.os.getuid = saved


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = []
    for case in CASES:
        try:
            case()
        except Exception as e:  # noqa: BLE001
            failed.append(f"{case.__name__}: {e!r}")
            results.append(False)
    for f in failed:
        print("ERROR", f)
    if not results or not all(results):
        print(f"FAIL  {results.count(False)} of {len(results)} failed")
        raise SystemExit(1)
    print(f"ok  {len(results)} passed")


if __name__ == "__main__":
    main()
