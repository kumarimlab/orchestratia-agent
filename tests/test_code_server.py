#!/usr/bin/env python3
"""code-server spawn — locked down and run as the project's restricted user.

Dependency-free — run directly:  python3 tests/test_code_server.py

The editor MUST be reachable only through the relay: it binds loopback with
--auth none (safe ONLY because loopback + the tunnel are the sole path), runs as
the project's restricted user, and keeps its data/extensions in a private dir.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import code_server as cs  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def test_spawn_argv_is_locked_down_and_runs_as_the_user():
    argv = cs.spawn_argv("orcp-a1b2c3d45e6f", 41000, "/srv/a", "/home/orcp/.cs")
    j = " ".join(argv)
    ok("runs as the project user via sudo -n -u -H",
       argv[:5] == ["sudo", "-n", "-u", "orcp-a1b2c3d45e6f", "-H"], argv[:5])
    ok("auth is disabled (relay is the gate)", "--auth" in argv and "none" in argv)
    ok("binds LOOPBACK only", "--bind-addr" in argv and "127.0.0.1:41000" in j,
       [a for a in argv if "bind" in a or "127" in a])
    ok("never binds a non-loopback address", "0.0.0.0" not in j)
    ok("telemetry + update check off",
       "--disable-telemetry" in argv and "--disable-update-check" in argv)
    ok("workspace trust off", "--disable-workspace-trust" in argv)
    ok("private user-data + extensions dirs (not the shared marketplace tree)",
       "--user-data-dir" in argv and "--extensions-dir" in argv)
    ok("opens the granted workspace", "/srv/a" in argv)


def test_spawn_argv_standard_user_would_be_a_bug():
    # Editors are restricted-only; spawn_argv must always drop privilege.
    argv = cs.spawn_argv("orcp-x", 41001, "/srv/b", "/tmp/cs")
    ok("no editor argv without sudo drop", argv[0] == "sudo")


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            failures.append((fn.__name__, f"{type(e).__name__}: {e}"))
    bad = [r for r in results if not r]
    if failures or bad:
        for name, msg in failures:
            print(f"ERROR {name}: {msg}")
        print(f"\n{len(bad)} assertion(s) failed, {len(failures)} error(s)")
        raise SystemExit(1)
    print(f"ok  {len(results)} assertions passed")


if __name__ == "__main__":
    main()
