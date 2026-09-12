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


# ── idle-stop: ACTIVITY, not connection presence (B2) ────────────────────────
# code-server holds its WebSocket open forever, so "no connection" never fires
# and every host would silently revert to always-on. Idle must be driven by
# actual user activity.

def test_idle_reap_uses_activity_not_connection():
    cs._reset_for_test()
    real = cs._clock
    try:
        cs._clock = lambda: 1000.0
        cs.note_activity("pid-A")
        cs._clock = lambda: 1000.0 + cs.IDLE_SECONDS - 1
        ok("not reaped before the idle threshold",
           cs.reap_idle(running={"pid-A"}) == [])
        cs._clock = lambda: 1000.0 + cs.IDLE_SECONDS + 1
        ok("reaped after the idle threshold",
           cs.reap_idle(running={"pid-A"}) == ["pid-A"])
    finally:
        cs._clock = real


def test_activity_resets_the_idle_clock():
    cs._reset_for_test()
    real = cs._clock
    try:
        cs._clock = lambda: 1000.0
        cs.note_activity("pid-A")
        cs._clock = lambda: 1000.0 + cs.IDLE_SECONDS - 1
        cs.note_activity("pid-A")   # fresh activity just before the threshold
        cs._clock = lambda: 1000.0 + cs.IDLE_SECONDS + 1
        ok("fresh activity keeps it alive", cs.reap_idle(running={"pid-A"}) == [])
    finally:
        cs._clock = real


def test_reap_ignores_projects_not_running():
    cs._reset_for_test()
    real = cs._clock
    try:
        cs._clock = lambda: 1000.0
        cs.note_activity("pid-gone")
        cs._clock = lambda: 1e9
        ok("a stale activity entry for a stopped project is not returned",
           cs.reap_idle(running=set()) == [])
    finally:
        cs._clock = real


# ── orc-attach: the editor terminal attaches to the project's governed tmux ───

def test_settings_json_points_terminal_at_orc_attach():
    s = cs.settings_json()
    default = s.get("terminal.integrated.defaultProfile.linux")
    profiles = s.get("terminal.integrated.profiles.linux", {})
    ok("a default terminal profile is set", bool(default), default)
    prof = profiles.get(default, {})
    ok("the default profile runs orc-attach",
       "orc-attach" in (prof.get("args") or []) or "orc-attach" in str(prof.get("path", "")),
       prof)
    ok("extension auto-update is off", s.get("extensions.autoUpdate") is False)


def test_orc_attach_choice():
    from orchestratia_agent import orc_attach as oa
    ok("no sessions -> nothing to attach", oa.choose_action([]) == ("none", None))
    ok("exactly one -> attach it", oa.choose_action(["orc-abc"]) == ("attach", "orc-abc"))
    act, payload = oa.choose_action(["orc-a", "orc-b"])
    ok("many -> present a picker", act == "pick" and payload == ["orc-a", "orc-b"])


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
