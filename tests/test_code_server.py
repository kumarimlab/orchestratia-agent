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



# ── relay bridge: target port is PINNED server-side, never from the message ──
# (finding #3) — else the relay↔agent link becomes a general loopback-SSRF
# primitive that could reach any local port.

def test_relay_bridge_pins_the_target_port():
    import asyncio
    from orchestratia_agent import relay_client as rc

    opened = {}

    async def fake_open(tunnel_id, host, port, ws_send):
        opened["host"] = host
        opened["port"] = port

    activity = {"n": 0}
    orig = rc.open_tunnel
    rc.open_tunnel = fake_open
    try:
        # A malicious/confused relay asks for port 9999; the agent must ignore it
        # and open ONLY the port code-server actually bound (41000).
        asyncio.get_event_loop().run_until_complete(
            rc.handle_relay_message(
                {"type": "tunnel_open", "tunnel_id": "t1", "target_port": 9999,
                 "target_host": "10.0.0.5"},
                pinned_port=41000,
                ws_send=lambda m: asyncio.sleep(0),
                on_activity=lambda: activity.__setitem__("n", activity["n"] + 1),
            )
        )
    finally:
        rc.open_tunnel = orig
    ok("target port is the pinned code-server port, not the message's",
       opened.get("port") == 41000, opened)
    ok("target host is loopback, not the message's",
       opened.get("host") == "127.0.0.1", opened)
    ok("inbound frame counted as activity", activity["n"] == 1)

def test_hub_code_server_start_launches_and_bridges():
    import asyncio
    from orchestratia_agent import hub, code_server, relay_client, privilege

    class St:
        config = {}
        api_key = "orc_test"
    st = St()

    from orchestratia_agent import tls
    started = {}
    connected = {}
    real_start, real_connect = code_server.start, relay_client.connect
    real_bssl = tls.build_ssl_context
    real_tc = hub._tier_config
    def _fake_start(pid, wd, tc):
        started["args"] = (pid, wd)
        return 41000
    code_server.start = _fake_start
    relay_client.connect = lambda sid, url, key, port, on_activity, ssl_ctx: \
        connected.setdefault("args", (sid, url, port))
    tls.build_ssl_context = lambda state=None: None   # local import in the handler
    hub._tier_config = lambda state: privilege.load_tier_config({})
    try:
        asyncio.get_event_loop().run_until_complete(hub._handle_code_server_start(
            st, "sess-1", "pid-A", "/srv/a", "wss://relay.example"))
    finally:
        code_server.start, relay_client.connect = real_start, real_connect
        tls.build_ssl_context, hub._tier_config = real_bssl, real_tc

    ok("code-server started for the project+workspace", started.get("args") == ("pid-A", "/srv/a"))
    ok("relay bridge connected with the PINNED port",
       connected.get("args") == ("sess-1", "wss://relay.example", 41000), connected)
    ok("editor session tracked for reaper teardown",
       "sess-1" in hub._editor_sessions.get("pid-A", set()))


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
