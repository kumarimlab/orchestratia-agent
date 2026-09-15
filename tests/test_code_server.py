#!/usr/bin/env python3
"""code-server spawn — locked down and run as the project's restricted user.

Dependency-free — run directly:  python3 tests/test_code_server.py

The editor MUST be reachable only through the relay: it binds loopback with
--auth none (safe ONLY because loopback + the tunnel are the sole path), runs as
the project's restricted user, and keeps its data/extensions in a private dir.
"""
import json
import os
import shutil
import sys
import tempfile

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
    # spawn_argv is the LOCKED-DOWN builder; it must always drop privilege.
    # (The standard editor uses spawn_argv_standard, which runs as the daemon user.)
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
    s = cs.settings_json("restricted")
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
        ws_connection = None
    st = St()

    from orchestratia_agent import tls
    started = {}
    connected = {}
    real_start, real_connect = code_server.start, relay_client.connect
    real_serving = code_server.check_serving
    real_bssl = tls.build_ssl_context
    real_tc = hub._tier_config
    def _fake_start(sid, pid, wd, tier, tc, *, hub_url=""):
        started["args"] = (pid, wd)
        return 41000
    code_server.start = _fake_start
    relay_client.connect = lambda sid, url, key, port, on_activity, ssl_ctx: \
        connected.setdefault("args", (sid, url, port))
    tls.build_ssl_context = lambda state=None: None   # local import in the handler
    hub._tier_config = lambda state: privilege.load_tier_config({})
    code_server.check_serving = lambda sid: True
    try:
        asyncio.get_event_loop().run_until_complete(hub._handle_code_server_start(
            st, "sess-1", "pid-A", "/srv/a", "wss://relay.example"))
    finally:
        code_server.start, relay_client.connect = real_start, real_connect
        tls.build_ssl_context, hub._tier_config = real_bssl, real_tc
        code_server.check_serving = real_serving

    ok("code-server started for the project+workspace", started.get("args") == ("pid-A", "/srv/a"))
    ok("relay bridge connected with the PINNED port",
       connected.get("args") == ("sess-1", "wss://relay.example", 41000), connected)
    ok("editor session tracked for close-time evidence",
       "sess-1" in hub._editor_workspaces)



def test_private_dirs_live_in_the_project_users_own_home():
    """The editor's data/extension dirs must sit under the user code-server RUNS
    as, not the daemon's home.

    They were built from os.path.expanduser("~"), which is the DAEMON's home.
    code-server then runs as orcp-<project> and cannot write there (the daemon
    home is 755 and owned by the daemon user), so it starts degraded: no IPC
    socket, unusable extensions dir. Observed live on staging 2026-09-13.

    It is also an isolation point, not just a permissions one: one shared tree
    under the daemon's home would put every project's editor state in the same
    place, which is precisely what the per-project users exist to prevent.
    """
    d = cs.cfg_dir_for("orcp-a1b2c3d45e6f", "01690d2f-47c6-4d37-b787-27904723922b")
    ok("cfg dir is under the PROJECT user's home",
       d.startswith("/home/orcp-a1b2c3d45e6f/"), d)
    ok("cfg dir is NOT under the daemon user's home",
       os.path.expanduser("~") not in d or not d.startswith(os.path.expanduser("~") + "/"), d)
    ok("cfg dir is per-project, not shared",
       "01690d2f-47c" in d, d)

    other = cs.cfg_dir_for("orcp-ffffffffffff", "99999999-4c6d-4d37-b787-279047239999")
    ok("different projects get different dirs", d != other)


# ── per-session processes; the standard editor runs as the daemon user ──────

class _FakeProc:
    _next = 4000

    def __init__(self, argv, **kw):
        _FakeProc._next += 1
        self.pid, self.argv, self.kw = _FakeProc._next, argv, kw

    def poll(self):
        return None


def _std_env():
    """Temp state root, fake installed binary, fake Popen; returns restore fn."""
    from orchestratia_agent import code_server_install as ci
    root = tempfile.mkdtemp()
    saved = (cs.subprocess.Popen, ci.installed, ci.binary_path, cs._STATE_ROOT_OVERRIDE, cs.os.killpg, cs.os.getpgid)
    spawned, killed = [], []

    def popen(argv, **kw):
        proc = _FakeProc(argv, **kw)
        spawned.append(proc)
        return proc
    cs.subprocess.Popen = popen
    ci.installed = lambda version=None: True
    ci.binary_path = lambda version=None: "/opt/fake/code-server/bin/code-server"
    cs._STATE_ROOT_OVERRIDE = root
    cs.os.getpgid = lambda pid: pid
    cs.os.killpg = lambda pgid, sig: killed.append(pgid)
    cs._reset_for_test()

    def restore():
        (cs.subprocess.Popen, ci.installed, ci.binary_path, cs._STATE_ROOT_OVERRIDE, cs.os.killpg, cs.os.getpgid) = saved
        cs._reset_for_test()
        shutil.rmtree(root, ignore_errors=True)
    return root, spawned, killed, restore


def test_standard_spawns_as_the_daemon_user_per_session():
    from orchestratia_agent import privilege
    root, spawned, killed, restore = _std_env()
    ws = tempfile.mkdtemp()
    try:
        tc = privilege.load_tier_config({})
        p1 = cs.start("sess-aaaaaaaaaaaa1", "proj-111111111111", ws, "standard", tc, hub_url="https://hub.example")
        p2 = cs.start("sess-bbbbbbbbbbbb2", "proj-111111111111", ws, "standard", tc, hub_url="https://hub.example")
        a1, a2 = spawned[0].argv, spawned[1].argv
        ok("two sessions of one project = two processes", len(spawned) == 2 and p1 != p2)
        ok("no sudo prefix (runs as the daemon user)", a1[0] == "/opt/fake/code-server/bin/code-server", a1[:2])
        ok("binds loopback only", f"127.0.0.1:{p1}" in a1)
        ok("--auth none", a1[a1.index("--auth") + 1] == "none")
        ok("opens the requested folder last", a1[-1] == ws)
        udd1, udd2 = a1[a1.index("--user-data-dir") + 1], a2[a2.index("--user-data-dir") + 1]
        ok("user-data-dir is per session", udd1 != udd2)
        ok("extensions dir is shared per project",
           a1[a1.index("--extensions-dir") + 1] == a2[a2.index("--extensions-dir") + 1])
        env = spawned[0].kw.get("env") or {}
        ok("editor session id in env", env.get("ORCHESTRATIA_EDITOR_SESSION_ID") == "sess-aaaaaaaaaaaa1")
        ok("project id in env", env.get("ORCHESTRATIA_PROJECT_ID") == "proj-111111111111")
        ok("hub url in env", env.get("ORCHESTRATIA_HUB_URL") == "https://hub.example")
        ok("new process group (stop kills the tree)", spawned[0].kw.get("start_new_session") is True)
    finally:
        restore()
        shutil.rmtree(ws, ignore_errors=True)


def test_standard_settings_written_and_user_keys_preserved():
    from orchestratia_agent import privilege
    root, spawned, killed, restore = _std_env()
    ws = tempfile.mkdtemp()
    try:
        state = cs.standard_state_dir("proj-222222222222")
        os.makedirs(state, exist_ok=True)
        with open(os.path.join(state, "settings.json"), "w") as f:
            json.dump({"editor.fontSize": 17, "terminal.integrated.defaultProfile.linux": "bash"}, f)
        cs.start("sess-cccccccccccc3", "proj-222222222222", ws, "standard", privilege.load_tier_config({}))
        a = spawned[0].argv
        path = os.path.join(a[a.index("--user-data-dir") + 1], "User", "settings.json")
        data = json.load(open(path))
        ok("settings.json written", os.path.exists(path))
        ok("user's own key preserved", data.get("editor.fontSize") == 17)
        ok("our terminal default wins", data.get("terminal.integrated.defaultProfile.linux") == "orchestratia")
        ok("profile runs orc-attach",
           data["terminal.integrated.profiles.linux"]["orchestratia"]["args"] == ["orc-attach"])
    finally:
        restore()
        shutil.rmtree(ws, ignore_errors=True)


def test_standard_stop_saves_settings_and_cleans_session_dir():
    from orchestratia_agent import privilege
    root, spawned, killed, restore = _std_env()
    ws = tempfile.mkdtemp()
    try:
        cs.start("sess-dddddddddddd4", "proj-333333333333", ws, "standard", privilege.load_tier_config({}))
        a = spawned[0].argv
        udd = a[a.index("--user-data-dir") + 1]
        sp = os.path.join(udd, "User", "settings.json")
        data = json.load(open(sp))
        data["editor.tabSize"] = 3
        json.dump(data, open(sp, "w"))
        cs.stop("sess-dddddddddddd4")
        saved = json.load(open(os.path.join(cs.standard_state_dir("proj-333333333333"), "settings.json")))
        ok("process group killed", killed == [spawned[0].pid], killed)
        ok("user's change saved to the project", saved.get("editor.tabSize") == 3)
        ok("session user-data-dir removed", not os.path.exists(udd))
        ok("no longer running", not cs.is_running("sess-dddddddddddd4"))
    finally:
        restore()
        shutil.rmtree(ws, ignore_errors=True)


def test_standard_refuses_missing_folder_and_missing_binary():
    from orchestratia_agent import privilege, code_server_install as ci
    root, spawned, killed, restore = _std_env()
    try:
        tc = privilege.load_tier_config({})
        try:
            cs.start("sess-eeeeeeeeeeee5", "proj-444444444444", "/does/not/exist", "standard", tc)
            ok("missing folder refused", False)
        except cs.EditorStartError as e:
            ok("missing folder refused", "/does/not/exist" in str(e), str(e))
        ci.installed = lambda version=None: False
        try:
            cs.start("sess-ffffffffffff6", "proj-444444444444", root, "standard", tc)
            ok("missing binary refused", False)
        except cs.EditorStartError:
            ok("missing binary refused", True)
        ok("nothing spawned", spawned == [])
    finally:
        restore()


def test_check_serving_answers_from_the_real_port():
    import socket as _s

    class Proc:
        def __init__(self, port, rc=None):
            self._orc_port, self._rc, self.pid = port, rc, 0
        def poll(self):
            return self._rc
    lsn = _s.socket()
    lsn.bind(("127.0.0.1", 0))
    port = lsn.getsockname()[1]
    saved = (dict(cs._running), dict(cs._session_key))
    try:
        cs._running["sess-live"] = Proc(port)
        cs._session_key["sess-live"] = "sess-live"
        ok("bound but not listening -> not serving", cs.check_serving("sess-live") is False)
        lsn.listen(1)
        ok("listening -> serving", cs.check_serving("sess-live") is True)
        cs._running["project:p"] = Proc(port, rc=3)
        cs._session_key["sess-dead"] = "project:p"
        try:
            cs.check_serving("sess-dead")
            ok("an exited process raises", False)
        except cs.EditorStartError as e:
            ok("an exited process raises with its exit code", "exit code 3" in str(e), str(e))
        try:
            cs.check_serving("sess-unknown")
            ok("an unknown session raises", False)
        except cs.EditorStartError:
            ok("an unknown session raises", True)
    finally:
        lsn.close()
        cs._running.clear(); cs._running.update(saved[0])
        cs._session_key.clear(); cs._session_key.update(saved[1])


def test_restricted_sessions_share_one_process_per_project():
    root, spawned, killed, restore = _std_env()
    saved = (cs.p.resolve_user, cs.p.verify_workspace, cs.cfg_dir_for)
    try:
        cs.p.resolve_user = lambda tier, pid, tc: "orcp-abc"
        cs.p.verify_workspace = lambda tier, wd, pid, tc: wd
        cs.cfg_dir_for = lambda user, pid: "/home/orcp-abc/.orchestratia/code-server/x"
        tc = cs.p.load_tier_config({})
        p1 = cs.start("sess-r1", "proj-555555555555", "/srv/a", "restricted", tc)
        p2 = cs.start("sess-r2", "proj-555555555555", "/srv/a", "restricted", tc)
        ok("same process reused", p1 == p2 and len(spawned) == 1)
        cs.stop("sess-r1")
        ok("still running while another session uses it", killed == [] and cs.is_running("sess-r2"))
        cs.stop("sess-r2")
        ok("stopped with the last session", killed == [spawned[0].pid])
    finally:
        (cs.p.resolve_user, cs.p.verify_workspace, cs.cfg_dir_for) = saved
        restore()


def test_reap_idle_is_per_session():
    from orchestratia_agent import privilege
    root, spawned, killed, restore = _std_env()
    ws = tempfile.mkdtemp()
    saved_clock = cs._clock
    try:
        t = [1000.0]
        cs._clock = lambda: t[0]
        tc = privilege.load_tier_config({})
        cs.start("sess-idle", "proj-666666666666", ws, "standard", tc)
        cs.start("sess-busy", "proj-666666666666", ws, "standard", tc)
        t[0] += cs.IDLE_SECONDS + 1
        cs.note_activity("sess-busy")
        ok("only the idle session is reaped", cs.reap_idle(cs.running_sessions()) == ["sess-idle"])
    finally:
        cs._clock = saved_clock
        restore()
        shutil.rmtree(ws, ignore_errors=True)


def test_classify_editor_proc_matches_only_our_code_server():
    cs._reset_for_test()
    std = ["/usr/lib/node", "/x/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:41000",
           "--user-data-dir", "/home/dev/.local/share/orchestratia/editor/proj12345678/sessions/abc123def456",
           "--extensions-dir", "/x/ext", "/srv/a"]
    r = cs.classify_editor_proc(std)
    ok("standard editor recognised by its user-data-dir", r == {"tier": "standard", "port": 41000,
       "udd": "/home/dev/.local/share/orchestratia/editor/proj12345678/sessions/abc123def456"}, r)
    res = ["node", "/usr/lib/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:60000",
           "--user-data-dir", "/home/orcp-abc/.orchestratia/code-server/proj12345678", "/srv/a"]
    ok("restricted editor recognised", cs.classify_editor_proc(res) ==
       {"tier": "restricted", "port": 60000, "udd": "/home/orcp-abc/.orchestratia/code-server/proj12345678"}, cs.classify_editor_proc(res))
    ok("a stranger's code-server is ignored",
       cs.classify_editor_proc(["node", "/x/code-server", "--user-data-dir", "/home/dev/.local/share/code-server", "--bind-addr", "127.0.0.1:9"]) is None)
    ok("a non-code-server process is ignored", cs.classify_editor_proc(["python3", "-m", "http.server"]) is None)
    ok("empty argv is ignored", cs.classify_editor_proc([]) is None)
    ok("our marker but no bind-addr is ignored (not a main process)", cs.classify_editor_proc(
       ["node", "--user-data-dir", "/home/dev/.local/share/orchestratia/editor/x/sessions/y"]) is None)


def test_reap_orphans_stops_own_editors_and_reports_foreign_ones():
    cs._reset_for_test()
    OUR = os.geteuid()
    procs = [
        (111, OUR, ["node", "/x/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:41000",
                    "--user-data-dir", "/home/dev/.local/share/orchestratia/editor/p/sessions/s1"]),   # own standard orphan
        (222, OUR + 1, ["node", "/usr/lib/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:60000",
                        "--user-data-dir", "/home/orcp-abc/.orchestratia/code-server/p"]),              # foreign restricted orphan
        (333, OUR, ["node", "/x/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:5",
                    "--user-data-dir", "/home/dev/.local/share/code-server"]),                          # a stranger's editor
        (444, OUR, ["python3", "-m", "http.server", "5173"]),                                           # unrelated
    ]
    killed = []
    res = cs.reap_orphans(proc_iter=lambda: iter(procs), own_uid=OUR,
                          pgid_of=lambda pid: pid, kill=lambda pgid, sig: killed.append((pgid, sig)))
    ok("the daemon's own orphaned editor is stopped", 111 in res["stopped"] and (111, cs.signal.SIGTERM) in killed, (res, killed))
    ok("a stranger's code-server is left alone", 333 not in res["stopped"] and all(k[0] != 333 for k in killed))
    ok("unrelated processes are ignored", 444 not in res["stopped"])
    ok("a project user's editor can't be signalled by the daemon, so it is reported",
       res["unkillable"] == [(222, OUR + 1)] and all(k[0] != 222 for k in killed), res)
    ok("nothing was killed twice", len(killed) == 1)


def test_reap_orphans_reports_a_restricted_editor_once_not_its_sudo_wrapper():
    """A locked-down editor shows up twice in /proc — the root `sudo` monitor and the
    code-server it dropped to — both carrying our --user-data-dir. Report the editor
    once, as the real (non-root) process."""
    cs._reset_for_test()
    OUR = os.geteuid()
    udd = "/home/orcp-abc/.orchestratia/code-server/p"
    argv = ["x", "--auth", "none", "--bind-addr", "127.0.0.1:60000", "--user-data-dir", udd]
    procs = [(900, 0, ["sudo", "-n", "-u", "orcp-abc", "-H", *argv]),   # root sudo wrapper
             (901, 1003, argv)]                                          # the dropped code-server
    res = cs.reap_orphans(proc_iter=lambda: iter(procs), own_uid=OUR,
                          pgid_of=lambda pid: pid, kill=lambda pgid, sig: None)
    ok("one report per orphaned editor, and it names the real process not the root wrapper",
       res["unkillable"] == [(901, 1003)], res)


def test_reap_orphans_never_touches_a_tracked_process():
    cs._reset_for_test()
    OUR = os.geteuid()
    udd = "/home/dev/.local/share/orchestratia/editor/p/sessions/live1"
    cs._key_meta["live1"] = {"tier": "standard", "project_id": "p", "udd": udd}
    procs = [(555, OUR, ["node", "/x/code-server", "--auth", "none", "--bind-addr", "127.0.0.1:1", "--user-data-dir", udd])]
    killed = []
    res = cs.reap_orphans(proc_iter=lambda: iter(procs), own_uid=OUR,
                          pgid_of=lambda pid: pid, kill=lambda pgid, sig: killed.append((pgid, sig)))
    ok("a process we are actively managing is never reaped", res["stopped"] == [] and killed == [], (res, killed))
    cs._reset_for_test()


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
