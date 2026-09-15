#!/usr/bin/env python3
"""orc-attach: the VS Code terminal is a picker over this project's Orchestratia sessions.
Dependency-free — run directly:  python3 tests/test_orc_attach.py
"""
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import orc_attach as oa  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
SESS = [
    {"id": "11111111-aaaa-bbbb-cccc-000000000001", "name": "orc-2", "status": "active",
     "created_by_email": "abhi@example.com", "started_at": (NOW - timedelta(hours=2)).isoformat(), "kind": "terminal"},
    {"id": "22222222-aaaa-bbbb-cccc-000000000002", "name": None, "status": "starting",
     "created_by_email": None, "started_at": (NOW - timedelta(minutes=5)).isoformat(), "kind": "terminal"},
]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(capture, body):
    def open_(req, context=None, timeout=None):
        capture.append(req)
        return _Resp(json.dumps(body).encode())
    return open_


def test_menu_lists_sessions_then_new_session_last():
    entries = oa.menu_entries(SESS, NOW)
    ok("one entry per session plus New session", len(entries) == 3, entries)
    ok("first entry targets the session's tmux name", entries[0][1] == "orc-11111111-aaa", entries[0])
    ok("label shows name, who and age", entries[0][0] == "orc-2 — abhi · 2h", entries[0][0])
    ok("unnamed session labelled", entries[1][0].startswith("unnamed — ?"), entries[1][0])
    ok("New session is last with no target", entries[-1] == ("New session", None))


def test_parse_choice():
    ok("enter picks New session (last)", oa.parse_choice("", 3) == 2)
    ok("1-based numbers", oa.parse_choice("1", 3) == 0)
    ok("out of range refused", oa.parse_choice("9", 3) is None)
    ok("garbage refused", oa.parse_choice("x", 3) is None)


def test_fetch_sessions_is_scoped_to_this_project_on_this_server():
    cap = []
    got = oa.fetch_sessions("https://hub.example", "orc_k", "proj-1",
                            opener=_opener(cap, {"sessions": SESS, "count": 2}))
    url = cap[0].full_url
    ok("returns sessions", got == SESS)
    ok("project scoped", "project_id=proj-1" in url, url)
    ok("this server only", "this_server=true" in url, url)
    ok("terminals only (no editors)", "kind=terminal" in url, url)
    ok("server api key header", cap[0].get_header("X-api-key") == "orc_k")


def test_create_session_posts_to_the_editor_endpoint():
    cap = []
    sid = oa.create_session("https://hub.example", "orc_k", "ed-9", "/srv/app",
                            opener=_opener(cap, {"session_id": "33333333-aaaa-bbbb-cccc-000000000003",
                                                 "name": "editor terminal"}))
    req = cap[0]
    ok("returns the new session id", sid == "33333333-aaaa-bbbb-cccc-000000000003")
    ok("POSTs to the editor's terminals endpoint",
       req.get_method() == "POST"
       and req.full_url == "https://hub.example/api/v1/server/editor-sessions/ed-9/terminals", req.full_url)
    ok("sends the cwd", json.loads(req.data) == {"working_directory": "/srv/app"})


def test_wait_for_tmux():
    calls = {"n": 0}

    def has(name):
        calls["n"] += 1
        return calls["n"] >= 3
    ok("appears after a few polls", oa.wait_for_tmux("orc-x", timeout=5, poll=0.01, has=has, sleep=lambda s: None))
    ok("gives up after timeout",
       not oa.wait_for_tmux("orc-y", timeout=0.05, poll=0.01, has=lambda n: False, sleep=lambda s: None))


def _run_main(env, *, fetch=None, create=None, choice="", tmux_ok=True):
    execs, legacy = [], []
    saved = (dict(os.environ), oa.fetch_sessions, oa.create_session, oa.wait_for_tmux, oa.os.execvp,
             oa._hub_credentials, oa._legacy_main, oa._input)
    try:
        for k in ("ORCHESTRATIA_EDITOR_SESSION_ID", "ORCHESTRATIA_PROJECT_ID"):
            os.environ.pop(k, None)
        os.environ.update(env)
        oa.fetch_sessions = fetch or (lambda *a, **k: SESS)
        oa.create_session = create or (lambda *a, **k: "44444444-aaaa-bbbb-cccc-000000000004")
        oa.wait_for_tmux = lambda name, **k: tmux_ok
        oa.os.execvp = lambda prog, argv: execs.append(argv)
        oa._hub_credentials = lambda: ("https://hub.example", "orc_k")
        oa._legacy_main = lambda: legacy.append(1) or 0
        oa._input = lambda prompt: choice
        oa.main()
    finally:
        (env_saved, oa.fetch_sessions, oa.create_session, oa.wait_for_tmux, oa.os.execvp,
         oa._hub_credentials, oa._legacy_main, oa._input) = saved
        os.environ.clear()
        os.environ.update(env_saved)
    return execs, legacy


EDITOR_ENV = {"ORCHESTRATIA_EDITOR_SESSION_ID": "ed-9", "ORCHESTRATIA_PROJECT_ID": "proj-1"}


def test_main_attaches_to_a_chosen_session():
    execs, _ = _run_main(EDITOR_ENV, choice="1")
    ok("tmux attach to the chosen session", execs == [["tmux", "attach-session", "-t", "orc-11111111-aaa"]], execs)


def test_main_enter_creates_and_attaches_a_new_session():
    created = []
    execs, _ = _run_main(EDITOR_ENV, choice="",
                         create=lambda *a, **k: created.append(a) or "44444444-aaaa-bbbb-cccc-000000000004")
    ok("created via the hub", len(created) == 1 and created[0][2] == "ed-9", created)
    ok("attached to the new session", execs == [["tmux", "attach-session", "-t", "orc-44444444-aaa"]], execs)


def test_main_hub_unreachable_falls_back_to_a_shell():
    def boom(*a, **k):
        raise OSError("connection refused")
    execs, _ = _run_main(EDITOR_ENV, fetch=boom)
    ok("execs a login shell", len(execs) == 1 and execs[0][-1] == "-l", execs)


def test_main_new_session_never_appears_falls_back_to_a_shell():
    execs, _ = _run_main(EDITOR_ENV, choice="", tmux_ok=False)
    ok("execs a login shell", len(execs) == 1 and execs[0][-1] == "-l", execs)


def test_main_without_editor_env_uses_local_behaviour():
    execs, legacy = _run_main({})
    ok("legacy local picker used (locked-down editors)", legacy == [1] and execs == [])


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
    if not all(results):
        print(f"FAIL  {results.count(False)} of {len(results)} failed")
        sys.exit(1)
    print(f"ok  {len(results)} assertions passed")


if __name__ == "__main__":
    main()
