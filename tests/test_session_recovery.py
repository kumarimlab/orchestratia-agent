#!/usr/bin/env python3
"""Recovery must scan EVERY project user, not just one.

Per-project users each live on their own tmux server (/tmp/tmux-<uid>/, 0700).
Scanning only one — as the pre-fix code did (tc.restricted_user, singular) —
declares every OTHER project's sessions dead on daemon restart while their tmux
keeps running unsupervised. This monkeypatches discover_tmux_sessions so no real
users are needed: it tests the ITERATION, which is exactly the bug.

Dependency-free — run directly:  python3 tests/test_session_recovery.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import session_posix, privilege  # noqa: E402


def _tc():
    return privilege.TierConfig(
        projects={
            "pid-A": privilege.ProjectTier("orcp-aaaaaaaaaaaa", ("/srv/a",)),
            "pid-B": privilege.ProjectTier("orcp-bbbbbbbbbbbb", ("/srv/b",)),
        },
        tmux_path="/usr/bin/tmux", git_path="/usr/bin/git")


def _with_fake_discover(mapping):
    """Return (scanned_list, restore_fn) after patching discover_tmux_sessions."""
    scanned = []

    def fake(run_as=None):
        scanned.append(run_as)
        return mapping.get(run_as, [])

    orig = session_posix.discover_tmux_sessions
    session_posix.discover_tmux_sessions = fake
    return scanned, (lambda: setattr(session_posix, "discover_tmux_sessions", orig))


def test_recovery_scans_every_project_user():
    scanned, restore = _with_fake_discover({
        None: [], "orcp-aaaaaaaaaaaa": ["orc-sessA"], "orcp-bbbbbbbbbbbb": ["orc-sessB"]})
    try:
        be = session_posix.PosixSessionBackend()
        be.tier_config = _tc()
        names = be.discover_surviving_sessions()
    finally:
        restore()
    assert "orcp-aaaaaaaaaaaa" in scanned and "orcp-bbbbbbbbbbbb" in scanned, scanned
    assert "orc-sessA" in names and "orc-sessB" in names, names


def test_owner_of_finds_the_right_project_user():
    scanned, restore = _with_fake_discover({
        None: [], "orcp-aaaaaaaaaaaa": ["orc-sessA"], "orcp-bbbbbbbbbbbb": ["orc-sessB"]})
    try:
        be = session_posix.PosixSessionBackend()
        be.tier_config = _tc()
        assert be.owner_of("orc-sessB") == "orcp-bbbbbbbbbbbb"
        assert be.owner_of("orc-sessA") == "orcp-aaaaaaaaaaaa"
    finally:
        restore()


def test_owner_of_returns_none_for_daemon_session():
    scanned, restore = _with_fake_discover({
        None: ["orc-daemon"], "orcp-aaaaaaaaaaaa": [], "orcp-bbbbbbbbbbbb": []})
    try:
        be = session_posix.PosixSessionBackend()
        be.tier_config = _tc()
        assert be.owner_of("orc-daemon") is None
    finally:
        restore()


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
        except AssertionError as e:
            failures.append((fn.__name__, str(e) or "assertion failed"))
        except Exception as e:  # noqa: BLE001
            failures.append((fn.__name__, f"{type(e).__name__}: {e}"))
    if failures:
        for name, msg in failures:
            print(f"FAIL  {name}: {msg}")
        print(f"\n{len(failures)}/{len(CASES)} failed")
        raise SystemExit(1)
    print(f"ok  {len(CASES)} passed")




# ── window-size must survive a dashboard resize ───────────────────────────────
# `tmux resize-window -x -y` (how a dashboard resize is applied) forces the
# session's window-size option to `manual`, pinning the window to that one
# client's size. Every OTHER client — a VS Code editor terminal attached to the
# same session, a second viewer — then sees a mismatched, dotted grid. So resize
# must restore `latest` (follow the active client) afterward. Found on prod,
# 2026-09-15, attaching an editor terminal to a dashboard-streamed session.

def _record_tmux():
    calls = []
    orig = session_posix._tmux
    session_posix._tmux = lambda handle, args, **kw: calls.append(list(args))
    return calls, (lambda: setattr(session_posix, "_tmux", orig))


def test_resize_restores_window_size_latest_so_other_clients_are_not_dotted():
    from orchestratia_agent.session_base import SessionHandle
    calls, restore = _record_tmux()
    r, w = os.pipe()
    try:
        backend = session_posix.PosixSessionBackend()
        h = SessionHandle(pid=os.getpid(), fd=w, tmux_name="orc-test123456", cols=80, rows=24, extra={})
        backend.resize(h, 120, 40)
        rw = ["resize-window", "-t", "orc-test123456", "-x", "120", "-y", "40"]
        ws = ["set-option", "-t", "orc-test123456", "window-size", "latest"]
        assert rw in calls, calls
        assert ws in calls, calls
        assert calls.index(rw) < calls.index(ws), f"latest must be restored AFTER the resize: {calls}"
    finally:
        restore()
        os.close(r); os.close(w)


def test_resize_without_tmux_does_nothing_tmux(): # a plain (non-tmux) pty session
    from orchestratia_agent.session_base import SessionHandle
    calls, restore = _record_tmux()
    r, w = os.pipe()
    try:
        session_posix.PosixSessionBackend().resize(
            SessionHandle(pid=os.getpid(), fd=w, tmux_name="", cols=80, rows=24, extra={}), 120, 40)
        assert calls == [], calls
    finally:
        restore()
        os.close(r); os.close(w)


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    main()
