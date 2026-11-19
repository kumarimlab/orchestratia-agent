#!/usr/bin/env python3
"""Session secrets must never reach argv, and a key file must be readable by
exactly one other user.

A production API key sat in world-readable /proc/<pid>/cmdline for 14 weeks
because the agent passed it via `tmux new-session -e`. These tests exist so the
delivery path cannot quietly regress to argv.

Dependency-free — run:  python3 tests/test_session_env.py
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import session_env as se  # noqa: E402


def test_no_token_returns_none():
    assert se.write_session_key("abc", "", "someuser") is None


def test_no_user_returns_none():
    assert se.write_session_key("abc", "tok", "") is None


def test_key_file_grants_nothing_to_group_or_other():
    """Assert on ACCESS, not on the mode integer.

    After setfacl the group bits show the ACL MASK, so st_mode reads 0640 even
    though `group::---`. Asserting 0600 would fail on correct code — as it did
    when this test was first written. What actually matters is that neither
    group nor other has any access, and that exactly one named user does.
    """
    path = se.write_session_key("modecheck123", "s3cret", os.environ.get("USER", "ubuntu"))
    if path is None:
        print("    (skipped: setfacl unavailable or user unknown)")
        return
    try:
        st = os.stat(path)
        assert st.st_uid == os.getuid(), "must be owned by the daemon user"
        assert st.st_mode & 0o007 == 0, f"other must have no access: {oct(st.st_mode & 0o777)}"
        acl = subprocess.run(["getfacl", "-p", path], capture_output=True,
                             text=True, timeout=5).stdout
        assert "group::---" in acl, acl
        assert "other::---" in acl, acl
        named = [l for l in acl.splitlines()
                 if l.startswith("user:") and not l.startswith("user::")]
        assert len(named) == 1, f"exactly one named user should be granted: {named}"
    finally:
        se.clear_session_key(path)


def test_round_trip():
    path = se.write_session_key("roundtrip12", "orcs_tok_value", os.environ.get("USER", "ubuntu"))
    if path is None:
        print("    (skipped)")
        return
    try:
        assert se.read_key_file(path) == "orcs_tok_value"
    finally:
        se.clear_session_key(path)


def test_directory_is_not_listable():
    """0711: reachable by path, not enumerable. Filenames are random anyway,
    but defence in depth costs nothing here."""
    se._ensure_dir()
    mode = os.stat(se._ensure_dir()).st_mode & 0o777
    assert mode == 0o711, oct(mode)


def test_filenames_are_unpredictable():
    u = os.environ.get("USER", "ubuntu")
    a = se.write_session_key("samesession", "t", u)
    b = se.write_session_key("samesession", "t", u)
    if a is None or b is None:
        print("    (skipped)")
        return
    try:
        assert a != b, "same session id must not produce the same path"
    finally:
        se.clear_session_key(a); se.clear_session_key(b)


def test_clear_is_idempotent():
    se.clear_session_key(None)
    se.clear_session_key("/tmp/definitely-not-here-xyz")


def test_read_missing_file_is_empty_not_an_error():
    assert se.read_key_file("/tmp/definitely-not-here-xyz") == ""
    assert se.read_key_file(None) == ""


def test_env_var_name_carries_a_path_not_a_secret():
    """The whole point: what lands in argv is a PATH."""
    assert se.ENV_VAR.endswith("_FILE"), se.ENV_VAR


def test_standard_session_gets_a_token_file_path_never_the_token():
    env, path, delivered = se.session_env("https://hub", "sess-std-123456", "standard", "orcs_std_tok", "")
    try:
        assert delivered and path, (env, path)
        assert env[se.STANDARD_ENV_VAR] == path and se.ENV_VAR not in env, env
        assert all("orcs_std_tok" not in v for v in env.values()), "the token must never be in env/argv"
        st = os.stat(path)
        assert st.st_uid == os.getuid() and st.st_mode & 0o077 == 0, oct(st.st_mode)
        assert se.read_key_file(path) == "orcs_std_tok"
    finally:
        se.clear_session_key(path)


def test_standard_session_without_a_token_is_unchanged():
    env, path, delivered = se.session_env("https://hub", "sess-none", "standard", None, "")
    assert delivered and path is None
    assert env == {"ORCHESTRATIA_HUB_URL": "https://hub", "ORCHESTRATIA_SESSION_ID": "sess-none"}, env


def test_standard_write_failure_still_starts_the_session():
    real = se.write_own_session_key
    se.write_own_session_key = lambda sid, tok: None
    try:
        env, path, delivered = se.session_env("https://hub", "sess-fail", "standard", "tok", "")
        assert delivered and path is None and se.STANDARD_ENV_VAR not in env, env
    finally:
        se.write_own_session_key = real


def test_restricted_undeliverable_token_refuses_the_session():
    real = se.write_session_key
    se.write_session_key = lambda sid, tok, user: None
    try:
        env, path, delivered = se.session_env("https://hub", "sess-r", "restricted", "tok", "orcp-x")
        assert not delivered and path is None and se.ENV_VAR not in env, env
    finally:
        se.write_session_key = real


def test_clear_session_keys_for_removes_every_file_of_that_session():
    a = se.write_own_session_key("abcdefabcdef-rest", "t1")
    b = se.write_own_session_key("abcdefabcdef-rest", "t2")
    other = se.write_own_session_key("999999999999-x", "t3")
    try:
        se.clear_session_keys_for("abcdefabcdef-rest")
        assert not os.path.exists(a) and not os.path.exists(b) and os.path.exists(other)
    finally:
        se.clear_session_key(other)


def test_hub_session_start_goes_through_session_env():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "orchestratia_agent", "hub.py")).read()
    assert "session_env.session_env(" in src
    assert 'session_token and privilege_tier == "restricted"' not in src
    assert src.count("_release_session_keys(state, session_id,") == 2, "both close paths release key files"


def test_stopping_daemon_keeps_key_files_of_surviving_sessions():
    import asyncio
    from orchestratia_agent import hub
    class St: running = True
    path = se.write_own_session_key("survivor-12345678", "t")
    try:
        st = St()
        st.running = False  # SIGTERM: handle_signal sets it before readers' finally runs _on_close
        hub._release_session_keys(st, "survivor-12345678", None)
        assert os.path.exists(path), "a graceful stop must not delete surviving sessions' key files"
        st.running = True   # an explicit close / the session really ended
        hub._release_session_keys(st, "survivor-12345678", None)
        assert not os.path.exists(path)
    finally:
        se.clear_session_key(path)


def test_cleanup_sessions_from_running_state_keeps_surviving_key_files():
    """The crash path: cleanup_sessions runs while state.running is still True. The real stop sequence
    cancels each reader, whose finally releases keys; the survivors' files must still exist."""
    import asyncio
    from orchestratia_agent import hub

    class Backend:
        def supports_persistence(self): return True
        def close_handle(self, h): pass

    class Sess:
        tmux_name = "orc-x"
        handle = object()
        reader_task = None

    class St:
        running = True
        backend = Backend()
        active_sessions = {}

    path = se.write_own_session_key("crashsess-1234567", "t")

    async def run():
        st = St()
        st.active_sessions = {}
        async def reader():
            try:
                await asyncio.sleep(3600)
            finally:
                hub._release_session_keys(st, "crashsess-1234567", None)
        sess = Sess()
        sess.reader_task = asyncio.ensure_future(reader())
        st.active_sessions["crashsess-1234567"] = sess
        await asyncio.sleep(0)
        await hub.cleanup_sessions(st)
        await asyncio.sleep(0.05)  # let the cancelled reader's finally run
    try:
        asyncio.run(run())
        assert os.path.exists(path), "cleanup_sessions on a crash deleted a surviving session's key file"
    finally:
        se.clear_session_key(path)


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


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


if __name__ == "__main__":
    main()
