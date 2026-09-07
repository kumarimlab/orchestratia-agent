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
