#!/usr/bin/env python3
"""Tests for provision.py — user/workspace validation and sudoers construction.

The bastion's --elevated-sudo once had a newline-injection hole that visudo
parsed as valid, appending an arbitrary rule that gave a read-only user full
root. These tests exist so that does not happen again here.

Dependency-free — run directly:  python3 tests/test_provision.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import provision as pv  # noqa: E402


def _rejects(fn, value, why):
    try:
        fn(value)
    except pv.ProvisionError:
        return
    raise AssertionError(why)


def test_accepts_a_normal_username():
    assert pv.validate_username("orc-agent") == "orc-agent"


def test_rejects_newline_in_username():
    _rejects(pv.validate_username, "orc\nubuntu ALL=(ALL) NOPASSWD: ALL",
             "newline injection into sudoers must be refused")


def test_rejects_shell_metacharacters_in_username():
    for bad in ["a b", "a;b", "a$b", "a`b`", "a|b", "a&b", "../root", "a\tb", "a\rb"]:
        _rejects(pv.validate_username, bad, f"{bad!r} must be refused")


def test_rejects_root_as_restricted_user():
    _rejects(pv.validate_username, "root", "root is not a restricted user")


def test_rejects_relative_workspace():
    _rejects(pv.validate_workspace, "relative/path", "workspace must be absolute")


def test_rejects_newline_in_workspace():
    _rejects(pv.validate_workspace, "/srv/a\n/etc",
             "newline in a workspace path must be refused")


def test_rejects_dangerous_workspace_roots():
    for bad in ["/", "/etc", "/usr", "/var", "/root", "/boot", "/etc/", "/etc/../etc"]:
        _rejects(pv.validate_workspace, bad, f"granting {bad} would defeat the tier")


def test_accepts_a_normal_workspace():
    assert pv.validate_workspace("/srv/acme") == "/srv/acme"


def test_sudoers_line_is_pinned():
    line = pv.sudoers_line("ubuntu", "orc-agent", "/usr/bin/tmux")
    assert line == "ubuntu ALL=(orc-agent) NOPASSWD: /usr/bin/tmux", line


def test_sudoers_line_refuses_bad_input():
    try:
        pv.sudoers_line("ubuntu", "orc\nevil", "/usr/bin/tmux")
    except pv.ProvisionError:
        return
    raise AssertionError("sudoers_line must validate its inputs")


def test_sudoers_line_refuses_bad_tmux_path():
    for bad in ["tmux", "/usr/bin/tmux\nubuntu ALL=(ALL) NOPASSWD: ALL", "/usr/bin/tmux *"]:
        try:
            pv.sudoers_line("ubuntu", "orc-agent", bad)
        except pv.ProvisionError:
            continue
        raise AssertionError(f"tmux path {bad!r} must be refused")


def test_acl_commands_grant_the_workspace():
    cmds = pv.acl_commands("orc-agent", "/srv/acme")
    assert ["setfacl", "-P", "-R", "-m", "u:orc-agent:rwX", "/srv/acme"] in cmds


def test_acl_commands_grant_traverse_up_the_parent_chain():
    """A repo inside a 750 home is unreachable without traverse on the parents.
    Must be --x, never r-x: r-x would expose directory listings."""
    cmds = pv.acl_commands("orc-agent", "/home/ubuntu/repo")
    traverse = [c for c in cmds if "u:orc-agent:--x" in c]
    targets = [c[-1] for c in traverse]
    assert "/home/ubuntu" in targets, targets
    assert "/home" in targets, targets
    assert not any("r-x" in " ".join(c) for c in cmds), "r-x would leak listings"


def test_acl_traverse_stops_at_root():
    cmds = pv.acl_commands("orc-agent", "/srv/acme")
    assert not any(c[-1] == "/" for c in cmds), "must not ACL the filesystem root"


def test_acl_commands_validate_their_inputs():
    try:
        pv.acl_commands("orc\nevil", "/srv/acme")
    except pv.ProvisionError:
        return
    raise AssertionError("acl_commands must validate the username")


def test_rejects_forbidden_subpaths_not_just_exact_matches():
    """SECURITY: an exact-match guard refused /etc but allowed /etc/cron.d,
    /etc/sudoers.d and /root/.ssh — each a direct route back to root."""
    for bad in ["/etc/cron.d", "/etc/sudoers.d", "/root/.ssh", "/usr/local/bin",
                "/usr/bin", "/etc/systemd/system", "/var/lib/docker"]:
        _rejects(pv.validate_workspace, bad, f"{bad!r} must be refused")


def test_rejects_double_slash_root():
    """SECURITY+HANG: normpath('//etc') == '//etc' bypassed the guard, and
    dirname('//') == '//' made the parent walk never terminate."""
    _rejects(pv.validate_workspace, "//etc", "//etc must be refused")


def test_acl_parent_walk_terminates():
    """Regression for the non-terminating dirname loop."""
    import signal

    def bail(*_):
        raise AssertionError("acl_commands did not terminate")
    signal.signal(signal.SIGALRM, bail)
    signal.alarm(5)
    try:
        cmds = pv.acl_commands("orc-agent", "/srv/acme/deep/nested/path")
        assert len(cmds) < 20, len(cmds)
    finally:
        signal.alarm(0)


def test_no_default_acl_is_emitted():
    """SECURITY: a -d default ACL made DAEMON-created files agent-writable.
    The daemon executes code from these dirs (build scripts, git hooks), so an
    agent could rewrite a script the root-equivalent daemon later runs."""
    cmds = pv.acl_commands("orc-agent", "/srv/acme")
    assert not any("-d" in c for c in cmds), cmds


def test_acl_does_not_follow_symlinks():
    cmds = pv.acl_commands("orc-agent", "/srv/acme")
    grant = [c for c in cmds if "rwX" in " ".join(c)][0]
    assert "-P" in grant, grant


def test_rejects_symlinked_workspace():
    """SECURITY: setfacl FOLLOWS a symlinked argument, so a workspace
    symlinked to / would ACL the entire filesystem."""
    import os, tempfile
    with tempfile.TemporaryDirectory() as td:
        link = os.path.join(td, "link")
        os.symlink("/etc", link)
        _rejects(pv.validate_workspace, link, "a symlinked workspace must be refused")


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
