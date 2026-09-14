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


def test_sudoers_lines_one_per_project_with_tmux_and_git():
    projects = {"pid-A": {"user": "orcp-aaaaaaaaaaaa"},
                "pid-B": {"user": "orcp-bbbbbbbbbbbb"}}
    lines = pv.sudoers_lines("ubuntu", projects, "/usr/bin/tmux", "/usr/bin/git")
    assert len(lines) == 2, lines
    assert "ubuntu ALL=(orcp-aaaaaaaaaaaa) NOPASSWD: /usr/bin/tmux, /usr/bin/git" in lines
    assert "ubuntu ALL=(orcp-bbbbbbbbbbbb) NOPASSWD: /usr/bin/tmux, /usr/bin/git" in lines


def test_sudoers_lines_refuses_bad_user():
    try:
        pv.sudoers_lines("ubuntu", {"p": {"user": "orc\nevil"}}, "/usr/bin/tmux", "/usr/bin/git")
    except pv.ProvisionError:
        return
    raise AssertionError("sudoers_lines must validate each project user")


def test_sudoers_lines_refuses_bad_tmux_path():
    for bad in ["tmux", "/usr/bin/tmux\nubuntu ALL=(ALL) NOPASSWD: ALL", "/usr/bin/tmux *"]:
        try:
            pv.sudoers_lines("ubuntu", {"p": {"user": "orcp-aaaaaaaaaaaa"}}, bad, "/usr/bin/git")
        except pv.ProvisionError:
            continue
        raise AssertionError(f"tmux path {bad!r} must be refused")


def test_sudoers_lines_refuses_bad_git_path():
    for bad in ["git", "/usr/bin/git; rm -rf /", "/usr/bin/git\nubuntu ALL=(ALL) NOPASSWD: ALL"]:
        try:
            pv.sudoers_lines("ubuntu", {"p": {"user": "orcp-aaaaaaaaaaaa"}}, "/usr/bin/tmux", bad)
        except pv.ProvisionError:
            continue
        raise AssertionError(f"git path {bad!r} must be refused")


def test_workspace_lockdown_removes_other_access():
    """A world-readable workspace under a shared parent is readable by a SIBLING
    project's user (each gets --x traverse on the parent). Removing 'other'
    access on the workspace root blocks that traverse. Owner and the ACL-granted
    project user are unaffected (they use owner bits / the named-user ACL)."""
    cmd = pv.workspace_lockdown_command("/srv/acme")
    assert cmd == ["chmod", "o=", "/srv/acme"], cmd


def test_workspace_lockdown_validates_the_path():
    for bad in ("relative", "/etc", "/srv/a\n/etc"):
        try:
            pv.workspace_lockdown_command(bad)
        except pv.ProvisionError:
            continue
        raise AssertionError(f"{bad!r} must be refused")


def test_sudoers_lines_include_code_server_when_provided():
    projects = {"p": {"user": "orcp-aaaaaaaaaaaa"}}
    line = pv.sudoers_lines("ubuntu", projects, "/usr/bin/tmux", "/usr/bin/git",
                            code_server_path="/usr/bin/code-server")[0]
    assert line == ("ubuntu ALL=(orcp-aaaaaaaaaaaa) NOPASSWD: "
                    "/usr/bin/tmux, /usr/bin/git, /usr/bin/code-server"), line


def test_sudoers_lines_omit_code_server_when_absent():
    projects = {"p": {"user": "orcp-aaaaaaaaaaaa"}}
    line = pv.sudoers_lines("ubuntu", projects, "/usr/bin/tmux", "/usr/bin/git")[0]
    assert line.endswith("/usr/bin/git"), line
    assert "code-server" not in line


def test_sudoers_lines_reject_bad_code_server_path():
    try:
        pv.sudoers_lines("ubuntu", {"p": {"user": "orcp-aaaaaaaaaaaa"}},
                         "/usr/bin/tmux", "/usr/bin/git",
                         code_server_path="/usr/bin/code-server; rm -rf /")
    except pv.ProvisionError:
        return
    raise AssertionError("bad code-server path must be refused")


def test_collision_guard_refuses_reused_username_for_new_project():
    existing = {"pid-A": {"user": "orcp-aaaaaaaaaaaa"}}
    try:
        pv.assert_no_collision("orcp-aaaaaaaaaaaa", "pid-B", existing)
    except pv.ProvisionError:
        pass
    else:
        raise AssertionError("must refuse a username already mapped to another project")
    # re-provisioning the SAME project is fine (idempotent)
    pv.assert_no_collision("orcp-aaaaaaaaaaaa", "pid-A", existing)


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



def test_provision_creates_exactly_the_dir_code_server_will_use():
    """Provisioning must pre-create the editor state dir, and it must be the SAME
    path code_server passes as --user-data-dir.

    code-server does not create the parents of --user-data-dir; it warns
    ("Could not create socket ...") and runs degraded with an unusable
    extensions dir. The daemon cannot create it either — the project home is
    0750 owned by that user — and the tier sudoers rule is deliberately limited
    to tmux/git/code-server, so a `sudo mkdir` is not available and widening the
    rule for a mkdir would be the wrong trade. Provisioning already runs as
    root, so that is where the directory belongs.

    The failure mode if these two ever drift is silent: the editor still starts,
    still serves, and is quietly degraded. So assert they agree.
    """
    from orchestratia_agent import code_server as cs
    user = "orcp-a1b2c3d45e6f"
    root = pv.editor_state_root(user)
    assert root.startswith("/home/" + user + "/"), root
    cfg = cs.cfg_dir_for(user, "01690d2f-47c6-4d37-b787-27904723922b")
    assert cfg.startswith(root.rstrip("/") + "/"), f"{cfg} not under {root}"


# ── locked-down workspaces must not hand out the daemon user's credentials ────
# A recursive rwX ACL on /home/<user> gave the restricted user ~/.ssh — a path to
# the daemon user and from there root. Found 2026-09-14.

def test_workspace_refuses_home_dirs_and_credential_stores():
    import shutil
    import tempfile
    base = tempfile.mkdtemp()
    home = os.path.join(base, "home-ubuntu")
    os.makedirs(os.path.join(home, "app"))
    creds = os.path.join(base, "with-ssh")
    os.makedirs(os.path.join(creds, ".ssh"))
    gcloud = os.path.join(base, "with-gcloud")
    os.makedirs(os.path.join(gcloud, ".config", "gcloud"))
    claude = os.path.join(base, "with-claude-creds")
    os.makedirs(os.path.join(claude, ".claude"))
    open(os.path.join(claude, ".claude", ".credentials.json"), "w").close()
    repo = os.path.join(base, "repo")
    os.makedirs(os.path.join(repo, ".claude"))
    os.makedirs(os.path.join(repo, ".orchestratia", "memory"))
    saved = pv._home_dirs
    try:
        pv._home_dirs = lambda: {home}
        _rejects(pv.validate_workspace, home, "a user's home directory must be refused")
        _rejects(pv.validate_workspace, creds, "a folder containing .ssh must be refused")
        _rejects(pv.validate_workspace, gcloud, "a folder containing .config/gcloud must be refused")
        _rejects(pv.validate_workspace, claude, "a folder holding Claude credentials must be refused")
        assert pv.validate_workspace(os.path.join(home, "app")) == os.path.join(home, "app"), \
            "a project folder inside a home is fine"
        assert pv.validate_workspace(repo) == repo, \
            "a repo with project .claude/ and .orchestratia/ folders is fine"
        os.makedirs(os.path.join(repo, ".orchestratia", "ssh_keys"))
        _rejects(pv.validate_workspace, repo, "a folder holding Orchestratia ssh keys must be refused")
    finally:
        pv._home_dirs = saved
        shutil.rmtree(base, ignore_errors=True)


def test_workspace_refuses_orchestratia_install_paths():
    _rejects(pv._validate_not_orchestratia, "/opt/orchestratia-agent", "the agent checkout must be refused")
    _rejects(pv._validate_not_orchestratia, "/opt/orchestratia-venv/lib", "the agent venv must be refused")
    pv._validate_not_orchestratia("/opt/orchestratia-agent-extra")   # a sibling name is not inside


def test_home_dirs_come_from_the_password_database():
    import pwd
    homes = pv._home_dirs()
    assert "/root" in homes, "/root is a home"
    assert os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir) in homes, "this user's home is included"


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
