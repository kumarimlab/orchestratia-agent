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


def test_workspace_refuses_paths_inside_credential_stores():
    """Refusing a folder that CONTAINS .ssh is not enough: `--workspace /home/dev/.ssh`
    passed and ACL'd the daemon user's private key to the locked-down user. Found on
    staging, 2026-09-14."""
    import shutil
    import tempfile
    base = tempfile.mkdtemp()
    ssh = os.path.join(base, "srv", ".ssh")
    os.makedirs(os.path.join(ssh, "sub"))
    gcloud_sub = os.path.join(base, "srv", ".config", "gcloud", "configs")
    os.makedirs(gcloud_sub)
    keys = os.path.join(base, "srv", ".orchestratia", "ssh_keys")
    os.makedirs(keys)
    upper = os.path.join(base, "srv", ".AWS")
    os.makedirs(upper)
    saved = pv._home_dirs
    try:
        pv._home_dirs = lambda: set()
        _rejects(pv.validate_workspace, ssh, "a .ssh folder itself must be refused")
        _rejects(pv.validate_workspace, os.path.join(ssh, "sub"), "a folder inside .ssh must be refused")
        _rejects(pv.validate_workspace, gcloud_sub, "a folder inside .config/gcloud must be refused")
        _rejects(pv.validate_workspace, keys, "Orchestratia's ssh_keys folder must be refused")
        _rejects(pv.validate_workspace, upper, "credential stores match case-insensitively (macOS)")
        hidden = os.path.join(base, "srv", ".cache-free", "proj")
        os.makedirs(hidden)
        assert pv.validate_workspace(hidden) == hidden, "a hidden folder outside any home is fine"
    finally:
        pv._home_dirs = saved
        shutil.rmtree(base, ignore_errors=True)


def test_workspace_refuses_a_homes_dotfolders_bin_and_ancestors():
    """Inside a home, the top-level dot-folders hold credentials and executables the
    daemon user runs (~/.config/gh tokens, ~/.local/share/orchestratia/code-server), and
    ~/bin is on its PATH: write access to any of them is a route back to that user.
    A folder ABOVE a home hands over the whole home, exactly like the home itself."""
    import shutil
    import tempfile
    base = tempfile.mkdtemp()
    home = os.path.join(base, "data", "home-dev")
    for d in (".config/gh", ".local/share/orchestratia/code-server", "bin", "app/.config", "binaries"):
        os.makedirs(os.path.join(home, d))
    saved = pv._home_dirs
    try:
        pv._home_dirs = lambda: {home}
        _rejects(pv.validate_workspace, os.path.join(home, ".config"), "~/.config must be refused")
        _rejects(pv.validate_workspace, os.path.join(home, ".local", "share", "orchestratia", "code-server"),
                 "the daemon user's editor install must be refused")
        _rejects(pv.validate_workspace, os.path.join(home, "bin"), "~/bin (on PATH) must be refused")
        _rejects(pv.validate_workspace, os.path.join(base, "data"), "a folder above a home must be refused")
        for ok_path in (os.path.join(home, "app"), os.path.join(home, "app", ".config"),
                        os.path.join(home, "binaries")):
            assert pv.validate_workspace(ok_path) == ok_path, f"{ok_path} is a project folder"
    finally:
        pv._home_dirs = saved
        shutil.rmtree(base, ignore_errors=True)


def test_home_dirs_include_login_users_outside_home():
    """A person's home at /data/alice is still a home; service accounts are not."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        alice, svc = os.path.join(td, "alice"), os.path.join(td, "svc")
        os.makedirs(alice)
        os.makedirs(svc)

        class E:
            def __init__(self, uid, d):
                self.pw_uid, self.pw_dir = uid, d
        homes = pv._home_dirs([E(1001, alice), E(998, svc), E(65534, "/nonexistent"), E(1002, "/")])
        assert alice in homes, homes
        assert svc not in homes, "a service account's home is not a person's home"
        assert "/" not in homes and "/nonexistent" not in homes, homes


def test_merge_is_additive_so_no_grant_goes_unrecorded():
    """Re-provisioning with a different --workspace replaced the recorded list while
    the old ACL stayed on disk — access that no config showed and nothing could revoke."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        a, b = os.path.join(td, "a"), os.path.join(td, "b")
        os.makedirs(a)
        os.makedirs(b)
        saved = pv._home_dirs
        try:
            pv._home_dirs = lambda: set()
            existing = {"P": {"user": "orcp-aaaaaaaaaaaa", "workspaces": [a]},
                        "Q": {"user": "orcp-bbbbbbbbbbbb", "workspaces": [b]}}
            merged = pv.merge_project_workspaces(existing, "P", "orcp-aaaaaaaaaaaa", [b, a])
            assert merged["P"]["workspaces"] == [a, b], merged
            assert merged["Q"] == existing["Q"], "other projects untouched"
            assert existing["P"]["workspaces"] == [a], "input not mutated"
            fresh = pv.merge_project_workspaces({}, "R", "orcp-cccccccccccc", [a])
            assert fresh["R"] == {"user": "orcp-cccccccccccc", "workspaces": [a]}, fresh
        finally:
            pv._home_dirs = saved


def test_merge_refuses_while_a_recorded_grant_is_no_longer_allowed():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        ok_dir, bad = os.path.join(td, "ok"), os.path.join(td, ".ssh")
        os.makedirs(ok_dir)
        os.makedirs(bad)
        saved = pv._home_dirs
        try:
            pv._home_dirs = lambda: set()
            existing = {"P": {"user": "orcp-aaaaaaaaaaaa", "workspaces": [bad]}}
            try:
                pv.merge_project_workspaces(existing, "P", "orcp-aaaaaaaaaaaa", [ok_dir])
            except pv.ProvisionError as e:
                assert "--revoke-workspace" in str(e) and bad in str(e), str(e)
            else:
                raise AssertionError("a recorded grant that is now refused must block re-provisioning")
        finally:
            pv._home_dirs = saved


def test_revoke_removes_the_grant_and_its_traverse_then_restores_what_remains():
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        gone, keep_inside, keep_apart = (os.path.join(td, "srv", "gone"),
                                         os.path.join(td, "srv", "gone", "kept"),
                                         os.path.join(td, "other", "kept"))
        for d in (keep_inside, keep_apart):
            os.makedirs(d)
        saved = pv._home_dirs
        try:
            pv._home_dirs = lambda: set()
            user = "orcp-aaaaaaaaaaaa"
            cmds = pv.revoke_commands(user, gone, [keep_inside, keep_apart])
            assert cmds[0] == ["setfacl", "-P", "-R", "-x", f"u:{user}", gone], cmds[0]
            parents = [c[-1] for c in cmds if c[:3] == ["setfacl", "-x", f"u:{user}"]]
            assert os.path.join(td, "srv") in parents and td in parents and "/" not in parents, parents
            # a remaining workspace inside the revoked tree lost its rwX: fully re-granted
            assert ["setfacl", "-P", "-R", "-m", f"u:{user}:rwX", keep_inside] in cmds, cmds
            # an unrelated one only needs its traverse chain back, not a recursive re-grant
            assert ["setfacl", "-P", "-R", "-m", f"u:{user}:rwX", keep_apart] not in cmds, cmds
            assert ["setfacl", "-m", f"u:{user}:--x", os.path.join(td, "other")] in cmds, cmds
            # removals come before every re-grant
            first_grant = next(i for i, c in enumerate(cmds) if "-m" in c)
            assert all("-x" in c for c in cmds[:first_grant]), cmds
        finally:
            pv._home_dirs = saved


def test_revoke_refuses_symlinks_and_bad_paths():
    """setfacl -P silently SKIPS a symlink argument (exit 0), leaving the target's
    grant in place — so a symlink must be refused, never passed through."""
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        target = os.path.join(td, "t")
        os.makedirs(target)
        link = os.path.join(td, "l")
        os.symlink(target, link)
        os.makedirs(os.path.join(target, "deep"))
        via_parent = os.path.join(link, "deep")      # not itself a link, but resolves elsewhere
        for bad, why in ((link, "symlink"), (via_parent, "symlinked-parent"),
                         ("relative/path", "relative"), ("/srv/x\nroot", "newline")):
            try:
                pv.revoke_commands("orcp-aaaaaaaaaaaa", bad, [])
            except pv.ProvisionError as e:
                assert why != "symlink" or "symlink" in str(e), f"say it is a symlink: {e}"
                continue
            raise AssertionError(f"revoke must refuse a {why} path")
        # a forbidden path CAN be revoked — removing access is always allowed
        assert pv.revoke_commands("orcp-aaaaaaaaaaaa", "/root/.ssh", [])[0][-1] == "/root/.ssh"
        # revoking a folder a remaining grant still covers would silently change nothing
        inner = os.path.join(target, "sub")
        os.makedirs(inner)
        try:
            pv.revoke_commands("orcp-aaaaaaaaaaaa", inner, [target])
        except pv.ProvisionError as e:
            assert target in str(e), str(e)
        else:
            raise AssertionError("revoking inside a still-granted workspace must be refused")


def test_acl_perms_reads_the_named_user_entry():
    out = ("user::rwx\nuser:orcp-aaaaaaaaaaaa:rwx\t#effective:r-x\n"
           "user:orcp-aaaaaaaaaaaab:--x\ngroup::r-x\nmask::r-x\nother::---\n")
    assert pv._acl_perms(out, "orcp-aaaaaaaaaaaa") == "rwx"
    assert pv._acl_perms(out, "orcp-bbbbbbbbbbbb") is None
    assert pv._acl_perms("user:orcp-aaaaaaaaaaaab:--x\n", "orcp-aaaaaaaaaaaa") is None, "prefix is not a match"


def test_locked_down_editor_settings_are_written_as_the_project_user():
    """The locked-down editor never got its settings: the daemon cannot write into the
    project user's home, so its VS Code terminal was a plain unrecorded shell. Provisioning
    (root) writes them — as that user, because the directory is theirs and a root write
    could be redirected through a symlink they planted."""
    import json
    import subprocess
    import tempfile
    from orchestratia_agent import code_server as cs
    calls = []
    saved = pv.subprocess.run

    def fake_run(argv, **kw):
        calls.append((argv, kw))
        return subprocess.CompletedProcess(argv, 0, "", "")
    pv.subprocess.run = fake_run
    try:
        pv._write_editor_settings("orcp-aaaaaaaaaaaa", "01690d2f-47c6-4d37-b787-27904723922b")
    finally:
        pv.subprocess.run = saved
    assert len(calls) == 1, calls
    argv, kw = calls[0]
    assert kw.get("user") == "orcp-aaaaaaaaaaaa" and kw.get("group") == "orcp-aaaaaaaaaaaa", kw
    assert kw.get("extra_groups") == [], "root's supplementary groups must be dropped"
    want = os.path.join(cs.cfg_dir_for("orcp-aaaaaaaaaaaa", "01690d2f-47c6-4d37-b787-27904723922b"),
                        "User", "settings.json")
    assert want in argv, argv
    # argv: python -c SCRIPT <path> <defaults-json> <forced-json>
    defaults = json.loads(argv[-2])
    forced = json.loads(argv[-1])
    assert forced.get("terminal.integrated.defaultProfile.linux") == "orchestratia", forced
    assert defaults["workbench.colorCustomizations"]["terminal.background"] == "#1a1816", defaults

    # the script itself: forced keys win, the user's own settings survive
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "cfg", "User", "settings.json")
        os.makedirs(os.path.dirname(path))
        with open(path, "w") as f:
            json.dump({"editor.fontSize": 15, "terminal.integrated.defaultProfile.linux": "bash"}, f)
        subprocess.run([argv[0], "-c", argv[2], path, argv[-2], argv[-1]], check=True)
        data = json.load(open(path))
        assert data["editor.fontSize"] == 15, data
        assert data["terminal.integrated.defaultProfile.linux"] == "orchestratia", data
        # the overridable theme reached the locked-down editor too
        assert data["workbench.colorCustomizations"]["terminal.background"] == "#1a1816", data
        # a user who recolours one thing keeps the rest of the palette
        with open(path) as f:
            cur = json.load(f)
        cur["workbench.colorCustomizations"] = {"terminal.background": "#222222"}
        json.dump(cur, open(path, "w"))
        subprocess.run([argv[0], "-c", argv[2], path, argv[-2], argv[-1]], check=True)
        d2 = json.load(open(path))
        assert d2["workbench.colorCustomizations"]["terminal.background"] == "#222222", d2
        assert d2["workbench.colorCustomizations"]["terminal.ansiRed"] == "#e06c75", d2
        fresh = os.path.join(td, "new", "User", "settings.json")
        subprocess.run([argv[0], "-c", argv[2], fresh, argv[-2], argv[-1]], check=True)
        assert json.load(open(fresh))["terminal.integrated.defaultProfile.linux"] == "orchestratia"


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
