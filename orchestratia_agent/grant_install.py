"""Install the access-grant helper and its one sudoers rule; the elevated-grant policy; remove the old broad rules
(hardening plan Task 4). Run as root by `secure-install`.

Every path here is fixed (module constants; tests pass their own). The helper is a copy of grant_helper.py behind a
`#!<system python3> -IS` line; root copies it only when the agent code it copies from is root's alone."""
import os
import stat

from orchestratia_agent import codetrust, grant_helper

HELPER = "/usr/local/libexec/orchestratia/grant-helper"
SUDOERS = "/etc/sudoers.d/orchestratia-grant"
LEGACY_SUDOERS = "/etc/sudoers.d/orchestratia-agent"
ELEVATED = grant_helper.SUDOERS
POLICY = grant_helper.POLICY
PYTHON = "/usr/bin/python3"
_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grant_helper.py")


class GrantInstallError(Exception):
    pass


def helper_body(python=PYTHON, source=None):
    with open(source or _SOURCE) as fh:
        return f"#!{python} -IS\n" + fh.read()


def _default_check(action):
    """The agent's code roots AND the package dir the helper is copied from: an editable (.pth) install's package
    lives outside the venv, so the venv check alone wouldn't cover what root copies."""
    codetrust.require_trusted(action, roots=codetrust.code_roots() + [os.path.dirname(_SOURCE)])


def install_grant_helper(daemon_user, *, python=PYTHON, target=HELPER, sudoers=SUDOERS, require_root=True,
                         visudo=None, check=None):
    from orchestratia_agent.provision import BIN_PATH_RE, ProvisionError, validate_username
    from orchestratia_agent.scanning import pack
    euid = os.geteuid()
    if require_root and euid != 0:
        raise GrantInstallError("run it as root: sudo orchestratia-agent secure-install")
    (check or _default_check)("install the access-grant helper")
    if daemon_user != "root":                    # validate_username reserves "root"; a root daemon needs no rule
        try:
            daemon_user = validate_username(daemon_user)
        except ProvisionError as e:
            raise GrantInstallError(f"invalid daemon user: {e}")
    for p in (python, target, sudoers):
        if not isinstance(p, str) or not BIN_PATH_RE.match(p):
            raise GrantInstallError(f"invalid path {p!r}")
    trusted = (0, euid)                          # (0, 0) as root; tests install unprivileged
    why = (codetrust.path_problem(os.path.dirname(python), trusted)
           or codetrust.path_problem(os.path.realpath(python), trusted))
    if why:
        raise GrantInstallError(f"python3 at {python} isn't root-owned and protected: {why}")
    try:
        pack._mkdir(os.path.dirname(target), base=os.path.dirname(os.path.dirname(target)))
        tmp = os.path.join(os.path.dirname(target), "." + os.path.basename(target) + ".tmp")
        pack._write_new(tmp, helper_body(python), 0o755)
        os.replace(tmp, target)
    except pack.InstallError as e:
        raise GrantInstallError(str(e))
    why = codetrust.path_problem(target, trusted)
    if why:
        raise GrantInstallError(f"the grant helper isn't protected: {why}")
    if daemon_user == "root":                    # a root daemon needs no rule
        if os.path.lexists(sudoers):
            os.unlink(sudoers)
        return
    lines = ["# Orchestratia access-grant helper (sudo orchestratia update / the installer). It takes a grant id and",
             "# at most one public key on stdin; it never takes a path, a user name or sudoers text from its caller.",
             f"Defaults!{target} env_reset, !use_pty",
             f"{daemon_user} ALL=(root) NOPASSWD: {target}", ""]
    # A name with a dot: sudo's includedir never reads it, so a half-written or invalid rule can't go live.
    tmp = os.path.join(os.path.dirname(sudoers), ".orchestratia-grant.tmp")
    pack._write_new(tmp, "\n".join(lines), 0o440)
    try:
        good = (visudo or pack._visudo)(tmp)
    except Exception as e:
        os.unlink(tmp)
        if isinstance(e, pack.InstallError):
            raise GrantInstallError(str(e))
        raise
    if not good:
        os.unlink(tmp)
        raise GrantInstallError("refusing to install an invalid sudoers rule for the grant helper")
    os.replace(tmp, sudoers)


def remove_legacy_sudoers(path=LEGACY_SUDOERS):
    """The rules earlier installers wrote (tee into sudoers.d, chown/chmod by wildcard): each one was root."""
    if not os.path.lexists(path):
        return False
    os.unlink(path)
    return True


def read_policy(policy=POLICY):
    try:
        with open(policy) as fh:
            for ln in fh.read().splitlines():
                if ln.strip() in ("elevated=allow", "elevated=deny"):
                    return ln.strip().split("=", 1)[1]
    except OSError:
        pass
    return None


def decide_policy(flag, *, policy=POLICY):
    """The owner's flag (root: secure-install --allow-/--deny-elevated-grants) when given. Without a flag: 'deny'
    when there is no policy file yet (every server, at the upgrade, including one with a live elevated grant);
    None when one exists: it is never changed automatically, so an owner's allow never lapses."""
    if flag in ("allow", "deny"):
        return flag
    return None if os.path.lexists(policy) else "deny"


def write_policy(value, *, policy=POLICY, elevated=ELEVATED):
    """Root-owned 0644 (the daemon reads it, without sudo, to notice a change). Rewritten only when it differs;
    `deny` also removes a live elevated rule, before the write."""
    from orchestratia_agent.scanning import pack
    if value not in ("allow", "deny"):
        raise GrantInstallError(f"invalid elevated-grant policy {value!r}")
    if value == "deny" and os.path.lexists(elevated):
        os.unlink(elevated)          # first: a policy write that fails must not leave the elevated rule live
    want = grant_helper.policy_text(value)
    try:
        st = os.lstat(policy)
        same = (stat.S_ISREG(st.st_mode) and st.st_uid in (0, os.geteuid()) and stat.S_IMODE(st.st_mode) == 0o644
                and st.st_nlink == 1)
        if same:
            with open(policy) as fh:
                same = fh.read() == want
    except OSError:
        same = False
    if not same:
        tmp = os.path.join(os.path.dirname(policy), "." + os.path.basename(policy) + ".tmp")
        pack._write_new(tmp, want, 0o644)
        os.replace(tmp, policy)
