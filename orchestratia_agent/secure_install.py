"""`sudo orchestratia-agent secure-install` (hardening plan Tasks 2-4): make this install's root-facing pieces match
the code that is installed. `sudo orchestratia update` runs it through the NEW entry point, and so does the installer.

It never blesses a tree another user owns: that is refused with "run: sudo orchestratia update", which rebuilds
the install. Steps, in order:
- remove the broad grant sudo rules earlier installers wrote (Task 4) — each of them was root for the daemon user;
- the trees (Task 2) — a failure here STOPS the run: every later step copies or points at code that must be root's
  alone;
- the PATH wrappers (Task 2) — a failure is reported and the run fails, but it doesn't skip the grant setup (a
  group-writable /usr/local/bin, e.g. Debian's setgid staff, would otherwise leave grants broken and an old elevated
  rule live; the helper needs only the trees, which each step re-checks itself);
- the access-grant helper and the elevated-grant policy (Task 4);
- the scanner runner, launcher and timer (Task 3), last: it is optional, and its failure must not skip the grant
  steps (ruling H2).
Steps marked `continue_on_error` report a failure and let the next step run; the run still fails at the end."""
import contextlib
import os
import stat
import tempfile
from types import SimpleNamespace

from orchestratia_agent import codetrust


class SecureInstallError(Exception):
    def __init__(self, msg, lines=()):
        super().__init__(msg)
        self.lines = list(lines)        # what the steps before (and around) the failure reported


def remove_legacy_grant_rules(daemon_user, ctx):
    """The old broad grant rules (/etc/sudoers.d/orchestratia-agent: tee into sudoers.d, chown/chmod by wildcard)
    let the daemon user become root. They go on every host, before anything else: removing them runs no code."""
    from orchestratia_agent import grant_install
    if grant_install.remove_legacy_sudoers(grant_install.LEGACY_SUDOERS):
        return f"removed the old broad grant sudo rules ({grant_install.LEGACY_SUDOERS})"
    return "old broad grant sudo rules: none"


remove_legacy_grant_rules.continue_on_error = True


def secure_trees(daemon_user, ctx):
    stale = codetrust.stale_venvs(ctx.layout)
    if stale and not os.path.lexists(ctx.layout.venv):
        raise SecureInstallError(f"{ctx.layout.venv} is missing: an update stopped half-way and left {stale[-1]}. "
                                 f"Put it back, then update: sudo mv {stale[-1]} {ctx.layout.venv} && "
                                 f"sudo orchestratia update")
    done = []
    for tree in (ctx.layout.venv, ctx.layout.assets):
        if not os.path.lexists(tree):
            continue
        foreign = codetrust.first_foreign(tree, ctx.uids)
        if foreign:
            raise SecureInstallError(f"{foreign}; {codetrust.FIX_HINT} (it rebuilds the install from a fresh clone)")
        try:
            codetrust.normalize(tree, ctx.uids)
        except codetrust.CodeTrustError as e:
            raise SecureInstallError(str(e))
        why = codetrust.tree_problem(tree, ctx.uids)
        if why:
            raise SecureInstallError(f"{why}; {codetrust.FIX_HINT}")
        done.append(tree)
    return "root-owned: " + (", ".join(done) or "nothing to secure")


_WRAPPERS = ("orchestratia-agent", "orchestratia")


def _wrapper_ok(path, want, uids):
    try:
        st = os.lstat(path)
        if not (stat.S_ISREG(st.st_mode) and st.st_uid in uids and stat.S_IMODE(st.st_mode) == 0o755
                and st.st_nlink == 1):
            return False
        with open(path, "rb") as fh:
            return fh.read() == want
    except OSError:
        return False


def secure_wrappers(daemon_user, ctx):
    """The PATH wrappers root runs (`sudo orchestratia …`): root-owned 0755 files that exec the venv's entry point.
    Anything else there (a legacy symlink into ~/.local, a wrapper the daemon user can change, one pointing
    elsewhere) is replaced by rename, so a symlink's target is never written."""
    bindir = ctx.layout.bindir
    why = codetrust.path_problem(bindir, ctx.uids)
    if why:
        raise SecureInstallError(f"{bindir} isn't root's alone: {why}")
    rewrote = []
    for name in _WRAPPERS:
        path = os.path.join(bindir, name)
        want = f'#!/bin/sh\nexec "{ctx.layout.venv}/bin/{name}" "$@"\n'.encode()
        if _wrapper_ok(path, want, ctx.uids):
            continue
        fd, tmp = tempfile.mkstemp(prefix=f".{name}.", dir=bindir)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(want)
                os.fchmod(fh.fileno(), 0o755)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        rewrote.append(path)
    return "wrappers: " + (f"rewrote {', '.join(rewrote)}" if rewrote else "ok")


secure_wrappers.continue_on_error = True


def refresh_scanner_pieces(daemon_user, ctx):
    """When the scanner pack is installed: the runner files, the daily refresh timer (this venv's python, -I) and
    the scan launcher + its sudoers rule, so `sudo orchestratia update` keeps them in step with the new code (no
    separate `sudo orchestratia scanners install` after an update). Runs after secure_trees: the code it copies and
    points the timer at is root's alone by then, and each piece re-checks that itself."""
    from orchestratia_agent.scanning import pack
    if not os.path.isdir(pack.SCANNERS_ROOT):
        return "scanner pack: not installed"
    pack.sync_runner_files()
    pack.install_timer(os.path.join(ctx.layout.venv, "bin", "python3"))
    pack.install_launcher(daemon_user)
    return "scanner pack: runner files, refresh timer and launcher updated"


refresh_scanner_pieces.continue_on_error = True


def grant_setup(daemon_user, ctx):
    """One root-owned helper for access grants and its one sudoers rule, and the elevated-grant policy (user decision,
    Option A). Only the owner's flag changes the policy: --allow-elevated-grants writes allow, --deny-elevated-grants
    deny. Without a flag a missing policy becomes deny (every server at the upgrade, also one with a live elevated
    grant) and an existing one is never changed. An elevated rule without an allow policy is removed, with a notice
    saying how to allow elevated grants and what that means."""
    from orchestratia_agent import grant_install
    allow_cmd = "sudo orchestratia-agent secure-install --allow-elevated-grants"
    warning = f"while elevated grants are allowed, any process running as {daemon_user} can become root"
    had_rule = os.path.lexists(grant_install.ELEVATED)
    policy = grant_install.decide_policy(ctx.elevated, policy=grant_install.POLICY)
    if policy is not None:
        grant_install.write_policy(policy, policy=grant_install.POLICY, elevated=grant_install.ELEVATED)
        source = {"allow": "--allow-elevated-grants", "deny": "--deny-elevated-grants"}.get(ctx.elevated,
                                                                                            "new policy")
    else:
        policy = "allow" if grant_install.read_policy(grant_install.POLICY) == "allow" else "deny"
        source = "kept"
        if policy != "allow" and os.path.lexists(grant_install.ELEVATED):
            os.unlink(grant_install.ELEVATED)              # the helper sets it only under allow
    grant_install.install_grant_helper(daemon_user, target=grant_install.HELPER, sudoers=grant_install.SUDOERS)
    line = f"access-grant helper installed; elevated grants: {policy} ({source})"
    if policy == "allow":
        line += f" — {warning}"
    elif had_rule and not os.path.lexists(grant_install.ELEVATED):
        line += (f". NOTICE: elevated SSH grants are now off on this server (its elevated sudo rule was removed). To "
                 f"allow them run: {allow_cmd} — {warning}")
    return line


grant_setup.continue_on_error = True

DEFAULT_STEPS = [remove_legacy_grant_rules, secure_trees, secure_wrappers, grant_setup, refresh_scanner_pieces]


def run(daemon_user, *, layout=None, euid=None, uids=(0,), steps=None, elevated=None, report=None):
    """Run the steps in order; returns their lines. `report(line)` sees each line as it happens. A failing step
    raises SecureInstallError carrying every line so far, unless it is `continue_on_error`: then its failure becomes
    a line, the next step runs, and the run raises at the end."""
    geteuid = euid or getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        raise SecureInstallError("run it as root: sudo orchestratia-agent secure-install")
    ctx = SimpleNamespace(layout=layout or codetrust.Layout(), uids=uids, elevated=elevated)
    lines, failed = [], []
    for step in (DEFAULT_STEPS if steps is None else steps):
        try:
            line = step(daemon_user, ctx)
        except Exception as e:  # noqa: BLE001 — every failure is reported; the step decides whether the run stops
            if not getattr(step, "continue_on_error", False):
                raise SecureInstallError(str(e), lines) from e
            line = f"{step.__name__.replace('_', ' ')}: FAILED: {e}"
            failed.append(f"{step.__name__}: {e}")
        lines.append(line)
        if report:
            report(line)
    if failed:
        raise SecureInstallError("; ".join(failed), lines)
    return lines
