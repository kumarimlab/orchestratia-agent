"""Provision the restricted OS user, its workspace ACLs, and the sudoers rule.

Root-only, run once per box. Kept out of cli.py because it is security-sensitive
and needs its own tests: the equivalent bastion script shipped a newline-injection
hole that visudo parsed as a second, entirely valid rule.

Everything here validates before it acts, and nothing is applied partially.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

# Deliberately strict: this feeds a sudoers file. Anything outside this charset
# is refused rather than escaped, because escaping is where the bugs live.
USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# An absolute path, no whitespace, no sudoers metacharacters.
TMUX_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")

# Granting any of these -- OR ANYTHING BENEATH THEM -- would hand back what the
# tier removes. Checked as ancestors, not as exact strings: an exact-match test
# refused /etc but happily allowed /etc/cron.d, /etc/sudoers.d and /root/.ssh,
# each of which is a direct route back to root.
FORBIDDEN_TREES = (
    "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
    "/root", "/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run",
    "/var/spool",
)

# Allowed as an ancestor of a workspace, but never AS one -- granting the whole
# tree would cover every project on the box.
FORBIDDEN_EXACT = {"/", "/home", "/srv", "/opt", "/tmp", "/var", "/mnt", "/media"}

RESERVED_USERS = {"root", "daemon", "bin", "sys", "adm", "sudo", "docker"}

# NOT a denylist. A denylist of "the dangerous groups" missed lxd (container
# escape to root), disk (raw block devices) and shadow (read /etc/shadow) --
# each of which defeats the tier on its own. The user is instead asserted to
# have NO supplementary groups at all, which is the only version of this check
# that cannot be out-of-date.
ALLOWED_SUPPLEMENTARY_GROUPS: tuple[str, ...] = ()


class ProvisionError(Exception):
    """Refuse to provision. Never partially apply."""


def validate_username(name: str) -> str:
    if not isinstance(name, str) or not USERNAME_RE.match(name):
        raise ProvisionError(
            f"invalid username {name!r}: must match {USERNAME_RE.pattern}"
        )
    if name in RESERVED_USERS:
        raise ProvisionError(f"{name!r} is not a restricted user")
    return name


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def validate_workspace(path: str) -> str:
    """Resolve and authorise a workspace path, or refuse.

    Resolves with realpath BEFORE checking, because setfacl follows a symlinked
    argument: a workspace symlinked to / would otherwise ACL the whole
    filesystem. A symlink is refused outright rather than silently followed, so
    what the operator typed is what gets granted.
    """
    if not isinstance(path, str) or any(c in path for c in "\n\r\t\0"):
        raise ProvisionError(f"invalid workspace {path!r}: control characters")
    if not path.startswith("/"):
        raise ProvisionError(f"workspace {path!r} must be an absolute path")

    normalised = os.path.normpath(path)
    # normpath keeps a leading '//' (POSIX-permitted), which also made the
    # parent walk below non-terminating. Collapse it.
    while normalised.startswith("//"):
        normalised = normalised[1:]

    if os.path.islink(normalised):
        raise ProvisionError(
            f"refusing to grant {normalised!r}: it is a symlink, and setfacl "
            f"would apply the grant to its target instead"
        )

    resolved = os.path.realpath(normalised)
    if resolved != normalised:
        raise ProvisionError(
            f"refusing to grant {normalised!r}: it resolves to {resolved!r} "
            f"(grant the real path explicitly)"
        )

    if resolved in FORBIDDEN_EXACT:
        raise ProvisionError(
            f"refusing to grant {resolved!r}: granting the whole tree would "
            f"cover every project on this box"
        )
    for tree in FORBIDDEN_TREES:
        if _is_within(resolved, tree):
            raise ProvisionError(
                f"refusing to grant {resolved!r}: it is inside {tree!r}, "
                f"which would defeat the tier"
            )
    return resolved


def sudoers_line(daemon_user: str, restricted_user: str, tmux_path: str) -> str:
    """One pinned rule: this daemon user may run THIS binary as THIS user.

    No wildcards, no shell, no ALL target. The caller writes it to a drop-in and
    validates with `visudo -cf` before moving it into place.

    Note this is a DOWNWARD privilege move — orc-agent has strictly less power
    than the daemon user — so it is not an escalation vector even though tmux
    can run arbitrary commands.
    """
    validate_username(daemon_user)
    validate_username(restricted_user)
    if not isinstance(tmux_path, str) or not TMUX_PATH_RE.match(tmux_path):
        raise ProvisionError(f"invalid tmux path {tmux_path!r}")
    return f"{daemon_user} ALL=({restricted_user}) NOPASSWD: {tmux_path}"


def acl_commands(user: str, workspace: str) -> list[list[str]]:
    """Grant rwX on the workspace, and traverse-only on every parent.

    A repo inside a 0750 home is unreachable without the parent traverse bit,
    even with a perfect ACL on the repo itself — verified on a real box, and
    the single most confusing failure this feature can produce.

    Traverse is `--x`, NEVER `r-x`: `r-x` would let the restricted user list the
    parent's contents.

    HONEST LIMIT — do not overstate this. `--x` blocks directory LISTING and
    blocks reads of 0600 files, but it does NOT hide world-readable content on
    a known path. With a workspace under /home/ubuntu, the restricted user can
    still read ~/.bashrc, ~/.gitconfig and anything in ~/.claude that carries
    world bits. Only mode-0600 material (~/.ssh, ~/.claude/.credentials.json)
    is actually protected.

    So: prefer workspaces OUTSIDE user homes. provision() warns when a granted
    workspace requires punching traverse through a home directory.
    """
    user = validate_username(user)
    workspace = validate_workspace(workspace)
    # -P so setfacl does not follow symlinks while recursing.
    # NO -d (default) ACL: that would make files the DAEMON user creates later
    # writable by the agent, and the daemon routinely executes code from these
    # directories (build scripts, git hooks, node_modules/.bin). An agent that
    # can rewrite a script the root-equivalent daemon later runs has escaped the
    # tier in one step -- proven in review. New agent-created files are owned by
    # the agent anyway, so the default ACL bought nothing it needed.
    cmds = [["setfacl", "-P", "-R", "-m", f"u:{user}:rwX", workspace]]

    parent = os.path.dirname(workspace)
    while True:
        nxt = os.path.dirname(parent)
        if parent == nxt:          # reached the root; dirname('/') == '/'
            break
        cmds.append(["setfacl", "-m", f"u:{user}:--x", parent])
        parent = nxt
    return cmds


def _strip_supplementary_groups(user: str) -> None:
    """Remove the user from every supplementary group.

    Enumerates what the user is ACTUALLY in rather than subtracting a fixed
    list, so a group nobody thought of (lxd, disk, shadow) is still removed.
    """
    out = _run(["id", "-nG", user], check=False).stdout or ""
    primary = (_run(["id", "-ng", user], check=False).stdout or "").strip()
    for group in out.split():
        if group == primary or group in ALLOWED_SUPPLEMENTARY_GROUPS:
            continue
        _run(["gpasswd", "-d", user, group], check=False)


def _assert_unprivileged(user: str) -> None:
    """Refuse to finish if the user still has a route to privilege.

    Verifying the end state beats trusting the steps that produced it: this is
    the check that would have caught a stale sudoers entry or a group the
    stripping missed.
    """
    groups = (_run(["id", "-nG", user], check=False).stdout or "").split()
    primary = (_run(["id", "-ng", user], check=False).stdout or "").strip()
    extra = [g for g in groups
             if g != primary and g not in ALLOWED_SUPPLEMENTARY_GROUPS]
    if extra:
        raise ProvisionError(
            f"{user} is still in supplementary groups {extra}; refusing to "
            f"present it as a restricted user"
        )

    sudo_check = _run(["sudo", "-n", "-l", "-U", user], check=False)
    listing = (sudo_check.stdout or "")
    if "not allowed to run sudo" not in listing and "may run" in listing:
        raise ProvisionError(
            f"{user} has sudo privileges according to `sudo -l -U {user}`; "
            f"refusing to present it as a restricted user"
        )


def _run(argv: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise ProvisionError(f"{' '.join(argv)} failed: {result.stderr.strip()}")
    return result


def provision(restricted_user: str, workspaces: list[str],
              daemon_user: str, config_path: str) -> int:
    """Create the user, apply ACLs, install sudoers, update config. Root only."""
    if os.geteuid() != 0:
        raise ProvisionError("provision-tier must be run as root (use sudo)")

    user = validate_username(restricted_user)
    if daemon_user == "root":
        # Reachable from a plain root shell, where $SUDO_USER is unset. The
        # generic validator would say "'root' is not a restricted user", which
        # names the wrong role and sends the operator looking in the wrong place.
        raise ProvisionError(
            "--daemon-user is required when running from a root shell "
            "(there is no $SUDO_USER to infer it from). Pass the user the "
            "agent daemon runs as, e.g. --daemon-user ubuntu"
        )
    daemon_user = validate_username(daemon_user)
    spaces = [validate_workspace(w) for w in workspaces]
    if not spaces:
        raise ProvisionError("at least one --workspace is required")
    for w in spaces:
        if not os.path.isdir(w):
            raise ProvisionError(f"workspace {w} does not exist")

    tmux_path = shutil.which("tmux")
    if not tmux_path:
        raise ProvisionError("tmux not found; the restricted tier requires it")
    if not shutil.which("setfacl"):
        raise ProvisionError(
            "setfacl not found; install the 'acl' package "
            "(apt install acl / brew install acl)"
        )

    # Build the sudoers line FIRST: if any input is bad we want to fail before
    # creating a user or touching anyone's filesystem.
    line = sudoers_line(daemon_user, user, tmux_path)

    # Load the config now too, for the same reason. It used to be read at the
    # very END, where a missing file raised FileNotFoundError (not
    # ProvisionError) AFTER the user, ACLs and sudoers rule had all been
    # applied -- a traceback on a half-provisioned box.
    from orchestratia_agent.config import load_config, save_config
    try:
        existing_cfg = load_config(config_path) or {}
    except FileNotFoundError:
        existing_cfg = {}
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"cannot read config {config_path}: {e}") from e

    # 1. The user: no login password, and explicitly none of the escalation groups.
    if _run(["id", user], check=False).returncode != 0:
        _run(["useradd", "-m", "-s", "/bin/bash",
              "--comment", "Orchestratia restricted agent", user])
        print(f"  created user {user}")
    else:
        print(f"  user {user} already exists — converging")
    _run(["passwd", "-l", user], check=False)
    _strip_supplementary_groups(user)
    _assert_unprivileged(user)

    # 2. Workspace ACLs.
    home_roots = [h for h in ("/home", "/Users") if os.path.isdir(h)]
    for w in spaces:
        for cmd in acl_commands(user, w):
            _run(cmd)
        print(f"  granted {w}")
        if any(_is_within(w, h) for h in home_roots):
            print(
                f"    WARNING: {w} is inside a user home. Traversing to it "
                f"exposes world-readable files in that home (~/.bashrc, "
                f"~/.gitconfig, parts of ~/.claude) to {user}. Mode-0600 files "
                f"stay protected. Prefer a workspace outside /home."
            )

    # 3. Sudoers drop-in, validated before it goes live.
    tmp = "/etc/sudoers.d/.orchestratia-agent-tiers.tmp"
    final = "/etc/sudoers.d/orchestratia-agent-tiers"
    with open(tmp, "w") as fh:
        fh.write(line + "\n")
    os.chmod(tmp, 0o440)
    check = _run(["visudo", "-cf", tmp], check=False)
    if check.returncode != 0:
        os.unlink(tmp)
        raise ProvisionError(
            f"refusing to install invalid sudoers: {check.stderr.strip()}"
        )
    os.replace(tmp, final)

    # 4. Config, so the daemon advertises and can honour the tier.
    cfg = existing_cfg
    cfg["privilege"] = {
        "restricted_user": user,
        "workspaces": spaces,
        "tmux_path": tmux_path,
    }
    save_config(config_path, cfg)

    print(f"\n  Restricted user:    {user}")
    print(f"  Workspaces granted: {', '.join(spaces)}")
    print(f"  Sudoers rule:       {line}")
    print("\n  NEXT — authenticate your agent tooling once, as that user:")
    print(f"      sudo -iu {user}")
    print("      claude login      # or: gemini auth / codex login")
    print("\n  Then restart the daemon:")
    print("      sudo systemctl restart orchestratia-agent\n")
    return 0
