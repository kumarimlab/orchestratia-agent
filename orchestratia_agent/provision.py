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
GIT_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")
BIN_PATH_RE = re.compile(r"^/[A-Za-z0-9_./-]+$")   # code-server et al.

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


def sudoers_lines(daemon_user: str, projects: dict, tmux_path: str, git_path: str,
                  code_server_path: str | None = None) -> list[str]:
    """One pinned, downward-only rule per project user.

    Each line permits exactly tmux, git, and (when provided) code-server as that
    project's user — nothing else, no wildcards, no shell, no ALL target. git is
    included so `git_changes` can inspect a repo AS the session's own
    unprivileged user; code-server so the editor runs as that user too.

    Still not an escalation: every orcp-* user has strictly LESS power than the
    daemon user, so letting the daemon run these as one is a downward move.

    The caller joins these with newlines into a drop-in and validates the whole
    file with `visudo -cf` before moving it into place — the belt to this
    braces, because a sudoers newline-injection once shipped here.
    """
    validate_username(daemon_user)
    if not isinstance(tmux_path, str) or not TMUX_PATH_RE.match(tmux_path):
        raise ProvisionError(f"invalid tmux path {tmux_path!r}")
    if not isinstance(git_path, str) or not GIT_PATH_RE.match(git_path):
        raise ProvisionError(f"invalid git path {git_path!r}")
    cmds = f"{tmux_path}, {git_path}"
    if code_server_path:
        if not BIN_PATH_RE.match(code_server_path):
            raise ProvisionError(f"invalid code-server path {code_server_path!r}")
        cmds += f", {code_server_path}"
    lines = []
    for spec in projects.values():
        user = validate_username((spec or {}).get("user"))
        lines.append(f"{daemon_user} ALL=({user}) NOPASSWD: {cmds}")
    return lines


def assert_no_collision(user: str, project_id: str, existing_projects: dict) -> None:
    """Refuse if `user` already belongs to a DIFFERENT project (D3).

    project_username derives the name from 12 hex of the project UUID; a
    collision is astronomically unlikely but its blast radius is a cross-tenant
    breach — two projects sharing one UID — so it is asserted, not assumed.
    Re-provisioning the same project is fine (idempotent).
    """
    for pid, spec in (existing_projects or {}).items():
        if (spec or {}).get("user") == user and pid != project_id:
            raise ProvisionError(
                f"username {user!r} already maps to project {pid!r}; refusing to "
                f"reuse it for {project_id!r} (hash collision — pick distinct projects)"
            )


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


def workspace_lockdown_command(workspace: str) -> list[str]:
    """Remove ALL 'other' access from the workspace root dir.

    Per-project users each get --x traverse on the SHARED parent (e.g. /srv), so
    without this a world-readable workspace (a 0755 git checkout is world-
    readable) is readable by a sibling project's user — a cross-tenant leak the
    ACLs alone do not close, because an ACL grants the named user access without
    removing 'other' access. `chmod o=` on the workspace root blocks traverse-in
    for everyone who is neither the owner nor the ACL-granted project user; files
    inside are then unreachable by 'other' regardless of their own mode bits.

    Not recursive: blocking traverse at the root is sufficient and leaves the
    operator's file modes untouched.
    """
    workspace = validate_workspace(workspace)
    return ["chmod", "o=", workspace]


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


def provision(project_id: str, workspaces: list[str],
              daemon_user: str, config_path: str,
              code_server_path: str | None = None) -> int:
    """Provision ONE project's restricted user. Additive, idempotent. Root only.

    Derives the OS user deterministically from project_id, refuses a hash
    collision with a different project, applies workspace ACLs, and rewrites the
    sudoers drop-in from ALL provisioned projects (so an existing project's rule
    survives a new project being added). Merges — never replaces — the projects map.
    """
    if os.geteuid() != 0:
        raise ProvisionError("provision-tier must be run as root (use sudo)")

    from orchestratia_agent.privilege import project_username
    user = project_username(project_id)          # validates the project_id shape
    validate_username(user)                       # and the derived username

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
    git_path = shutil.which("git")
    if not git_path:
        raise ProvisionError("git not found; the restricted tier requires it")
    # code-server is OPTIONAL: if present (or explicitly given) the editor is
    # enabled for this box's projects; if absent, the tier is tmux+git only and
    # no editor is advertised.
    cs_path = code_server_path or shutil.which("code-server")
    if not shutil.which("setfacl"):
        raise ProvisionError(
            "setfacl not found; install the 'acl' package "
            "(apt install acl / brew install acl)"
        )

    # Load the config FIRST: everything below either validates against it
    # (collision guard) or merges into it, and a read error must abort before we
    # create a user or touch anyone's filesystem — not leave a half-provisioned box.
    from orchestratia_agent.config import load_config, save_config
    try:
        existing_cfg = load_config(config_path) or {}
    except FileNotFoundError:
        existing_cfg = {}
    except Exception as e:  # noqa: BLE001
        raise ProvisionError(f"cannot read config {config_path}: {e}") from e

    priv = dict(existing_cfg.get("privilege") or {})
    existing_projects = dict(priv.get("projects") or {})
    assert_no_collision(user, project_id, existing_projects)

    # Merge this project in, then build ALL sudoers lines. Validating the whole
    # set now means bad input fails before any user/ACL/file change.
    merged_projects = dict(existing_projects)
    merged_projects[project_id] = {"user": user, "workspaces": spaces}
    lines = sudoers_lines(daemon_user, merged_projects, tmux_path, git_path,
                          code_server_path=cs_path)

    # 1. The user: no login password, and explicitly none of the escalation groups.
    if _run(["id", user], check=False).returncode != 0:
        _run(["useradd", "-m", "-s", "/bin/bash",
              "--comment", f"Orchestratia restricted agent (project {project_id})", user])
        print(f"  created user {user}")
    else:
        print(f"  user {user} already exists — converging")
    _run(["passwd", "-l", user], check=False)
    _strip_supplementary_groups(user)
    _assert_unprivileged(user)

    # 2. Workspace ACLs for THIS project's workspaces.
    home_roots = [h for h in ("/home", "/Users") if os.path.isdir(h)]
    for w in spaces:
        for cmd in acl_commands(user, w):
            _run(cmd)
        # Close the cross-tenant read: a sibling project's user has --x on the
        # shared parent, so a world-readable workspace would otherwise be
        # readable across tenants. Remove 'other' access on the workspace root.
        _run(workspace_lockdown_command(w))
        print(f"  granted {w} (world access removed)")
        if any(_is_within(w, h) for h in home_roots):
            print(
                f"    WARNING: {w} is inside a user home. Traversing to it "
                f"exposes world-readable files in that home (~/.bashrc, "
                f"~/.gitconfig, parts of ~/.claude) to {user}. Mode-0600 files "
                f"stay protected. Prefer a workspace outside /home."
            )

    # 3. Sudoers drop-in (all projects), validated before it goes live.
    tmp = "/etc/sudoers.d/.orchestratia-agent-tiers.tmp"
    final = "/etc/sudoers.d/orchestratia-agent-tiers"
    with open(tmp, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o440)
    check = _run(["visudo", "-cf", tmp], check=False)
    if check.returncode != 0:
        os.unlink(tmp)
        raise ProvisionError(
            f"refusing to install invalid sudoers: {check.stderr.strip()}"
        )
    os.replace(tmp, final)

    # 4. Config: merge this project into the projects map, pin both binaries.
    cfg = existing_cfg
    priv["projects"] = merged_projects
    priv["tmux_path"] = tmux_path
    priv["git_path"] = git_path
    if cs_path:
        priv["code_server_path"] = cs_path      # enables the editor capability
    priv.pop("restricted_user", None)   # drop any legacy flat keys once migrated
    priv.pop("workspaces", None)
    cfg["privilege"] = priv
    save_config(config_path, cfg)

    print(f"\n  Project:            {project_id}")
    print(f"  Restricted user:    {user}")
    print(f"  Workspaces granted: {', '.join(spaces)}")
    print(f"  Projects on this box: {', '.join(merged_projects)}")
    print("\n  NEXT — authenticate your agent tooling once, as that user:")
    print(f"      sudo -iu {user}")
    print("      claude login      # or: gemini auth / codex login")
    print("\n  Then restart the daemon:")
    print("      sudo systemctl restart orchestratia-agent\n")
    return 0
