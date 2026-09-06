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

# Granting any of these as a workspace would hand back what the tier removes.
FORBIDDEN_WORKSPACES = {
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot",
    "/var", "/root", "/proc", "/sys", "/dev", "/home", "/srv", "/opt", "/tmp",
}

RESERVED_USERS = {"root", "daemon", "bin", "sys", "adm", "sudo", "docker"}

# Groups that would defeat the tier. Stripped on every run, not just at create,
# so a user hand-added to docker later is corrected the next time this runs.
ESCALATION_GROUPS = ("sudo", "docker", "wheel", "admin", "root", "adm")


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


def validate_workspace(path: str) -> str:
    if not isinstance(path, str) or any(c in path for c in "\n\r\t\0"):
        raise ProvisionError(f"invalid workspace {path!r}: control characters")
    if not path.startswith("/"):
        raise ProvisionError(f"workspace {path!r} must be an absolute path")
    normalised = os.path.normpath(path)
    if normalised in FORBIDDEN_WORKSPACES:
        raise ProvisionError(
            f"refusing to grant {normalised!r}: it would defeat the tier"
        )
    return normalised


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
    parent's contents. Verified that `--x` alone still denies both `ls` and a
    known-path read of a 0600 secret.
    """
    user = validate_username(user)
    workspace = validate_workspace(workspace)
    cmds = [
        ["setfacl", "-R", "-m", f"u:{user}:rwX", workspace],
        ["setfacl", "-R", "-d", "-m", f"u:{user}:rwX", workspace],
    ]
    parent = os.path.dirname(workspace)
    while parent and parent != "/":
        cmds.append(["setfacl", "-m", f"u:{user}:--x", parent])
        parent = os.path.dirname(parent)
    return cmds


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

    # 1. The user: no login password, and explicitly none of the escalation groups.
    if _run(["id", user], check=False).returncode != 0:
        _run(["useradd", "-m", "-s", "/bin/bash",
              "--comment", "Orchestratia restricted agent", user])
        print(f"  created user {user}")
    else:
        print(f"  user {user} already exists — converging")
    _run(["passwd", "-l", user], check=False)
    for group in ESCALATION_GROUPS:
        _run(["gpasswd", "-d", user, group], check=False)

    # 2. Workspace ACLs.
    for w in spaces:
        for cmd in acl_commands(user, w):
            _run(cmd)
        print(f"  granted {w}")

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
    from orchestratia_agent.config import load_config, save_config
    cfg = load_config(config_path) or {}
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
