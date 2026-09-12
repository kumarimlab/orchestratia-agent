"""Privilege tiers for agent sessions.

The single place that decides which OS user a session runs as. Everything else
(session_posix, hub, cli) asks this module rather than reasoning about tiers itself.

Two tiers only:
  standard   — the daemon's own user. Today's behaviour. Unconfined.
  restricted — a dedicated OS user, ONE PER PROJECT (orcp-<project>), with no
               sudo and no docker group, able to write only the workspaces
               granted to that project at provision time.

Per-project (not per-host) is the point: co-located restricted sessions for two
different clients get two different UIDs, so neither can read, inject into, or
kill the other. The tenancy boundary is the project.

Deliberately NOT the bastion's read_only/elevated/break_glass: a coding agent
that cannot write is useless, so a read-only tier would never be selected.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

TIER_STANDARD = "standard"
TIER_RESTRICTED = "restricted"
VALID_TIERS = (TIER_STANDARD, TIER_RESTRICTED)

# Sentinel project key for a legacy single-user config (restricted_user +
# workspaces, no projects map). It never equals a real project_id, so a
# restricted session on a not-yet-migrated host is refused until the operator
# re-provisions with --project. Kept only so the legacy config loads without
# error and the deprecation warning fires.
LEGACY_KEY = "__legacy__"

log = logging.getLogger("orchestratia-agent.privilege")


def _default_tmux_path() -> str:
    """Where tmux actually is on THIS box.

    Never hardcode /usr/bin/tmux: macOS ships none there and Homebrew installs
    to /opt/homebrew/bin. Hardcoding it made the daemon exec a nonexistent
    binary while still reporting a successful spawn.
    """
    import shutil
    return shutil.which("tmux") or "/usr/bin/tmux"


def _default_git_path() -> str:
    import shutil
    return shutil.which("git") or "/usr/bin/git"


DEFAULT_TMUX_PATH = _default_tmux_path()


class PrivilegeError(Exception):
    """A tier could not be honoured. Always fatal to the spawn — never downgrade."""


def project_username(project_id: str) -> str:
    """orcp-<first 12 hex of the project UUID>. Deterministic; no lookup table.

    17 chars, within the 32-char limit and USERNAME_RE. Any component (daemon,
    recovery, provisioning) computes the same name from project_id alone. Raises
    rather than producing a malformed name, which would later fail useradd or
    visudo with a far less obvious error.
    """
    hexchars = (project_id or "").replace("-", "").lower()
    if len(hexchars) < 12 or any(c not in "0123456789abcdef" for c in hexchars[:12]):
        raise PrivilegeError(f"project_id {project_id!r} is not a hex UUID")
    return "orcp-" + hexchars[:12]


@dataclass(frozen=True)
class ProjectTier:
    user: str
    workspaces: tuple[str, ...]


@dataclass(frozen=True)
class TierConfig:
    projects: dict            # project_id (or LEGACY_KEY) -> ProjectTier
    tmux_path: str
    git_path: str


def load_tier_config(cfg: dict) -> TierConfig:
    block = (cfg or {}).get("privilege") or {}
    tmux_path = block.get("tmux_path") or DEFAULT_TMUX_PATH
    git_path = block.get("git_path") or _default_git_path()

    projects: dict = {}
    for pid, spec in (block.get("projects") or {}).items():
        user = (spec or {}).get("user")
        if not user:
            continue
        raw = (spec or {}).get("workspaces") or []
        ws = tuple(os.path.realpath(os.path.expanduser(w)) for w in raw if w)
        projects[pid] = ProjectTier(user=user, workspaces=ws)

    # Legacy flat config: normalize to a single mapping under LEGACY_KEY, which
    # never matches a real project_id, so restricted sessions are refused (D4)
    # until the operator re-provisions. Warn loudly.
    if not projects and block.get("restricted_user"):
        raw = block.get("workspaces") or []
        ws = tuple(os.path.realpath(os.path.expanduser(w)) for w in raw if w)
        projects[LEGACY_KEY] = ProjectTier(user=block["restricted_user"], workspaces=ws)
        log.warning(
            "privilege config uses the legacy single-user shape; re-provision with "
            "`orchestratia-agent provision-tier --project <id> --workspace <dir>` — "
            "restricted sessions are refused until then"
        )

    return TierConfig(projects=projects, tmux_path=tmux_path, git_path=git_path)


def _real_projects(tc: TierConfig) -> list[str]:
    """Project ids that actually confer the restricted tier (LEGACY_KEY excluded)."""
    return [k for k in tc.projects if k != LEGACY_KEY]


def available_tiers(tc: TierConfig) -> list[str]:
    """What this box can honour. The hub must not offer more than this."""
    if _real_projects(tc):
        return [TIER_STANDARD, TIER_RESTRICTED]
    return [TIER_STANDARD]


def resolve_user(tier: str, project_id: str | None, tc: TierConfig) -> str | None:
    """Tier + project -> OS user. None means the daemon's own user (standard).

    Restricted refuses (never falls back to another user) when the project is
    unprovisioned — a fallback would be a cross-tenant breach dressed as
    convenience. LEGACY_KEY is not addressable here: a real project_id will
    never equal it, so a legacy host refuses restricted until re-provisioned.
    """
    if tier == TIER_STANDARD:
        return None
    if tier == TIER_RESTRICTED:
        pt = tc.projects.get(project_id) if project_id else None
        if pt is None or project_id == LEGACY_KEY:
            raise PrivilegeError(
                f"tier 'restricted' requested for project {project_id!r}, which is "
                f"not provisioned on this server (run: orchestratia-agent "
                f"provision-tier --project {project_id} --workspace <dir>)"
            )
        return pt.user
    raise PrivilegeError(f"unknown privilege tier {tier!r}")


def _is_within(path: str, root: str) -> bool:
    """True iff `path` is `root` or lives beneath it.

    Uses os.path.commonpath rather than str.startswith so that /srv/acme-other
    is not treated as inside /srv/acme.
    """
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:      # different drives / relative vs absolute
        return False


def verify_workspace(tier: str, working_dir: str | None,
                     project_id: str | None, tc: TierConfig) -> str:
    """Resolve and authorise the session's working directory for its project.

    Raises rather than falling back to $HOME. A restricted session may only use
    a directory granted to ITS OWN project — never another project's workspace,
    even on a box that provisions both.
    """
    if tier == TIER_STANDARD:
        return working_dir or os.path.expanduser("~")

    if not working_dir:
        raise PrivilegeError(
            "tier 'restricted' requires an explicit working directory "
            "(no $HOME fallback: it would leave the granted workspaces)"
        )

    pt = tc.projects.get(project_id) if project_id else None
    if pt is None or project_id == LEGACY_KEY:
        raise PrivilegeError(
            f"tier 'restricted' has no provisioned project {project_id!r}"
        )

    resolved = os.path.realpath(os.path.expanduser(working_dir))
    for root in pt.workspaces:
        if _is_within(resolved, root):
            # Return the RESOLVED path, never the caller's raw string: the check
            # and the chdir must refer to the same object, or a symlink flipped
            # in between escapes the grant (~3%/attempt, unlimited retries).
            return resolved

    raise PrivilegeError(
        f"tier 'restricted' project {project_id!r} has no workspace grant for "
        f"{resolved!r} (granted: {', '.join(pt.workspaces) or 'none'})"
    )


def sudo_prefix(user: str | None, tc: TierConfig) -> list[str]:
    """argv prefix that drops privilege to `user`. Empty for the daemon's own user.

    -n  never prompt (a password prompt would hang a PTY spawn forever)
    -H  set HOME to the target user's home
    NOT -i: that runs the command through a login shell, which re-parses the
    argv and breaks any workspace path containing a space.
    """
    if user is None:
        return []
    return ["sudo", "-n", "-u", user, "-H"]


def tmux_exec_argv(user: str | None, args: list[str], tc: TierConfig) -> list[str]:
    """Full argv to run tmux, dropping privilege when `user` is set.

    For the daemon's own user this deliberately keeps PATH semantics ("tmux"),
    matching has_tmux()'s PATH probe. Only the sudo form needs an absolute
    path, because sudo requires one to match its sudoers rule.
    """
    if user is None:
        return ["tmux"] + args
    return sudo_prefix(user, tc) + [tc.tmux_path] + args


def capability_payload(tc: TierConfig) -> dict:
    """What the daemon advertises to the hub, under capabilities['privilege'].

    Per-project: the hub offers `restricted` for a session only if that session's
    project appears here. A UX affordance, NOT a security control — enforcement
    is at spawn, here. LEGACY_KEY is never advertised (a legacy host must
    re-provision before it can honour restricted).
    """
    return {
        "tiers": available_tiers(tc),
        "projects": {
            pid: {"workspaces": list(pt.workspaces)}
            for pid, pt in tc.projects.items() if pid != LEGACY_KEY
        },
    }


def merge_capabilities(existing: dict | None, tc: TierConfig) -> dict:
    """Fold the privilege advertisement into the server's capabilities blob.

    capabilities is shared with the hub's task-matching service (tags, tools,
    languages, max_concurrent_tasks), so this merges rather than replaces.
    Returns a new dict — the caller's config must not be edited underneath it.
    """
    merged = dict(existing or {})
    merged["privilege"] = capability_payload(tc)
    return merged
