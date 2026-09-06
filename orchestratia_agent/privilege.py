"""Privilege tiers for agent sessions.

The single place that decides which OS user a session runs as. Everything else
(session_posix, hub, cli) asks this module rather than reasoning about tiers itself.

Two tiers only:
  standard   — the daemon's own user. Today's behaviour. Unconfined.
  restricted — a dedicated OS user with no sudo and no docker group, able to
               write only the workspaces granted at provision time.

Deliberately NOT the bastion's read_only/elevated/break_glass: a coding agent
that cannot write is useless, so a read-only tier would never be selected.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

TIER_STANDARD = "standard"
TIER_RESTRICTED = "restricted"
VALID_TIERS = (TIER_STANDARD, TIER_RESTRICTED)

DEFAULT_TMUX_PATH = "/usr/bin/tmux"


class PrivilegeError(Exception):
    """A tier could not be honoured. Always fatal to the spawn — never downgrade."""


@dataclass(frozen=True)
class TierConfig:
    restricted_user: str | None
    workspaces: tuple[str, ...]
    tmux_path: str


def load_tier_config(cfg: dict) -> TierConfig:
    block = (cfg or {}).get("privilege") or {}
    user = block.get("restricted_user") or None
    raw = block.get("workspaces") or []
    workspaces = tuple(os.path.realpath(os.path.expanduser(w)) for w in raw if w)
    return TierConfig(
        restricted_user=user,
        workspaces=workspaces,
        tmux_path=block.get("tmux_path") or DEFAULT_TMUX_PATH,
    )


def available_tiers(tc: TierConfig) -> list[str]:
    """What this box can actually honour. The hub must not offer more than this."""
    if tc.restricted_user and tc.workspaces:
        return [TIER_STANDARD, TIER_RESTRICTED]
    return [TIER_STANDARD]


def resolve_user(tier: str, tc: TierConfig) -> str | None:
    """Tier -> OS user. None means the daemon's own user (standard)."""
    if tier == TIER_STANDARD:
        return None
    if tier == TIER_RESTRICTED:
        if not tc.restricted_user:
            raise PrivilegeError(
                "tier 'restricted' requested but no restricted user is provisioned "
                "on this server (run: orchestratia-agent provision-tier)"
            )
        return tc.restricted_user
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


def verify_workspace(tier: str, working_dir: str | None, tc: TierConfig) -> str:
    """Resolve and authorise the session's working directory.

    Raises rather than falling back to $HOME. A fallback would silently relocate
    a confined agent to a directory nobody granted — a privilege decision taken
    by an error branch.
    """
    if tier == TIER_STANDARD:
        return working_dir or os.path.expanduser("~")

    if not working_dir:
        raise PrivilegeError(
            "tier 'restricted' requires an explicit working directory "
            "(no $HOME fallback: it would leave the granted workspaces)"
        )

    resolved = os.path.realpath(os.path.expanduser(working_dir))
    for root in tc.workspaces:
        if _is_within(resolved, root):
            return working_dir if os.path.isabs(working_dir) else resolved

    raise PrivilegeError(
        f"tier 'restricted' has no workspace grant for {resolved!r} "
        f"(granted: {', '.join(tc.workspaces) or 'none'})"
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


def capability_payload(tc: TierConfig) -> dict:
    """What the daemon advertises to the hub, under capabilities['privilege'].

    This is a UX affordance so the hub does not offer a tier this box cannot
    honour. It is NOT a security control — enforcement is at spawn, here.
    """
    return {
        "tiers": available_tiers(tc),
        "restricted_workspaces": list(tc.workspaces),
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
