"""Which OS user an upload or download acts as.

Restricted sessions: always their project user — nothing here changes that.

Standard sessions: the user actually running in the terminal. Someone who ran
`sudo -iu ppt` and started their agent as ppt expects a download to read ppt's
files and an upload to land where ppt can open it. Anyone who can type into that
terminal already has ppt's access, so acting as ppt gives the transfer nothing
the typist doesn't have. The limits:

- only when the hub asks (`follow_terminal`): an older hub never carries the
  chosen user back on open/cancel, and an upload's prepare and write must agree
  on the folder;
- never root;
- only a user whose uids are all equal at the terminal (terminal_user);
- only if the agent can become them (`sudo -n -u <user>` runs the helper);
- a user the hub carries back (`os_user`) only if this agent saw it at THIS
  session's terminal, or it is there now — the hub can never name anyone else.
"""
from __future__ import annotations

import asyncio
import logging
import os
import stat as st
import subprocess
import sys
import time
from dataclasses import dataclass

from orchestratia_agent import privilege, upload_dirs
from orchestratia_agent.terminal_user import foreground_uid, snapshot, user_for_uid

log = logging.getLogger("orchestratia-agent.transfer_user")

PROBE_TTL = 300
PROBE_TIMEOUT = 10
MAX_SESSIONS = 256
MAX_USERS_PER_SESSION = 8

_seen: dict[str, set[str]] = {}                   # session_id -> users seen at its terminal
_probe_cache: dict[str, tuple[float, bool]] = {}  # user -> (when, can the agent become them)


class TerminalChanged(Exception):
    """The hub carried a user this agent can't vouch for (or can no longer become)."""


@dataclass(frozen=True)
class Acting:
    run_as: str | None              # None = the daemon's own user, no sudo
    name: str                       # the login name the transfer acts as (the hub's evidence)
    followed: bool = False          # a user taken from the terminal, not the session's tier
    terminal_user: str | None = None  # the terminal's user when the transfer did NOT act as them


def helper_cmd() -> list[str]:
    """The helper as another user: the installed root-owned copy when there is one,
    else this python on the package's file (readable by every user in a system venv)."""
    from orchestratia_agent.downloads import HELPER_INSTALL_PATH, HELPER_SOURCE
    try:
        s = os.stat(HELPER_INSTALL_PATH)
        if s.st_uid == 0 and not s.st_mode & 0o022:
            return [HELPER_INSTALL_PATH]
    except OSError:
        pass
    return [sys.executable, "-I", HELPER_SOURCE]


def _terminal_uid(session_id: str, sessions) -> int | None:
    """uid at the session's terminal (blocking: tmux + /proc). None if unknown."""
    managed = (sessions or {}).get(session_id)
    handle = getattr(managed, "handle", None)
    if handle is None:
        return None
    pane_pid = None
    if getattr(handle, "tmux_name", ""):
        from orchestratia_agent.session_posix import _tmux
        try:
            r = _tmux(handle, ["display-message", "-p", "-t", handle.tmux_name, "#{pane_pid}"],
                      timeout=3, text=True)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                pane_pid = int(r.stdout.strip())
        except (OSError, subprocess.TimeoutExpired):
            return None
    elif isinstance(getattr(handle, "pid", None), int):
        pane_pid = handle.pid
    if not pane_pid:
        return None
    return foreground_uid(pane_pid, snapshot())


def _can_become(user: str) -> bool:
    """Can the agent run the helper as `user`, without a password? (blocking)"""
    try:
        r = subprocess.run(privilege.sudo_prefix(user, None) + helper_cmd() + ["--help"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=PROBE_TIMEOUT, cwd="/")
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


async def _reachable(user: str) -> bool:
    now = time.monotonic()
    hit = _probe_cache.get(user)
    if hit is not None and now - hit[0] < PROBE_TTL:
        return hit[1]
    can = await asyncio.get_running_loop().run_in_executor(None, _can_become, user)
    _probe_cache[user] = (now, can)
    if not can:
        log.info("transfers can't act as %s here (sudo -n -u %s failed); using the session user", user, user)
    return can


def _remember(session_id: str, user: str) -> None:
    users = _seen.pop(session_id, set())             # re-insert: most recent last
    if len(users) < MAX_USERS_PER_SESSION:
        users.add(user)
    _seen[session_id] = users
    while len(_seen) > MAX_SESSIONS:
        _seen.pop(next(iter(_seen)))


async def resolve(msg: dict, tc, sessions) -> Acting:
    """The user this transfer acts as. Raises privilege.PrivilegeError (tier can't be
    honoured) or TerminalChanged (a carried user this agent can't vouch for)."""
    tier = msg.get("privilege_tier") or privilege.TIER_STANDARD
    run_as = privilege.resolve_user(tier, msg.get("project_id"), tc)
    if run_as is not None:
        return Acting(run_as, run_as)
    if sys.platform == "win32":
        return Acting(None, "")
    own = upload_dirs.own_user()
    session_user = Acting(None, own)
    if msg.get("follow_terminal") is not True or not sys.platform.startswith("linux"):
        return session_user
    sid = str(msg.get("session_id") or "")
    loop = asyncio.get_running_loop()
    uid = await loop.run_in_executor(None, _terminal_uid, sid, sessions) if sid else None
    now = user_for_uid(uid) if uid is not None else None
    carried = msg.get("os_user")

    if carried is not None:                          # open / cancel: continue what stat/prepare chose
        if carried == own:
            return session_user
        vouched = isinstance(carried, str) and sid and carried != "root" and (
            carried in _seen.get(sid, ()) or carried == now)
        if vouched and await _reachable(carried):
            _remember(sid, carried)
            return Acting(carried, carried, followed=True)
        raise TerminalChanged(str(carried)[:32])

    if uid is None:
        return session_user
    if uid == 0:
        return Acting(None, own, terminal_user="root")
    if now is None or now == own:
        return session_user
    if not await _reachable(now):
        return Acting(None, own, terminal_user=now)
    _remember(sid, now)
    return Acting(now, now, followed=True)


def folder_for(acting: Acting) -> str:
    """The acting user's private upload folder. A followed user's folder is created
    (0700, theirs) with sudo when missing: the shared parent belongs to root or the
    agent, so they can't create it themselves. (blocking)"""
    if not acting.followed:
        return upload_dirs.folder_for(acting.run_as)
    import grp
    import pwd
    user = acting.run_as
    base = upload_dirs.ensure_base()
    path = os.path.join(base, user)
    if not os.path.lexists(path) and os.geteuid() != 0:
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            raise upload_dirs.UploadDirError("privilege", f"user {user!r} does not exist on this server") from None
        try:
            group = grp.getgrgid(pw.pw_gid).gr_name
        except KeyError:
            group = str(pw.pw_gid)
        fix = f"sudo install -d -m 0700 -o {user} -g {group} {path}"
        try:
            r = subprocess.run(["sudo", "-n", "install", "-d", "-m", "0700", "-o", user, "-g", group, "--", path],
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=PROBE_TIMEOUT, cwd="/")
            created = r.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            created = False
        if not created and not os.path.lexists(path):
            raise upload_dirs.UploadDirError("unsafe_destination", f"cannot create {path}; run: {fix}")
    return upload_dirs.ensure_user_dir(base, user)


def followed_users(tc) -> list[str]:
    """Users with a folder under the upload parent that is neither the agent's nor a
    project user's: the ones transfers followed. For the hourly sweep. (blocking)"""
    if not sys.platform.startswith("linux"):
        return []
    import pwd
    own = upload_dirs.own_user()
    project_users = {pt.user for pt in tc.projects.values()}
    try:
        base = upload_dirs.ensure_base()
        names = os.listdir(base)
    except (OSError, upload_dirs.UploadDirError):
        return []
    out = []
    for name in sorted(names):
        if name in project_users or name == own:
            continue
        try:
            s = os.lstat(os.path.join(base, name))
            uid = pwd.getpwnam(name).pw_uid
        except (OSError, KeyError):
            continue
        if st.S_ISDIR(s.st_mode) and s.st_uid == uid and user_for_uid(uid) == name:
            out.append(name)
    return out
