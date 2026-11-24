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
  session's terminal, or it is there now — the hub can never name anyone else;
- never a project user (orcp-*): their folders are another tenant's.

Only the first step of a transfer (download stat, upload prepare) decides; open
and cancel continue with the user it chose, which the hub carries back. Without a
carried user they act as the session user, exactly as before this existed.
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
from orchestratia_agent.terminal_user import foreground_uid, pane_start, snapshot, user_for_uid

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
    """uid at the session's terminal (blocking: tmux + /proc). None if unknown.

    tmux sessions only: the pane must be alive and its first process still on the
    pane's own terminal, or a reused pid (anyone's) could pick the user."""
    managed = (sessions or {}).get(session_id)
    handle = getattr(managed, "handle", None)
    if handle is None or not getattr(handle, "tmux_name", ""):
        return None
    from orchestratia_agent.session_posix import _tmux
    try:
        r = _tmux(handle, ["display-message", "-p", "-t", handle.tmux_name,
                           "#{pane_pid} #{pane_dead} #{pane_tty}"], timeout=3, text=True)
    except (OSError, subprocess.TimeoutExpired):
        return None
    parts = r.stdout.split() if r.returncode == 0 else []
    if len(parts) != 3 or not parts[0].isdigit() or not parts[2].startswith("/dev/"):
        return None
    try:
        rdev = os.stat(parts[2]).st_rdev
    except OSError:
        return None
    snap = snapshot()
    start = pane_start(int(parts[0]), rdev, parts[1] != "0", snap)
    return foreground_uid(start, snap) if start else None


def _uid_of(name: str) -> int | None:
    import pwd
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


def _owns_folder(user: str) -> bool:
    """`<base>/<user>` exists as a real folder owned by `user`. (blocking)"""
    try:
        s = os.lstat(os.path.join(upload_dirs.ensure_base(), user))
    except (OSError, upload_dirs.UploadDirError):
        return False
    return st.S_ISDIR(s.st_mode) and s.st_uid == _uid_of(user)


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


async def resolve(msg: dict, tc, sessions, purpose: str = "decide") -> Acting:
    """The user this transfer acts as. Raises privilege.PrivilegeError (tier can't be
    honoured) or TerminalChanged (a carried user this agent can't vouch for).

    purpose: "decide" (download stat / upload prepare: may follow the terminal),
    "continue" (open: only the carried user), "cancel" (as continue, and also a carried
    user whose folder is there — cancelling only deletes that upload's own files)."""
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
    project_users = {pt.user for pt in tc.projects.values()}

    async def at_terminal() -> tuple[int | None, str | None]:
        uid = await loop.run_in_executor(None, _terminal_uid, sid, sessions) if sid else None
        name = await loop.run_in_executor(None, user_for_uid, uid) if uid else None
        return uid, name

    if purpose != "decide":                          # open / cancel: continue what stat/prepare chose
        carried = msg.get("os_user")
        if carried is None or carried == own:
            return session_user
        if not isinstance(carried, str) or not sid or carried == "root" or carried in project_users:
            raise TerminalChanged(str(carried)[:32])
        vouched = carried in _seen.get(sid, ())
        if not vouched:
            vouched = (await at_terminal())[1] == carried
        by_folder = False
        if not vouched and purpose == "cancel":
            uid = await loop.run_in_executor(None, _uid_of, carried)
            by_folder = (uid is not None and await loop.run_in_executor(None, user_for_uid, uid) == carried
                         and await loop.run_in_executor(None, _owns_folder, carried))
        if (vouched or by_folder) and await _reachable(carried):
            if vouched:                              # a folder alone never vouches for later writes
                _remember(sid, carried)
            return Acting(carried, carried, followed=True)
        raise TerminalChanged(carried[:32])

    uid, now = await at_terminal()
    if uid is None:
        return session_user
    if uid == 0:
        return Acting(None, own, terminal_user="root")
    if now is None or now == own or now in project_users:
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
