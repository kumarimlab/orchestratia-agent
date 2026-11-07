"""Where uploads land: <temp>/orchestratia-uploads/<os-user>/, one private folder per user.

The temp dir is deliberate: the user moves what they keep and the OS cleans up the
rest. Safety comes from ownership, not location:

- the shared parent belongs to root (reserved at every boot by
  /etc/tmpfiles.d/orchestratia.conf, written by `provision-tier --upload-dirs`) or to
  the daemon's own user, and nobody else can write it;
- each user's folder is owned by that user, mode 0700;
- a parent anyone else owns is never used: the daemon falls back to a fresh mkdtemp
  parent, logs it, and every reply carries the real path.

On Linux the base is the same for every euid — /var/tmp when /tmp is tmpfs (so a
multi-GB upload lands on disk, not in RAM), else /tmp — because root (provisioning)
and the non-root daemon must agree on where a project user's folder is. Elsewhere
(macOS) it is the per-user $TMPDIR.
"""
from __future__ import annotations

import logging
import os
import re
import stat as st
import sys
import tempfile

log = logging.getLogger("orchestratia-agent.upload_dirs")

# statfs(2) f_type of tmpfs. Python has no os.statfs, so the filesystem type is read
# from /proc/self/mountinfo instead; the constant stays as the reference value.
TMPFS_MAGIC = 0x01021994
BASE_NAME = "orchestratia-uploads"
TMPFILES_PATH = "/etc/tmpfiles.d/orchestratia.conf"
FIX_HINT = "sudo orchestratia-agent provision-tier --upload-dirs"
_TMPFILES_NAME_RE = re.compile(r"^(?:[a-z_][a-z0-9_-]{0,31}\$?|[0-9]{1,10})$")
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_cache: dict[str, str] = {}


class UploadDirError(Exception):
    """The folder can't be used. `code` is the wire error (unsafe_destination, privilege, ...)."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _unescape(field: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def fstype_of(path: str, mountinfo: str | None = None) -> str | None:
    """Filesystem type of the mount that holds `path` (the longest matching mount
    point; on a tie the later, i.e. top, mount wins)."""
    if mountinfo is None:
        try:
            with open("/proc/self/mountinfo") as fh:
                mountinfo = fh.read()
        except OSError:
            return None
    best, kind = None, None
    for line in mountinfo.splitlines():
        fields = line.split()
        if "-" not in fields:
            continue
        sep = fields.index("-")
        if sep < 5 or len(fields) <= sep + 1:
            continue
        mnt = _unescape(fields[4])
        if path == mnt or path.startswith(mnt.rstrip("/") + "/"):
            if best is None or len(mnt) >= len(best):
                best, kind = mnt, fields[sep + 1]
    return kind


def temp_root(mountinfo: str | None = None) -> str:
    if sys.platform.startswith("linux"):
        if fstype_of("/tmp", mountinfo) == "tmpfs" and os.path.isdir("/var/tmp"):
            return "/var/tmp"
        return "/tmp"
    return tempfile.gettempdir()


def own_user() -> str:
    import pwd
    return pwd.getpwuid(os.geteuid()).pw_name


def _usable(path: str, uids) -> bool | None:
    """None if missing; True iff a real directory (not a symlink) owned by one of
    `uids` that no one else can write."""
    try:
        s = os.lstat(path)
    except FileNotFoundError:
        return None
    return st.S_ISDIR(s.st_mode) and s.st_uid in uids and not s.st_mode & 0o022


def _chmod_dir(path: str, mode: int) -> None:
    fd = os.open(path, _DIR_FLAGS)
    try:
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def ensure_base(root: str | None = None, fallback: bool = True, trusted_uids=()) -> str:
    """The shared parent in use, `<root>/orchestratia-uploads`, created 0755 if missing.

    Accepted only if owned by root, by this euid, or by a `trusted_uids` member, and
    writable by nobody else. Otherwise (squatted, a symlink, group-writable) it is
    never touched: with `fallback` a fresh mkdtemp parent is used instead, without it
    UploadDirError. The choice is cached for the process and re-checked on every call."""
    root = root or temp_root()
    uids = {0, os.geteuid(), *trusted_uids}
    cached = _cache.get(root)
    if cached and _usable(cached, uids):
        return cached
    canonical = os.path.join(root, BASE_NAME)
    if _usable(canonical, uids) is None:
        try:
            os.mkdir(canonical, 0o755)
            _chmod_dir(canonical, 0o755)            # whatever the umask: users must traverse it
        except FileExistsError:
            pass                                    # lost a race; judged below like any folder
        except OSError as e:
            log.warning("cannot create %s: %s", canonical, e)
    if _usable(canonical, uids):
        _cache[root] = canonical
        return canonical
    if not fallback:
        raise UploadDirError("unsafe_destination",
                             f"{canonical} exists but is not a folder that only root (or the agent) "
                             f"can write; remove it (or reboot) and run again")
    fresh = tempfile.mkdtemp(prefix=BASE_NAME + "-", dir=root)
    _chmod_dir(fresh, 0o755)
    log.warning("upload folder %s is not safe to use (someone else owns it); using %s instead",
                canonical, fresh)
    _cache[root] = fresh
    return fresh


def ensure_user_dir(base: str, user: str) -> str:
    """`<base>/<user>`, owned by `user`, mode 0700, never a symlink.

    Created when missing by root, or by `user` itself. The daemon usually is NOT root
    (the restricted tier requires that), so a project user's folder is created by
    provisioning and by tmpfiles at boot; here it is only verified."""
    import pwd
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        raise UploadDirError("privilege", f"user {user!r} does not exist on this server") from None
    path = os.path.join(base, user)
    euid = os.geteuid()
    can_fix = euid in (0, pw.pw_uid)
    try:
        s = os.lstat(path)
    except FileNotFoundError:
        s = None
    if s is None:
        if not can_fix:
            raise UploadDirError("unsafe_destination", f"{path} does not exist; create it with: {FIX_HINT}")
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError as e:
            raise UploadDirError("unsafe_destination",
                                 f"cannot create {path} ({e.strerror}); run: {FIX_HINT}") from None
        try:
            fd = os.open(path, _DIR_FLAGS)
        except OSError:
            raise UploadDirError("unsafe_destination", f"{path} is not a folder") from None
        try:
            if euid == 0 and pw.pw_uid != 0:
                os.fchown(fd, pw.pw_uid, pw.pw_gid)
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
        s = os.lstat(path)
    if not st.S_ISDIR(s.st_mode) or s.st_uid != pw.pw_uid:
        raise UploadDirError("unsafe_destination", f"{path} is not a folder owned by {user}")
    if s.st_mode & 0o077:
        if can_fix:
            _chmod_dir(path, 0o700)
        elif s.st_mode & 0o022:
            raise UploadDirError("unsafe_destination", f"{path} is writable by other users")
    return path


def folder_for(run_as: str | None) -> str:
    """The upload folder for a session user (None = the daemon's own user)."""
    if sys.platform == "win32":
        raise UploadDirError("invalid", "streamed uploads are not supported on Windows")
    return ensure_user_dir(ensure_base(), run_as or own_user())


UPLOAD_MAX_AGE = "10d"


def tmpfiles_conf(users=(), root: str | None = None) -> str:
    """Content of /etc/tmpfiles.d/orchestratia.conf: the shared parents for root (both
    /tmp and /var/tmp, whichever the box uses), plus one private folder per (user,
    group). Listed paths are also exempt from the temp dir's own age cleanup."""
    base = os.path.join(root or temp_root(), BASE_NAME)
    parents = [f"/tmp/{BASE_NAME}", f"/var/tmp/{BASE_NAME}"]
    if base not in parents:
        parents.append(base)
    lines = ["# Orchestratia upload folders. Written by `orchestratia-agent provision-tier`;",
             "# local edits are overwritten. The parent is root's so no user can squat it;",
             "# each user's folder is private to that user."]
    lines += [f"d {p} 0755 root root -" for p in parents]
    for user, group in users:
        if not _TMPFILES_NAME_RE.match(str(user)) or not _TMPFILES_NAME_RE.match(str(group)):
            raise ValueError(f"unsafe name for tmpfiles.d: {user!r}:{group!r}")
        # 10d: a path with its own line is exempt from the temp dir's age cleanup, so the
        # age must be stated here or uploads in /var/tmp would never be cleaned up.
        # systemd-tmpfiles skips flock()ed files, so a live part is never aged out.
        lines.append(f"d {base}/{user} 0700 {user} {group} {UPLOAD_MAX_AGE}")
    return "\n".join(lines) + "\n"
