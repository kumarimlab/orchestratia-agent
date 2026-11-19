"""Root-owned agent code (hardening plan Task 2).

Root runs this agent's code: `sudo orchestratia …`, `sudo orchestratia-agent …` and the daily scan-data timer. Root
also copies parts of it into root-owned places (the scanner runner dir, the download helper, the grant helper). So
that code must be root's alone: the venv (every package the agent imports) and the asset tree.

These checks are tripwires. They make an insecure layout loud, and they stop root from copying code another user
can change into root-owned places. They can't make an already-changed tree safe to run: `sudo orchestratia update`
rebuilds the install from a fresh clone instead.

Stdlib only."""
import os
import stat
import sys
from dataclasses import dataclass

VENV_DIR = "/opt/orchestratia-venv"
ASSET_DIR = "/opt/orchestratia-agent"
REPO_URL = "https://github.com/kumarimlab/orchestratia-agent.git"
FIX_HINT = "run: sudo orchestratia update"


class CodeTrustError(Exception):
    pass


@dataclass(frozen=True)
class Layout:
    venv: str = VENV_DIR
    assets: str = ASSET_DIR
    opt: str = "/opt"
    system_python: str = "/usr/bin/python3"
    bindir: str = "/usr/local/bin"          # the PATH wrappers (orchestratia, orchestratia-agent)


def stale_venvs(layout):
    """`<venv>.old-<stamp>` dirs an interrupted `sudo orchestratia update` left beside the venv, oldest first.
    Only root can create them: the parent directory is root's alone (update checks it first)."""
    base = os.path.basename(layout.venv) + ".old-"
    try:
        names = os.listdir(os.path.dirname(layout.venv) or os.sep)
    except OSError:
        return []
    found = [n for n in names if n.startswith(base) and n[len(base):].isdigit()]
    return [os.path.join(os.path.dirname(layout.venv), n) for n in sorted(found, key=lambda n: int(n[len(base):]))]


def path_problem(path, uids=(0,)):
    """Why `path` or a directory above it could be changed by someone outside `uids`, or None. Every component AS
    GIVEN is lstat'ed, never resolved: a symlink anywhere is refused. Each must be owned by a uid in `uids` and not
    group/world-writable; a root-owned sticky directory (such as /tmp) is allowed ABOVE `path`."""
    path = os.path.abspath(path)
    parts = path.split(os.sep)
    for i in range(1, len(parts) + 1):
        p = os.sep.join(parts[:i]) or os.sep
        try:
            st = os.lstat(p)
        except OSError:
            return f"{p} is missing"
        if stat.S_ISLNK(st.st_mode):
            return f"{p} is a symlink"
        if st.st_uid not in uids:
            return f"{p} is owned by uid {st.st_uid}"
        if st.st_mode & 0o022 and not (stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX and st.st_uid == 0
                                       and p != path):
            return f"{p} is writable by group or others"
    return None


def _raise(err):
    raise err


def _entries(root):
    """(path, lstat) for every entry below `root`, top-down, never following a symlink; an unreadable dir raises."""
    for dirpath, dirnames, filenames in os.walk(root, onerror=_raise, followlinks=False):
        for name in sorted(dirnames) + sorted(filenames):
            p = os.path.join(dirpath, name)
            yield p, os.lstat(p)


def first_foreign(root, uids=(0,)):
    """'<path> is owned by uid N' for the first entry at or below `root` owned outside `uids`, else None."""
    try:
        st = os.lstat(root)
        if st.st_uid not in uids:
            return f"{root} is owned by uid {st.st_uid}"
        for p, st in _entries(root):
            if st.st_uid not in uids:
                return f"{p} is owned by uid {st.st_uid}"
    except OSError as e:
        return f"{root}: {e.strerror or e}"
    return None


def tree_problem(root, uids=(0,)):
    """Why someone outside `uids` could change what is in `root`, or None: `root` and every directory above it
    (path_problem), every entry below it owned by `uids` and not group/world-writable, and every symlink resolving
    to a path with no path_problem."""
    why = path_problem(root, uids)
    if why:
        return why
    try:
        for p, st in _entries(root):
            if st.st_uid not in uids:
                return f"{p} is owned by uid {st.st_uid}"
            if stat.S_ISLNK(st.st_mode):
                target = os.path.realpath(p)
                why = path_problem(target, uids)
                if why:
                    return f"{p} points at {target}: {why}"
            elif st.st_mode & 0o022:
                return f"{p} is writable by group or others"
    except OSError as e:
        return f"{root}: {e.strerror or e}"
    return None


def normalize(root, uids=(0,)):
    """Modes for a tree ALREADY wholly owned by `uids`: directories 0755, files 0755 when any execute bit is set and
    0644 otherwise; symlinks untouched. Every entry is checked before the first chmod. It refuses an entry owned by
    anyone else, a hard-linked file (chmod would reach the other name too), and anything not a file, directory or
    symlink. Returns how many entries it checked."""
    st = os.lstat(root)
    if stat.S_ISLNK(st.st_mode):
        raise CodeTrustError(f"{root} is a symlink")
    plan = []
    for p, st in [(root, st), *_entries(root)]:
        if st.st_uid not in uids:
            raise CodeTrustError(f"{p} is owned by uid {st.st_uid}; {FIX_HINT}")
        if stat.S_ISLNK(st.st_mode):
            continue
        if stat.S_ISDIR(st.st_mode):
            want = 0o755
        elif stat.S_ISREG(st.st_mode):
            if st.st_nlink != 1:
                raise CodeTrustError(f"{p} has {st.st_nlink} hard links; refusing to change its mode")
            want = 0o755 if st.st_mode & 0o111 else 0o644
        else:
            raise CodeTrustError(f"{p} is not a file, directory or symlink")
        if stat.S_IMODE(st.st_mode) != want:
            plan.append((p, want))
    for p, want in plan:
        os.chmod(p, want)
    return len(list(_entries(root))) + 1


def code_roots(pkg_dir=None, prefix=None, base_prefix=None, assets=ASSET_DIR):
    """What root runs when it runs this agent: the interpreter's prefix when it is a venv (every package the agent
    imports is there), else the agent package directory; plus the asset tree when there is one."""
    pkg_dir = pkg_dir or os.path.dirname(os.path.abspath(__file__))
    prefix = sys.prefix if prefix is None else prefix
    base = sys.base_prefix if base_prefix is None else base_prefix
    roots = [prefix] if prefix != base else [pkg_dir]
    if os.path.isdir(assets):
        roots.append(assets)
    return roots


def install_problem(roots=None, uids=(0,)):
    for r in code_roots() if roots is None else roots:
        why = tree_problem(r, uids)
        if why:
            return why
    return None


def require_trusted(action, *, roots=None, uids=(0,), euid=None):
    """As root: raise CodeTrustError unless every code root is root's alone. A non-root caller runs nothing as root,
    so it passes (tests and the non-root daemon use the same code paths)."""
    geteuid = euid or getattr(os, "geteuid", None)
    if geteuid is None or geteuid() != 0:
        return None
    why = install_problem(roots, uids)
    if why:
        raise CodeTrustError(f"refusing to {action}: {why}. Root would run or copy code another user can change; "
                             f"{FIX_HINT}")
    return None
