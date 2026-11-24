"""Who is actually at a terminal: the OS user of the program in its foreground.

A standard session starts as the daemon's user, but the person in it can switch
(`sudo -iu ppt`, `su - ppt`) and run their agent as someone else. Uploads and
downloads should act as that user, so this module reads it from /proc.

The answer is always a process whose real, effective, saved and filesystem uids
are equal. A process mid-switch (sudo, su's waiting parent, any setuid program)
is never the answer: we follow it into the one place the user went — its single
nested terminal (sudo's use_pty) or its single child — and give up on anything
ambiguous. Unknown (None) means "behave as before". Linux only; elsewhere the
snapshot is empty.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

MAX_DEPTH = 8
_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}")


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    sid: int
    tty_nr: int
    tpgid: int
    uids: tuple[int, int, int, int]

    @property
    def uniform(self) -> bool:
        return len(set(self.uids)) == 1


def _read(path: str) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    except OSError:
        return None


def _parse(pid: int, stat: str, status: str) -> Proc | None:
    # comm is in parentheses and may itself contain ") (": split at the LAST ')'
    rest = stat[stat.rfind(")") + 1:].split()
    uids = None
    for line in status.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()[1:5]
            if len(parts) == 4:
                uids = tuple(int(x) for x in parts)
            break
    if len(rest) < 6 or uids is None:
        return None
    try:
        ppid, sid, tty_nr, tpgid = int(rest[1]), int(rest[3]), int(rest[4]), int(rest[5])
    except ValueError:
        return None
    return Proc(pid=pid, ppid=ppid, sid=sid, tty_nr=tty_nr, tpgid=tpgid, uids=uids)


def snapshot(proc_root: str = "/proc") -> dict[int, Proc]:
    """Every readable process, once. Processes that exit mid-read are skipped."""
    try:
        names = os.listdir(proc_root)
    except OSError:
        return {}
    out: dict[int, Proc] = {}
    for name in names:
        if not name.isdigit():
            continue
        stat = _read(os.path.join(proc_root, name, "stat"))
        status = _read(os.path.join(proc_root, name, "status"))
        if stat is None or status is None:
            continue
        try:
            p = _parse(int(name), stat, status)
        except ValueError:
            p = None
        if p is not None:
            out[p.pid] = p
    return out


def _descendants(pid: int, snap: dict[int, Proc]) -> list[Proc]:
    kids: dict[int, list[Proc]] = {}
    for p in snap.values():
        kids.setdefault(p.ppid, []).append(p)
    out, todo, seen = [], [pid], {pid}
    while todo:
        for child in kids.get(todo.pop(), []):
            if child.pid not in seen:
                seen.add(child.pid)
                out.append(child)
                todo.append(child.pid)
    return out


def foreground_uid(pane_pid: int, snap: dict[int, Proc]) -> int | None:
    """The uid at the terminal whose first process is `pane_pid`, or None if unknown."""
    node = snap.get(pane_pid)
    visited: set[int] = set()
    for _ in range(MAX_DEPTH):
        if node is None:
            return None
        visited.add(node.pid)
        # the foreground process group's leader on this terminal, unless we came from it
        if node.tty_nr and node.tpgid > 0 and node.tpgid not in visited:
            lead = snap.get(node.tpgid)
            if lead is not None and lead.tty_nr == node.tty_nr:
                node = lead
                visited.add(node.pid)
        if node.uniform:
            return node.uids[0]
        # mid-switch: follow into the single nested terminal, else the single child
        desc = _descendants(node.pid, snap)
        nested = {p.tty_nr for p in desc if p.tty_nr and p.tty_nr != node.tty_nr}
        if len(nested) > 1:
            return None
        if nested:
            tty = nested.pop()
            leaders = [p for p in desc if p.tty_nr == tty and p.sid == p.pid]
            if len(leaders) != 1:
                return None
            node = leaders[0]
            continue
        kids = [p for p in desc if p.ppid == node.pid]
        if len(kids) != 1:
            return None
        node = kids[0]
    return None


def user_for_uid(uid: int | None) -> str | None:
    """Login name for a uid; None for root, an unknown uid or a name unsafe to pass on."""
    if uid is None or uid == 0:
        return None
    import pwd
    try:
        name = pwd.getpwuid(uid).pw_name
    except KeyError:
        return None
    return name if _NAME_RE.fullmatch(name) else None
