#!/usr/bin/env python3
"""Which OS user an upload or download acts as (transfer_user.resolve).

Run:  python3 tests/test_transfer_user.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import downloads as dl  # noqa: E402
from orchestratia_agent import transfer_user as tu, uploads as ul, upload_dirs  # noqa: E402
from orchestratia_agent.privilege import ProjectTier, TierConfig  # noqa: E402

results = []
PROJECT = "01234567-89ab-cdef-0123-456789abcdef"
TC = TierConfig(projects={PROJECT: ProjectTier(user="orcp-0123456789ab", workspaces=("/srv/w",))},
                tmux_path="/usr/bin/tmux", git_path="/usr/bin/git")
OWN = upload_dirs.own_user()
SID = "sess-1"


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class World:
    """Fakes for the two things resolve() asks the host: who is at the terminal, and
    whether the agent can become a user."""
    def __init__(self, uid=None, names=None, reachable=()):
        self.uid, self.names, self.reachable, self.asked = uid, names or {}, set(reachable), []

    def install(self):
        tu._seen.clear()
        tu._probe_cache.clear()
        tu._terminal_uid = lambda session_id, sessions: (
            self.asked.append(session_id), self.uid if session_id in sessions else None)[1]
        tu.user_for_uid = lambda uid: self.names.get(uid)
        tu._can_become = lambda user: user in self.reachable
        tu._uid_of = lambda name: {v: k for k, v in self.names.items()}.get(name)
        tu._owns_folder = lambda user: user in self.folders
        self.folders = set()
        return self


def msg(**kw):
    base = {"privilege_tier": "standard", "project_id": PROJECT, "session_id": SID, "follow_terminal": True}
    base.update(kw)
    return base


def run(m, sessions=None, purpose="decide"):
    return asyncio.run(tu.resolve(m, TC, sessions or {SID: object()}, purpose))


def test_gate():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    a = run(msg(follow_terminal=None))
    ok("old hub (no follow_terminal): the session user, terminal never read",
       a.run_as is None and a.name == OWN and not a.followed and w.asked == [], a)


def test_restricted_never_follows():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    a = run(msg(privilege_tier="restricted", os_user="ppt"))
    ok("restricted: always the project user, carried user ignored",
       a.run_as == "orcp-0123456789ab" and a.name == "orcp-0123456789ab" and not a.followed and w.asked == [], a)


def test_follows_terminal():
    World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    a = run(msg())
    ok("terminal runs as ppt: act as ppt", a.run_as == "ppt" and a.name == "ppt" and a.followed, a)
    ok("ppt remembered for this session", "ppt" in tu._seen.get(SID, set()))


def test_same_as_session_user():
    World(uid=os.geteuid(), names={os.geteuid(): OWN}, reachable=set()).install()
    a = run(msg())
    ok("terminal is the session user: unchanged", a.run_as is None and a.name == OWN and a.terminal_user is None, a)


def test_root_never():
    World(uid=0, names={}, reachable={"root"}).install()
    a = run(msg())
    ok("root shell: session user, reply says root", a.run_as is None and a.terminal_user == "root", a)


def test_unknown():
    World(uid=None).install()
    a = run(msg())
    ok("terminal unknown: session user, nothing claimed", a.run_as is None and a.terminal_user is None, a)
    World(uid=1001, names={1001: "ppt"}).install()
    a = run(msg(session_id="gone"), sessions={})
    ok("session not on this agent: session user", a.run_as is None, a)


def test_unreachable():
    World(uid=1001, names={1001: "ppt"}, reachable=set()).install()
    a = run(msg())
    ok("can't become ppt: session user, reply names ppt",
       a.run_as is None and a.terminal_user == "ppt" and not tu._seen.get(SID), a)


def test_carried_user():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    run(msg())                                    # prepare/stat saw ppt
    w.uid = os.geteuid()                          # ...then the user left the ppt shell
    w.names[os.geteuid()] = OWN
    a = run(purpose="continue", m=msg(os_user="ppt"))
    ok("open continues as ppt (seen for this session) after the terminal changed",
       a.run_as == "ppt" and a.followed, a)
    a = run(purpose="continue", m=msg(os_user=OWN))
    ok("carried session user: the session user", a.run_as is None and a.name == OWN, a)
    try:
        run(purpose="continue", m=msg(os_user="mallory"))
        ok("carried user never seen here: refused", False)
    except tu.TerminalChanged:
        ok("carried user never seen here: refused", True)
    try:
        run(purpose="continue", m=msg(os_user="ppt", session_id="other"), sessions={"other": object()})
        ok("ppt seen in another session doesn't count", False)
    except tu.TerminalChanged:
        ok("ppt seen in another session doesn't count", True)
    try:
        run(purpose="continue", m=msg(os_user="root"))
        ok("carried root: refused", False)
    except tu.TerminalChanged:
        ok("carried root: refused", True)


def test_carried_after_restart():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()   # empty memory
    a = run(purpose="continue", m=msg(os_user="ppt"))
    ok("after an agent restart: accepted while the terminal is still ppt", a.run_as == "ppt", a)
    tu._seen.clear()
    w.uid = None
    try:
        run(purpose="continue", m=msg(os_user="ppt"))
        ok("after a restart with the terminal changed: refused", False)
    except tu.TerminalChanged:
        ok("after a restart with the terminal changed: refused", True)


def test_carried_unreachable():
    World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    run(msg())
    tu._probe_cache.clear()                       # the 5-minute probe cache expired
    tu._can_become = lambda user: False
    try:
        run(purpose="continue", m=msg(os_user="ppt"))
        ok("carried ppt but sudo to ppt now fails: refused", False)
    except tu.TerminalChanged:
        ok("carried ppt but sudo to ppt now fails: refused", True)


def test_open_without_saved_user():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    for purpose in ("continue", "cancel"):
        a = run(msg(), purpose=purpose)
        ok(f"{purpose} with no saved user: the session user, terminal not read (I-1)",
           a.run_as is None and a.name == OWN and w.asked == [], a)


def test_project_users_never_followed():
    World(uid=1500, names={1500: "orcp-0123456789ab"}, reachable={"orcp-0123456789ab"}).install()
    a = run(msg())
    ok("terminal runs as a project user: not followed (tenant folder)", a.run_as is None and not a.followed, a)
    try:
        run(purpose="continue", m=msg(os_user="orcp-0123456789ab"))
        ok("carried project user: refused", False)
    except tu.TerminalChanged:
        ok("carried project user: refused", True)


def test_cancel_after_restart():
    w = World(uid=None, names={1001: "ppt"}, reachable={"ppt"}).install()     # memory empty, terminal changed
    w.folders = {"ppt"}
    a = run(msg(os_user="ppt"), purpose="cancel")
    ok("cancel after a restart: ppt's own folder still cleaned (M-9)", a.run_as == "ppt" and a.followed, a)
    w.folders = set()
    try:
        run(msg(os_user="ppt"), purpose="cancel")
        ok("cancel: no folder owned by ppt -> refused", False)
    except tu.TerminalChanged:
        ok("cancel: no folder owned by ppt -> refused", True)
    try:
        run(msg(os_user="ppt"), purpose="continue")
        ok("but a write after a restart with the terminal changed: refused", False)
    except tu.TerminalChanged:
        ok("but a write after a restart with the terminal changed: refused", True)


def test_seen_user_skips_proc():
    w = World(uid=1001, names={1001: "ppt"}, reachable={"ppt"}).install()
    run(msg())
    w.asked.clear()
    run(purpose="continue", m=msg(os_user="ppt"))
    ok("a user already vouched for: no /proc scan on open (M-8)", w.asked == [], w.asked)


def test_helper_argv():
    a = dl.helper_argv("ppt", TC, ["stat", "--cwd", "/w"], "x", followed=True)
    ok("followed: sudo -n -u ppt -H, then the helper", a[:5] == ["sudo", "-n", "-u", "ppt", "-H"], a)
    ok("followed: the helper command", a[5:5 + len(tu.helper_cmd())] == tu.helper_cmd(), a)
    r = dl.helper_argv("orcp-0123456789ab", TC, ["stat"], "x")
    ok("restricted unchanged: the installed helper", r[5] == dl.HELPER_INSTALL_PATH, r)
    u = ul.helper_argv("ppt", TC, "ul-prepare", "/b/ppt", followed=True)
    ok("upload followed: sudo + helper + op", u[:5] == ["sudo", "-n", "-u", "ppt", "-H"] and u[-3:] == [
        "ul-prepare", "--base", "/b/ppt"], u)


def test_helper_cmd():
    cmd = tu.helper_cmd()
    if os.path.isfile(dl.HELPER_INSTALL_PATH) and os.stat(dl.HELPER_INSTALL_PATH).st_uid == 0:
        ok("installed root-owned helper preferred", cmd == [dl.HELPER_INSTALL_PATH], cmd)
    else:
        ok("no installed helper: this python, isolated, the package's helper",
           cmd == [sys.executable, "-I", dl.HELPER_SOURCE], cmd)


test_gate()
test_restricted_never_follows()
test_follows_terminal()
test_same_as_session_user()
test_root_never()
test_unknown()
test_unreachable()
test_carried_user()
test_carried_after_restart()
test_carried_unreachable()
test_open_without_saved_user()
test_project_users_never_followed()
test_cancel_after_restart()
test_seen_user_skips_proc()
test_helper_argv()
test_helper_cmd()
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
