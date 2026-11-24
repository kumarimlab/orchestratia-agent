#!/usr/bin/env python3
"""Who is actually at the terminal, read from fake /proc trees.

Run:  python3 tests/test_terminal_user.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import terminal_user as tu  # noqa: E402

results = []
UBUNTU, PPT, ROOT = 1000, 1001, 0
TTY_A, TTY_B, TTY_C = 34816, 34817, 34818        # /dev/pts/0, 1, 2


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def fake_proc(procs):
    """procs: (pid, comm, ppid, sid, tty, tpgid, uids) — uids a 4-tuple or one int."""
    root = tempfile.mkdtemp(prefix="fakeproc-")
    for pid, comm, ppid, sid, tty, tpgid, uids in procs:
        if isinstance(uids, int):
            uids = (uids,) * 4
        d = os.path.join(root, str(pid))
        os.mkdir(d)
        with open(os.path.join(d, "stat"), "w") as fh:
            fh.write(f"{pid} ({comm}) S {ppid} {pid} {sid} {tty} {tpgid} 4194560 0 0 0 0 0 0\n")
        with open(os.path.join(d, "status"), "w") as fh:
            fh.write(f"Name:\t{comm}\nUid:\t{uids[0]}\t{uids[1]}\t{uids[2]}\t{uids[3]}\nGid:\t0\t0\t0\t0\n")
    os.mkdir(os.path.join(root, "self"))          # non-numeric entries are ignored
    return root


def uid_of(procs, pane_pid=100):
    return tu.foreground_uid(pane_pid, tu.snapshot(fake_proc(procs)))


def test_plain_shell():
    ok("idle shell: the shell's user",
       uid_of([(100, "bash", 1, 100, TTY_A, 100, UBUNTU)]) == UBUNTU)


def test_foreground_program():
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "codex", 100, 100, TTY_A, 200, UBUNTU)]
    ok("program in the foreground: its user", uid_of(procs) == UBUNTU)


def test_sudo_use_pty():
    # bash(ubuntu) -> sudo (ruid ubuntu, euid root; fg on pts/0) -> sudo monitor (root, session
    # leader of pts/1) -> bash as ppt -> codex as ppt (fg on pts/1)
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "sudo", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)),
             (201, "sudo", 200, 201, TTY_B, 300, ROOT),
             (202, "bash", 201, 201, TTY_B, 300, PPT),
             (300, "codex", 202, 201, TTY_B, 300, PPT)]
    ok("sudo -iu ppt (use_pty): followed into the nested terminal → ppt", uid_of(procs) == PPT,
       uid_of(procs))


def test_sudo_without_pty():
    # sudo stays in the foreground, its one child runs as ppt on the same terminal
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "sudo", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)),
             (202, "bash", 200, 100, TTY_A, 200, PPT)]
    ok("sudo without a pty: its single child → ppt", uid_of(procs) == PPT, uid_of(procs))


def test_su():
    # su's parent keeps root while it waits; the user's shell took the foreground
    procs = [(100, "bash", 1, 100, TTY_A, 202, UBUNTU),
             (200, "su", 100, 100, TTY_A, 202, ROOT),
             (202, "bash", 200, 100, TTY_A, 202, PPT)]
    ok("su - ppt: the foreground shell → ppt", uid_of(procs) == PPT)


def test_root_shell():
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "sudo", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)),
             (201, "sudo", 200, 201, TTY_B, 202, ROOT),
             (202, "bash", 201, 201, TTY_B, 202, ROOT)]
    ok("sudo -i: uid 0 (the caller refuses it)", uid_of(procs) == 0)
    ok("user_for_uid never names root", tu.user_for_uid(0) is None)


def test_setuid_foreground():
    # passwd waiting for input: ruid ubuntu, euid root, no child — never treated as a user
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "passwd", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT))]
    ok("setuid program in the foreground: unknown", uid_of(procs) is None, uid_of(procs))


def test_ambiguous():
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "sudo", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)),
             (201, "x", 200, 201, TTY_B, 201, PPT),
             (202, "y", 200, 202, TTY_C, 202, PPT)]
    ok("two nested terminals: unknown", uid_of(procs) is None)
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU),
             (200, "sudo", 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)),
             (201, "a", 200, 100, TTY_A, 200, PPT),
             (202, "b", 200, 100, TTY_A, 200, PPT)]
    ok("two children, no nested terminal: unknown", uid_of(procs) is None)


def test_loop_is_bounded():
    # each sudo's one child is another sudo: depth runs out instead of looping
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU)]
    for i in range(20):
        procs.append((200 + i, "sudo", 199 + i if i else 100, 100, TTY_A, 200, (UBUNTU, ROOT, ROOT, ROOT)))
    ok("a chain longer than the depth limit: unknown", uid_of(procs) is None)


def test_missing_and_odd():
    ok("pane pid gone: unknown", uid_of([(100, "bash", 1, 100, TTY_A, 100, UBUNTU)], pane_pid=999) is None)
    procs = [(100, "bash", 1, 100, TTY_A, 200, UBUNTU)]
    ok("foreground leader exited: the pane's own process", uid_of(procs) == UBUNTU)
    procs = [(100, "we) ird (x", 1, 100, TTY_A, 100, PPT)]
    ok("a comm containing ') (' still parses", uid_of(procs) == PPT)
    ok("no /proc (macOS): empty snapshot", tu.snapshot("/nonexistent-proc-root") == {})
    ok("unknown pane: unknown", tu.foreground_uid(100, {}) is None)


def test_login_users_only():
    defs = os.path.join(tempfile.mkdtemp(), "login.defs")
    with open(defs, "w") as fh:
        fh.write("# comment\nUID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n")
    ok("login.defs range read", tu.login_uid_range(defs) == (1000, 60000), tu.login_uid_range(defs))
    ok("login.defs missing: 1000..60000", tu.login_uid_range("/nonexistent") == (1000, 60000))
    ok("a system account (uid 1) is never named", tu.user_for_uid(1) is None)
    ok("nobody (65534) is never named", tu.user_for_uid(65534) is None)
    me = os.getuid()
    if 1000 <= me <= 60000:
        import pwd
        ok("a login user is named", tu.user_for_uid(me) == pwd.getpwuid(me).pw_name)
    import pwd as _pwd
    real = _pwd.getpwnam
    try:                                   # a name that maps back to a different uid (duplicate / NSS shadow)
        _pwd.getpwnam = lambda n: type("P", (), {"pw_uid": 4242})()
        ok("uid -> name -> uid must round-trip", tu.user_for_uid(me) is None)
    finally:
        _pwd.getpwnam = real


def test_pane_start():
    snap = tu.snapshot(fake_proc([(100, "bash", 1, 100, TTY_A, 100, PPT)]))
    ok("live pane on its own terminal: its pid", tu.pane_start(100, TTY_A, False, snap) == 100)
    ok("dead pane (remain-on-exit): refused", tu.pane_start(100, TTY_A, True, snap) is None)
    ok("pid now on another terminal (reused): refused", tu.pane_start(100, TTY_B, False, snap) is None)
    ok("pid gone: refused", tu.pane_start(101, TTY_A, False, snap) is None)
    ok("no terminal known: refused", tu.pane_start(100, None, False, snap) is None)


def test_live_self():
    # against the real /proc: this test process's own uid
    if not os.path.isdir("/proc/self"):
        ok("live /proc skipped (none here)", True)
        return
    ok("live: this process resolves to its own uid",
       tu.foreground_uid(os.getpid(), tu.snapshot()) in (os.getuid(), None))


test_plain_shell()
test_foreground_program()
test_sudo_use_pty()
test_sudo_without_pty()
test_su()
test_root_shell()
test_setuid_foreground()
test_ambiguous()
test_loop_is_bounded()
test_missing_and_odd()
test_login_users_only()
test_pane_start()
test_live_self()
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
