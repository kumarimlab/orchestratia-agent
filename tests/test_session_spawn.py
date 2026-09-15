#!/usr/bin/env python3
"""A locked-down session starts in its workspace as the project user, not the daemon.

The spawn child did os.chdir(workspace) as the DAEMON user before exec'ing
`sudo -u <project user> tmux`. provision-tier removes 'other' access from every
workspace, so a workspace the daemon user does not own (root-owned is common:
`sudo mkdir /srv/acme`) refused the chdir and every locked-down session died on spawn
with exit code 1 and no reason shown. Found on staging, 2026-09-14.

Dependency-free — run directly:  python3 tests/test_session_spawn.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import session_posix as sp  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def test_daemon_session_still_starts_in_its_folder():
    ok("the daemon's own session chdirs into the folder",
       sp.spawn_start_dir(None, "/srv/a") == ("/srv/a", []), sp.spawn_start_dir(None, "/srv/a"))


def test_locked_down_session_lets_tmux_enter_the_folder_as_the_project_user():
    chdir, args = sp.spawn_start_dir("orcp-aaaaaaaaaaaa", "/srv/a")
    ok("the daemon does not enter a workspace it may not be able to read", chdir == "/", chdir)
    ok("tmux starts the session in the folder, as the project user", args == ["-c", "/srv/a"], args)


def main():
    for case in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        case()
    if not results or not all(results):
        print(f"FAIL  {results.count(False)} of {len(results)} failed")
        raise SystemExit(1)
    print(f"ok  {len(results)} passed")


if __name__ == "__main__":
    main()
