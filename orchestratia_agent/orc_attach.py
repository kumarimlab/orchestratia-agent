"""orc-attach — the editor terminal's default command.

code-server ships an integrated terminal. Left as a raw shell, work typed there
runs unrecorded and outside the privilege tiers. Instead the editor's terminal
profile defaults to this: it attaches to the PROJECT's governed tmux session,
which flows through the hub (recorded) and is already the project's restricted
user.

It runs AS the project user, so `tmux list-sessions` shows only that project's
sessions — the kernel boundary from Spec A (per-project OS users) is what makes
this safe. There is no way from here to reach another project's sessions.
"""

from __future__ import annotations

import os
import subprocess
import sys


def choose_action(session_names: list[str]):
    """Given the project's live tmux sessions, decide what to do.

    ("none", None)        — nothing running yet
    ("attach", name)      — exactly one; attach straight to it
    ("pick", names)       — several; let the human choose
    """
    names = [n for n in session_names if n]
    if not names:
        return ("none", None)
    if len(names) == 1:
        return ("attach", names[0])
    return ("pick", names)


def _list_sessions() -> list[str]:
    try:
        r = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode != 0:
            return []
        return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []


def main() -> int:
    """Entry for the editor terminal. Runs as the project user (its own tmux)."""
    action, payload = choose_action(_list_sessions())
    if action == "none":
        print("No Orchestratia session is running for this project yet.")
        print("Start one from the dashboard; it will appear here.")
        return 0
    if action == "attach":
        os.execvp("tmux", ["tmux", "attach-session", "-t", payload])
        return 0  # unreachable after execvp
    # pick
    print("Project sessions:")
    for i, name in enumerate(payload, 1):
        print(f"  {i}) {name}")
    try:
        choice = input("attach to # (or blank to cancel): ").strip()
    except EOFError:
        return 0
    if not choice:
        return 0
    try:
        name = payload[int(choice) - 1]
    except (ValueError, IndexError):
        print("no such session")
        return 1
    os.execvp("tmux", ["tmux", "attach-session", "-t", name])
    return 0


if __name__ == "__main__":
    sys.exit(main())
