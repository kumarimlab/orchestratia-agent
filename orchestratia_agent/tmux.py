"""tmux helpers for session discovery and screen capture."""

import subprocess


def has_tmux() -> bool:
    """Check if tmux is available on this system."""
    try:
        result = subprocess.run(["tmux", "-V"], capture_output=True, timeout=2)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def discover_tmux_sessions(run_as: str | None = None) -> list[str]:
    """List existing orc-* tmux sessions, optionally on another user's tmux server.

    A tmux server is per-user. A restricted session's sessions are invisible to
    the daemon's own `tmux list-sessions`, so recovery has to ask each user
    we may have spawned as — otherwise those sessions are abandoned (and
    reported dead) on every daemon restart while they keep running.
    """
    argv = ["tmux", "list-sessions", "-F", "#{session_name}"]
    if run_as is not None:
        argv = ["sudo", "-n", "-u", run_as, "-H"] + argv
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return []
        return [n.strip() for n in result.stdout.strip().split("\n")
                if n.strip().startswith("orc-")]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
