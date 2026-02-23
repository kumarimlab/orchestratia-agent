"""tmux helpers for session discovery and screen capture."""

import subprocess


def has_tmux() -> bool:
    """Check if tmux is available on this system."""
    try:
        result = subprocess.run(["tmux", "-V"], capture_output=True, timeout=2)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def discover_tmux_sessions() -> list[str]:
    """List existing orc-* tmux sessions."""
    try:
        result = subprocess.run(
            ["tmux", "list-sessions", "-F", "#{session_name}"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return []
        return [n.strip() for n in result.stdout.strip().split("\n")
                if n.strip().startswith("orc-")]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
