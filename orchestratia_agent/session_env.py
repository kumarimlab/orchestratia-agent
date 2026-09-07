"""Session secret delivery — never through argv.

Passing secrets as `tmux new-session -e KEY=VALUE` puts them in the tmux
server's argv, and /proc/<pid>/cmdline is world-readable (mode 0444) on a
default Linux with no `hidepid`. Worse, a tmux server outlives the session it
was started for, so the value persists for the life of the server. That is how
a production API key sat readable by every local account on a box for 14 weeks.

Two delivery paths, because the two tiers have different constraints:

  standard   — runs as the daemon's own user, which can already read
               config.yaml (0600, same owner). Deliver NOTHING; the CLI reads
               the config. This is the common case and needs no machinery.

  restricted — runs as a different user that cannot read config.yaml, so it
               genuinely needs its scoped token delivered. Written to a 0600
               file readable by that user via a POSIX ACL, with only the PATH
               passed in argv. A path is not a secret.
"""

from __future__ import annotations

import logging
import os
import secrets
import subprocess

log = logging.getLogger("orchestratia-agent")

# tmpfs-backed and cleared on reboot, which is right for short-lived secrets.
# 0711: traversable so the target user can reach a known path, not listable so
# filenames cannot be enumerated. Filenames are random regardless.
SECRET_DIR = os.path.join("/tmp", f"orchestratia-agent-{os.getuid()}")

ENV_VAR = "ORCHESTRATIA_KEY_FILE"


def _ensure_dir() -> str:
    os.makedirs(SECRET_DIR, mode=0o711, exist_ok=True)
    # makedirs honours umask, so set the mode explicitly.
    os.chmod(SECRET_DIR, 0o711)
    return SECRET_DIR


def write_session_key(session_id: str, token: str, run_as: str) -> str | None:
    """Write `token` where only `run_as` can read it. Returns the path, or None.

    The file is owned by the daemon user at 0600 and extended to exactly one
    other user by ACL — not by widening the mode, which would expose it to
    every account on the box and recreate the original problem in a new shape.
    """
    if not token or not run_as:
        return None
    try:
        _ensure_dir()
        path = os.path.join(SECRET_DIR, f"{session_id[:12]}-{secrets.token_hex(8)}")
        # Create 0600 from the outset — never write then chmod, or the content
        # is briefly readable at whatever the umask happens to be.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, token.encode())
        finally:
            os.close(fd)

        result = subprocess.run(
            ["setfacl", "-m", f"u:{run_as}:r", path],
            capture_output=True, timeout=5,
        )
        if result.returncode != 0:
            # Fail closed: a file the session cannot read is useless, and
            # leaving it on disk is exposure that buys nothing.
            os.unlink(path)
            log.error(
                f"Could not grant {run_as} read access to the session key: "
                f"{result.stderr.decode(errors='replace').strip()}"
            )
            return None
        return path
    except Exception:
        log.exception("Failed to write session key file")
        return None


def clear_session_key(path: str | None) -> None:
    """Remove a key file. Safe with None or an already-removed path."""
    if not path:
        return
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except Exception:
        log.exception(f"Failed to remove session key file {path}")


def read_key_file(path: str | None) -> str:
    """Read a key written by write_session_key. Empty string if unavailable."""
    if not path:
        return ""
    try:
        with open(path) as fh:
            return fh.read().strip()
    except Exception:
        return ""
