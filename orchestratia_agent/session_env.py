"""Session secret delivery — never through argv.

Passing secrets as `tmux new-session -e KEY=VALUE` puts them in the tmux
server's argv, and /proc/<pid>/cmdline is world-readable (mode 0444) on a
default Linux with no `hidepid`. Worse, a tmux server outlives the session it
was started for, so the value persists for the life of the server. That is how
a production API key sat readable by every local account on a box for 14 weeks.

Two delivery paths, because the two tiers have different constraints:

  standard   — runs as the daemon's own user. Since 0.35.0 it gets its own session token too (so the hub
               knows which session acts), in a 0600 file of the daemon user; only the PATH is in the
               environment. The server key in config.yaml stays readable to it (same user): spec §18.

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
import tempfile

log = logging.getLogger("orchestratia-agent")

ENV_VAR = "ORCHESTRATIA_KEY_FILE"


def _secret_dir() -> str:
    """Per-user directory for short-lived session secrets.

    Computed lazily, NOT at import time: os.getuid() does not exist on Windows,
    and hub.py imports this module unconditionally — evaluating it at module
    scope made the whole agent fail to import on Windows.

    tempfile.gettempdir() rather than a hardcoded /tmp so macOS and Windows get
    their own correct locations. On Linux that is tmpfs, so secrets do not
    survive a reboot, which is what we want.
    """
    uid = getattr(os, "getuid", None)
    suffix = uid() if uid else os.environ.get("USERNAME", "user")
    return os.path.join(tempfile.gettempdir(), f"orchestratia-agent-{suffix}")


def _ensure_dir() -> str:
    d = _secret_dir()
    os.makedirs(d, mode=0o711, exist_ok=True)
    # makedirs honours umask, so set the mode explicitly.
    os.chmod(d, 0o711)
    return d


def write_session_key(session_id: str, token: str, run_as: str) -> str | None:
    """Write `token` where only `run_as` can read it. Returns the path, or None.

    The file is owned by the daemon user at 0600 and extended to exactly one
    other user by ACL — not by widening the mode, which would expose it to
    every account on the box and recreate the original problem in a new shape.
    """
    if not token or not run_as:
        return None
    try:
        path = os.path.join(_ensure_dir(), f"{session_id[:12]}-{secrets.token_hex(8)}")
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


STANDARD_ENV_VAR = "ORCHESTRATIA_SESSION_TOKEN_FILE"


def write_own_session_key(session_id: str, token: str) -> str | None:
    """A STANDARD session's own token (agent 0.35.0). The session runs as the daemon's user, so the file is the
    daemon user's 0600 file in its 0711 secret directory: no ACL, nobody else can read it. Only the PATH goes into
    the session's environment (tmux -e is argv). Returns None when it can't be written."""
    if not token:
        return None
    try:
        path = os.path.join(_ensure_dir(), f"{session_id[:12]}-{secrets.token_hex(8)}")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, token.encode())
        finally:
            os.close(fd)
        return path
    except Exception:
        log.exception("Failed to write the session's token file")
        return None


def clear_session_keys_for(session_id: str) -> None:
    """Remove every key file written for this session. A daemon restart re-creates ManagedSession objects
    without their key_file, so the close path can't rely on that attribute alone."""
    d = _secret_dir()
    prefix = f"{session_id[:12]}-"
    try:
        names = os.listdir(d)
    except OSError:
        return
    for name in names:
        if name.startswith(prefix):
            clear_session_key(os.path.join(d, name))


def session_env(hub_url: str, session_id: str, tier: str, token: str | None, run_as: str):
    """(env_vars, key_file, delivered) for a new session. NO SECRET in env_vars: they become `tmux -e` argv.
      restricted -> ORCHESTRATIA_KEY_FILE, ACL'd to run_as. delivered=False when it can't be written: the
                    caller refuses the session rather than put the token in argv.
      standard   -> ORCHESTRATIA_SESSION_TOKEN_FILE, 0600 for the daemon user. A failed write still starts the
                    session (delivered=True): the CLI then uses config.yaml, exactly as before 0.35.0.
    No token (an older hub) changes nothing."""
    env = {"ORCHESTRATIA_HUB_URL": hub_url, "ORCHESTRATIA_SESSION_ID": session_id}
    if not token:
        return env, None, True
    if tier == "restricted":
        path = write_session_key(session_id, token, run_as or "")
        if not path:
            return env, None, False
        env[ENV_VAR] = path
        return env, path, True
    path = write_own_session_key(session_id, token)
    if path:
        env[STANDARD_ENV_VAR] = path
    return env, path, True
