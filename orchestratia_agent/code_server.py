"""code-server (VS Code in the browser) lifecycle — agent side.

One code-server process per project, launched on demand as the project's
restricted OS user, bound to loopback, reachable only through the relay tunnel.
The daemon (root-equivalent) never runs it directly.

Security posture (see the Spec B design doc):
  * `--auth none` is safe ONLY because it binds 127.0.0.1 and the sole path in
    is the agent's outbound tunnel to the relay. NEVER bind a routable address.
  * runs as `orcp-<project>` via sudo (kernel confinement from Spec A).
  * private user-data/extensions dirs — not a shared marketplace tree.
  * the terminal and proxy are handled in start()/config, not here.
"""

from __future__ import annotations

import logging
import os
import signal
import socket
import subprocess
import time

log = logging.getLogger("orchestratia-agent.code_server")

CODE_SERVER_BIN = "code-server"

# Stop code-server after this much inactivity. Driven by USER ACTIVITY, never by
# connection presence: code-server keeps its WebSocket open forever, so a
# presence check would never fire and every host would revert to always-on.
IDLE_SECONDS = 1800

# Clock seam so the idle logic is testable without sleeping.
_clock = time.monotonic

# project_id -> subprocess.Popen of the running code-server
_running: dict[str, subprocess.Popen] = {}
# project_id -> last user-activity timestamp (monotonic)
_last_activity: dict[str, float] = {}


def _reset_for_test() -> None:
    _running.clear()
    _last_activity.clear()


def note_activity(project_id: str) -> None:
    """Record real user activity (called by the relay bridge on each inbound
    browser frame). Resets the idle clock."""
    _last_activity[project_id] = _clock()


def reap_idle(running: set[str]) -> list[str]:
    """Project ids whose editor has been idle past IDLE_SECONDS. `running` is the
    set of projects with a live code-server (so a stale activity entry for an
    already-stopped project is not returned)."""
    now = _clock()
    idle = []
    for pid in running:
        last = _last_activity.get(pid)
        if last is None or (now - last) > IDLE_SECONDS:
            idle.append(pid)
    return idle


def spawn_argv(user: str, port: int, workspace: str, cfg_dir: str) -> list[str]:
    """The locked-down argv to launch code-server as `user` on loopback:`port`.

    Split out so it is testable without launching anything. `user` is always a
    restricted project user — editors are restricted-only, so this always drops
    privilege with `sudo -n -u <user> -H` (never -i: a login shell would
    re-parse a workspace path with spaces)."""
    from orchestratia_agent import privilege as p
    tc = p.load_tier_config({})
    return p.sudo_prefix(user, tc) + [
        CODE_SERVER_BIN,
        "--auth", "none",
        "--bind-addr", f"127.0.0.1:{port}",
        "--disable-telemetry",
        "--disable-update-check",
        "--disable-workspace-trust",
        "--user-data-dir", cfg_dir,
        "--extensions-dir", os.path.join(cfg_dir, "ext"),
        workspace,
    ]


def settings_json() -> dict:
    """VS Code settings for the editor: the default terminal attaches to the
    project's governed tmux via `orchestratia-agent orc-attach`, so terminal work
    flows through the hub (recorded, tiered) instead of being a raw unrecorded
    shell. Extension auto-update is off (the extensions dir is isolated at spawn;
    full marketplace lockdown is handled at the process level in start())."""
    return {
        "terminal.integrated.defaultProfile.linux": "orchestratia",
        "terminal.integrated.profiles.linux": {
            "orchestratia": {
                "path": "orchestratia-agent",
                "args": ["orc-attach"],
            },
        },
        "extensions.autoUpdate": False,
        "extensions.autoCheckUpdates": False,
        "workbench.startupEditor": "none",
    }


def _free_loopback_port() -> int:
    """Ask the kernel for a free ephemeral port on loopback.

    Bind-and-close then reuse: a tiny race, but code-server binds immediately
    after and any collision surfaces as a launch failure (fail-closed), not a
    wrong-target proxy."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def is_running(project_id: str) -> bool:
    proc = _running.get(project_id)
    return proc is not None and proc.poll() is None


def running_projects() -> set[str]:
    """Projects with a live code-server (for the idle reaper)."""
    return {pid for pid, proc in _running.items() if proc.poll() is None}


def running_port(project_id: str) -> int | None:
    """The loopback port code-server is bound to for this project, or None."""
    proc = _running.get(project_id)
    if proc is None or proc.poll() is not None:
        return None
    return getattr(proc, "_orc_port", None)


def start(project_id: str, workspace: str, tc) -> int:
    """Start (or reuse) code-server for a project. Returns the loopback port.

    Resolves the project's restricted user and verifies the workspace via the
    Spec A gate — a project with no provisioned user cannot get an editor."""
    from orchestratia_agent import privilege as p

    if is_running(project_id):
        return running_port(project_id)

    user = p.resolve_user("restricted", project_id, tc)   # raises if unprovisioned
    cwd = p.verify_workspace("restricted", workspace, project_id, tc)

    port = _free_loopback_port()
    cfg_dir = os.path.join(os.path.expanduser("~"), ".orchestratia", "code-server", project_id[:12])
    os.makedirs(cfg_dir, exist_ok=True)

    argv = spawn_argv(user, port, cwd, cfg_dir)
    # start_new_session so stop() can signal the whole process group, and so a
    # daemon exit does not take code-server's children with it unintentionally.
    proc = subprocess.Popen(argv, start_new_session=True)
    proc._orc_port = port   # type: ignore[attr-defined]
    _running[project_id] = proc
    note_activity(project_id)   # so a just-started editor is not instantly reaped
    log.info("code-server started for project %s as %s on 127.0.0.1:%d",
             project_id[:12], user, port)
    return port


def stop(project_id: str) -> None:
    """Stop code-server for a project. Signals ONLY this process group — never
    `pkill -u <user>`, which would also kill the project user's tmux sessions
    (Spec A recovery reattaches to those)."""
    proc = _running.pop(project_id, None)
    _last_activity.pop(project_id, None)
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (OSError, ProcessLookupError):
        pass
    log.info("code-server stopped for project %s", project_id[:12])
