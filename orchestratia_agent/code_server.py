"""code-server (VS Code in the browser) lifecycle — agent side.

Two tiers, one session-keyed API:
  * standard (default): one code-server process PER EDITOR SESSION, run as the
    daemon user — the same power as a normal terminal session — from the pinned
    binary the agent downloads itself (code_server_install). Settings and
    extensions persist per project; each session gets its own user-data-dir so two
    VS Code servers never contend for one.
  * restricted: one process PER PROJECT, launched as the project's restricted OS
    user via sudo (Spec A/B), shared by that project's editor sessions.

Security posture (see the Spec B and zero-touch editor design docs):
  * `--auth none` is safe ONLY because it binds 127.0.0.1 and the sole path in
    is the agent's outbound tunnel to the relay. NEVER bind a routable address.
  * the relay decides what code-server's port proxy may reach, per tier.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import time

from orchestratia_agent import code_server_install
from orchestratia_agent import privilege as p

log = logging.getLogger("orchestratia-agent.code_server")

CODE_SERVER_BIN = "code-server"

# Stop code-server after this much inactivity. Driven by USER ACTIVITY, never by
# connection presence: code-server keeps its WebSocket open forever, so a
# presence check would never fire and every host would revert to always-on.
IDLE_SECONDS = 1800

# Clock seam so the idle logic is testable without sleeping.
_clock = time.monotonic
_STATE_ROOT_OVERRIDE: str | None = None

# A "key" owns one process: standard -> the editor session id;
# restricted -> "project:<id>" (shared by that project's editor sessions).
_running: dict[str, subprocess.Popen] = {}      # key -> process
_session_key: dict[str, str] = {}               # editor session id -> key
_key_meta: dict[str, dict] = {}                 # key -> {"tier", "project_id", "udd"}
_last_activity: dict[str, float] = {}           # key -> monotonic time


class EditorStartError(Exception):
    """The editor could not be started; str(e) is shown to the user."""


def _reset_for_test() -> None:
    _running.clear()
    _session_key.clear()
    _key_meta.clear()
    _last_activity.clear()


def _key(session_id: str) -> str:
    return _session_key.get(session_id, session_id)


def note_activity(session_id: str) -> None:
    """Record real user activity (called by the relay bridge on each inbound
    browser frame). Resets the idle clock of the process serving this session."""
    _last_activity[_key(session_id)] = _clock()


def reap_idle(running: set[str]) -> list[str]:
    """Editor session ids whose process has been idle past IDLE_SECONDS. `running`
    is the set of live sessions (so a stale activity entry is not returned)."""
    now = _clock()
    idle = []
    for sid in running:
        last = _last_activity.get(_key(sid))
        if last is None or (now - last) > IDLE_SECONDS:
            idle.append(sid)
    return sorted(idle)


def cfg_dir_for(user: str, project_id: str) -> str:
    """Private code-server state, inside the home of the user it RUNS as.

    This used to be built from os.path.expanduser("~") — the DAEMON's home —
    while code-server runs as orcp-<project>. The daemon home is 0755 and owned
    by the daemon user, so code-server could not write there and started
    degraded: "Could not create socket ... code-server-ipc.sock", and an
    extensions dir it cannot populate.

    It is also an isolation boundary, not only a permissions one: a single tree
    under the daemon's home would hold every project's editor state together,
    which is exactly what the per-project users exist to prevent.
    """
    import pwd
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        home = os.path.join("/home", user)
    return os.path.join(home, ".orchestratia", "code-server", project_id[:12])


def spawn_argv(user: str, port: int, workspace: str, cfg_dir: str) -> list[str]:
    """The LOCKED-DOWN argv: code-server as the restricted `user` on loopback:`port`.

    Split out so it is testable without launching anything. Always drops
    privilege with `sudo -n -u <user> -H` (never -i: a login shell would
    re-parse a workspace path with spaces)."""
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


def spawn_argv_standard(binary: str, port: int, workspace: str, user_data_dir: str,
                        extensions_dir: str) -> list[str]:
    """The standard editor's argv: the pinned binary, as the daemon user, loopback only."""
    return [
        binary,
        "--auth", "none",
        "--bind-addr", f"127.0.0.1:{port}",
        "--disable-telemetry",
        "--disable-update-check",
        "--disable-workspace-trust",
        "--user-data-dir", user_data_dir,
        "--extensions-dir", extensions_dir,
        workspace,
    ]


def settings_json(tier: str) -> dict:
    """VS Code settings forced on every editor: the default terminal is the
    Orchestratia session picker (`orchestratia-agent orc-attach`), so terminal work
    flows through recorded sessions instead of a raw shell. Extension auto-update
    is off."""
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


def write_settings(user_data_dir: str, tier: str, saved: str | None = None) -> str:
    """Write <udd>/User/settings.json: the project's saved settings, ours forced on top."""
    data: dict = {}
    if saved and os.path.exists(saved):
        try:
            with open(saved) as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                data.update(loaded)
        except (OSError, ValueError):
            log.warning("ignoring unreadable saved editor settings at %s", saved)
    data.update(settings_json(tier))
    path = os.path.join(user_data_dir, "User", "settings.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return path


def _state_root() -> str:
    return _STATE_ROOT_OVERRIDE or os.path.expanduser("~/.local/share/orchestratia/editor")


def standard_state_dir(project_id: str) -> str:
    return os.path.join(_state_root(), project_id[:12])


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


def is_running(session_id: str) -> bool:
    proc = _running.get(_key(session_id)) if session_id in _session_key else None
    return proc is not None and proc.poll() is None


def running_sessions() -> set[str]:
    """Editor sessions whose process is live (for the idle reaper)."""
    return {sid for sid in _session_key if is_running(sid)}


def running_port(session_id: str) -> int | None:
    """The loopback port serving this editor session, or None."""
    if not is_running(session_id):
        return None
    return getattr(_running[_key(session_id)], "_orc_port", None)


# How long a spawned code-server gets to accept connections before the start fails.
STARTUP_TIMEOUT = 45.0


def check_serving(session_id: str) -> bool:
    """True once this editor's code-server accepts connections on its loopback port.

    The relay bridge and the hub's "ready" wait on this: spawning is not serving, and
    reporting ready early sent the first page load to a port nothing listened on.
    A process that has already exited raises, so a crash reaches the user as its
    reason rather than as a timeout."""
    key = _session_key.get(session_id)
    proc = _running.get(key) if key is not None else None
    if proc is None:
        raise EditorStartError("the editor is not running")
    rc = proc.poll()
    if rc is not None:
        raise EditorStartError(f"the editor exited while starting (exit code {rc})")
    try:
        with socket.create_connection(("127.0.0.1", proc._orc_port), timeout=0.5):
            return True
    except OSError:
        return False


def start(session_id: str, project_id: str, workspace: str, tier: str, tc, *, hub_url: str = "") -> int:
    """Start (or, for the restricted tier, reuse) code-server for an editor session.
    Returns the loopback port."""
    if tier == "standard":
        return _start_standard(session_id, project_id, workspace, hub_url)
    return _start_restricted(session_id, project_id, workspace, tc)


def _start_standard(session_id: str, project_id: str, workspace: str, hub_url: str) -> int:
    folder = os.path.expanduser(workspace or "~")
    if not os.path.isdir(folder):
        raise EditorStartError(f"folder {folder} does not exist on this server")
    if not code_server_install.installed():
        raise EditorStartError("the editor is not installed on this server yet")
    state = standard_state_dir(project_id)
    ext = os.path.join(state, "ext")
    udd = os.path.join(state, "sessions", session_id[:12])
    os.makedirs(ext, exist_ok=True)
    write_settings(udd, "standard", saved=os.path.join(state, "settings.json"))
    port = _free_loopback_port()
    env = dict(os.environ)
    env.update({
        "ORCHESTRATIA_EDITOR_SESSION_ID": session_id,
        "ORCHESTRATIA_PROJECT_ID": project_id,
        "ORCHESTRATIA_HUB_URL": hub_url,
    })
    argv = spawn_argv_standard(code_server_install.binary_path(), port, folder, udd, ext)
    # start_new_session so stop() can signal the whole process group.
    proc = subprocess.Popen(argv, start_new_session=True, env=env)
    proc._orc_port = port   # type: ignore[attr-defined]
    _running[session_id] = proc
    _session_key[session_id] = session_id
    _key_meta[session_id] = {"tier": "standard", "project_id": project_id, "udd": udd}
    _last_activity[session_id] = _clock()   # so a just-started editor is not instantly reaped
    log.info("code-server started for session %s (standard) on 127.0.0.1:%d", session_id[:8], port)
    return port


def _start_restricted(session_id: str, project_id: str, workspace: str, tc) -> int:
    key = f"project:{project_id}"
    proc = _running.get(key)
    if proc is not None and proc.poll() is None:
        _session_key[session_id] = key
        _last_activity[key] = _clock()
        return proc._orc_port   # type: ignore[attr-defined]

    user = p.resolve_user("restricted", project_id, tc)   # raises if unprovisioned
    cwd = p.verify_workspace("restricted", workspace, project_id, tc)
    port = _free_loopback_port()
    # The cfg dir is deliberately NOT created here: the daemon cannot write into the
    # restricted user's home, and widening the tier sudoers rule for a mkdir would
    # trade a real boundary for a convenience. code-server creates it as itself.
    argv = spawn_argv(user, port, cwd, cfg_dir_for(user, project_id))
    proc = subprocess.Popen(argv, start_new_session=True)
    proc._orc_port = port   # type: ignore[attr-defined]
    _running[key] = proc
    _session_key[session_id] = key
    _key_meta[key] = {"tier": "restricted", "project_id": project_id, "udd": None}
    _last_activity[key] = _clock()
    log.info("code-server started for project %s as %s on 127.0.0.1:%d", project_id[:12], user, port)
    return port


def stop(session_id: str) -> None:
    """End an editor session. Stops its process once no other session uses it.

    Signals ONLY that process group — never `pkill -u <user>`, which would also
    kill tmux sessions running as the same user. For the standard tier the
    session's settings are saved back to the project before its dir is removed."""
    key = _session_key.pop(session_id, None)
    if key is None or key in _session_key.values():
        return
    proc = _running.pop(key, None)
    meta = _key_meta.pop(key, {})
    _last_activity.pop(key, None)
    if proc is not None and proc.poll() is None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    udd = meta.get("udd")
    if meta.get("tier") == "standard" and udd:
        src = os.path.join(udd, "User", "settings.json")
        dst = os.path.join(standard_state_dir(meta["project_id"]), "settings.json")
        try:
            if os.path.exists(src):
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(src, dst)
        except OSError:
            log.warning("could not save editor settings for session %s", session_id[:8])
        finally:
            shutil.rmtree(udd, ignore_errors=True)
    log.info("code-server stopped for %s", key if key.startswith("project:") else f"session {key[:8]}")
