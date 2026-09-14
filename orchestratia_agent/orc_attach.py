"""orc-attach — the editor terminal's default command.

code-server ships an integrated terminal. Left as a raw shell, work typed there
runs unrecorded. Instead the editor's terminal profile defaults to this picker
over the project's Orchestratia sessions:

  * standard editor (runs as the daemon user, env carries the editor session id):
    lists THIS project's terminal sessions on THIS server from the hub, and can
    create a New session through the hub — a real, recorded session credited to
    the editor's owner. Local `tmux ls` would show every project's sessions here,
    so the hub is the source of truth.
  * locked-down editor (runs as the project user via sudo, which strips the env):
    the original local behaviour — that user's own tmux sessions are exactly the
    project's (the Spec A kernel boundary).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone


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


def _legacy_main() -> int:
    """Locked-down editor: the project user's own tmux sessions."""
    action, payload = choose_action(_list_sessions())
    if action == "none":
        print("No Orchestratia session is running for this project yet.")
        print("Start one from the dashboard; it will appear here.")
        return 0
    if action == "attach":
        os.execvp("tmux", ["tmux", "attach-session", "-t", payload])
        return 0  # unreachable after execvp
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


# ── standard editor: hub-backed picker ───────────────────────────────────────

def _input(prompt: str) -> str:
    return input(prompt)


def _hub_credentials() -> tuple[str, str]:
    from orchestratia_agent.config import default_config_path, load_config
    cfg = load_config(default_config_path()) or {}
    hub_url = cfg.get("hub_url") or os.environ.get("ORCHESTRATIA_HUB_URL", "")
    return hub_url.rstrip("/"), cfg.get("api_key") or ""


def _ssl():
    from orchestratia_agent.tls import build_ssl_context
    return build_ssl_context()


def fetch_sessions(hub_url: str, api_key: str, project_id: str, *, opener=None) -> list[dict]:
    """This project's terminal sessions on this server (the key identifies the server)."""
    real = opener is None
    opener = opener or urllib.request.urlopen
    url = (f"{hub_url}/api/v1/server/sessions?project_id={project_id}"
           f"&this_server=true&kind=terminal")
    req = urllib.request.Request(url, headers={"X-API-Key": api_key})
    with opener(req, context=_ssl() if real else None, timeout=10) as r:
        return json.loads(r.read())["sessions"]


def create_session(hub_url: str, api_key: str, editor_session_id: str, cwd: str, *, opener=None) -> str:
    """Ask the hub for a new session, credited to the owner of this live editor."""
    real = opener is None
    opener = opener or urllib.request.urlopen
    req = urllib.request.Request(
        f"{hub_url}/api/v1/server/editor-sessions/{editor_session_id}/terminals",
        data=json.dumps({"working_directory": cwd}).encode(), method="POST",
        headers={"X-API-Key": api_key, "Content-Type": "application/json"})
    with opener(req, context=_ssl() if real else None, timeout=15) as r:
        return json.loads(r.read())["session_id"]


def tmux_name_for(session_id: str) -> str:
    """Same rule as session_posix.py: orc-<first 12 chars of the session id>."""
    return f"orc-{session_id[:12]}"


def _age(started_at: str | None, now: datetime) -> str:
    try:
        secs = int((now - datetime.fromisoformat(started_at)).total_seconds())
    except (TypeError, ValueError):
        return "?"
    if secs < 3600:
        return f"{max(secs // 60, 0)}m"
    if secs < 86400:
        return f"{secs // 3600}h"
    return f"{secs // 86400}d"


def menu_entries(sessions: list[dict], now: datetime) -> list[tuple[str, str | None]]:
    out = []
    for s in sessions:
        who = (s.get("created_by_email") or "?").split("@")[0]
        out.append((f"{s.get('name') or 'unnamed'} — {who} · {_age(s.get('started_at'), now)}",
                    tmux_name_for(s["id"])))
    out.append(("New session", None))
    return out


def parse_choice(text: str, n: int) -> int | None:
    text = text.strip()
    if text == "":
        return n - 1
    if text.isdigit() and 1 <= int(text) <= n:
        return int(text) - 1
    return None


def _has_tmux_session(name: str) -> bool:
    return subprocess.run(["tmux", "has-session", "-t", name], capture_output=True).returncode == 0


def wait_for_tmux(name: str, timeout: float = 20.0, poll: float = 0.5, has=None, sleep=None) -> bool:
    has, sleep = has or _has_tmux_session, sleep or time.sleep
    deadline = time.monotonic() + timeout
    while True:
        if has(name):
            return True
        if time.monotonic() >= deadline:
            return False
        sleep(poll)


def _shell(message: str) -> int:
    print(message)
    shell = os.environ.get("SHELL", "/bin/bash")
    os.execvp(shell, [shell, "-l"])
    return 0


def main() -> int:
    editor_id = os.environ.get("ORCHESTRATIA_EDITOR_SESSION_ID")
    project_id = os.environ.get("ORCHESTRATIA_PROJECT_ID")
    if not editor_id or not project_id:
        return _legacy_main()
    hub_url, api_key = _hub_credentials()
    try:
        sessions = fetch_sessions(hub_url, api_key, project_id)
    except Exception as e:  # noqa: BLE001
        return _shell(f"Could not reach Orchestratia ({e}). Opening a plain shell — it is not recorded.")
    entries = menu_entries(sessions, datetime.now(timezone.utc))
    print("Orchestratia sessions for this project:")
    for i, (label, _) in enumerate(entries, 1):
        print(f"  {i}. {label}")
    idx = None
    while idx is None:
        try:
            idx = parse_choice(_input(f"Choose [1-{len(entries)}] (Enter = New session): "), len(entries))
        except EOFError:
            return 0
    target = entries[idx][1]
    if target is None:
        try:
            sid = create_session(hub_url, api_key, editor_id, os.getcwd())
        except Exception as e:  # noqa: BLE001
            return _shell(f"Could not create a session ({e}). Opening a plain shell — it is not recorded.")
        target = tmux_name_for(sid)
        print("Starting a new session…")
        if not wait_for_tmux(target):
            return _shell("The new session did not start in time. Opening a plain shell — it is not recorded.")
    os.execvp("tmux", ["tmux", "attach-session", "-t", target])
    return 0


if __name__ == "__main__":
    sys.exit(main())
