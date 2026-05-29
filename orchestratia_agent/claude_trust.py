"""Pre-trust a working directory for Claude Code.

Claude Code records per-folder trust in ``~/.claude.json`` under
``projects[<abs_dir>].hasTrustDialogAccepted``. On first launch in an untrusted
folder it shows an interactive "Is this a project you trust?" dialog. A
daemon-launched worker runs keystroke-free with no human to answer it, so it
would hang there forever instead of reading ``task://current``.

The daemon therefore marks the working dir trusted *before* it launches the
CLI — the same shape as pre-writing ``.mcp.json`` into the workspace. Only
Claude Code uses this trust file; other agent types are a no-op here.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile

log = logging.getLogger(__name__)


def ensure_folder_trusted(
    working_dir: str | None,
    agent_type: str | None,
    home: str | None = None,
) -> bool:
    """Mark ``working_dir`` trusted in the launching user's ``~/.claude.json``.

    No-op (returns False) for non-Claude agents, a missing/invalid dir, an
    already-trusted dir, or an unparuseable config. Returns True only when it
    actually wrote a new trust entry. Never raises — a failure here must not
    block a spawn (worst case the worker shows the dialog, the prior behavior).

    ``home`` is injectable for testing; defaults to the daemon user's home
    (the worker runs as the same user, so they share ``~/.claude.json``).
    """
    try:
        from orchestratia_agent.agent_registry import AgentType, coerce_agent_type

        if coerce_agent_type(agent_type) != AgentType.CLAUDE_CODE:
            return False
        if not working_dir:
            return False
        d = os.path.abspath(working_dir)
        if not os.path.isdir(d):
            return False

        cfg_path = os.path.join(home or os.path.expanduser("~"), ".claude.json")

        data: dict = {}
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path) as f:
                    data = json.load(f)
            except (OSError, json.JSONDecodeError):
                # Never clobber a config we can't read/parse.
                log.warning("claude_trust: cannot parse %s; skipping pre-trust", cfg_path)
                return False
        if not isinstance(data, dict):
            return False

        projects = data.setdefault("projects", {})
        if not isinstance(projects, dict):
            return False

        entry = projects.get(d)
        if isinstance(entry, dict) and entry.get("hasTrustDialogAccepted") is True:
            return False  # already trusted -> no write (also avoids needless races)
        if not isinstance(entry, dict):
            entry = {}
        entry["hasTrustDialogAccepted"] = True
        projects[d] = entry

        # Atomic replace: a concurrent Claude Code write can never observe a
        # partial file. (There is a tiny lost-update window if another process
        # writes between our read and replace; acceptable — it only fires once
        # per never-before-seen working dir, and the file stays valid JSON.)
        cfg_dir = os.path.dirname(cfg_path) or "."
        fd, tmp = tempfile.mkstemp(dir=cfg_dir, prefix=".claude.json.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, cfg_path)
        finally:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
        log.info("claude_trust: marked %s trusted in %s", d, cfg_path)
        return True
    except Exception:
        log.exception("claude_trust: failed to pre-trust working dir")
        return False
