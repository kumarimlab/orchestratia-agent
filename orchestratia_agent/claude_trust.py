"""Pre-trust a working directory for Claude Code.

Claude Code records per-folder trust in ``~/.claude.json`` under
``projects[<abs_dir>].hasTrustDialogAccepted`` — set true so the "Is this a
project you trust?" dialog never appears, which a daemon-launched
(keystroke-free) session can't answer.

Only Claude Code uses this file; other agent types are a no-op here. Never
raises — a failure must not block a launch (worst case the dialog reappears,
the prior behavior).
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
    """Pre-trust ``working_dir`` in ``~/.claude.json``.

    Returns True if it wrote a change, False otherwise (non-Claude agent,
    missing/invalid dir, unreadable config, or nothing to change). ``home`` is
    injectable for testing; defaults to the launching user's home (the session
    runs as the same user, so they share ``~/.claude.json``).
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
                log.warning("claude_trust: cannot parse %s; skipping pre-trust", cfg_path)
                return False
        if not isinstance(data, dict):
            return False

        projects = data.setdefault("projects", {})
        if not isinstance(projects, dict):
            return False

        entry = projects.get(d)
        if not isinstance(entry, dict):
            entry = {}

        changed = False

        # Folder trust
        if entry.get("hasTrustDialogAccepted") is not True:
            entry["hasTrustDialogAccepted"] = True
            changed = True

        if not changed:
            return False

        projects[d] = entry

        # Atomic replace so a concurrent Claude Code write never sees a partial
        # file. (Tiny lost-update window if Claude writes between our read and
        # replace — acceptable; this fires rarely and the file stays valid JSON.)
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
        log.info("claude_trust: pre-trusted %s in %s", d, cfg_path)
        return True
    except Exception:
        log.exception("claude_trust: failed to pre-trust working dir")
        return False
