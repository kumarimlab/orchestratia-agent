"""Pre-trust a working directory + pre-approve our MCP server for Claude Code.

Claude Code records two per-folder things in ``~/.claude.json`` under
``projects[<abs_dir>]``:

* ``hasTrustDialogAccepted`` — set true so the "Is this a project you trust?"
  dialog never appears.
* ``enabledMcpjsonServers`` — the list of project-scoped (``.mcp.json``) MCP
  servers the user has approved. Adding ``orchestratia`` here suppresses the
  "New MCP server found: orchestratia — Use / Use all / Continue without"
  prompt, which a daemon-launched (keystroke-free) session can't answer.

The daemon writes ``.mcp.json`` into the workspace itself, so pre-approving it
is the natural companion. Only Claude Code uses this file; other agent types
are a no-op here. Never raises — a failure must not block a launch (worst case
the prompt reappears, the prior behavior).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile

log = logging.getLogger(__name__)

MCP_SERVER_NAME = "orchestratia"


def ensure_folder_trusted(
    working_dir: str | None,
    agent_type: str | None,
    home: str | None = None,
    mcp_server_name: str = MCP_SERVER_NAME,
) -> bool:
    """Pre-trust ``working_dir`` and pre-approve our MCP server in ``~/.claude.json``.

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

        # 1) Folder trust
        if entry.get("hasTrustDialogAccepted") is not True:
            entry["hasTrustDialogAccepted"] = True
            changed = True

        # 2) Approve our project-scoped MCP server
        enabled = entry.get("enabledMcpjsonServers")
        if not isinstance(enabled, list):
            enabled = []
        if mcp_server_name not in enabled:
            enabled.append(mcp_server_name)
            entry["enabledMcpjsonServers"] = enabled
            changed = True
        # ...and make sure it isn't simultaneously disabled
        disabled = entry.get("disabledMcpjsonServers")
        if isinstance(disabled, list) and mcp_server_name in disabled:
            entry["disabledMcpjsonServers"] = [s for s in disabled if s != mcp_server_name]
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
        log.info(
            "claude_trust: pre-trusted %s + approved MCP '%s' in %s",
            d, mcp_server_name, cfg_path,
        )
        return True
    except Exception:
        log.exception("claude_trust: failed to pre-trust working dir")
        return False
