"""One-shot workspace scan that ensures every configured repo has an MCP
config pointing at this daemon.

Why this exists: a user may have started `claude` (or `gemini`, or `codex`)
in a tmux *before* installing our daemon. Our `session_start` handler
never fires for that PTY, so the workspace's config file is never written
and the agent runs without our MCP integration. This module walks the
daemon's configured repos at startup and writes the appropriate file for
each one — making the MCP wiring live next time the agent restarts.

Idempotent: running it twice writes identical content. Safe to re-run on
SIGHUP or daemon restart.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from orchestratia_agent.agent_registry import (
    AgentType,
    WriteStatus,
    detect_from_workspace,
    merge_config,
)

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent.workspace-scan")


def _repo_paths(config: dict) -> list[tuple[str, str]]:
    """Yield (repo_name, absolute_path) for every entry in config['repos'].

    `repos` accepts both `{name: "path"}` and `{name: {path: "..."}}` shapes,
    matching system.get_repos_info — kept consistent here.
    """
    out: list[tuple[str, str]] = []
    for name, repo_config in (config.get("repos") or {}).items():
        path = repo_config.get("path", "") if isinstance(repo_config, dict) else repo_config
        if not path:
            continue
        out.append((name, os.path.expanduser(str(path))))
    return out


def _agent_for(workspace_dir: str, default: AgentType) -> AgentType:
    """Pick the agent type for a workspace.

    Priority: explicit workspace markers (e.g. `.gemini/`) → daemon default.
    No hub round-trip — this runs before sessions exist for these dirs.
    """
    detected = detect_from_workspace(workspace_dir)
    return detected or default


def _default_agent_from_config(config: dict) -> AgentType:
    """Daemon-wide default for repos that don't reveal their agent via markers.

    Today the daemon only configures `claude.binary`; future agent binaries
    (e.g. `gemini.binary`) can hint via the same `<agent>.binary` convention.
    """
    # Configured-binary fallbacks: presence of `<agent>.binary` in config
    # implies the user has that agent set up. Iterates in spec priority order
    # so a config block with both gemini and codex doesn't accidentally pick
    # Claude (which is the global default).
    for key, agent in (
        ("gemini", AgentType.GEMINI_CLI),
        ("codex", AgentType.CODEX_CLI),
        ("aider", AgentType.AIDER),
        ("cursor", AgentType.CURSOR),
        ("claude", AgentType.CLAUDE_CODE),
    ):
        block = config.get(key)
        if isinstance(block, dict) and block.get("binary"):
            return agent
    return AgentType.CLAUDE_CODE


def scan_and_write(state: "DaemonState") -> dict[str, int]:
    """Walk every configured repo, write/merge the MCP config for its agent.

    Returns a per-agent-type tally for logging. Safe to call repeatedly —
    writes are idempotent and merge-aware (won't clobber unrelated keys).
    """
    if not state.mcp_enabled:
        log.debug("workspace-scan: skipping (MCP disabled in config)")
        return {}

    repos = _repo_paths(state.config)
    if not repos:
        log.debug("workspace-scan: no repos configured; nothing to do")
        return {}

    default_agent = _default_agent_from_config(state.config)

    # Phase 1.5 uses a synthetic, no-session URL so the workspace config is
    # *present* even before any session is created. When a session is later
    # spawned in this workspace, hub.py session_start rewrites the same file
    # with the actual per-session URL via the registry's merge logic — same
    # foreign-key-preserving path. The probe URL lets the user (or their
    # agent) discover us quickly without waiting for a hub-issued session.
    probe_url = f"http://127.0.0.1:{state.mcp_port}/mcp/sessions/probe/mcp"

    tally: dict[str, int] = {}
    for name, path in repos:
        if not os.path.isdir(path):
            log.debug(f"workspace-scan: repo {name!r} path {path!r} is not a directory; skipping")
            continue
        agent = _agent_for(path, default_agent)
        status, written_path = merge_config(path, agent, probe_url)
        key = f"{agent.value}={status.value}"
        tally[key] = tally.get(key, 0) + 1
        if status in (WriteStatus.WRITTEN, WriteStatus.MERGED):
            log.info(f"workspace-scan: {status.value} {written_path} (repo={name}, agent={agent.value})")
        elif status == WriteStatus.PERMISSION_DENIED:
            log.warning(f"workspace-scan: read-only workspace {path!r} (repo={name}); PTY fallback active")
        else:
            log.warning(f"workspace-scan: {status.value} for {path!r} (repo={name}, agent={agent.value})")
    summary = ", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "(no writeable repos)"
    log.info(f"workspace-scan complete: {summary}")
    return tally
