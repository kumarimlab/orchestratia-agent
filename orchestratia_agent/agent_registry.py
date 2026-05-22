"""Per-agent MCP config locations + format-preserving mergers.

Single source of truth for "which file does each coding agent read its MCP
servers out of, and how do we write to it without clobbering the user's
existing entries."

Every agent we support speaks MCP — the only divergence between Claude
Code, Gemini CLI, Codex CLI, Aider, and Cursor is *where* the config lives
and *what format* it's in. This module owns both, so the rest of the daemon
can stay agent-agnostic: it picks an `AgentType` and calls `merge_config()`.

Hard contract: every writer must preserve foreign keys. We only touch the
`orchestratia` entry. User's other MCP servers, comments, and key order
survive a write where the format allows it.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger("orchestratia-agent.agent-registry")


class AgentType(str, Enum):
    CLAUDE_CODE = "claude_code"
    GEMINI_CLI = "gemini_cli"
    CODEX_CLI = "codex_cli"
    AIDER = "aider"
    CURSOR = "cursor"
    UNKNOWN = "unknown"


class WriteStatus(str, Enum):
    """Outcome reported back to the hub via PATCH /sessions/{id}/mcp-status."""

    WRITTEN = "written"             # File didn't exist; created with our entry.
    MERGED = "merged"               # File existed; upserted our entry, foreign keys preserved.
    PERMISSION_DENIED = "workspace_readonly"  # Surfaced as amber pip + PTY fallback.
    UNSUPPORTED = "unsupported"     # Agent type recognised but writer not available.
    SKIPPED = "skipped"             # No workspace dir (e.g. session never resolved cwd).


# Per-agent metadata. Keep entries small — adding an agent should be a
# one-row change here plus one writer dispatch in `_write_for_agent`.
@dataclass(frozen=True)
class AgentSpec:
    type: AgentType
    config_path: str                # Path relative to workspace root.
    fallback_user_path: str | None  # `~`-expanded; only used if workspace write fails.
    format: str                     # 'json' | 'toml' | 'yaml'
    workspace_markers: tuple[str, ...]  # Files/dirs whose presence implies this agent.
    system_prompt_file: str | None  # Where the orchestrator system prompt goes (Phase 2).


REGISTRY: dict[AgentType, AgentSpec] = {
    AgentType.CLAUDE_CODE: AgentSpec(
        type=AgentType.CLAUDE_CODE,
        config_path=".mcp.json",
        fallback_user_path=None,
        format="json",
        workspace_markers=(".mcp.json", "CLAUDE.md", ".claude"),
        system_prompt_file="CLAUDE.md",
    ),
    AgentType.GEMINI_CLI: AgentSpec(
        type=AgentType.GEMINI_CLI,
        config_path=".gemini/settings.json",
        fallback_user_path="~/.gemini/settings.json",
        format="json",
        workspace_markers=(".gemini", "GEMINI.md"),
        system_prompt_file="GEMINI.md",
    ),
    AgentType.CODEX_CLI: AgentSpec(
        type=AgentType.CODEX_CLI,
        config_path=".codex/config.toml",
        fallback_user_path="~/.codex/config.toml",
        format="toml",
        workspace_markers=(".codex", "AGENTS.md"),
        system_prompt_file="AGENTS.md",
    ),
    AgentType.AIDER: AgentSpec(
        type=AgentType.AIDER,
        config_path=".aider.conf.yml",
        fallback_user_path="~/.aider.conf.yml",
        format="yaml",
        workspace_markers=(".aider.conf.yml",),
        system_prompt_file=None,
    ),
    AgentType.CURSOR: AgentSpec(
        type=AgentType.CURSOR,
        config_path=".cursor/mcp.json",
        fallback_user_path=None,
        format="json",
        workspace_markers=(".cursor",),
        system_prompt_file=None,
    ),
}

# Workspace-marker priority for detection. Order matters: the first match wins.
# Claude Code is intentionally last because `CLAUDE.md`/`.claude` are common
# defaults projects ship even when the team also runs other tools.
_DETECTION_ORDER: tuple[AgentType, ...] = (
    AgentType.GEMINI_CLI,
    AgentType.CODEX_CLI,
    AgentType.AIDER,
    AgentType.CURSOR,
    AgentType.CLAUDE_CODE,
)


def coerce_agent_type(value: str | None) -> AgentType:
    """Permissive parse. Unknown strings (or None) → CLAUDE_CODE default."""
    if not value:
        return AgentType.CLAUDE_CODE
    try:
        return AgentType(value)
    except ValueError:
        log.warning(f"agent_registry: unknown agent_type {value!r}, falling back to claude_code")
        return AgentType.CLAUDE_CODE


def detect_from_workspace(workspace_dir: str | os.PathLike) -> AgentType | None:
    """Walk the workspace for known marker files. Returns None on no match.

    Caller decides what "no match" means — usually fall back to the daemon's
    configured default (`claude_code`).
    """
    p = Path(workspace_dir)
    if not p.is_dir():
        return None
    for agent in _DETECTION_ORDER:
        spec = REGISTRY[agent]
        for marker in spec.workspace_markers:
            if (p / marker).exists():
                log.debug(f"agent_registry: detected {agent.value} via marker {marker!r} in {p}")
                return agent
    return None


# ── Format-preserving mergers ───────────────────────────────────────


def _build_server_entry(url: str, agent: AgentType) -> dict[str, Any]:
    """Shape of the orchestratia server entry per agent.

    Claude Code's `.mcp.json` documents a `type: "http"` discriminator that
    the others don't expect — we keep it only where the spec actually
    documents it. The URL is universally understood.
    """
    if agent in (AgentType.CLAUDE_CODE, AgentType.CURSOR):
        return {"type": "http", "url": url}
    return {"url": url}


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _merge_json(path: Path, server_entry: dict[str, Any]) -> WriteStatus:
    existed = path.exists()
    doc: dict[str, Any] = {}
    if existed:
        try:
            with path.open() as f:
                content = f.read().strip()
                doc = json.loads(content) if content else {}
            if not isinstance(doc, dict):
                log.warning(f"agent_registry: {path} root is not an object; rewriting")
                doc = {}
        except (OSError, ValueError) as e:
            log.warning(f"agent_registry: {path} unreadable ({e}); writing fresh file with our entry only")
            doc = {}
    servers = doc.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {}
    servers["orchestratia"] = server_entry
    doc["mcpServers"] = servers
    _ensure_parent(path)
    with path.open("w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    return WriteStatus.MERGED if existed else WriteStatus.WRITTEN


def _merge_toml(path: Path, server_entry: dict[str, Any]) -> WriteStatus:
    # Codex stores MCP servers under `[mcp_servers.<name>]`. We use
    # `tomllib` for reading (stdlib on 3.11+) and `tomli_w` for writing.
    # `tomli_w` doesn't preserve comments — the TOML spec doesn't promise
    # round-trip, and the Codex ecosystem (today) ships config without
    # comments. If users start adding them we can swap in `tomlkit`.
    import sys
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        import tomli as tomllib  # type: ignore[import-not-found]
    import tomli_w

    existed = path.exists()
    doc: dict[str, Any] = {}
    if existed:
        try:
            with path.open("rb") as f:
                doc = tomllib.load(f)
        except (OSError, ValueError) as e:
            log.warning(f"agent_registry: {path} unreadable ({e}); writing fresh TOML with our entry only")
            doc = {}
    servers = doc.get("mcp_servers")
    if not isinstance(servers, dict):
        servers = {}
    servers["orchestratia"] = server_entry
    doc["mcp_servers"] = servers
    _ensure_parent(path)
    with path.open("wb") as f:
        tomli_w.dump(doc, f)
    return WriteStatus.MERGED if existed else WriteStatus.WRITTEN


def _merge_yaml(path: Path, server_entry: dict[str, Any]) -> WriteStatus:
    # Aider's `.aider.conf.yml` is hand-edited by users — comments and
    # key order matter. `ruamel.yaml` round-trip mode preserves both;
    # PyYAML does not.
    from ruamel.yaml import YAML
    yaml = YAML(typ="rt")  # round-trip
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)

    existed = path.exists()
    doc: Any = None
    if existed:
        try:
            with path.open() as f:
                doc = yaml.load(f)
        except Exception as e:
            log.warning(f"agent_registry: {path} unreadable ({e}); writing fresh YAML with our entry only")
            doc = None
    if not isinstance(doc, dict):
        doc = {}
    mcp = doc.get("mcp")
    if not isinstance(mcp, dict):
        mcp = {}
    mcp["orchestratia"] = server_entry
    doc["mcp"] = mcp
    _ensure_parent(path)
    with path.open("w") as f:
        yaml.dump(doc, f)
    return WriteStatus.MERGED if existed else WriteStatus.WRITTEN


_MERGERS: dict[str, Callable[[Path, dict[str, Any]], WriteStatus]] = {
    "json": _merge_json,
    "toml": _merge_toml,
    "yaml": _merge_yaml,
}


def merge_config(
    workspace_dir: str | os.PathLike,
    agent: AgentType,
    url: str,
) -> tuple[WriteStatus, Path | None]:
    """Write/merge the orchestratia MCP entry into `agent`'s config file.

    Returns `(status, path)`. `path` is None if the workspace dir doesn't
    exist (status=SKIPPED). On PermissionError, returns PERMISSION_DENIED
    with the intended path so the daemon can include it in its hub-status
    update.

    Foreign keys are always preserved — see the per-format mergers.
    """
    wd = Path(workspace_dir) if workspace_dir else None
    if not wd or not wd.is_dir():
        log.debug(f"agent_registry: skipping (not a directory): {workspace_dir!r}")
        return WriteStatus.SKIPPED, None

    if agent not in REGISTRY:
        log.warning(f"agent_registry: unsupported agent {agent!r}; falling back to claude_code")
        agent = AgentType.CLAUDE_CODE
    spec = REGISTRY[agent]
    merger = _MERGERS.get(spec.format)
    if merger is None:
        log.error(f"agent_registry: no merger for format {spec.format!r} (agent={agent.value})")
        return WriteStatus.UNSUPPORTED, None

    path = wd / spec.config_path
    server_entry = _build_server_entry(url, agent)
    try:
        status = merger(path, server_entry)
        log.info(f"agent_registry: {status.value} {path} (agent={agent.value})")
        return status, path
    except PermissionError as e:
        log.warning(f"agent_registry: permission denied writing {path} ({e}); leaving PTY fallback active")
        return WriteStatus.PERMISSION_DENIED, path
    except Exception:
        log.exception(f"agent_registry: failed to write {path} (agent={agent.value})")
        return WriteStatus.UNSUPPORTED, path


def config_path_for(workspace_dir: str | os.PathLike, agent: AgentType) -> Path:
    """Where would we write for this agent? (No I/O; useful for logs/tests.)"""
    return Path(workspace_dir) / REGISTRY[agent].config_path
