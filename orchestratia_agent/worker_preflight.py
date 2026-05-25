"""Worker-readiness preflight probe (Phase 2.5, plan §8.5.3).

The orchestrator is blind before a worker's MCP client connects — it cannot
answer trust/auth/login dialogs a fresh CLI might raise. So instead of having
the orchestrator cope at spawn time, we certify each server *worker-ready per
agent_type at provisioning time* and let `spawn_worker` only target ready
servers. The result lives on `servers.worker_ready` and is refreshed on the
daemon's heartbeat.

Readiness vocabulary (the hub's gate keys off the prefix):
    "ready"                     — eligible for spawn.
    "installed"                 — binary present, auth not yet verified.
                                  Treated as allowed (optimistic) by the hub.
    "not_installed: <hint>"     — binary missing on PATH. Hard block.
    "needs_auth: <hint>"        — present but not logged in / no key. Block.
    "blocked: <reason>"         — present but failed to reach live-MCP. Block.

This module currently implements the **deterministic tier**: binary presence
on the same login-shell PATH the worker spawn uses (`bash -lc`). The
**launch-based tier** — spawn the CLI in a throwaway dir and confirm its MCP
client connects within N seconds, upgrading "installed" → "ready" or
classifying "needs_auth"/"blocked" — slots into `_probe_runtime`; it needs
live per-CLI iteration (first-run trust dialogs, connection timing) before it
can be trusted, so it is intentionally not enabled yet.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent.preflight")

# agent_type → CLI binary. Mirrors the hub's _AGENT_CLI; kept here so the
# daemon can probe without a hub round trip.
PROBE_CLIS: dict[str, str] = {
    "claude_code": "claude",
    "gemini_cli": "gemini",
    "codex_cli": "codex",
    "aider": "aider",
    "cursor": "cursor-agent",
}

# Seconds to wait for a CLI's MCP client to connect during the launch tier.
_RUNTIME_PROBE_TIMEOUT = 25.0


class WorkerPreflight:
    """Probes which agent CLIs this server can launch as autonomous workers."""

    def __init__(self, state: "DaemonState"):
        self.state = state
        # agent_type → readiness string. Empty until the first probe runs.
        self.results: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def probe_all(self) -> dict[str, str]:
        """(Re)probe every known agent_type. Cached on self.results and on
        state.worker_ready so the heartbeat carries the latest snapshot."""
        async with self._lock:
            results: dict[str, str] = {}
            for agent_type, cli in PROBE_CLIS.items():
                results[agent_type] = await self._probe_one(agent_type, cli)
            self.results = results
            self.state.worker_ready = dict(results)
            ready = [a for a, r in results.items() if r in ("ready", "installed")]
            log.info(f"preflight: worker-ready agents: {ready or 'none'}")
            return results

    async def _probe_one(self, agent_type: str, cli: str) -> str:
        """Classify a single agent_type's readiness on this server."""
        if not await self._binary_present(cli):
            return f"not_installed: `{cli}` not found on PATH — install it on this server"
        # Deterministic tier can confirm presence but not auth. The launch
        # tier (when enabled) upgrades this to "ready" or "needs_auth".
        runtime = await self._probe_runtime(agent_type, cli)
        return runtime or "installed"

    async def _binary_present(self, cli: str) -> bool:
        """True if `cli` resolves on the same login-shell PATH a worker spawn
        uses (`bash -l` sources the user profile, matching session_posix)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "bash", "-lc", f"command -v {shlex.quote(cli)}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                rc = await asyncio.wait_for(proc.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                proc.kill()
                return False
            return rc == 0
        except Exception:
            log.exception(f"preflight: binary-presence check for {cli!r} failed")
            return False

    async def _probe_runtime(self, agent_type: str, cli: str) -> str | None:
        """Launch tier — confirm the CLI boots to a live-MCP state.

        Not yet implemented (returns None → caller falls back to
        "installed"). Will launch `cli` as a root process in a throwaway dir
        with an MCP config pointing at a probe session, watch the MCP
        dispatch for that session id within _RUNTIME_PROBE_TIMEOUT, and
        return "ready" / "needs_auth: …" / "blocked: …". Deferred until it can
        be validated against each real CLI (first-run trust dialogs etc.).
        """
        return None
