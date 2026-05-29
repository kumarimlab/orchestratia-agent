"""Governance routing on the daemon side — Phase 2.

Two concerns live together because they share state (pending request
map + orchestrator pointer cache):

  WORKER side — runs in every daemon:
    * Loopback HTTP endpoint `POST /governance/evaluate` consumed by the
      PreToolUse hook on rule-cache miss. Sends a
      `governance_decision_request` over the hub WS and blocks until the
      hub replies (or times out → escalate).

  ORCHESTRATOR side — runs in the daemon that owns the orchestrator
  session:
    * Receives `governance_decision_request_to_orchestrator` over the
      hub WS, delivers to the local orchestrator MCP session as a
      notification + makes the request payload available to the
      `evaluate_tool_call` tool. When Claude responds via that tool, the
      daemon sends `governance_decision_response` back to the hub.

Static deny list is enforced *here* (worker side) before any hub call:
no orchestrator opinion can approve `rm -rf /` etc. Kept short on
purpose — more nuanced patterns go in approval_rules.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent.governance")


# ── Static deny list ────────────────────────────────────────────────
#
# Patterns matched here always deny — no rule, no orchestrator opinion can
# approve. Intentionally short. The check is best-effort (regex against
# the rendered tool input as JSON); structural checks are deferred to the
# orchestrator + escalation.
_DENY_PATTERNS: list[re.Pattern] = [
    # rm -rf at root or home — most-asked-for guardrail.
    re.compile(r"\brm\s+-rf?\s+(/|~|\$HOME|\$\{HOME\})(\s|$|/)"),
    re.compile(r"\brm\s+-fr?\s+(/|~|\$HOME|\$\{HOME\})(\s|$|/)"),
    # Force-push to protected branches.
    re.compile(
        r"\bgit\s+push\s+(-f|--force(-with-lease)?)\b.*\b("
        r"main|master|production|prod|release/[^\s]+"
        r")\b"
    ),
    # Direct git dir / secrets / env tampering.
    re.compile(r"(?:^|[\s/])\.git/(?:HEAD|config|refs/)"),
    re.compile(r"(?:^|[\s/])\.env(?:\.|$|\s)"),
    re.compile(r"\bcredentials(?:\.json|\.yaml|\.yml)?\b"),
]


def _input_blob(tool: str, tool_input: dict[str, Any]) -> str:
    """Render a tool call as a flat string for pattern matching."""
    parts = [tool]
    try:
        import json
        parts.append(json.dumps(tool_input, default=str))
    except Exception:
        parts.append(str(tool_input))
    return " ".join(parts)


def static_deny_check(tool: str, tool_input: dict[str, Any]) -> tuple[bool, str | None]:
    """Return (denied, pattern) — the matched pattern's source if denied."""
    blob = _input_blob(tool, tool_input)
    for pat in _DENY_PATTERNS:
        if pat.search(blob):
            return True, pat.pattern
    return False, None


# ── State ────────────────────────────────────────────────────────────


@dataclass
class _PendingRequest:
    """A worker-side request awaiting the hub's decision."""
    request_id: str
    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: str | None = None  # 'allow' | 'deny' | 'escalate'
    reason: str | None = None
    escalation_path: list[str] | None = None
    started_at: float = field(default_factory=time.monotonic)


@dataclass
class _OrchestratorInbox:
    """An orchestrator-side request awaiting Claude's evaluate_tool_call response."""
    request_id: str
    tool: str
    tool_input: dict[str, Any]
    requesting_session_id: str | None
    agent_name: str | None
    received_at: float = field(default_factory=time.monotonic)
    event: asyncio.Event = field(default_factory=asyncio.Event)
    decision: str | None = None  # 'allow' | 'deny' | 'escalate'
    reason: str | None = None


class GovernanceManager:
    """Per-daemon governance routing state. Attached to DaemonState."""

    def __init__(self, state: "DaemonState"):
        self.state = state
        # Worker side
        self._pending_worker: dict[str, _PendingRequest] = {}
        # Orchestrator side — keyed by request_id
        self._inbox: dict[str, _OrchestratorInbox] = {}
        # The orchestrator queue per session (for MCP tool to pull from)
        self._inbox_by_session: dict[str, list[str]] = {}  # session_id → [request_ids]
        # Cached pointer: project_id → pointer dict (None means we know none)
        self._pointer_cache: dict[str, dict[str, Any]] = {}
        # Worker-side wait AND orchestrator-side auto-escalate window. Must
        # exceed the hub's _DECISION_TIMEOUT_SECONDS (so the hub's verdict
        # arrives first) and stay under the PreToolUse hook's Claude Code
        # timeout (30s) and the hook's HTTP read timeout (28s). 5.5s was far
        # too short for an LLM orchestrator to read its inbox and decide —
        # every governed call timed out → escalate → native prompt.
        self._timeout_seconds = 26.0

    # ── Worker side ─────────────────────────────────────────────────

    async def evaluate(
        self,
        session_id: str,
        project_id: str | None,
        tool: str,
        tool_input: dict[str, Any],
        agent_name: str | None = None,
    ) -> dict[str, Any]:
        """Local hook entrypoint. Returns
            {decision, reason, decided_by, escalation_path}.
        """
        # 1. Static deny — non-negotiable.
        denied, pattern = static_deny_check(tool, tool_input)
        if denied:
            log.info(f"governance: static deny on {tool} (pattern={pattern!r})")
            return {
                "decision": "deny",
                "reason": "static_deny_list",
                "decided_by": "rule",
                "escalation_path": ["static_deny"],
            }

        # 2. Hub round trip via WS.
        if not project_id:
            return {
                "decision": "escalate",
                "reason": "no_project_context",
                "decided_by": "rule",
                "escalation_path": ["no_project"],
            }

        if not self.state.ws_connection:
            log.info("governance: no hub WS — escalating")
            return {
                "decision": "escalate",
                "reason": "hub_disconnected",
                "decided_by": "rule",
                "escalation_path": ["hub_disconnected"],
            }

        request_id = str(uuid.uuid4())
        pending = _PendingRequest(request_id=request_id)
        self._pending_worker[request_id] = pending

        # Lazy import to avoid a cycle (hub imports this module).
        from orchestratia_agent.hub import ws_send
        ok = await ws_send(self.state, {
            "type": "governance_decision_request",
            "request_id": request_id,
            "session_id": session_id,
            "project_id": project_id,
            "tool": tool,
            "tool_input": tool_input,
            "agent_name": agent_name or "claude",
        })
        if not ok:
            self._pending_worker.pop(request_id, None)
            return {
                "decision": "escalate",
                "reason": "hub_send_failed",
                "decided_by": "rule",
                "escalation_path": ["hub_send_failed"],
            }

        try:
            await asyncio.wait_for(pending.event.wait(), timeout=self._timeout_seconds)
        except asyncio.TimeoutError:
            self._pending_worker.pop(request_id, None)
            return {
                "decision": "escalate",
                "reason": "governance_timeout",
                "decided_by": "rule",
                "escalation_path": ["governance_timeout"],
            }

        # Decision arrived. The handler already wrote to `pending`.
        self._pending_worker.pop(request_id, None)
        return {
            "decision": pending.decision or "escalate",
            "reason": pending.reason,
            # decided_by isn't returned by the hub explicitly — infer:
            "decided_by": "orchestrator" if pending.decision in ("allow", "deny") else "rule",
            "escalation_path": pending.escalation_path,
        }

    def handle_worker_response(self, msg: dict[str, Any]) -> None:
        """Wire handler for `governance_decision_response_to_worker`."""
        request_id = msg.get("request_id")
        if not request_id or request_id not in self._pending_worker:
            return
        pending = self._pending_worker[request_id]
        pending.decision = msg.get("decision")
        pending.reason = msg.get("reason")
        pending.escalation_path = msg.get("escalation_path")
        pending.event.set()

    # ── Orchestrator side ───────────────────────────────────────────

    def handle_orchestrator_request(self, msg: dict[str, Any]) -> None:
        """Wire handler for `governance_decision_request_to_orchestrator`."""
        request_id = msg.get("request_id") or ""
        session_id = msg.get("orchestrator_session_id") or ""
        if not request_id or not session_id:
            log.warning(f"governance: bad orchestrator request {msg}")
            return
        inbox = _OrchestratorInbox(
            request_id=request_id,
            tool=msg.get("tool") or "",
            tool_input=msg.get("tool_input") or {},
            requesting_session_id=msg.get("requesting_session_id"),
            agent_name=msg.get("agent_name"),
        )
        self._inbox[request_id] = inbox
        self._inbox_by_session.setdefault(session_id, []).append(request_id)

        # Notify the MCP session that a new decision is waiting. The
        # orchestrator Claude reads the queue via the orchestrator-only
        # MCP resource `governance://inbox`.
        try:
            if self.state.mcp_manager:
                # FastMCP doesn't have a generic notification; we lean on
                # the existing resource_list_changed channel. The
                # orchestrator MCP session exposes `governance://inbox`,
                # and bumping that signals "re-read me".
                asyncio.create_task(
                    self.state.mcp_manager.notify_governance_inbox(session_id)  # type: ignore[attr-defined]
                )
        except Exception:
            log.debug("governance: notify_governance_inbox failed", exc_info=True)

        # Time-bound: if Claude doesn't respond in time, send `escalate`.
        asyncio.create_task(self._orchestrator_timeout(request_id))

    async def _orchestrator_timeout(self, request_id: str) -> None:
        await asyncio.sleep(self._timeout_seconds)
        inbox = self._inbox.pop(request_id, None)
        if not inbox or inbox.decision is not None:
            return  # already replied
        log.info(f"governance: orchestrator timeout on {request_id[:8]} — auto-escalating")
        await self._send_response(request_id, "escalate", "orchestrator_no_response")

    def pop_inbox_for_session(self, session_id: str) -> list[dict[str, Any]]:
        """Return all pending requests for an orchestrator session — read by MCP."""
        request_ids = self._inbox_by_session.get(session_id, [])
        out: list[dict[str, Any]] = []
        for rid in request_ids:
            inbox = self._inbox.get(rid)
            if not inbox or inbox.decision is not None:
                continue
            out.append({
                "request_id": inbox.request_id,
                "tool": inbox.tool,
                "tool_input": inbox.tool_input,
                "requesting_session_id": inbox.requesting_session_id,
                "agent_name": inbox.agent_name,
                "age_seconds": int(time.monotonic() - inbox.received_at),
            })
        return out

    async def respond_to_request(
        self, request_id: str, decision: str, reason: str = ""
    ) -> tuple[bool, str]:
        """Called by the orchestrator's MCP `evaluate_tool_call` tool."""
        inbox = self._inbox.get(request_id)
        if not inbox:
            return False, "unknown_request_id"
        if decision not in ("allow", "deny", "escalate"):
            return False, "invalid_decision"
        if inbox.decision is not None:
            return False, "already_responded"
        inbox.decision = decision
        inbox.reason = reason
        inbox.event.set()
        await self._send_response(request_id, decision, reason)
        # Clean up after a brief moment — the timeout task may also fire.
        self._inbox.pop(request_id, None)
        return True, "ok"

    async def _send_response(self, request_id: str, decision: str, reason: str) -> None:
        from orchestratia_agent.hub import ws_send
        await ws_send(self.state, {
            "type": "governance_decision_response",
            "request_id": request_id,
            "decision": decision,
            "reason": reason,
        })

    # ── Pointer cache ───────────────────────────────────────────────

    def invalidate_pointer(self, project_id: str) -> None:
        """Drop cached orchestrator pointer for a project (forces refetch)."""
        self._pointer_cache.pop(project_id, None)


# ── Local HTTP endpoint (loopback only) ─────────────────────────────


async def _evaluate_endpoint(request: Request) -> JSONResponse:
    """Loopback POST /governance/evaluate — called by the PreToolUse hook.

    Body: `{session_id, project_id, tool, tool_input, agent_name?}`.
    Returns: `{decision, reason, decided_by, escalation_path}`.
    """
    state = request.app.state.daemon_state  # type: ignore[attr-defined]
    mgr: GovernanceManager | None = getattr(state, "governance_manager", None)
    if mgr is None:
        return JSONResponse(
            {"decision": "escalate", "reason": "governance_not_initialized"},
            status_code=503,
        )
    body = await request.json()
    result = await mgr.evaluate(
        session_id=body.get("session_id", ""),
        project_id=body.get("project_id"),
        tool=body.get("tool", ""),
        tool_input=body.get("tool_input", {}),
        agent_name=body.get("agent_name"),
    )
    return JSONResponse(result)


def register_governance_endpoint(app) -> None:
    """Wire `/governance/evaluate` into the local MCP HTTP app.

    Called from `mcp_server.MCPServerManager._build_app` so the loopback
    server hosts both the MCP routes and this HTTP endpoint side by side.
    """
    # The MCP manager dispatches at the raw-ASGI scope level; the actual
    # routing for /governance/evaluate is wired in `mcp_server._build_app`.
    # This function is kept so callers can register additional governance
    # surface in the future without touching mcp_server.
    setattr(app, "_governance_evaluate", _evaluate_endpoint)


# ── Orchestrator system prompt writing (Phase 2) ────────────────────


_ORCHESTRATOR_PROMPT_TEMPLATE = """\
# Orchestrator role — Orchestratia

You are this project's **Orchestrator**: its long-lived project manager. You
plan the work, run a fleet of short-lived **worker** agents to do it, and
govern what they're allowed to do. The user is your supervisor, not your
operator — they see summaries and approve the rare destructive or novel
action; they do not babysit individual tool calls.

Mental model: **you are the project manager; workers are disposable
contractors.** Spawn a worker for a unit of work, supervise it, and reap it
when the work is done (or when its context is polluted and a fresh worker
would be cheaper). You persist across sessions; workers don't.

## Running the worker fleet

- **Spawn**: `spawn_worker(name, agent_type, working_dir, task_spec)` starts a
  worker. It comes up with the agent CLI as its own process and reads its full
  spec from the `task://current` MCP resource — you never type into its
  terminal. `agent_type` may differ from yours (a Claude orchestrator can
  spawn a Gemini worker). Spawning fails if the project's worker cap is
  reached (reap one first) or the server can't run that agent_type yet.
- **Supervise** through structured channels only — never a terminal stream:
  - Risky worker tool calls arrive as governance decisions (see below).
  - Ask a worker something with `ask_agent(session_id, question)`; the reply
    lands in your `notes://inbox`.
  - Worker progress notes arrive in `notes://inbox`.
- **Review** finished work with
  `review_task_result(task_id, decision, feedback)`, decision ∈
  {{accept, revise, reject}}. `revise` sends your feedback to the worker and it
  re-works; `reject` fails the task; `accept` marks it done.
- **Reassign vs. reap**: `assign_task(session_id, task_spec)` hands a running
  worker new work (it re-reads `task://current` itself — no keystrokes). But
  when the next task is unrelated, prefer `terminate_worker` + a fresh
  `spawn_worker` over reusing a context-polluted worker — usually cheaper and
  cleaner.
- **Reap**: `terminate_worker(session_id, reason)` when a worker is done or
  stuck. If the project requires terminate approval, a human confirms first.

## Governing permissions

1. A worker attempts a tool call (Bash, Edit, …).
2. Static approval rules match first (zero round trip).
3. On a miss it reaches you via the `governance://inbox` resource — each entry
   has a `request_id`, the `tool`, its `tool_input`, and the asker.
4. Respond with `evaluate_tool_call(request_id, decision, reason)`,
   decision ∈ {{allow, deny, escalate}}:
   - `allow` — worker proceeds.
   - `deny` — worker is blocked; the reason is shown to it.
   - `escalate` — a human intervention is created; use it when you won't
     commit either way.

The **static deny list** (`rm -rf /`, force-pushing protected branches,
touching `.git/`, `.env*`, `credentials*`) ALWAYS overrides you — you cannot
approve those, ever. Decide within ~5 seconds or escalate.

## Memory — use it

- `remember(fact, tags)` — persist a durable fact (architecture decision,
  convention, gotcha, user preference). It's written to a file in the repo and
  survives across worker lifecycles and your own restarts.
- `recall(query)` — search what you've already learned before planning or
  deciding. Check memory before re-deriving something.

## Worker bootstrap — when a freshly spawned worker stalls

A just-spawned worker comes up as a raw agent CLI; its structured channels
(`task://current`, `post_note`, governance) don't exist until it finishes
starting. In that window it can stall on a one-time CLI onboarding prompt that
an autonomous worker can't answer. The daemon pre-trusts the working dir, but
other gates — MCP-server approval, and per-agent onboarding prompts — can still
appear. This is the ONE place screen-level supervision is the correct tool, not
a failure:

- If a spawned worker isn't progressing (no task start / note / governance call
  within ~60s), `peek_worker(session_id)` — a live one-shot screen snapshot.
- If it's sitting on a recognizable, safe onboarding prompt, answer it with
  `send_keys` (enabled by default; e.g. choose "yes / trust / use this server"
  then Enter — these prompts change across agents and versions, so read the
  screen, don't assume a fixed keystroke). If the prompt is unfamiliar or risky,
  `escalate_to_human` with what you saw rather than guessing.
- Once the worker reaches its task and its MCP channel is live, STOP using
  break-glass and operate through structured channels only.

## Break-glass (last resort, post-bootstrap)

After bootstrap, structured channels are how you operate workers. Reserve
`peek_worker` / `interrupt_worker` (Esc to unstick) / `send_keys` (bounded,
every use audited) for a worker that has gone non-responsive to `ask_agent`.
Routine post-bootstrap `send_keys` means a structured channel has failed — fix
that instead.

## Escalation policy

{escalation_policy}

## Cadence

- At the start of every turn, check `governance://inbox` (pending decisions)
  and `notes://inbox` (worker questions/progress); handle the oldest first.
- Keep the fleet healthy: reap finished or stuck workers, spawn new ones as
  work arises, and record what you learn with `remember`.
- When the queues are empty and nothing is pending, do nothing; the next turn
  fires when a new request or note arrives.
"""


def _default_escalation_policy() -> str:
    return (
        "When in doubt, escalate. Always escalate: production deploys, "
        "secret rotation, force-pushes to main, modifications under .git/, "
        "anything touching auth/, payment/, or migration files."
    )


# A short preamble injected into ordinary *worker* sessions. Deliberately
# minimal — a worker just needs to know it's governed and how to reach its
# orchestrator. The bulk of a worker's instructions come from its task spec
# (task://current) and the repo's own project CLAUDE.md, NOT from here.
_WORKER_PROMPT_TEMPLATE = """\
# Worker role — Orchestratia

You are a **worker** agent in an Orchestratia fleet: a short-lived contractor
spawned to complete one unit of work. An **orchestrator** supervises you; the
human is reached through it, not directly.

- Your assignment lives in the `task://current` MCP resource — read it for the
  full spec, acceptance criteria, and any resolved inputs. Do the work in your
  working directory; follow the repo's own project conventions.
- Report progress with `post_note`; ask the orchestrator a question with
  `ask_agent`; request human help with `request_intervention`. These are your
  lifelines — they never block.
- Risky tool calls (shell, edits outside your workspace, network) are
  **governed**: a call that misses the static approval rules is routed to your
  orchestrator for an allow/deny verdict. Expect occasional short waits; don't
  work around them.
- You do **not** govern other agents, spawn workers, or read the
  orchestrator's queues — those tools aren't yours. Finish your task, report
  the result, and stop.
"""


def role_system_prompt(role: str | None, escalation_policy: str | None = None) -> str:
    """Return the system-prompt text for a session's role.

    Single source of truth for role instructions. Consumed by the
    SessionStart hook (via the `orchestratia context-prompt` CLI command),
    which injects the returned markdown into the agent's context at launch —
    so the role travels with the *session/env*, never written to disk and
    never inherited by child sessions through the directory tree.

    `role` is the hub-stamped ORCHESTRATIA_ROLE; anything other than the
    literal "orchestrator" is treated as a worker (fail-safe default).
    """
    if (role or "").strip().lower() == "orchestrator":
        policy = (escalation_policy or "").strip() or _default_escalation_policy()
        return _ORCHESTRATOR_PROMPT_TEMPLATE.format(escalation_policy=policy)
    return _WORKER_PROMPT_TEMPLATE


def write_orchestrator_system_prompt(
    workspace_dir: str,
    agent_type: str | None,
    escalation_policy: str | None = None,
) -> str | None:
    """DEPRECATED — superseded by `role_system_prompt()` + the SessionStart
    hook (`orchestratia context-prompt`).

    Historically this wrote the orchestrator role into the cwd's system-prompt
    file (CLAUDE.md/GEMINI.md/AGENTS.md). That delivery leaks: a CLAUDE.md at a
    directory that is a *parent* of worker repos is merged into every worker's
    context (so workers inherited the orchestrator role), and it pollutes a
    repo's own tracked CLAUDE.md. Role is now injected ephemerally per-session
    by the SessionStart hook keyed on ORCHESTRATIA_ROLE — nothing on disk, no
    cross-tree inheritance. Kept only for backward reference; no longer called.

    Write the orchestrator role's system prompt to whichever file the chosen
    CLI reads. Returns the path written, or None if no writer is defined for
    `agent_type`. Idempotent.
    """
    from orchestratia_agent.agent_registry import REGISTRY, AgentType, coerce_agent_type

    agent = coerce_agent_type(agent_type)
    spec = REGISTRY.get(agent)
    if spec is None or not spec.system_prompt_file:
        log.info(
            f"governance: no system-prompt path for agent={agent.value}; "
            "orchestrator will fall back to MCP prompts/list"
        )
        return None
    policy = (escalation_policy or "").strip() or _default_escalation_policy()
    content = _ORCHESTRATOR_PROMPT_TEMPLATE.format(escalation_policy=policy)
    path = os.path.join(workspace_dir, spec.system_prompt_file)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        # Append-with-marker so we don't clobber a user's existing
        # project conventions (CLAUDE.md often has codebase rules already).
        marker_start = "<!-- BEGIN orchestratia-orchestrator -->"
        marker_end = "<!-- END orchestratia-orchestrator -->"
        existing = ""
        if os.path.exists(path):
            try:
                with open(path) as f:
                    existing = f.read()
            except OSError:
                existing = ""

        block = f"{marker_start}\n{content}\n{marker_end}\n"
        if marker_start in existing and marker_end in existing:
            # Replace our managed block in place; leave the user's
            # surrounding content alone.
            before, _, rest = existing.partition(marker_start)
            _, _, after = rest.partition(marker_end)
            new_content = f"{before}{block}{after.lstrip()}"
        else:
            sep = "\n\n" if existing and not existing.endswith("\n") else ("\n" if existing else "")
            new_content = f"{existing}{sep}{block}"

        with open(path, "w") as f:
            f.write(new_content)
        log.info(f"governance: wrote orchestrator system prompt → {path}")
        return path
    except PermissionError:
        log.warning(f"governance: cannot write orchestrator prompt to {path} (read-only)")
        return None
    except Exception:
        log.exception(f"governance: failed to write orchestrator prompt to {path}")
        return None
