"""Orchestratia MCP server hosted inside the agent daemon.

Each active session is mounted at a per-session URL on a local loopback
HTTP/SSE endpoint:

    http://127.0.0.1:<mcp_port>/mcp/sessions/<session_id>/mcp

Claude Code in that session reads `.mcp.json` from its workspace, which
points at the above URL, and gets a Claude-facing API onto Orchestratia:

  - Resources:
      task://current             — current task spec (or "no task assigned")
      task://current/inputs      — resolved_inputs from upstream tasks
      task://current/dependencies — task graph slice
      notes://inbox              — pending notes addressed to this session

  - Tools:
      post_note(text, task_id?)              — proxy to hub
      complete_task(result)                  — proxy to hub
      fail_task(error)                       — proxy to hub
      request_intervention(question, ...)    — proxy to hub

When the hub pushes a note for this session, the daemon emits an MCP
resource-list-changed notification so Claude consumes the new note on its
next reasoning step — no PTY injection, no Enter key required.

Loopback-only by design (binds 127.0.0.1). The daemon's hub credentials
back every request: workers never see API keys.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import TYPE_CHECKING, Any

import httpx
import uvicorn
from mcp.server.fastmcp import Context, FastMCP
from starlette.responses import PlainTextResponse

if TYPE_CHECKING:
    from orchestratia_agent.main import DaemonState

log = logging.getLogger("orchestratia-agent.mcp")

# Hub API timeout for proxied tool calls. Generous to absorb the hub being
# behind nginx/granian and occasionally slow on cold paths; tools that
# care about latency can retry on their own.
_HUB_TIMEOUT = 30.0


class _SessionMCP:
    """One FastMCP instance scoped to a single Orchestratia session.

    `role` selects the toolset: 'worker' (default) gets the existing
    task/note/intervention tools; 'orchestrator' adds the Phase 2
    governance plane (`governance://inbox` + `evaluate_tool_call`).
    """

    def __init__(
        self,
        state: DaemonState,
        session_id: str,
        task_id: str | None,
        role: str = "worker",
    ):
        self.state = state
        self.session_id = session_id
        self.task_id = task_id
        self.role = role
        self.mcp = FastMCP(
            name=f"orchestratia-session-{session_id[:8]}",
            instructions=(
                "Orchestratia governance + coordination plane for this session. "
                "Use `task://current` to inspect your assigned task, "
                "`notes://inbox` to see pending notes, and the post_note / "
                "complete_task / request_intervention tools to act."
                if role == "worker"
                else (
                    "You are an Orchestrator. Read `governance://inbox` for "
                    "permission decisions awaiting your verdict, then call "
                    "`evaluate_tool_call(request_id, decision, reason)` with "
                    "`allow`, `deny`, or `escalate`. Static rules already ran; "
                    "you only see calls those missed. The static deny list "
                    "still overrides anything you approve."
                )
            ),
            host="127.0.0.1",
            # Stateful streamable HTTP — the MCP protocol session persists
            # across requests via the Mcp-Session-Id header, enabling
            # server-initiated notifications (resource_list_changed) which
            # is the whole point: we push note-arrival to Claude without
            # waiting for it to poll.
            stateless_http=False,
        )
        self._inbox_version = 0  # bumps when a new note arrives — Claude re-reads
        self._governance_version = 0  # bumps when an evaluate request arrives
        self._register_resources()
        self._register_tools()
        if role == "orchestrator":
            self._register_orchestrator_resources()
            self._register_orchestrator_tools()
        # Materialize the streamable HTTP app once so the underlying
        # StreamableHTTPSessionManager is created and reachable for the
        # lifespan we manage ourselves (start/stop below).
        self._http_app = self.mcp.streamable_http_app()
        self._sm_task: asyncio.Task | None = None

    async def start(self):
        """Hold the session manager's run() context open for this session.

        StreamableHTTPSessionManager requires an active anyio task group to
        dispatch each request into. Normally Starlette's lifespan calls
        `run()` for you, but we dispatch ASGI calls directly to the sub-app
        and bypass its lifespan. So we run() it ourselves on a background
        task that lives as long as the session.
        """
        sm = self.mcp._session_manager  # type: ignore[attr-defined]
        if sm is None:
            log.warning(f"mcp session {self.session_id[:8]}: no session manager — http app not yet built")
            return
        ready = asyncio.Event()

        async def _hold():
            try:
                async with sm.run():
                    ready.set()
                    # Sleep forever until cancelled.
                    await asyncio.Event().wait()
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception(f"mcp session {self.session_id[:8]}: lifespan crashed")
                ready.set()  # unblock the waiter

        self._sm_task = asyncio.create_task(_hold())
        await ready.wait()

    async def stop(self):
        if self._sm_task and not self._sm_task.done():
            self._sm_task.cancel()
            try:
                await self._sm_task
            except (asyncio.CancelledError, Exception):
                pass
        self._sm_task = None

    # ── Hub HTTP helpers ────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {"X-API-Key": self.state.api_key}

    def _working_dir(self) -> str | None:
        """This session's resolved working directory (for memory file I/O)."""
        sess = self.state.active_sessions.get(self.session_id)
        return getattr(sess, "working_dir", None) if sess else None

    async def _hub_get(self, path: str) -> dict[str, Any] | None:
        url = f"{self.state.hub_url}{path}"
        try:
            from orchestratia_agent.tls import httpx_verify
            async with httpx.AsyncClient(timeout=_HUB_TIMEOUT, verify=httpx_verify(state=self.state)) as client:
                resp = await client.get(url, headers=self._headers())
                if resp.status_code >= 400:
                    log.warning(f"mcp hub GET {path} -> {resp.status_code}: {resp.text[:200]}")
                    return None
                return resp.json()
        except Exception:
            log.exception(f"mcp hub GET {path} failed")
            return None

    async def _hub_post(self, path: str, body: dict[str, Any]) -> dict[str, Any] | None:
        url = f"{self.state.hub_url}{path}"
        try:
            from orchestratia_agent.tls import httpx_verify
            async with httpx.AsyncClient(timeout=_HUB_TIMEOUT, verify=httpx_verify(state=self.state)) as client:
                resp = await client.post(url, headers=self._headers(), json=body)
                if resp.status_code >= 400:
                    log.warning(f"mcp hub POST {path} -> {resp.status_code}: {resp.text[:200]}")
                    return None
                if resp.status_code == 204 or not resp.content:
                    return {"ok": True}
                return resp.json()
        except Exception:
            log.exception(f"mcp hub POST {path} failed")
            return None

    # ── Resources ────────────────────────────────────────────────────

    def _register_resources(self):
        @self.mcp.resource("task://current")
        async def task_current() -> str:
            """Spec, status, and metadata for this session's assigned task."""
            if not self.task_id:
                return json.dumps({"assigned": False, "message": "No task assigned to this session."})
            data = await self._hub_get(f"/api/v1/server/tasks/{self.task_id}")
            if data is None:
                return json.dumps({"assigned": True, "task_id": self.task_id, "error": "Failed to fetch task from hub."})
            return json.dumps(data, default=str)

        @self.mcp.resource("task://current/inputs")
        async def task_inputs() -> str:
            """Resolved inputs from upstream tasks (contract exchange)."""
            if not self.task_id:
                return json.dumps({"inputs": []})
            data = await self._hub_get(f"/api/v1/server/tasks/{self.task_id}")
            inputs = (data or {}).get("resolved_inputs", []) or []
            return json.dumps({"inputs": inputs}, default=str)

        @self.mcp.resource("task://current/dependencies")
        async def task_deps() -> str:
            """Task graph slice — what blocks/feeds this task."""
            if not self.task_id:
                return json.dumps({"dependencies": []})
            data = await self._hub_get(f"/api/v1/server/tasks/{self.task_id}")
            deps = (data or {}).get("dependencies", []) or []
            return json.dumps({"dependencies": deps}, default=str)

        @self.mcp.resource("notes://inbox")
        async def notes_inbox() -> str:
            """Notes addressed to this session, freshest first.

            Re-read this resource after a `notifications/resources/list_changed`
            notification arrives — the daemon emits one when a new note is
            pushed from the hub.
            """
            if not self.task_id:
                return json.dumps({"notes": [], "version": self._inbox_version})
            data = await self._hub_get(f"/api/v1/server/tasks/{self.task_id}/notes")
            notes = (data or {}).get("notes", []) if isinstance(data, dict) else (data or [])
            return json.dumps({"notes": notes, "version": self._inbox_version}, default=str)

    # ── Tools ────────────────────────────────────────────────────────

    def _register_tools(self):
        @self.mcp.tool()
        async def post_note(text: str, task_id: str | None = None, ctx: Context = None) -> str:  # type: ignore[assignment]
            """Post a note onto a task. Defaults to this session's current task."""
            tid = task_id or self.task_id
            if not tid:
                return "error: no task_id (this session has no assigned task — pass task_id explicitly)"
            r = await self._hub_post(f"/api/v1/server/tasks/{tid}/notes", {"content": text})
            return "ok" if r is not None else "error: hub rejected the note"

        @self.mcp.tool()
        async def complete_task(result: dict[str, Any], ctx: Context = None) -> str:  # type: ignore[assignment]
            """Mark this session's assigned task as done. `result` follows
            the orchestratia/task-result/v1 schema."""
            if not self.task_id:
                return "error: this session has no assigned task to complete"
            r = await self._hub_post(f"/api/v1/server/tasks/{self.task_id}/complete", {"result": result})
            return "ok" if r is not None else "error: hub rejected the completion"

        @self.mcp.tool()
        async def fail_task(error: str, ctx: Context = None) -> str:  # type: ignore[assignment]
            """Mark this session's assigned task as failed with an error message."""
            if not self.task_id:
                return "error: this session has no assigned task to fail"
            r = await self._hub_post(f"/api/v1/server/tasks/{self.task_id}/fail", {"error": error})
            return "ok" if r is not None else "error: hub rejected the failure"

        @self.mcp.tool()
        async def ask_agent(
            target_session_id: str,
            question: str,
            context: str = "",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Ask another agent in this project a blocking clarifying question.

            Same project only (cross-project asks are rejected with 403).
            Cross-agent by default — works homogeneously (Claude→Claude) and
            heterogeneously (Claude→Gemini, Codex→Aider, any combo). The
            target agent sees the question in its `notes://inbox` flagged
            `mentioned_via='ask'`. Their response arrives in your inbox.

            Returns the intervention id; poll `notes://inbox` for the reply.
            """
            if not self.task_id:
                return "error: this session has no assigned task to attach the ask to"
            if not target_session_id:
                return "error: target_session_id required"
            r = await self._hub_post(
                f"/api/v1/server/tasks/{self.task_id}/help",
                {
                    "question": question,
                    "context": context,
                    "intervention_type": "question",
                    "target_session_id": target_session_id,
                },
            )
            if r is None:
                return "error: hub rejected the ask (target session may be in a different project or closed)"
            return f"ok intervention_id={r.get('intervention_id', '?')}"

        @self.mcp.tool()
        async def request_intervention(
            question: str,
            context: str = "",
            urgency: str = "normal",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Ask a human for help on a blocking question. Returns once posted —
            the response arrives back as a note in `notes://inbox`."""
            if not self.task_id:
                return "error: this session has no assigned task to attach the intervention to"
            r = await self._hub_post(
                f"/api/v1/server/tasks/{self.task_id}/help",
                {"question": question, "context": context, "urgency": urgency},
            )
            return "ok" if r is not None else "error: hub rejected the intervention"

    # ── Orchestrator resources + tools (Phase 2) ─────────────────────

    def _register_orchestrator_resources(self):
        @self.mcp.resource("governance://inbox")
        async def governance_inbox() -> str:
            """Pending permission-decision requests addressed to this
            orchestrator. Each entry includes the request_id you must pass
            back via `evaluate_tool_call`. Re-read this resource after a
            `notifications/resources/list_changed` arrives.
            """
            mgr = getattr(self.state, "governance_manager", None)
            if mgr is None:
                return json.dumps({"requests": [], "version": self._governance_version})
            items = mgr.pop_inbox_for_session(self.session_id)
            return json.dumps(
                {"requests": items, "version": self._governance_version},
                default=str,
            )

        @self.mcp.resource("orchestrator://memory")
        async def orchestrator_memory() -> str:
            """Recent project memories (file path + tags + summary). Use the
            `recall` tool to search and read full contents."""
            data = await self._hub_get(
                f"/api/v1/server/orchestrator/memory/search"
                f"?orchestrator_session_id={self.session_id}&limit=20"
            )
            entries = (data or {}).get("entries", []) if isinstance(data, dict) else []
            return json.dumps({"memories": entries}, default=str)

    def _register_orchestrator_tools(self):
        @self.mcp.tool()
        async def evaluate_tool_call(
            request_id: str,
            decision: str,
            reason: str = "",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Decide on a worker's tool call. `decision` ∈ allow/deny/escalate.

            `allow` lets the worker proceed. `deny` blocks it. `escalate`
            hands the decision to a human (an intervention is created).
            The static deny list still overrides `allow` — patterns like
            `rm -rf /` can never be approved by this tool.
            """
            mgr = getattr(self.state, "governance_manager", None)
            if mgr is None:
                return "error: governance manager not initialised"
            ok, info = await mgr.respond_to_request(request_id, decision, reason)
            return "ok" if ok else f"error: {info}"

        @self.mcp.tool()
        async def escalate_to_human(
            request_id: str,
            reason: str,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Shorthand for `evaluate_tool_call(request_id, 'escalate', reason)`.

            Use when the policy says "always escalate" or the call is
            ambiguous enough that a human should weigh in.
            """
            mgr = getattr(self.state, "governance_manager", None)
            if mgr is None:
                return "error: governance manager not initialised"
            ok, info = await mgr.respond_to_request(request_id, "escalate", reason)
            return "ok" if ok else f"error: {info}"

        # ── Phase 2.5: worker lifecycle ──────────────────────────────
        @self.mcp.tool()
        async def spawn_worker(
            name: str | None = None,
            agent_type: str = "claude_code",
            working_dir: str | None = None,
            task_spec: str | None = None,
            task_title: str | None = None,
            launch_command: str | None = None,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Spawn a disposable worker session in this project.

            The worker comes up with the agent CLI as its root process (no
            shell, no keystrokes) on your server. If `task_spec` is given, a
            task is created and bound to the worker so it reads its full spec
            from `task://current` over MCP and begins on its own.

            `agent_type` ∈ claude_code | gemini_cli | codex_cli | aider |
            cursor (default claude_code) — cross-agent: a Claude orchestrator
            can spawn a Gemini worker. `launch_command` overrides the CLI
            binary (e.g. "claude --model opus"); otherwise it's derived from
            `agent_type`. `working_dir` is where the worker runs.

            Fails if the project's worker limit is reached (try
            `terminate_worker` first) or the requested agent_type isn't
            worker-ready on the server (a human must authenticate it once).
            Returns the new session_id (and task_id, if a task was created).
            """
            body: dict[str, Any] = {
                "orchestrator_session_id": self.session_id,
                "agent_type": agent_type,
            }
            if name:
                body["name"] = name
            if working_dir:
                body["working_dir"] = working_dir
            if task_spec:
                body["task_spec"] = task_spec
            if task_title:
                body["task_title"] = task_title
            if launch_command:
                body["launch_command"] = launch_command
            r = await self._hub_post("/api/v1/server/orchestrator/spawn-worker", body)
            if r is None:
                return (
                    "error: hub rejected the spawn (worker limit reached, "
                    "agent_type not worker-ready, or daemon unreachable — "
                    "check the project's worker fleet + server readiness)"
                )
            parts = [f"ok session_id={r.get('session_id')}"]
            if r.get("task_id"):
                parts.append(f"task_id={r['task_id']}")
            parts.append(f"agent_type={r.get('agent_type')}")
            return " ".join(parts)

        @self.mcp.tool()
        async def terminate_worker(
            session_id: str,
            reason: str = "",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Reap a worker session in your project when its task is done or
            its context has gotten polluted.

            If the project requires terminate approval, this raises a human
            approval request and the worker keeps running until a human
            approves — the tool returns the intervention id. Otherwise the
            worker is killed immediately. Reap freely: workers are disposable;
            a fresh worker is often cheaper than reassigning a polluted one.
            """
            if not session_id:
                return "error: session_id required"
            r = await self._hub_post(
                "/api/v1/server/orchestrator/terminate-worker",
                {
                    "orchestrator_session_id": self.session_id,
                    "session_id": session_id,
                    "reason": reason,
                },
            )
            if r is None:
                return (
                    "error: hub rejected the terminate (worker not in your "
                    "project, already stopped, or you are not its orchestrator)"
                )
            if r.get("requires_approval"):
                return (
                    f"pending human approval — intervention_id={r.get('intervention_id')}. "
                    "The worker keeps running until approved."
                )
            return "ok worker terminated"

        # ── Persistent project memory (§8.5.2) ───────────────────────
        @self.mcp.tool()
        async def remember(
            fact: str,
            tags: list[str] | None = None,
            related_task_id: str | None = None,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Persist a durable project fact (architecture decision, user
            preference, gotcha) to orchestrator memory. Stored as a markdown
            file in your working tree (.orchestratia/memory/) and indexed for
            `recall`. Survives across worker lifecycles and your own restarts.
            Tag it so future recall is sharp (e.g. ["auth","db"])."""
            cwd = self._working_dir()
            if not cwd:
                return "error: this orchestrator session has no working directory"
            from orchestratia_agent.orchestrator_memory import write_memory
            try:
                payload = write_memory(cwd, fact, tags or [], related_task_id)
            except Exception as e:
                return f"error: failed to write memory file: {e}"
            r = await self._hub_post(
                "/api/v1/server/orchestrator/memory",
                {"orchestrator_session_id": self.session_id, **payload},
            )
            if r is None:
                return (
                    f"saved to {payload['file_path']} but index push failed — "
                    "it will be picked up on the next reindex"
                )
            return f"ok remembered -> {payload['file_path']}"

        @self.mcp.tool()
        async def recall(
            query: str = "",
            tags: str = "",
            limit: int = 10,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Search orchestrator memory and return matching facts with their
            full content. `query` matches summary/path/tags; `tags` is a
            comma-separated any-match filter; empty args return recent
            memories. Reads the canonical files, so it works even if the index
            was rebuilt."""
            from urllib.parse import quote
            cwd = self._working_dir()
            path = (
                f"/api/v1/server/orchestrator/memory/search"
                f"?orchestrator_session_id={self.session_id}&limit={int(limit)}"
            )
            if query:
                path += f"&q={quote(query)}"
            if tags:
                path += f"&tags={quote(tags)}"
            data = await self._hub_get(path)
            entries = (data or {}).get("entries", []) if isinstance(data, dict) else []
            from orchestratia_agent.orchestrator_memory import read_memory
            results = []
            for e in entries:
                body = read_memory(cwd, e["file_path"]) if cwd else None
                results.append({
                    "file": e["file_path"],
                    "tags": e.get("tags", []),
                    "summary": e.get("summary"),
                    "content": body,
                })
            return json.dumps({"memories": results}, default=str)

        # ── Task supervision (§8.5.3) ────────────────────────────────
        @self.mcp.tool()
        async def review_task_result(
            task_id: str,
            decision: str,
            feedback: str = "",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Accept, revise, or reject a worker's task result. `decision` ∈
            accept | revise | reject. `accept` marks it done. `reject` fails
            it. `revise` keeps the worker on the task and pushes your
            `feedback` to its MCP inbox so it fixes and re-completes — no
            keystrokes. Always give concrete feedback when revising."""
            if decision not in ("accept", "revise", "reject"):
                return "error: decision must be accept|revise|reject"
            r = await self._hub_post(
                "/api/v1/server/orchestrator/review-task",
                {
                    "orchestrator_session_id": self.session_id,
                    "task_id": task_id,
                    "decision": decision,
                    "feedback": feedback,
                },
            )
            if r is None:
                return "error: hub rejected the review (task not in your project?)"
            return f"ok decision={r.get('decision')} task_status={r.get('new_status')}"

        @self.mcp.tool()
        async def assign_task(
            session_id: str,
            task_spec: str = "",
            task_id: str = "",
            task_title: str = "",
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Assign work to an already-running worker, keystroke-free. Pass
            a new `task_spec` (a task is created) or an existing `task_id`.
            The worker's `task://current` updates and it re-reads the task
            over MCP on its own — nothing is typed into its terminal. (Often
            it's cheaper to terminate a context-polluted worker and spawn a
            fresh one than to reassign it.)"""
            if not session_id:
                return "error: session_id required"
            if not task_spec and not task_id:
                return "error: provide task_spec or task_id"
            body: dict[str, Any] = {
                "orchestrator_session_id": self.session_id,
                "session_id": session_id,
            }
            if task_id:
                body["task_id"] = task_id
            if task_spec:
                body["task_spec"] = task_spec
            if task_title:
                body["task_title"] = task_title
            r = await self._hub_post("/api/v1/server/orchestrator/assign-task", body)
            if r is None:
                return "error: hub rejected the assignment (worker not in your project or not running)"
            return f"ok assigned task_id={r.get('task_id')} to session={r.get('session_id')}"

        # ── Break-glass (§8.5.3a) — escape hatches, not the normal channel ──
        @self.mcp.tool()
        async def peek_worker(
            session_id: str,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Break-glass: one-shot snapshot of a worker's current screen.
            Use ONLY when a worker has gone non-responsive to `ask_agent` —
            this is not how you normally observe workers (no streaming). Pull
            only; returns the last rendered screen lines."""
            data = await self._hub_get(
                f"/api/v1/server/orchestrator/worker-screen"
                f"?orchestrator_session_id={self.session_id}&session_id={session_id}"
            )
            if data is None:
                return "error: hub rejected peek (worker not in your project?)"
            screen = data.get("last_screen") or []
            return json.dumps({"session_id": session_id, "screen": screen}, default=str)

        @self.mcp.tool()
        async def worker_context(
            session_id: str,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Latest context-window usage for a worker, measured at the
            worker itself (only its own agent process knows its real usage).
            Returns `{session_id, pct, used, window, ts}` or a clear error
            string. A high pct means the worker is near its context limit —
            consider terminating + respawning a fresh one rather than letting
            it degrade."""
            data = await self._hub_get(
                f"/api/v1/server/orchestrator/worker-context"
                f"?orchestrator_session_id={self.session_id}&session_id={session_id}"
            )
            if data is None:
                return (
                    "error: context reading not available yet (hub endpoint "
                    "missing, or no reading reported for this worker)"
                )
            return json.dumps({
                "session_id": session_id,
                "pct": data.get("pct"),
                "used": data.get("used"),
                "window": data.get("window"),
                "ts": data.get("ts"),
            }, default=str)

        @self.mcp.tool()
        async def interrupt_worker(
            session_id: str,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Break-glass: send Esc to unstick a hung worker without a full
            kill+respawn. For a worker non-responsive to `ask_agent` only —
            if you reach for this routinely, the supervision channel has
            failed. Audited."""
            r = await self._hub_post(
                "/api/v1/server/orchestrator/worker-input",
                {"orchestrator_session_id": self.session_id, "session_id": session_id, "mode": "interrupt"},
            )
            if r is None:
                return "error: hub rejected interrupt (worker not in your project or not running)"
            return "ok interrupt sent (Esc)"

        @self.mcp.tool()
        async def send_keys(
            session_id: str,
            keys: str,
            ctx: Context = None,  # type: ignore[assignment]
        ) -> str:
            """Break-glass: inject a bounded keystroke string into a worker's
            terminal. Disabled unless the project enables
            `allow_worker_keystrokes` (default off), because it can route
            around the permission system. Every call is audited. Last resort
            for a worker no structured channel can reach — prefer fixing the
            structured path instead."""
            if not keys:
                return "error: keys required"
            r = await self._hub_post(
                "/api/v1/server/orchestrator/worker-input",
                {"orchestrator_session_id": self.session_id, "session_id": session_id,
                 "mode": "keys", "keys": keys},
            )
            if r is None:
                return (
                    "error: hub rejected send_keys (disabled for this project "
                    "[allow_worker_keystrokes=false], worker not in your project, "
                    "or input too long)"
                )
            return "ok keys sent"

    # ── Notifications ────────────────────────────────────────────────

    async def notify_governance_inbox(self):
        """Tell connected MCP clients that `governance://inbox` has changed."""
        self._governance_version += 1
        try:
            server = self.mcp._mcp_server  # type: ignore[attr-defined]
            await server.request_context.session.send_resource_list_changed()
        except Exception:
            log.debug("notify_governance_inbox: no active mcp session to push to")

    async def notify_note_inbox(self):
        """Tell connected MCP clients that `notes://inbox` has new content.

        We bump our internal version (so the next read returns fresh JSON)
        and emit a resources-list-changed notification on every active SSE
        session attached to this server.
        """
        self._inbox_version += 1
        try:
            # FastMCP exposes the underlying Server; use its session manager.
            server = self.mcp._mcp_server  # type: ignore[attr-defined]
            # No-op if no client is currently subscribed.
            await server.request_context.session.send_resource_list_changed()
        except Exception:
            # Best effort — Claude can still poll the resource. Logged at
            # debug to avoid noise when no MCP client is connected yet.
            log.debug("notify_note_inbox: no active mcp session to push to")

    async def notify_task_changed(self):
        """Phase 2.5: tell the MCP client `task://current` changed (live
        reassignment). A resources-list-changed nudge makes Claude re-read
        its task on its own — keystroke-free."""
        try:
            server = self.mcp._mcp_server  # type: ignore[attr-defined]
            await server.request_context.session.send_resource_list_changed()
        except Exception:
            log.debug("notify_task_changed: no active mcp session to push to")


class MCPServerManager:
    """Manages per-session MCP servers and the loopback ASGI app hosting them."""

    def __init__(self, state: DaemonState):
        self.state = state
        self._sessions: dict[str, _SessionMCP] = {}

    async def register_session(
        self,
        session_id: str,
        task_id: str | None,
        role: str = "worker",
    ) -> _SessionMCP:
        if session_id in self._sessions:
            log.debug(f"mcp: session {session_id[:8]} already registered")
            return self._sessions[session_id]
        sess = _SessionMCP(self.state, session_id, task_id, role=role)
        await sess.start()
        self._sessions[session_id] = sess
        log.info(
            f"mcp: registered session {session_id[:8]} "
            f"(role={role}, task={task_id[:8] if task_id else 'none'})"
        )
        return sess

    def unregister_session(self, session_id: str):
        sess = self._sessions.pop(session_id, None)
        if sess:
            # Don't await — let the cancellation propagate on the loop.
            asyncio.create_task(sess.stop())
            log.info(f"mcp: unregistered session {session_id[:8]}")

    async def notify_note_inbox(self, session_id: str):
        sess = self._sessions.get(session_id)
        if not sess:
            return
        await sess.notify_note_inbox()

    async def notify_governance_inbox(self, session_id: str):
        """Phase 2: tell an orchestrator session a new evaluate_tool_call
        request is waiting. Mirrors notify_note_inbox but addresses
        `governance://inbox`, which only orchestrator-role sessions expose."""
        sess = self._sessions.get(session_id)
        if not sess:
            return
        await sess.notify_governance_inbox()

    async def notify_task_changed(self, session_id: str):
        """Phase 2.5: tell a (re)assigned worker its `task://current` changed."""
        sess = self._sessions.get(session_id)
        if not sess:
            return
        await sess.notify_task_changed()

    def _build_app(self):
        """Build the ASGI app that routes per-session MCP URLs.

        Dispatch is done at the raw-ASGI layer so we can hand off `(scope,
        receive, send)` cleanly to each per-session FastMCP. Starlette's
        path-templated routes pass a `Request` object instead, which is
        not what the downstream ASGI app expects.

        Each per-session FastMCP exposes its `_http_app` (the
        streamable_http_app result), which we serve directly after path
        rewriting. The session manager's run() context is held open by a
        background task started in `_SessionMCP.start()`.
        """
        manager = self

        async def dispatch(scope, receive, send):
            if scope["type"] != "http":
                if scope["type"] == "lifespan":
                    # Drain lifespan events so uvicorn doesn't hang. We
                    # don't forward lifespan to per-session sub-apps —
                    # their session managers are run by _SessionMCP.start()
                    # on a dedicated task that outlives any single request.
                    try:
                        while True:
                            msg = await receive()
                            if msg["type"] == "lifespan.startup":
                                await send({"type": "lifespan.startup.complete"})
                            elif msg["type"] == "lifespan.shutdown":
                                await send({"type": "lifespan.shutdown.complete"})
                                return
                    except asyncio.CancelledError:
                        # Server is shutting down — clean exit.
                        return
                return

            path = scope["path"]
            if path == "/health":
                resp = PlainTextResponse("ok")
                await resp(scope, receive, send)
                return

            # Phase 2: governance evaluate endpoint for the PreToolUse hook.
            # Loopback-only (the whole MCP server binds 127.0.0.1).
            if path == "/governance/evaluate" and scope["method"] == "POST":
                await _governance_evaluate_asgi(manager.state, scope, receive, send)
                return

            # Worker context monitoring: the statusLine hook reports the
            # worker's own context-window usage here. Loopback-only.
            if path == "/context/report" and scope["method"] == "POST":
                await _context_report_asgi(manager.state, scope, receive, send)
                return

            # /mcp/sessions/<session_id>/<anything>
            prefix = "/mcp/sessions/"
            if not path.startswith(prefix):
                resp = PlainTextResponse("not found", status_code=404)
                await resp(scope, receive, send)
                return

            remainder = path[len(prefix):]
            session_id, sep, sub_path = remainder.partition("/")
            if not session_id:
                resp = PlainTextResponse("missing session_id", status_code=400)
                await resp(scope, receive, send)
                return

            sess = manager._sessions.get(session_id)
            if sess is None:
                resp = PlainTextResponse(
                    f"unknown session {session_id}", status_code=404,
                )
                await resp(scope, receive, send)
                return

            # Strip the per-session prefix so FastMCP sees its own root.
            new_scope = dict(scope)
            new_scope["path"] = "/" + sub_path if sub_path else "/"
            new_scope["raw_path"] = new_scope["path"].encode("latin-1")
            await sess._http_app(new_scope, receive, send)

        return dispatch

    async def serve(self, host: str = "127.0.0.1", port: int = 8765):
        """Run the loopback MCP HTTP server until cancelled."""
        if host not in ("127.0.0.1", "localhost", "::1"):
            log.warning(f"mcp: refusing to bind non-loopback host {host}; forcing 127.0.0.1")
            host = "127.0.0.1"
        app = self._build_app()
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
            lifespan="on",
        )
        server = uvicorn.Server(config)
        log.info(f"mcp: serving on http://{host}:{port}/mcp/sessions/<id>/")
        try:
            await server.serve()
        except asyncio.CancelledError:
            log.info("mcp: shutting down")
            server.should_exit = True
            raise


async def _governance_evaluate_asgi(state, scope, receive, send) -> None:
    """Raw-ASGI shim for POST /governance/evaluate.

    Bypasses Starlette's routing layer because the surrounding dispatcher
    in `_build_app` already operates at the ASGI scope level. Reads the
    JSON body, dispatches to `GovernanceManager.evaluate`, returns JSON.
    """
    # Body
    body = b""
    while True:
        msg = await receive()
        if msg["type"] != "http.request":
            continue
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break

    try:
        payload = json.loads(body or b"{}")
    except Exception:
        payload = {}

    mgr = getattr(state, "governance_manager", None)
    if mgr is None:
        result = {"decision": "escalate", "reason": "governance_not_initialized"}
        status = 503
    else:
        try:
            result = await mgr.evaluate(
                session_id=payload.get("session_id", ""),
                project_id=payload.get("project_id"),
                tool=payload.get("tool", ""),
                tool_input=payload.get("tool_input", {}),
                agent_name=payload.get("agent_name"),
            )
            status = 200
        except Exception as e:
            log.exception("governance: evaluate failed")
            result = {"decision": "escalate", "reason": f"governance_error: {e}"}
            status = 500

    response = json.dumps(result).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(response)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": response})


async def _context_report_asgi(state, scope, receive, send) -> None:
    """Raw-ASGI shim for POST /context/report.

    The statusLine hook posts `{session_id, used_tokens, window_size?}`.
    We compute a reading via `context_meter` and store only the latest
    sample per session on the daemon state (the hook fires often, so we
    throttle by keeping just the most recent). Loopback-only, no auth.
    """
    body = b""
    while True:
        msg = await receive()
        if msg["type"] != "http.request":
            continue
        body += msg.get("body", b"")
        if not msg.get("more_body"):
            break

    try:
        payload = json.loads(body or b"{}")
    except Exception:
        payload = {}

    session_id = payload.get("session_id") or ""
    if not session_id:
        result = {"ok": False, "error": "missing session_id"}
        status = 400
    else:
        try:
            from orchestratia_agent.context_meter import make_reading, DEFAULT_WINDOW_SIZE
            window = payload.get("window_size") or DEFAULT_WINDOW_SIZE
            reading = make_reading(payload.get("used_tokens", 0), window)
            cache = getattr(state, "context_readings", None)
            if cache is None:
                cache = {}
                state.context_readings = cache
            # Throttle: keep only the latest reading per session.
            cache[session_id] = reading.to_dict()
            result = {"ok": True, **reading.to_dict()}
            status = 200
        except Exception as e:
            log.exception("context: report failed")
            result = {"ok": False, "error": f"context_error: {e}"}
            status = 500

    response = json.dumps(result).encode("utf-8")
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(response)).encode("ascii")),
        ],
    })
    await send({"type": "http.response.body", "body": response})


def mcp_url_for_session(host: str, port: int, session_id: str) -> str:
    """Return the URL a session's MCP config should point at."""
    return f"http://{host}:{port}/mcp/sessions/{session_id}/mcp"


def write_mcp_config(
    working_dir: str,
    host: str,
    port: int,
    session_id: str,
    agent_type: str | None = None,
) -> tuple[str, str | None]:
    """Write the MCP config file appropriate to the session's agent type.

    Dispatches to the per-format mergers in `agent_registry`. Foreign keys
    in any existing config file are preserved — only the `orchestratia`
    entry is upserted.

    Returns `(status, path)` where status ∈
    {written, merged, workspace_readonly, unsupported, skipped}, matching
    the `mcp_status` value the hub records on the session row. `path` is
    the file we wrote (or attempted to write) or None if the workspace dir
    didn't exist at all.
    """
    from orchestratia_agent.agent_registry import (
        AgentType,
        WriteStatus,
        coerce_agent_type,
        detect_from_workspace,
        merge_config,
    )

    if not working_dir or not os.path.isdir(working_dir):
        log.debug(f"mcp: skipping config (workspace not a dir: {working_dir!r})")
        return (WriteStatus.SKIPPED.value, None)

    # Resolve the agent: explicit hub-supplied type wins, otherwise detect
    # from workspace markers (.gemini/, .codex/, CLAUDE.md, …), otherwise
    # fall back to the registry default (claude_code).
    if agent_type:
        agent = coerce_agent_type(agent_type)
    else:
        agent = detect_from_workspace(working_dir) or AgentType.CLAUDE_CODE

    url = mcp_url_for_session(host, port, session_id)
    status, path = merge_config(working_dir, agent, url)
    return (status.value, str(path) if path else None)


def write_session_mcp_config(
    host: str,
    port: int,
    session_id: str,
    home: str | None = None,
) -> str | None:
    """Write a per-session Claude Code MCP config to a unique path; return it.

    cwd-collision fix: the per-format writers (write_mcp_config) drop a
    `.mcp.json` into the session's working directory, so two sessions sharing a
    cwd clobber each other's route — a worker's config can overwrite an
    orchestrator's, silently handing the orchestrator the worker toolset. This
    writes an isolated config keyed by session_id under ~/.orchestratia/mcp/,
    to be passed via `claude --mcp-config <path> --strict-mcp-config` so the
    session uses ONLY its own route regardless of what's in its cwd.

    Claude-Code-format only (the --mcp-config flag is Claude-specific). Returns
    the path written, or None on failure (caller falls back to cwd config).
    """
    try:
        url = mcp_url_for_session(host, port, session_id)
        base = os.path.join(home or os.path.expanduser("~"), ".orchestratia", "mcp")
        os.makedirs(base, exist_ok=True)
        path = os.path.join(base, f"{session_id}.json")
        doc = {"mcpServers": {"orchestratia": {"type": "http", "url": url}}}
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(doc, f, indent=2)
        os.replace(tmp, path)
        return path
    except Exception:
        log.exception("mcp: failed to write per-session MCP config")
        return None
