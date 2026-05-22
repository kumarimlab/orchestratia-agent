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
    """One FastMCP instance scoped to a single Orchestratia session."""

    def __init__(self, state: DaemonState, session_id: str, task_id: str | None):
        self.state = state
        self.session_id = session_id
        self.task_id = task_id
        self.mcp = FastMCP(
            name=f"orchestratia-session-{session_id[:8]}",
            instructions=(
                "Orchestratia governance + coordination plane for this session. "
                "Use `task://current` to inspect your assigned task, "
                "`notes://inbox` to see pending notes, and the post_note / "
                "complete_task / request_intervention tools to act."
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
        self._register_resources()
        self._register_tools()
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

    # ── Notifications ────────────────────────────────────────────────

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


class MCPServerManager:
    """Manages per-session MCP servers and the loopback ASGI app hosting them."""

    def __init__(self, state: DaemonState):
        self.state = state
        self._sessions: dict[str, _SessionMCP] = {}

    async def register_session(self, session_id: str, task_id: str | None) -> _SessionMCP:
        if session_id in self._sessions:
            log.debug(f"mcp: session {session_id[:8]} already registered")
            return self._sessions[session_id]
        sess = _SessionMCP(self.state, session_id, task_id)
        await sess.start()
        self._sessions[session_id] = sess
        log.info(f"mcp: registered session {session_id[:8]} (task={task_id[:8] if task_id else 'none'})")
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


def mcp_url_for_session(host: str, port: int, session_id: str) -> str:
    """Return the URL a Claude session's .mcp.json should point at."""
    return f"http://{host}:{port}/mcp/sessions/{session_id}/mcp"


def write_mcp_config(working_dir: str, host: str, port: int, session_id: str) -> str | None:
    """Write `.mcp.json` into the session workspace pointing at this daemon.

    Returns the path written, or None if the workspace dir is missing.
    """
    import os
    if not working_dir or not os.path.isdir(working_dir):
        log.debug(f"mcp: skipping .mcp.json (workspace not a dir: {working_dir!r})")
        return None
    config_path = os.path.join(working_dir, ".mcp.json")
    # Don't clobber a user-provided .mcp.json with custom servers — merge by
    # inserting/overwriting only the 'orchestratia' key, leaving the rest alone.
    existing: dict[str, Any] = {}
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                existing = json.load(f) or {}
        except Exception:
            log.warning(f"mcp: existing {config_path} unreadable; overwriting")
            existing = {}
    servers = existing.get("mcpServers", {})
    servers["orchestratia"] = {
        "type": "http",
        "url": mcp_url_for_session(host, port, session_id),
    }
    existing["mcpServers"] = servers
    try:
        with open(config_path, "w") as f:
            json.dump(existing, f, indent=2)
        log.info(f"mcp: wrote {config_path}")
        return config_path
    except OSError as e:
        log.warning(f"mcp: failed to write {config_path}: {e}")
        return None
