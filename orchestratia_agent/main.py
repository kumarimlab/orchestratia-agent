"""Main entry point for the Orchestratia Agent Daemon."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import platform
import signal
import sys
from dataclasses import dataclass, field

import httpx

from orchestratia_agent import __version__
from orchestratia_agent.config import (
    default_config_path,
    ensure_config_for_register,
    load_config,
)
from orchestratia_agent.hub import (
    _inject_text,
    cleanup_sessions,
    heartbeat_loop,
    pending_pulls_loop,
    pending_uploads_loop,
    permlog_flush_loop,
    register_with_hub,
    ws_connection_loop,
)
from orchestratia_agent.logging_config import setup_logging
from orchestratia_agent.session import ManagedSession, get_session_backend
from orchestratia_agent.session_base import SessionBackend

log = logging.getLogger("orchestratia-agent")


@dataclass
class DaemonState:
    """Central state passed to all functions instead of module globals."""
    config: dict = field(default_factory=dict)
    config_path: str = ""
    api_key: str = ""
    hub_url: str = ""
    running: bool = True
    ws_connection: object | None = None
    active_sessions: dict[str, ManagedSession] = field(default_factory=dict)
    backend: SessionBackend | None = None
    pending_notes: dict[str, list] = field(default_factory=dict)
    # MCP server hosted on loopback for local Claude sessions. None until the
    # daemon starts the bootstrap task in main(). mcp_port/enabled mirror the
    # config knobs so call-sites don't have to dig through state.config.
    mcp_manager: object | None = None
    mcp_port: int = 8765
    mcp_enabled: bool = True
    # Phase 2 governance: orchestrates the PreToolUse hook ↔ hub ↔ orchestrator
    # MCP session round trip. Initialized alongside mcp_manager. None when
    # MCP is disabled.
    governance_manager: object | None = None
    # Phase 2.5 worker-readiness preflight: agent_type → readiness string,
    # populated by WorkerPreflight.probe_all() and shipped on the heartbeat
    # so spawn_worker only targets servers that can actually launch workers.
    worker_ready: dict = field(default_factory=dict)
    worker_preflight: object | None = None
    # Worker context-window monitoring: latest reading per session, reported
    # by the statusLine hook to the loopback POST /context/report endpoint.
    # Throttled to the latest sample per session_id (the hook fires often).
    context_readings: dict = field(default_factory=dict)


async def main():
    parser = argparse.ArgumentParser(
        description="Orchestratia Agent Daemon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  orchestratia-agent --register orcreg_xxx   Register with hub\n"
            "  orchestratia-agent                         Start daemon (uses default config)\n"
            "  orchestratia-agent --config /path/to.yaml  Start with custom config\n"
            "  orchestratia-agent --debug                 Start with debug logging\n"
        ),
    )
    parser.add_argument(
        "--config",
        default=default_config_path(),
        help=f"Config file path (default: {default_config_path()})",
    )
    parser.add_argument("--register", metavar="TOKEN", help="One-time registration token")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", action="version", version=f"orchestratia-agent {__version__}")
    parser.add_argument("--pty-host", action="store_true", help="Start the PTY host server (Windows only)")
    args = parser.parse_args()

    setup_logging(debug=args.debug, verbose=args.verbose)

    state = DaemonState()
    state.config_path = args.config

    if args.register:
        state.config = ensure_config_for_register(state.config_path, args.register)
        state.hub_url = state.config.get("hub_url", "").rstrip("/")
        if not state.hub_url:
            log.error("hub_url not set in config")
            sys.exit(1)

        from orchestratia_agent.tls import httpx_verify
        async with httpx.AsyncClient(timeout=30, verify=httpx_verify(state=state)) as client:
            key = await register_with_hub(client, state)
            if not key:
                log.error("Registration failed.")
                sys.exit(1)
            log.info("Registration successful. Start the daemon with: orchestratia-agent")
            if sys.platform == "win32":
                log.info("  Or install as service: see scripts/install-windows.ps1")
            elif sys.platform == "darwin":
                log.info("  Or via launchd: see scripts/install-macos.sh")
            else:
                log.info("  Or via systemd: sudo systemctl start orchestratia-agent")
        return

    elif os.path.exists(state.config_path):
        state.config = load_config(state.config_path)
    else:
        log.error(f"Config file not found: {state.config_path}")
        log.error("Use --register TOKEN to set up, or create the config manually.")
        log.error(f"  Expected path: {state.config_path}")
        sys.exit(1)

    state.hub_url = state.config.get("hub_url", "").rstrip("/")

    if not state.hub_url:
        log.error("hub_url not set in config")
        sys.exit(1)

    # MCP server config (loopback Claude-facing plane). Disable with
    # `mcp_enabled: false` in config to fall back to PTY-only delivery
    # for compliance/debug, or to free the port.
    mcp_cfg = state.config.get("mcp", {}) or {}
    state.mcp_enabled = bool(mcp_cfg.get("enabled", True))
    state.mcp_port = int(mcp_cfg.get("port", 8765))

    # Set up session backend (pty-host on Windows, tmux on Linux)
    state.backend = get_session_backend()
    if hasattr(state.backend, "connect"):
        if not await state.backend.connect():
            log.warning("pty-host connect failed, falling back to direct ConPTY")
            from orchestratia_agent.session_windows import WindowsSessionBackend
            state.backend = WindowsSessionBackend()

    log.info(f"Orchestratia Agent Daemon v{__version__} starting...")
    log.info(f"Hub URL: {state.hub_url}")
    log.info(f"Server name: {state.config.get('server_name', platform.node())}")
    log.info(f"Platform: {platform.system()} {platform.release()}")
    log.info(f"Session backend: {type(state.backend).__name__}")
    if state.backend.supports_persistence():
        backend_name = type(state.backend).__name__
        if "PtyHost" in backend_name:
            persist_label = "yes (pty-host)"
        else:
            persist_label = "yes (tmux)"
    else:
        persist_label = "no"
    log.info(f"Persistence: {persist_label}")
    from orchestratia_agent.tls import httpx_verify
    async with httpx.AsyncClient(timeout=30, verify=httpx_verify(state=state)) as client:
        key = await register_with_hub(client, state)
        if not key:
            log.error("Failed to obtain API key. Exiting.")
            sys.exit(1)

        # Signal handling (cross-platform)
        loop = asyncio.get_event_loop()

        def handle_signal(sig, frame):
            sig_name = signal.Signals(sig).name if hasattr(signal, "Signals") else str(sig)
            log.info(f"Received {sig_name}, shutting down...")
            state.running = False
            # Close the WebSocket to unblock ws.recv()
            ws = state.ws_connection
            if ws:
                asyncio.ensure_future(ws.close())

        signal.signal(signal.SIGINT, handle_signal)
        if sys.platform == "win32":
            signal.signal(signal.SIGBREAK, handle_signal)
        else:
            signal.signal(signal.SIGTERM, handle_signal)
            # SIGHUP rescans every configured repo and rewrites MCP configs.
            # Useful after the user edits config.yaml (`repos:`) without
            # wanting a full daemon restart. POSIX-only.
            def _sighup_rescan(sig, frame):
                from orchestratia_agent.workspace_scan import scan_and_write
                log.info("SIGHUP received — rescanning configured repos for MCP configs")
                try:
                    scan_and_write(state)
                except Exception:
                    log.exception("workspace-scan on SIGHUP failed")
                # Re-probe worker-readiness too — handy right after a human
                # installs/authenticates a CLI on this server.
                if state.worker_preflight is not None:
                    try:
                        asyncio.ensure_future(state.worker_preflight.probe_all())
                    except Exception:
                        log.exception("preflight re-probe on SIGHUP failed")
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, _sighup_rescan)

        log.info("Agent daemon running. Heartbeats every 30s, WS auto-reconnect enabled.")

        # Start MCP server (loopback only). Attaching the manager to state
        # makes it visible to hub.py's session_start handler — that's where
        # per-session MCPs are registered and .mcp.json is written.
        # ws_send factory — returns a callable bound to whatever ws_connection
        # is currently live. Used by grant_reconcile_loop because the WS can
        # change across reconnects and we don't want a stale sender captured.
        from orchestratia_agent.hub import grant_reconcile_loop, ws_send as _ws_send_fn

        def _sender_factory():
            async def _send(msg):
                return await _ws_send_fn(state, msg)
            return _send

        background_tasks = [
            heartbeat_loop(client, state),
            ws_connection_loop(state),
            idle_note_flush_loop(state),
            permlog_flush_loop(state),
            pending_uploads_loop(client, state),
            pending_pulls_loop(client, state),
            # Reconcile grant state with hub every 60s. Defensive against
            # missed WS pushes (grant_ssh_access / revoke_grant_access).
            # See _reconcile_grants for the bug class this addresses.
            grant_reconcile_loop(state, _sender_factory),
            # Phase 2.5: probe which agent CLIs can run as workers and keep
            # servers.worker_ready fresh via the heartbeat.
            worker_preflight_loop(state),
            # Phase 2.5: reconcile orchestrator memory files → hub index.
            orchestrator_memory_sync_loop(state),
        ]
        if state.mcp_enabled:
            from orchestratia_agent.mcp_server import MCPServerManager
            from orchestratia_agent.governance_hook import GovernanceManager
            state.mcp_manager = MCPServerManager(state)
            # Phase 2: governance routing manager — must exist before any
            # session registers, so the orchestrator MCP tools can find it.
            state.governance_manager = GovernanceManager(state)
            background_tasks.append(state.mcp_manager.serve(host="127.0.0.1", port=state.mcp_port))
            log.info(f"MCP server enabled on http://127.0.0.1:{state.mcp_port}/mcp/sessions/")

            # Phase 1.5: ensure every configured repo has an MCP config file
            # pointing at us, even for agents started outside the daemon
            # (e.g. user-launched `claude` in their own tmux). Idempotent.
            try:
                from orchestratia_agent.workspace_scan import scan_and_write
                scan_and_write(state)
            except Exception:
                log.exception("workspace-scan at startup failed (continuing without it)")
        else:
            log.info("MCP server disabled by config (mcp.enabled = false)")

        try:
            await asyncio.gather(*background_tasks)
        finally:
            await cleanup_sessions(state)

    log.info("Agent daemon stopped.")


async def orchestrator_memory_sync_loop(state: DaemonState):
    """Reconcile orchestrator memory files → hub index every ~10s.

    Picks up files the user created/edited/deleted by hand (scenarios 6/7)
    and rebuilds the index from the canonical files after a wipe (8/12). Only
    runs for active orchestrator sessions; cheap when the memory dir is empty.
    """
    import httpx
    from orchestratia_agent.orchestrator_memory import scan_memory
    from orchestratia_agent.tls import httpx_verify

    while state.running:
        await asyncio.sleep(10)
        if not state.mcp_manager or not state.mcp_enabled:
            continue
        try:
            mcp_sessions = dict(getattr(state.mcp_manager, "_sessions", {}))
        except Exception:
            continue
        for sid, msess in mcp_sessions.items():
            if getattr(msess, "role", "worker") != "orchestrator":
                continue
            managed = state.active_sessions.get(sid)
            cwd = getattr(managed, "working_dir", None) if managed else None
            if not cwd:
                continue
            try:
                entries = scan_memory(cwd)
                async with httpx.AsyncClient(timeout=15, verify=httpx_verify(state=state)) as client:
                    await client.post(
                        f"{state.hub_url}/api/v1/server/orchestrator/memory/sync",
                        headers={"X-API-Key": state.api_key},
                        json={"orchestrator_session_id": sid, "entries": entries},
                    )
            except Exception:
                log.debug(f"memory: sync for orchestrator {sid[:8]} failed (will retry)")


async def worker_preflight_loop(state: DaemonState):
    """Probe worker-readiness at startup, then refresh every 10 minutes.

    Cheap (binary-presence on the login-shell PATH), so re-running keeps
    servers.worker_ready current when a CLI is installed or authenticated
    after the daemon started — without a restart. Results ride the heartbeat.
    """
    from orchestratia_agent.worker_preflight import WorkerPreflight

    preflight = WorkerPreflight(state)
    state.worker_preflight = preflight
    # Small initial delay so the first heartbeat (which sends worker_ready)
    # doesn't race the probe — a stale-empty first beat is harmless either way.
    await asyncio.sleep(2)
    while state.running:
        try:
            await preflight.probe_all()
        except Exception:
            log.exception("preflight: probe_all failed (will retry)")
        await asyncio.sleep(600)


async def idle_note_flush_loop(state: DaemonState):
    """Check every 2 seconds for idle sessions and deliver queued non-urgent notes."""
    while state.running:
        await asyncio.sleep(2)
        if not state.pending_notes:
            continue

        for session_id in list(state.pending_notes.keys()):
            notes = state.pending_notes.get(session_id, [])
            if not notes:
                state.pending_notes.pop(session_id, None)
                continue

            session = state.active_sessions.get(session_id)
            if not session or session.closed:
                # Session gone — discard notes
                state.pending_notes.pop(session_id, None)
                continue

            if session.is_idle:
                # Deliver all queued notes
                for note in notes:
                    content = note.get("content", "")
                    author = note.get("author", "")
                    message = f"Note from {author}: {content}"
                    _inject_text(session, message, send_enter=True)
                state.pending_notes.pop(session_id, None)
                log.info(f"Flushed {len(notes)} queued note(s) to idle session {session_id[:8]}")


def _test_pty():
    """Diagnostic: test ConPTY session spawning outside the daemon context."""
    import time
    import subprocess

    print(f"orchestratia-agent {__version__} — ConPTY diagnostic")
    print(f"Platform: {platform.system()} {platform.release()}")
    print(f"OS build: {sys.getwindowsversion().build if sys.platform == 'win32' else 'N/A'}")
    print(f"Python: {sys.version}")
    print(f"Executable: {sys.executable}")
    print(f"Frozen: {getattr(sys, 'frozen', False)}")
    print(f"CWD: {os.getcwd()}")
    print()

    if sys.platform != "win32":
        print("This test is Windows-only.")
        return

    # ── Test 1: Basic subprocess (sanity check) ──────────────────────
    print("=" * 60)
    print("TEST 1: subprocess.Popen (no ConPTY, sanity check)")
    print("=" * 60)
    try:
        p = subprocess.Popen(
            "cmd.exe /c echo hello",
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        out, _ = p.communicate(timeout=5)
        print(f"  Output: {out.strip()!r}, exit_code={p.returncode}")
        print(f"  {'PASS' if p.returncode == 0 else 'FAIL'}")
    except Exception as e:
        print(f"  FAIL: {e}")
    print()

    # ── Test 2: ConPTY — short command ───────────────────────────────
    print("=" * 60)
    print("TEST 2: ConPTY via ConPtyProcess (cmd /c echo)")
    print("=" * 60)
    try:
        from orchestratia_agent.conpty import ConPtyProcess

        print(f"  Spawning: cmd.exe /c echo ConPTY_WORKS")
        proc = ConPtyProcess.spawn("cmd.exe /c echo ConPTY_WORKS", cols=80, rows=25)
        print(f"  Child PID: {proc.pid}")

        for i in range(20):
            if not proc.isalive():
                break
            time.sleep(0.25)

        exit_code = proc.exitstatus
        print(f"  Exit code: {exit_code}")

        avail = proc.peek()
        print(f"  Bytes in output pipe: {avail}")

        if avail > 0:
            data = proc.read(avail)
            print(f"  Output: {data[:200]!r}")
            if "ConPTY_WORKS" in data:
                print(f"  PASS: ConPTY I/O works!")
            else:
                print(f"  PARTIAL: Got output but not expected string")
        else:
            print(f"  FAIL: No output in pipe")

        proc.close()
    except Exception as e:
        import traceback
        print(f"  FAIL: {e}")
        traceback.print_exc()
    print()

    # ── Test 3: Interactive shell via ConPtyProcess ───────────────────
    print("=" * 60)
    print("TEST 3: Interactive shell via ConPtyProcess")
    print("=" * 60)
    try:
        from orchestratia_agent.conpty import ConPtyProcess

        proc = ConPtyProcess.spawn("cmd.exe", cols=80, rows=25)
        print(f"  PID: {proc.pid}")

        print(f"  Waiting for shell output...")
        avail = 0
        for i in range(16):
            avail = proc.peek()
            if avail > 0:
                print(f"    [{i*0.5:.1f}s] {avail} bytes available!")
                break
            time.sleep(0.5)
        else:
            print(f"    [8.0s] Still 0 bytes")

        if avail > 0:
            data = proc.read(avail)
            print(f"  Output: {data[:200]!r}")
            print(f"  PASS: Interactive ConPTY shell works!")
        else:
            exit_code = proc.exitstatus
            print(f"  Process alive: {proc.isalive()}")
            if exit_code is not None:
                print(f"  Exit code: {exit_code} (0x{exit_code & 0xFFFFFFFF:08X})")
            print(f"  FAIL: No shell output through ConPTY pipes")

        proc.terminate(force=True)
        proc.close()
    except Exception as e:
        import traceback
        print(f"  FAIL: {e}")
        traceback.print_exc()
    print()

    print("Diagnostic complete.")


def _attach_parent_console():
    """Attach to the parent process's console for interactive output.

    The exe is built with console=False (WINDOWS subsystem) so no
    console window is ever created — essential for daemon mode.
    For interactive commands (--version, --test-pty, --register),
    we attach to the parent's console (cmd.exe / PowerShell) so
    print() output is visible.
    """
    if sys.platform != "win32":
        return
    import ctypes
    ATTACH_PARENT_PROCESS = 0xFFFFFFFF
    # Note: this code path handles console attachment for the rare case
    # where a user invokes the exe via `Start-Process -RedirectStandardOutput`
    # or similar. The common case — a human typing `orchestratia-agent
    # --version` at a PowerShell prompt — is handled by the .cmd/.ps1
    # wrapper shipped alongside the exe (see scripts/windows-wrappers/),
    # because PowerShell's default invocation of a windowed-subsystem exe
    # does not display child stdout at the prompt regardless of what the
    # child does with its handles.
    if ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
        try:
            sys.stdout = open("CONOUT$", "w", buffering=1)
            sys.stderr = open("CONOUT$", "w", buffering=1)
        except OSError:
            pass


def entry_point():
    """Entry point for console_scripts and legacy shims.

    When the exe is invoked as 'orchestratia' (not 'orchestratia-agent'),
    route to the CLI instead of the daemon.  This allows the install script
    to copy orchestratia-agent.exe → orchestratia.exe and have it work as
    the CLI tool automatically.
    """
    # Detect if invoked as "orchestratia" (CLI) vs "orchestratia-agent" (daemon).
    # On Windows the exe name might be orchestratia.exe, orchestratia.EXE, etc.
    exe_name = os.path.basename(sys.executable if getattr(sys, "frozen", False) else sys.argv[0])
    exe_stem = os.path.splitext(exe_name)[0].lower()
    if exe_stem == "orchestratia":
        _attach_parent_console()
        from orchestratia_agent.cli import main as cli_main
        cli_main()
        return

    if "--pty-host" in sys.argv:
        # Must run BEFORE asyncio.run() — pty_host.main() calls asyncio.run() itself
        if sys.platform != "win32":
            print("--pty-host is only available on Windows")
            sys.exit(1)
        from orchestratia_agent.pty_host import main as pty_host_main
        pty_host_main()
        return

    # For interactive commands, attach to parent's console so output is visible.
    # The exe is built with console=False (WINDOWS subsystem) so no console
    # window is ever created — perfect for daemon mode but print() goes
    # nowhere without AttachConsole.
    interactive_flags = {"--version", "--test-pty", "--register", "--help", "-h"}
    if any(flag in sys.argv for flag in interactive_flags):
        _attach_parent_console()

    if "--test-pty" in sys.argv:
        _test_pty()
        return

    # PidfdChildWatcher avoids the SIGCHLD/waitpid race that causes
    # synchronous subprocess.run(input=..., timeout=...) calls inside
    # async contexts to spuriously time out. The default
    # ThreadedChildWatcher calls waitpid(-1, ...) in a background thread,
    # which reaps children spawned by subprocess.run before its own
    # communicate() loop can see them — leaving subprocess.run to wait
    # the full timeout and then try (and fail) to kill an already-reaped
    # PID. We hit this on ssh_setup.py's `sudo tee` calls, where the
    # subprocess completed in milliseconds but Python saw a 10s timeout
    # followed by PermissionError on the kill.
    # PidfdChildWatcher (Python 3.9+, Linux 5.3+) uses pidfd_open(2)
    # instead of SIGCHLD and doesn't reap unowned children.
    if sys.platform == "linux" and hasattr(asyncio, "PidfdChildWatcher"):
        try:
            asyncio.set_child_watcher(asyncio.PidfdChildWatcher())
        except (AttributeError, NotImplementedError, OSError):
            pass  # Older kernel / interpreter — fall back to default

    try:
        asyncio.run(main())
    except Exception:
        # Write crash info to file — essential with console=False on Windows
        # where stderr goes to devnull and crashes are invisible.
        import traceback
        try:
            if sys.platform == "win32":
                crash_dir = os.path.join(
                    os.environ.get("LOCALAPPDATA", "."), "Orchestratia", "logs",
                )
            else:
                crash_dir = os.path.expanduser("~/.local/state/orchestratia/logs")
            os.makedirs(crash_dir, exist_ok=True)
            with open(os.path.join(crash_dir, "crash.log"), "a") as f:
                traceback.print_exc(file=f)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    entry_point()
