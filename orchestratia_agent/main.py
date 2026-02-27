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
    args = parser.parse_args()

    setup_logging(debug=args.debug, verbose=args.verbose)

    state = DaemonState()
    state.config_path = args.config
    state.backend = get_session_backend()

    if args.register:
        state.config = ensure_config_for_register(state.config_path, args.register)
        state.hub_url = state.config.get("hub_url", "").rstrip("/")
        if not state.hub_url:
            log.error("hub_url not set in config")
            sys.exit(1)

        async with httpx.AsyncClient(timeout=30) as client:
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

    log.info(f"Orchestratia Agent Daemon v{__version__} starting...")
    log.info(f"Hub URL: {state.hub_url}")
    log.info(f"Server name: {state.config.get('server_name', platform.node())}")
    log.info(f"Platform: {platform.system()} {platform.release()}")
    log.info(f"Session backend: {type(state.backend).__name__}")
    log.info(f"Persistence: {'yes (tmux)' if state.backend.supports_persistence() else 'no'}")

    async with httpx.AsyncClient(timeout=30) as client:
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

        log.info("Agent daemon running. Heartbeats every 30s, WS auto-reconnect enabled.")

        try:
            await asyncio.gather(
                heartbeat_loop(client, state),
                ws_connection_loop(state),
                idle_note_flush_loop(state),
            )
        finally:
            await cleanup_sessions(state)

    log.info("Agent daemon stopped.")


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
    print(f"CWD: {os.getcwd()}")
    print()

    if sys.platform != "win32":
        print("This test is Windows-only.")
        return

    # Test 1: Basic subprocess (no ConPTY)
    print("=" * 60)
    print("TEST 1: subprocess.Popen (no ConPTY)")
    print("=" * 60)
    try:
        p = subprocess.Popen(
            "cmd.exe /c echo hello",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        out, _ = p.communicate(timeout=5)
        print(f"  Result: exit_code={p.returncode}")
        print(f"  Output: {out.strip()}")
        if p.returncode == 0:
            print("  PASS: Basic subprocess works")
        else:
            print(f"  FAIL: exit_code={p.returncode}")
    except Exception as e:
        print(f"  FAIL: {e}")
    print()

    # Test 2: subprocess with CREATE_NEW_CONSOLE
    print("=" * 60)
    print("TEST 2: subprocess with CREATE_NEW_CONSOLE")
    print("=" * 60)
    try:
        p = subprocess.Popen(
            "cmd.exe /c echo hello & timeout /t 2 >nul",
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )
        time.sleep(1)
        alive = p.poll() is None
        print(f"  Alive after 1s: {alive}")
        p.terminate()
        p.wait(timeout=3)
        print(f"  Result: exit_code={p.returncode}")
        if alive:
            print("  PASS: CREATE_NEW_CONSOLE works")
        else:
            print(f"  FAIL: Process died immediately (exit_code={p.returncode})")
    except Exception as e:
        print(f"  FAIL: {e}")
    print()

    # Test 3: pywinpty ConPTY
    print("=" * 60)
    print("TEST 3: pywinpty PtyProcess.spawn (ConPTY)")
    print("=" * 60)
    try:
        from winpty import PtyProcess
        print(f"  pywinpty imported OK")

        for shell_name, shell_cmd in [("cmd.exe", "cmd.exe"), ("powershell", "powershell.exe")]:
            print(f"\n  --- Spawning {shell_name} ---")
            try:
                proc = PtyProcess.spawn(shell_cmd, dimensions=(25, 80))
                print(f"  PID: {proc.pid}")
                time.sleep(1)
                alive = proc.isalive()
                print(f"  Alive after 1s: {alive}")

                if alive:
                    try:
                        data = proc.read(4096)
                        print(f"  Read {len(data)} chars: {data[:100]!r}")
                    except Exception as e:
                        print(f"  Read error: {e}")
                    proc.terminate(force=True)
                    print(f"  PASS: {shell_name} ConPTY works")
                else:
                    exit_code = getattr(proc, "exitstatus", None)
                    print(f"  FAIL: Died immediately, exit_code={exit_code}", end="")
                    if exit_code:
                        print(f" (0x{exit_code:08X})")
                    else:
                        print()
            except Exception as e:
                print(f"  FAIL: {e}")
    except ImportError as e:
        print(f"  FAIL: Cannot import pywinpty: {e}")
    except Exception as e:
        print(f"  FAIL: {e}")
    print()

    # Test 4: Native ConPTY via ctypes (our implementation)
    print("=" * 60)
    print("TEST 4: Native ConPTY via ctypes (conpty.py)")
    print("=" * 60)
    try:
        from orchestratia_agent.conpty import ConPtyProcess
        print("  conpty module imported OK")

        for shell_name, shell_cmd in [("cmd.exe", "cmd.exe"), ("powershell", "powershell.exe")]:
            print(f"\n  --- Spawning {shell_name} ---")
            try:
                proc = ConPtyProcess.spawn(shell_cmd, cols=80, rows=25)
                print(f"  PID: {proc.pid}")
                time.sleep(1)
                alive = proc.isalive()
                print(f"  Alive after 1s: {alive}")

                if alive:
                    try:
                        data = proc.read(4096)
                        print(f"  Read {len(data)} chars: {data[:100]!r}")
                    except Exception as e:
                        print(f"  Read error: {e}")
                    proc.terminate(force=True)
                    proc.close()
                    print(f"  PASS: {shell_name} native ConPTY works")
                else:
                    exit_code = proc.exitstatus
                    print(f"  FAIL: Died immediately, exit_code={exit_code}", end="")
                    if exit_code:
                        print(f" (0x{exit_code:08X})")
                    else:
                        print()
                    proc.close()
            except Exception as e:
                print(f"  FAIL: {e}")
    except Exception as e:
        print(f"  FAIL: {e}")
    print()
    print("Diagnostic complete.")


def entry_point():
    """Entry point for console_scripts and legacy shims."""
    if "--test-pty" in sys.argv:
        _test_pty()
        return
    asyncio.run(main())


if __name__ == "__main__":
    entry_point()
