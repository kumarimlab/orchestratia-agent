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
    parser.add_argument("--pty-host", action="store_true", help="Start the PTY host server (Windows only)")
    args = parser.parse_args()

    setup_logging(debug=args.debug, verbose=args.verbose)

    state = DaemonState()
    state.config_path = args.config
    state.backend = get_session_backend()

    # Async connect for pty-host backend (TCP handshake)
    if hasattr(state.backend, "connect"):
        if not await state.backend.connect():
            log.warning("pty-host connect failed, falling back to direct ConPTY")
            from orchestratia_agent.session_windows import WindowsSessionBackend
            state.backend = WindowsSessionBackend()

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
    if state.backend.supports_persistence():
        backend_name = type(state.backend).__name__
        if "PtyHost" in backend_name:
            persist_label = "yes (pty-host)"
        else:
            persist_label = "yes (tmux)"
    else:
        persist_label = "no"
    log.info(f"Persistence: {persist_label}")
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
    if ctypes.windll.kernel32.AttachConsole(ATTACH_PARENT_PROCESS):
        # Reopen stdout/stderr to the attached console
        try:
            sys.stdout = open("CONOUT$", "w")
            sys.stderr = open("CONOUT$", "w")
        except OSError:
            pass


def entry_point():
    """Entry point for console_scripts and legacy shims."""
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
