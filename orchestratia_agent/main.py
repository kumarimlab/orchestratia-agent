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
    if sys.platform == "win32":
        try:
            from orchestratia_agent.conpty import _use_bundled
            log.info(f"ConPTY: {'bundled conpty.dll + OpenConsole.exe' if _use_bundled else 'kernel32 (system conhost.exe)'}")
        except ImportError:
            pass

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
    meipass = getattr(sys, '_MEIPASS', None)
    if meipass:
        print(f"_MEIPASS: {meipass}")
    print(f"CWD: {os.getcwd()}")
    print()

    if sys.platform != "win32":
        print("This test is Windows-only.")
        return

    # ── Test 0: Bundled ConPTY DLL detection ──────────────────────────
    print("=" * 60)
    print("TEST 0: Bundled ConPTY DLL detection")
    print("=" * 60)
    try:
        from orchestratia_agent.conpty import (
            _use_bundled, _conpty_dll, _find_bundled_conpty_dll,
            _CreatePseudoConsole, _ResizePseudoConsole, _ClosePseudoConsole,
        )
        dll_path = _find_bundled_conpty_dll()
        print(f"  Bundled conpty.dll path: {dll_path or 'NOT FOUND'}")
        print(f"  Using bundled DLL: {_use_bundled}")
        if _use_bundled:
            dll_dir = os.path.dirname(dll_path)
            openconsole = os.path.join(dll_dir, "OpenConsole.exe")
            print(f"  OpenConsole.exe: {openconsole}")
            print(f"  OpenConsole.exe exists: {os.path.isfile(openconsole)}")
            if os.path.isfile(openconsole):
                oc_size = os.path.getsize(openconsole)
                print(f"  OpenConsole.exe size: {oc_size} bytes")
            # Verify the DLL actually exports the Conpty-prefixed functions
            import ctypes
            try:
                fn = ctypes.cast(
                    ctypes.windll.kernel32.GetProcAddress(
                        ctypes.c_void_p(_conpty_dll._handle),
                        b"ConptyCreatePseudoConsole"
                    ),
                    ctypes.c_void_p
                )
                print(f"  ConptyCreatePseudoConsole export: {'FOUND' if fn.value else 'NOT FOUND'} (0x{fn.value or 0:X})")
            except Exception as e:
                print(f"  Export check: {e}")
            print(f"  _CreatePseudoConsole points to: {_CreatePseudoConsole}")
            print(f"  PASS: Bundled ConPTY loaded")
        else:
            print(f"  INFO: Will use kernel32 (system conhost.exe)")
            print(f"  NOTE: Bundle conpty.dll + OpenConsole.exe to fix Win 11 24H2/25H2")
    except Exception as e:
        import traceback
        print(f"  ERROR: {e}")
        traceback.print_exc()
    print()

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

    # ── Test 2: ConPTY via ConPtyProcess + process monitoring ────────
    # THIS IS THE KEY TEST. It uses ConPtyProcess.spawn() which routes
    # through the bundled conpty.dll. We monitor which console host
    # process spawns (OpenConsole.exe vs conhost.exe) to verify the
    # bundled DLL is actually used.
    print("=" * 60)
    print("TEST 2: ConPTY via ConPtyProcess (bundled DLL path)")
    print("       + process monitoring (OpenConsole vs conhost)")
    print("=" * 60)
    try:
        import psutil
        from orchestratia_agent.conpty import ConPtyProcess

        # Snapshot console host processes BEFORE creating ConPTY
        def get_console_hosts():
            hosts = {"conhost.exe": set(), "OpenConsole.exe": set()}
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    name = proc.info['name']
                    if name in hosts:
                        hosts[name].add(proc.info['pid'])
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return hosts

        before = get_console_hosts()
        print(f"  BEFORE: conhost.exe PIDs={before['conhost.exe'] or 'none'}")
        print(f"  BEFORE: OpenConsole.exe PIDs={before['OpenConsole.exe'] or 'none'}")

        # Spawn via ConPtyProcess (uses bundled DLL if available)
        print(f"  Using bundled DLL: {_use_bundled}")
        print(f"  Spawning: cmd.exe /c echo ConPTY_WORKS")
        proc = ConPtyProcess.spawn("cmd.exe /c echo ConPTY_WORKS", cols=80, rows=25)
        print(f"  Child PID: {proc.pid}")

        # Brief pause then snapshot AFTER
        time.sleep(1)
        after = get_console_hosts()
        new_conhost = after["conhost.exe"] - before["conhost.exe"]
        new_openconsole = after["OpenConsole.exe"] - before["OpenConsole.exe"]
        print(f"  AFTER:  new conhost.exe PIDs={new_conhost or 'none'}")
        print(f"  AFTER:  new OpenConsole.exe PIDs={new_openconsole or 'none'}")

        if new_openconsole:
            print(f"  >>> OpenConsole.exe SPAWNED — bundled DLL is working! <<<")
        elif new_conhost:
            print(f"  >>> conhost.exe spawned — bundled DLL fell back to system conhost! <<<")
            print(f"  >>> This means conpty.dll couldn't find OpenConsole.exe next to it <<<")
        else:
            print(f"  >>> No new console host found — ConPTY may have failed silently <<<")

        # Wait for process and check output
        for i in range(20):
            if not proc.isalive():
                break
            time.sleep(0.25)

        exit_code = proc.exitstatus
        alive = proc.isalive()
        print(f"  Child alive: {alive}, exit_code: {exit_code}", end="")
        if exit_code is not None and exit_code != 0:
            print(f" (0x{exit_code & 0xFFFFFFFF:08X})")
        else:
            print()

        avail = proc.peek()
        print(f"  Bytes in output pipe: {avail}")

        if avail > 0:
            data = proc.read(avail)
            print(f"  Output: {data[:200]!r}")
            if "ConPTY_WORKS" in data:
                print(f"  PASS: ConPTY I/O works with bundled DLL!")
            else:
                print(f"  PARTIAL: Got output but not expected string")
        else:
            if exit_code is not None and (exit_code & 0xFFFFFFFF) == 0xC0000142:
                print(f"  FAIL: Child crashed with STATUS_DLL_INIT_FAILED (0xC0000142)")
                print(f"  >>> Bundled OpenConsole.exe did NOT fix the issue <<<")
                if new_conhost and not new_openconsole:
                    print(f"  >>> REASON: conpty.dll fell back to system conhost.exe <<<")
                    print(f"  >>> Check that OpenConsole.exe is in same dir as conpty.dll <<<")
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
        import psutil
        from orchestratia_agent.conpty import ConPtyProcess

        before = get_console_hosts()
        proc = ConPtyProcess.spawn("cmd.exe", cols=80, rows=25)
        print(f"  PID: {proc.pid}")
        print(f"  Using bundled: {proc.using_bundled_conpty}")

        time.sleep(1)
        after = get_console_hosts()
        new_oc = after["OpenConsole.exe"] - before["OpenConsole.exe"]
        new_ch = after["conhost.exe"] - before["conhost.exe"]
        if new_oc:
            print(f"  Console host: OpenConsole.exe (PID {new_oc})")
        elif new_ch:
            print(f"  Console host: conhost.exe (PID {new_ch}) — SYSTEM FALLBACK!")

        # Wait for shell output
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

    # ── Test 4: Verify DLL file paths in _MEIPASS ────────────────────
    print("=" * 60)
    print("TEST 4: File layout verification")
    print("=" * 60)
    try:
        from orchestratia_agent.conpty import _find_bundled_conpty_dll
        dll_path = _find_bundled_conpty_dll()
        if dll_path:
            dll_dir = os.path.dirname(dll_path)
            print(f"  conpty.dll dir: {dll_dir}")
            print(f"  Contents:")
            for f in os.listdir(dll_dir):
                fpath = os.path.join(dll_dir, f)
                size = os.path.getsize(fpath) if os.path.isfile(fpath) else 0
                print(f"    {f} ({size} bytes)")
        else:
            print(f"  No bundled conpty.dll found")

        # Also check _MEIPASS root
        meipass = getattr(sys, '_MEIPASS', None)
        if meipass:
            print(f"\n  _MEIPASS root: {meipass}")
            conpty_dir = os.path.join(meipass, "conpty")
            if os.path.isdir(conpty_dir):
                print(f"  conpty/ subdir exists: YES")
                for f in os.listdir(conpty_dir):
                    fpath = os.path.join(conpty_dir, f)
                    size = os.path.getsize(fpath) if os.path.isfile(fpath) else 0
                    print(f"    {f} ({size} bytes)")
            else:
                print(f"  conpty/ subdir exists: NO — files may not be bundled!")
    except Exception as e:
        print(f"  ERROR: {e}")
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
