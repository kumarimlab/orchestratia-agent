#!/usr/bin/env python3
"""Orchestratia Agent Daemon

Runs on dev servers to:
1. Register with the Orchestratia hub
2. Send heartbeats every 30s with system stats
3. Manage interactive PTY sessions (spawn, I/O relay, resize, close/kill)
4. Relay terminal I/O bidirectionally via WebSocket

The daemon does NOT run Claude autonomously. All sessions are interactive,
controlled by the admin through the web dashboard.
"""

import argparse
import asyncio
import base64
import fcntl
import json
import logging
import os
import platform
import pty
import signal
import ssl
import struct
import sys
import termios
from datetime import datetime
from pathlib import Path

import httpx
import psutil
import websockets
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("orchestratia-agent")

# Globals
config: dict = {}
api_key: str = ""
hub_url: str = ""
running = True

# Shared WebSocket reference - updated on reconnect, read by session readers
ws_connection = None
ws_lock = asyncio.Lock() if False else None  # Initialized in main()

# Active PTY sessions: session_id -> PTYSession
active_sessions: dict[str, "PTYSession"] = {}


async def ws_send(msg: dict):
    """Send a message on the current WebSocket, silently dropping if disconnected."""
    ws = ws_connection
    if ws and not getattr(ws, "close_code", None):
        try:
            await ws.send(json.dumps(msg))
            return True
        except Exception:
            return False
    return False


class PTYSession:
    """Manages a single PTY session (one spawned process)."""

    def __init__(self, session_id: str, master_fd: int, pid: int):
        self.session_id = session_id
        self.master_fd = master_fd
        self.pid = pid
        self.reader_task: asyncio.Task | None = None
        self.closed = False

    async def start_reader(self):
        """Start async reader that relays PTY output via the shared WebSocket."""
        if self.reader_task and not self.reader_task.done():
            self.reader_task.cancel()
            try:
                await self.reader_task
            except (asyncio.CancelledError, Exception):
                pass
        self.reader_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self):
        """Read from PTY master fd and send to hub as base64.

        Uses the global ws_connection reference so it survives WS reconnections.
        If WS is down, output is silently dropped (same as a real terminal with
        no viewer connected). The PTY process keeps running regardless.
        """
        loop = asyncio.get_event_loop()
        try:
            while not self.closed:
                try:
                    data = await loop.run_in_executor(None, self._blocking_read)
                    if data is None:
                        # EOF - process exited
                        break
                    if data:
                        b64 = base64.b64encode(data).decode("ascii")
                        # Use shared ws_connection - may fail if WS is down, that's OK
                        await ws_send({
                            "type": "session_output",
                            "session_id": self.session_id,
                            "data": b64,
                        })
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    if not self.closed:
                        log.error(f"Session {self.session_id[:8]} read error: {e}")
                    break
        finally:
            # Process ended - report exit
            exit_code = self._wait_for_exit()
            self.closed = True
            try:
                os.close(self.master_fd)
            except OSError:
                pass
            await ws_send({
                "type": "session_closed",
                "session_id": self.session_id,
                "exit_code": exit_code,
            })
            # Remove from active sessions
            active_sessions.pop(self.session_id, None)
            log.info(f"Session {self.session_id[:8]} closed (exit_code={exit_code})")

    def _blocking_read(self) -> bytes | None:
        """Blocking read from master fd (runs in executor)."""
        try:
            data = os.read(self.master_fd, 4096)
            if not data:
                return None  # EOF — child exited
            return data
        except OSError as e:
            import errno
            if e.errno == errno.EIO:
                return None  # EIO means child closed the PTY
            raise  # Re-raise unexpected errors

    def _wait_for_exit(self) -> int | None:
        """Wait for the child process to exit and return exit code."""
        try:
            _, status = os.waitpid(self.pid, os.WNOHANG)
            if os.WIFEXITED(status):
                return os.WEXITSTATUS(status)
            if os.WIFSIGNALED(status):
                return -os.WTERMSIG(status)
        except ChildProcessError:
            pass
        return None

    def is_alive(self) -> bool:
        """Check if the child process is still running."""
        if self.closed:
            return False
        try:
            os.kill(self.pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def write_input(self, data: bytes):
        """Write input data to the PTY."""
        try:
            os.write(self.master_fd, data)
        except OSError as e:
            log.warning(f"Session {self.session_id[:8]} write error: {e}")

    def resize(self, cols: int, rows: int):
        """Resize the PTY terminal."""
        try:
            fcntl.ioctl(
                self.master_fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", rows, cols, 0, 0),
            )
            # Send SIGWINCH to the child process group
            os.killpg(os.getpgid(self.pid), signal.SIGWINCH)
        except (OSError, ProcessLookupError) as e:
            log.warning(f"Session {self.session_id[:8]} resize error: {e}")

    def close_graceful(self):
        """Send SIGHUP to the child process (graceful close)."""
        try:
            os.killpg(os.getpgid(self.pid), signal.SIGHUP)
        except (OSError, ProcessLookupError):
            pass

    def kill_force(self):
        """Send SIGKILL to the child process (force kill)."""
        try:
            os.killpg(os.getpgid(self.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass


def spawn_pty_session(session_id: str, working_directory: str | None, cols: int, rows: int) -> PTYSession | None:
    """Spawn a login shell with a pseudo-terminal.

    The admin gets a plain shell and can run whatever they want:
    claude, git, ls, etc. This is like SSH in a browser.
    """
    # Use the user's default shell, fallback to bash
    user_shell = os.environ.get("SHELL", "/bin/bash")
    if not os.path.isfile(user_shell):
        user_shell = "/bin/bash"

    # Resolve working directory
    cwd = working_directory or os.path.expanduser("~")
    if not os.path.isdir(cwd):
        log.warning(f"Working directory {cwd} doesn't exist, using home")
        cwd = os.path.expanduser("~")

    try:
        master_fd, slave_fd = pty.openpty()

        # Set terminal size on slave
        fcntl.ioctl(
            slave_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )

        pid = os.fork()
        if pid == 0:
            # Child process
            try:
                os.setsid()
                fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)
                os.dup2(slave_fd, 0)
                os.dup2(slave_fd, 1)
                os.dup2(slave_fd, 2)
                os.close(master_fd)
                os.close(slave_fd)
                os.chdir(cwd)
                os.environ["TERM"] = "xterm-256color"
                os.environ["COLORTERM"] = "truecolor"
                # Spawn a login shell (- prefix makes it a login shell)
                os.execvp(user_shell, [f"-{os.path.basename(user_shell)}"])
            except Exception as e:
                os.write(2, f"Failed to exec shell: {e}\n".encode())
                os._exit(1)
        else:
            # Parent process
            os.close(slave_fd)
            # Keep master fd blocking — we read in a thread executor
            log.info(f"Spawned PTY session {session_id[:8]}: pid={pid}, cwd={cwd}")
            return PTYSession(session_id, master_fd, pid)

    except Exception as e:
        log.error(f"Failed to spawn PTY session: {e}")
        return None


# --- Config Management ---

def load_config(path: str) -> dict:
    """Load YAML config file."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def save_config(path: str, data: dict) -> None:
    """Write config back to YAML file."""
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


def parse_token_hub_url(token: str) -> str | None:
    """Extract the hub URL from a self-contained registration token."""
    if not token.startswith("orcreg_"):
        return None
    payload = token[7:]
    parts = payload.split(".", 1)
    if len(parts) != 2:
        return None
    url_b64 = parts[0]
    padding = 4 - len(url_b64) % 4
    if padding != 4:
        url_b64 += "=" * padding
    try:
        return base64.urlsafe_b64decode(url_b64).decode()
    except Exception:
        return None


def ensure_config_for_register(config_path: str, token: str) -> dict:
    """Create or update config for --register mode."""
    hub = parse_token_hub_url(token)
    if not hub:
        log.error("Invalid token format — cannot extract hub URL")
        sys.exit(1)

    if os.path.exists(config_path):
        cfg = load_config(config_path)
    else:
        cfg = {
            "agent_name": platform.node(),
            "repos": {},
            "claude": {
                "binary": "claude",
            },
        }

    cfg["hub_url"] = hub
    cfg["registration_token"] = token
    cfg.pop("api_key", None)

    os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
    save_config(config_path, cfg)
    log.info(f"Config written to {config_path}")
    return cfg


def persist_api_key(config_path: str, key: str) -> None:
    """After registration, save the API key and remove the consumed token."""
    if not os.path.exists(config_path):
        return
    cfg = load_config(config_path)
    cfg["api_key"] = key
    cfg.pop("registration_token", None)
    save_config(config_path, cfg)
    log.info(f"API key saved to {config_path} (registration_token removed)")


# --- System Info ---

def get_system_info() -> dict:
    """Gather current system stats."""
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_total_gb": round(mem.total / (1024**3), 1),
        "memory_used_gb": round(mem.used / (1024**3), 1),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_percent": round(disk.used / disk.total * 100, 1),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": platform.python_version(),
        "uptime_seconds": int(psutil.boot_time()),
    }


def get_repos_info() -> dict:
    """Get repo paths from config."""
    repos = {}
    for name, repo_config in config.get("repos", {}).items():
        path = repo_config.get("path", "") if isinstance(repo_config, dict) else repo_config
        repos[name] = path
    return repos


# --- Hub Communication ---

async def register_with_hub(client: httpx.AsyncClient, config_path: str = "") -> str | None:
    """Register this agent with the hub. Returns API key if new registration needed."""
    global api_key

    if config.get("api_key"):
        api_key = config["api_key"]
        log.info(f"Using configured API key: {api_key[:8]}...")
        return api_key

    reg_token = config.get("registration_token", "")
    if not reg_token:
        log.error(
            "No api_key and no registration_token in config. "
            "Get a registration token from the Orchestratia dashboard: "
            "Agents -> Register Agent"
        )
        return None

    try:
        resp = await client.post(
            f"{hub_url}/api/v1/agents/register",
            json={
                "name": config.get("agent_name", platform.node()),
                "hostname": platform.node(),
                "ip": "0.0.0.0",
                "os": platform.system().lower(),
                "repos": get_repos_info(),
                "system_info": get_system_info(),
                "registration_token": reg_token,
            },
        )
        if resp.status_code == 401:
            detail = resp.json().get("detail", "Unknown error")
            log.error(f"Registration failed: {detail}")
            return None
        resp.raise_for_status()
        data = resp.json()
        api_key = data["api_key"]
        log.info(f"Registered with hub. Agent ID: {data['id']}, Key: {api_key[:8]}...")

        if config_path:
            persist_api_key(config_path, api_key)
        else:
            log.warning(f"SAVE THIS API KEY to your config.yaml: {api_key}")

        return api_key
    except httpx.HTTPError as e:
        log.error(f"Failed to register with hub: {e}")
        return None


async def send_heartbeat(client: httpx.AsyncClient) -> bool:
    """Send a heartbeat with system stats to the hub."""
    try:
        resp = await client.post(
            f"{hub_url}/api/v1/agents/heartbeat",
            json={"system_info": get_system_info()},
            headers={"X-API-Key": api_key},
        )
        resp.raise_for_status()
        return True
    except httpx.HTTPError as e:
        log.warning(f"Heartbeat failed: {e}")
        return False


# --- WebSocket ---

async def connect_ws():
    """Connect to the hub's agent WebSocket."""
    ws_url = hub_url.replace("https://", "wss://").replace("http://", "ws://")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        ws = await websockets.connect(
            f"{ws_url}/ws/agent",
            ssl=ssl_ctx if ws_url.startswith("wss") else None,
            ping_interval=30,
            ping_timeout=10,
            max_size=2**20,  # 1MB max message
        )
        await ws.send(json.dumps({"type": "auth", "api_key": api_key}))
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        if resp.get("type") == "auth_ok":
            log.info("WebSocket connected and authenticated")
            return ws
        else:
            log.error(f"WebSocket auth failed: {resp}")
            await ws.close()
            return None
    except Exception as e:
        log.warning(f"WebSocket connection failed: {e}")
        return None


# --- Main Loops ---

async def heartbeat_loop(client: httpx.AsyncClient):
    """Send heartbeats every 30 seconds."""
    while running:
        await send_heartbeat(client)
        await asyncio.sleep(30)


async def ws_receive_loop(ws):
    """Receive messages from hub and dispatch to session handlers.

    Returns when the WebSocket connection drops (triggering reconnect in the caller).
    """
    try:
        while running:
            raw = await ws.recv()
            msg = json.loads(raw)
            msg_type = msg.get("type")

            if msg_type == "session_start":
                session_id = msg.get("session_id")
                working_dir = msg.get("working_directory")
                cols = msg.get("cols", 120)
                rows = msg.get("rows", 40)
                log.info(f"Hub requests session start: {session_id[:8]}")

                session = spawn_pty_session(session_id, working_dir, cols, rows)
                if session:
                    active_sessions[session_id] = session
                    await session.start_reader()
                    # Report success
                    await ws_send({
                        "type": "session_started",
                        "session_id": session_id,
                        "pid": session.pid,
                    })
                else:
                    await ws_send({
                        "type": "session_error",
                        "session_id": session_id,
                        "error": "Failed to spawn PTY",
                    })

            elif msg_type == "session_input":
                session_id = msg.get("session_id")
                b64_data = msg.get("data", "")
                session = active_sessions.get(session_id)
                if session and not session.closed and b64_data:
                    raw_bytes = base64.b64decode(b64_data)
                    session.write_input(raw_bytes)

            elif msg_type == "session_resize":
                session_id = msg.get("session_id")
                cols = msg.get("cols", 120)
                rows = msg.get("rows", 40)
                session = active_sessions.get(session_id)
                if session and not session.closed:
                    session.resize(cols, rows)

            elif msg_type == "session_close":
                session_id = msg.get("session_id")
                session = active_sessions.get(session_id)
                if session and not session.closed:
                    log.info(f"Graceful close requested for session {session_id[:8]}")
                    session.close_graceful()

            elif msg_type == "session_kill":
                session_id = msg.get("session_id")
                session = active_sessions.get(session_id)
                if session and not session.closed:
                    log.info(f"Force kill requested for session {session_id[:8]}")
                    session.kill_force()

            elif msg_type == "pong":
                pass  # Expected response to our pings

    except websockets.exceptions.ConnectionClosed:
        log.warning("WebSocket connection closed by hub")
    except asyncio.CancelledError:
        pass
    except Exception as e:
        log.error(f"WebSocket receive error: {e}")


async def report_alive_sessions():
    """After WS reconnect, report any sessions that are still alive.

    This lets the hub know which sessions survived the disconnect
    and re-marks them as active.
    """
    # Clean up dead sessions first
    dead = [sid for sid, s in active_sessions.items() if not s.is_alive()]
    for sid in dead:
        session = active_sessions.pop(sid)
        session.closed = True
        try:
            os.close(session.master_fd)
        except OSError:
            pass
        log.info(f"Cleaned up dead session {sid[:8]}")

    # Report alive sessions
    alive = list(active_sessions.keys())
    if alive:
        log.info(f"Reporting {len(alive)} alive session(s) to hub")
        for sid in alive:
            session = active_sessions[sid]
            await ws_send({
                "type": "session_started",
                "session_id": sid,
                "pid": session.pid,
            })
            # Restart the reader if it died (it would have stopped when WS dropped)
            if session.reader_task is None or session.reader_task.done():
                log.info(f"Restarting reader for session {sid[:8]}")
                await session.start_reader()


async def ws_connection_loop():
    """Maintain the WebSocket connection with automatic reconnection.

    When the connection drops, waits with exponential backoff and reconnects.
    Active PTY sessions survive disconnections - their output is just dropped
    until the WS comes back, then readers are re-attached.
    """
    global ws_connection
    backoff = 1  # seconds, increases up to 30

    while running:
        ws = await connect_ws()
        if ws:
            ws_connection = ws
            backoff = 1  # Reset backoff on successful connect

            # Report any sessions that survived the disconnect
            await report_alive_sessions()

            # Run receive loop until it returns (connection dropped)
            await ws_receive_loop(ws)

            # Connection dropped
            ws_connection = None
            log.info("WebSocket disconnected, will reconnect...")
        else:
            log.warning(f"WebSocket connect failed, retrying in {backoff}s...")

        if not running:
            break

        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 30)


async def cleanup_sessions():
    """Cleanup all active sessions on shutdown."""
    for session_id, session in list(active_sessions.items()):
        log.info(f"Cleaning up session {session_id[:8]}")
        session.close_graceful()
        if session.reader_task:
            session.reader_task.cancel()
    active_sessions.clear()


async def main():
    global config, hub_url, running

    parser = argparse.ArgumentParser(description="Orchestratia Agent Daemon")
    parser.add_argument("--config", default="/etc/orchestratia/config.yaml", help="Config file path")
    parser.add_argument("--register", metavar="TOKEN", help="One-time registration token (hub URL encoded)")
    args = parser.parse_args()

    config_path = args.config

    if args.register:
        config = ensure_config_for_register(config_path, args.register)
        hub_url = config.get("hub_url", "").rstrip("/")
        if not hub_url:
            log.error("hub_url not set in config")
            sys.exit(1)

        async with httpx.AsyncClient(timeout=30) as client:
            key = await register_with_hub(client, config_path=config_path)
            if not key:
                log.error("Registration failed.")
                sys.exit(1)
            log.info("Registration successful. Start the daemon with: sudo systemctl start orchestratia-agent")
        return

    elif os.path.exists(config_path):
        config = load_config(config_path)
    else:
        log.error(f"Config file not found: {config_path}")
        log.error("Use --register TOKEN to set up, or create the config manually.")
        sys.exit(1)

    hub_url = config.get("hub_url", "").rstrip("/")

    if not hub_url:
        log.error("hub_url not set in config")
        sys.exit(1)

    log.info("Orchestratia Agent Daemon starting...")
    log.info(f"Hub URL: {hub_url}")
    log.info(f"Agent name: {config.get('agent_name', platform.node())}")

    # HTTP client
    async with httpx.AsyncClient(timeout=30) as client:
        # Register or use existing key
        key = await register_with_hub(client, config_path=config_path)
        if not key:
            log.error("Failed to obtain API key. Exiting.")
            sys.exit(1)

        # Signal handling
        def handle_signal(sig, frame):
            global running
            log.info(f"Received signal {sig}, shutting down...")
            running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        log.info("Agent daemon running. Heartbeats every 30s, WS auto-reconnect enabled.")

        # Run heartbeat loop and WS connection loop concurrently
        # WS connection loop handles its own reconnection internally
        try:
            await asyncio.gather(
                heartbeat_loop(client),
                ws_connection_loop(),
            )
        finally:
            await cleanup_sessions()

    log.info("Agent daemon stopped.")


if __name__ == "__main__":
    asyncio.run(main())
