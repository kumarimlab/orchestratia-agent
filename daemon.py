#!/usr/bin/env python3
"""Orchestratia Agent Daemon

Runs on dev servers to:
1. Register with the Orchestratia hub
2. Send heartbeats every 30s with system stats
3. Poll for assigned tasks
4. Execute Claude Code in persistent screen sessions
5. Stream output back to the hub via WebSocket
6. Reconcile orphaned sessions on startup
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import shutil
import signal
import subprocess
import ssl
import sys
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
# Track active tasks: task_id -> asyncio.Task
active_tasks: dict[str, asyncio.Task] = {}


def load_config(path: str) -> dict:
    """Load YAML config file."""
    with open(path) as f:
        return yaml.safe_load(f)


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


# --- Screen Session Management ---

def screen_session_name(task_id: str) -> str:
    """Generate a predictable screen session name for a task."""
    return f"orchestratia-task-{task_id}"


def list_screen_sessions() -> list[str]:
    """List all orchestratia screen sessions."""
    try:
        result = subprocess.run(
            ["screen", "-ls"],
            capture_output=True, text=True, timeout=5,
        )
        sessions = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if "orchestratia-task-" in line:
                parts = line.split(".")
                if len(parts) >= 2:
                    name_part = ".".join(parts[1:]).split("\t")[0].split(" ")[0]
                    sessions.append(name_part)
        return sessions
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def spawn_claude_in_screen(task_id: str, spec: str, repo_path: str) -> tuple[bool, Path]:
    """Spawn Claude Code in a detached screen session. Returns (success, log_path)."""
    session_name = screen_session_name(task_id)
    claude_bin = config.get("claude", {}).get("binary", "claude")
    allowed_tools = config.get("claude", {}).get("allowed_tools", "Bash,Read,Edit,Write,Grep,Glob")
    max_turns = config.get("claude", {}).get("max_turns", 50)

    log_dir = Path(config.get("session", {}).get("log_dir", "/var/log/orchestratia"))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"task-{task_id}.log"

    # Clear old log file if it exists
    if log_file.exists():
        log_file.unlink()

    cmd = [
        "screen", "-dmS", session_name,
        "-L", "-Logfile", str(log_file),
        claude_bin, "-p", spec,
        "--allowedTools", allowed_tools,
        "--max-turns", str(max_turns),
    ]

    try:
        subprocess.run(cmd, cwd=repo_path, check=True, timeout=10)
        log.info(f"Spawned Claude in screen session: {session_name}")
        return True, log_file
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        log.error(f"Failed to spawn screen session: {e}")
        return False, log_file


def kill_screen_session(session_name: str) -> None:
    """Terminate a screen session."""
    try:
        subprocess.run(
            ["screen", "-S", session_name, "-X", "quit"],
            capture_output=True, timeout=5,
        )
        log.info(f"Killed screen session: {session_name}")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass


def is_screen_session_alive(session_name: str) -> bool:
    """Check if a screen session is still running."""
    try:
        result = subprocess.run(
            ["screen", "-ls"],
            capture_output=True, text=True, timeout=5,
        )
        return session_name in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# --- Reconciliation ---

def reconcile_sessions() -> list[str]:
    """Find orphaned orchestratia screen sessions from a previous daemon run."""
    sessions = list_screen_sessions()
    if sessions:
        log.info(f"Found {len(sessions)} orphaned session(s): {sessions}")
    else:
        log.info("No orphaned sessions found")
    return sessions


# --- Hub Communication ---

async def register_with_hub(client: httpx.AsyncClient) -> str | None:
    """Register this agent with the hub. Returns API key if new registration needed."""
    global api_key

    if config.get("api_key"):
        api_key = config["api_key"]
        log.info(f"Using configured API key: {api_key[:8]}...")
        return api_key

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
            },
        )
        resp.raise_for_status()
        data = resp.json()
        api_key = data["api_key"]
        log.info(f"Registered with hub. Agent ID: {data['id']}, Key: {api_key[:8]}...")
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


async def poll_for_tasks(client: httpx.AsyncClient) -> list[dict]:
    """Poll the hub for assigned tasks."""
    try:
        resp = await client.get(
            f"{hub_url}/api/v1/agents/tasks/poll",
            headers={"X-API-Key": api_key},
        )
        if resp.status_code == 200:
            return resp.json()
        return []
    except httpx.HTTPError:
        return []


async def notify_task_start(client: httpx.AsyncClient, task_id: str) -> bool:
    """Tell the hub we're starting a task."""
    try:
        resp = await client.post(
            f"{hub_url}/api/v1/agents/tasks/{task_id}/start",
            json={},
            headers={"X-API-Key": api_key},
        )
        return resp.status_code == 200
    except httpx.HTTPError as e:
        log.error(f"Failed to notify task start: {e}")
        return False


async def notify_task_complete(client: httpx.AsyncClient, task_id: str, result: dict | None = None) -> bool:
    """Tell the hub a task completed successfully."""
    try:
        resp = await client.post(
            f"{hub_url}/api/v1/agents/tasks/{task_id}/complete",
            json={"result": result or {}},
            headers={"X-API-Key": api_key},
        )
        return resp.status_code == 200
    except httpx.HTTPError as e:
        log.error(f"Failed to notify task complete: {e}")
        return False


async def notify_task_fail(client: httpx.AsyncClient, task_id: str, error: str = "") -> bool:
    """Tell the hub a task failed."""
    try:
        resp = await client.post(
            f"{hub_url}/api/v1/agents/tasks/{task_id}/fail",
            json={"error": error},
            headers={"X-API-Key": api_key},
        )
        return resp.status_code == 200
    except httpx.HTTPError as e:
        log.error(f"Failed to notify task fail: {e}")
        return False


# --- WebSocket Output Streaming ---

async def connect_ws() -> websockets.WebSocketClientProtocol | None:
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
        )
        # Authenticate
        await ws.send(json.dumps({"type": "auth", "api_key": api_key}))
        resp = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
        if resp.get("type") == "auth_ok":
            log.info("WebSocket connected to hub")
            return ws
        else:
            log.error(f"WebSocket auth failed: {resp}")
            await ws.close()
            return None
    except Exception as e:
        log.warning(f"WebSocket connection failed: {e}")
        return None


async def stream_output(ws, task_id: str, content: str, stream: str = "stdout"):
    """Send output to the hub via WebSocket."""
    if ws and ws.open:
        try:
            await ws.send(json.dumps({
                "type": "output",
                "task_id": task_id,
                "content": content,
                "stream": stream,
            }))
        except Exception:
            pass  # Non-critical, output is also in the log file


# --- Task Execution ---

async def execute_task(
    client: httpx.AsyncClient,
    ws,
    task: dict,
):
    """Execute a single task: spawn Claude, stream output, detect completion."""
    task_id = task["id"]
    spec = task["spec"]
    repo_name = task.get("target_repo", "")
    repo_path = config.get("repos", {}).get(repo_name, {})
    if isinstance(repo_path, dict):
        repo_path = repo_path.get("path", ".")
    if not repo_path:
        repo_path = "."

    log.info(f"Executing task {task_id[:8]}: {task.get('title', 'untitled')}")

    # Notify hub we're starting
    if not await notify_task_start(client, task_id):
        log.error(f"Failed to start task {task_id[:8]}")
        return

    await stream_output(ws, task_id, f"[system] Starting task: {task.get('title', 'untitled')}\n", "system")

    # Spawn Claude in screen
    success, log_file = spawn_claude_in_screen(task_id, spec, repo_path)
    if not success:
        await stream_output(ws, task_id, "[system] Failed to spawn Claude Code\n", "system")
        await notify_task_fail(client, task_id, "Failed to spawn screen session")
        return

    session_name = screen_session_name(task_id)
    await stream_output(ws, task_id, f"[system] Claude Code running in screen: {session_name}\n", "system")

    # Tail the log file and stream output
    last_pos = 0
    check_interval = 2  # seconds between checks

    while running:
        # Check if session is still alive
        if not is_screen_session_alive(session_name):
            # Read any remaining output
            if log_file.exists():
                with open(log_file) as f:
                    f.seek(last_pos)
                    remaining = f.read()
                    if remaining.strip():
                        await stream_output(ws, task_id, remaining, "stdout")

            await stream_output(ws, task_id, "\n[system] Claude Code process exited\n", "system")
            log.info(f"Task {task_id[:8]}: Claude Code finished")

            # Check log for success indicators
            full_output = ""
            if log_file.exists():
                full_output = log_file.read_text()

            # Simple heuristic: if the output contains error patterns, mark as failed
            if any(pattern in full_output.lower() for pattern in ["error:", "fatal:", "panic:", "traceback"]):
                await notify_task_fail(client, task_id, "Process exited with errors")
            else:
                await notify_task_complete(client, task_id, {"output_lines": len(full_output.splitlines())})

            break

        # Read new output from log file
        if log_file.exists():
            try:
                with open(log_file) as f:
                    f.seek(last_pos)
                    new_content = f.read()
                    if new_content:
                        last_pos = f.tell()
                        await stream_output(ws, task_id, new_content, "stdout")
            except OSError:
                pass

        await asyncio.sleep(check_interval)

    # Cleanup
    active_tasks.pop(task_id, None)
    log.info(f"Task {task_id[:8]}: execution complete")


# --- Main Loops ---

async def heartbeat_loop(client: httpx.AsyncClient):
    """Send heartbeats every 30 seconds."""
    while running:
        await send_heartbeat(client)
        await asyncio.sleep(30)


async def task_poll_loop(client: httpx.AsyncClient, ws):
    """Poll for tasks every 10 seconds and execute them."""
    while running:
        tasks = await poll_for_tasks(client)
        for task in tasks:
            task_id = task.get("id")
            if task_id and task_id not in active_tasks:
                # Launch task execution as a background coroutine
                coro = execute_task(client, ws, task)
                active_tasks[task_id] = asyncio.create_task(coro)
                log.info(f"Launched task executor for {task_id[:8]}")
        await asyncio.sleep(10)


async def ws_keepalive_loop(ws):
    """Keep WebSocket connection alive."""
    while running and ws and ws.open:
        try:
            await ws.send(json.dumps({"type": "ping"}))
            await asyncio.sleep(30)
        except Exception:
            break


async def main():
    global config, hub_url, running

    parser = argparse.ArgumentParser(description="Orchestratia Agent Daemon")
    parser.add_argument("--config", default="/etc/orchestratia/config.yaml", help="Config file path")
    args = parser.parse_args()

    config_path = args.config
    if not os.path.exists(config_path):
        log.error(f"Config file not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    hub_url = config.get("hub_url", "").rstrip("/")

    if not hub_url:
        log.error("hub_url not set in config")
        sys.exit(1)

    log.info("Orchestratia Agent Daemon starting...")
    log.info(f"Hub URL: {hub_url}")
    log.info(f"Agent name: {config.get('agent_name', platform.node())}")

    # Check screen is available
    if not shutil.which("screen"):
        log.error("'screen' is not installed. Install it: sudo apt install screen")
        sys.exit(1)

    # Reconcile orphaned sessions
    if config.get("session", {}).get("reconcile_on_start", True):
        orphaned = reconcile_sessions()

    # HTTP client
    async with httpx.AsyncClient(timeout=30) as client:
        # Register or use existing key
        key = await register_with_hub(client)
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

        # Connect WebSocket for output streaming
        ws = await connect_ws()

        # Run loops concurrently
        log.info("Agent daemon running. Heartbeats every 30s, task poll every 10s.")
        loops = [
            heartbeat_loop(client),
            task_poll_loop(client, ws),
        ]
        if ws:
            loops.append(ws_keepalive_loop(ws))

        try:
            await asyncio.gather(*loops)
        finally:
            # Cleanup
            if ws:
                await ws.close()
            for task_id, t in active_tasks.items():
                t.cancel()

    log.info("Agent daemon stopped.")


if __name__ == "__main__":
    asyncio.run(main())
