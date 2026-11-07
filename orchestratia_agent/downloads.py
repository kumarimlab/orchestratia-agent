"""Downloads streamed to the relay tier.

`download_stat` (hub request/response) and `download_open` (pushed by the relay
through realtime) both run dl_helper AS THE SESSION'S USER — the daemon never opens
the requested path. The tier and project come from the hub's session row; the OS
user is resolved from THIS host's config, exactly like spawn.

The relay starts us with WINDOW bytes of credit and grants more as the browser
drains, so a slow browser slows the helper instead of filling memory anywhere.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys

import websockets

from orchestratia_agent import privilege

log = logging.getLogger("orchestratia-agent.downloads")

HELPER_INSTALL_PATH = "/usr/local/libexec/orchestratia/dl-helper"
HELPER_SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dl_helper.py")
CHUNK = 256 * 1024
WINDOW = 4 * 1024 * 1024
STAT_TIMEOUT = 30


def helper_argv(run_as, tc, args: list[str], path: str) -> list[str]:
    """`-I` keeps PYTHONPATH/user-site/cwd off sys.path; `--` keeps a path starting
    with '-' from ever being read as an option."""
    if run_as is None:
        return [sys.executable, "-I", HELPER_SOURCE, *args, "--", path]
    return privilege.sudo_prefix(run_as, tc) + [HELPER_INSTALL_PATH, *args, "--", path]


def _run_as(msg: dict, tc):
    return privilege.resolve_user(msg.get("privilege_tier") or "standard", msg.get("project_id"), tc)


async def _spawn(argv):
    return await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd="/", limit=CHUNK * 2)


async def _stop(proc) -> None:
    """Terminate (sudo relays SIGTERM to the helper), close OUR end of the pipe so a
    surviving child can't keep wait() blocked, bounded wait, then kill."""
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    transport = getattr(proc, "_transport", None)
    try:
        pipe = transport.get_pipe_transport(1) if transport else None
        if pipe is not None:
            pipe.close()
    except Exception:                                    # noqa: BLE001
        pass
    try:
        await asyncio.wait_for(proc.wait(), 5)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except asyncio.TimeoutError:
            log.warning("download helper pid %s did not exit", proc.pid)


async def _read_header(proc) -> dict:
    line = await proc.stdout.readline()
    try:
        return json.loads(line or b"{}")
    except ValueError:
        return {}


def _check_header(header: dict, stderr_text: str = "", need_op: str | None = None) -> dict | None:
    """None if usable, else an error dict.

    Downloads work with any helper protocol >= 1, so a restricted host whose installed
    helper is older than the agent keeps downloading. An upload op (`need_op`) needs
    protocol >= 2 AND the op listed in the header's `ops`. A pre-upload helper never
    gets as far as a header for an upload op: argparse refuses the op on stderr."""
    if not header:
        if need_op and ("invalid choice" in stderr_text or "unrecognized arguments" in stderr_text):
            return {"ok": False, "error": "helper_outdated"}
        return {"ok": False, "error": "privilege" if "sudo" in stderr_text else "invalid"}
    proto = header.get("protocol")
    if not isinstance(proto, int) or isinstance(proto, bool) or proto < 1:
        return {"ok": False, "error": "helper_outdated"}
    if need_op is not None and (proto < 2 or need_op not in (header.get("ops") or [])):
        return {"ok": False, "error": "helper_outdated"}
    return None


async def stat_request(msg: dict, tc) -> dict:
    try:
        run_as = _run_as(msg, tc)
    except privilege.PrivilegeError:
        return {"ok": False, "error": "privilege"}
    proc = await _spawn(helper_argv(run_as, tc, ["stat", "--cwd", msg.get("working_dir") or ""],
                                    msg.get("path") or ""))
    try:
        header = await asyncio.wait_for(_read_header(proc), timeout=STAT_TIMEOUT)
    except asyncio.TimeoutError:
        await _stop(proc)
        return {"ok": False, "error": "timeout"}
    err_text = ""
    if not header:
        try:
            err_text = (await asyncio.wait_for(proc.stderr.read(), 2)).decode("utf-8", "replace")
        except asyncio.TimeoutError:
            pass
    await _stop(proc)
    return _check_header(header, err_text) or header


async def _wait_credit(more: asyncio.Event, reader: asyncio.Task) -> None:
    w = asyncio.ensure_future(more.wait())
    try:
        await asyncio.wait({w, reader}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        w.cancel()


async def open_download(msg: dict, tc, api_key: str, ssl_ctx=None) -> None:
    """Dial the relay for ONE browser request and stream it. Never raises."""
    target = f"{(msg.get('relay_url') or '').rstrip('/')}/ws/relay-dl"
    proc = None
    reader = None
    did = str(msg.get("download_id"))[:8]
    try:
        async with websockets.connect(target, ssl=ssl_ctx if target.startswith("wss") else None,
                                      max_size=2 ** 20, compression=None,
                                      ping_interval=20, ping_timeout=20) as ws:
            await ws.send(json.dumps({"type": "auth", "api_key": api_key, "download_id": msg.get("download_id"),
                                      "request_id": msg.get("request_id")}))

            async def error(code, size=None):
                await ws.send(json.dumps({"type": "error", "code": code, "message": code, "size": size}))

            try:
                run_as = _run_as(msg, tc)
            except privilege.PrivilegeError:
                await error("privilege")
                return
            kind = "dir" if msg.get("kind") == "dir" else "file"
            args = ["zip" if kind == "dir" else "read", "--cwd", msg.get("working_dir") or ""]
            if kind == "file" and msg.get("range"):
                args += ["--range", msg["range"]]
            if kind == "file" and msg.get("if_range"):
                args += ["--if-range", msg["if_range"]]
            proc = await _spawn(helper_argv(run_as, tc, args, msg.get("path") or ""))
            header = await _read_header(proc)
            bad = _check_header(header)
            if bad or not header.get("ok"):
                await error((bad or header).get("error") or "invalid", header.get("size"))
                return
            await ws.send(json.dumps({"type": "head", "status": header.get("status", 200),
                                      "offset": header.get("offset", 0), "length": header.get("length"),
                                      "size": header.get("size"), "etag": header.get("etag"),
                                      "mtime_ns": header.get("mtime_ns")}))
            if (msg.get("method") or "GET") == "HEAD":
                await _stop(proc)
                await ws.send(json.dumps({"type": "end", "bytes": 0}))
                return

            credit = {"n": WINDOW}
            more = asyncio.Event()

            async def credits():
                async for m in ws:
                    if isinstance(m, str):
                        try:
                            f = json.loads(m)
                        except ValueError:
                            continue
                        if f.get("type") == "credit":
                            credit["n"] += int(f.get("bytes") or 0)
                            more.set()
            reader = asyncio.create_task(credits())

            sent = 0
            while True:
                chunk = await proc.stdout.read(CHUNK)
                if not chunk:
                    break
                while credit["n"] < len(chunk):
                    if reader.done():
                        return                           # the relay went away
                    more.clear()
                    await _wait_credit(more, reader)
                credit["n"] -= len(chunk)
                await ws.send(chunk)
                sent += len(chunk)
            rc = await asyncio.wait_for(proc.wait(), 30)
            if rc != 0:
                await error("read_failed")               # never let a short body look complete
            else:
                await ws.send(json.dumps({"type": "end", "bytes": sent}))
    except websockets.exceptions.ConnectionClosed:
        log.info("download %s: relay closed the socket", did)
    except Exception as e:                               # noqa: BLE001
        log.warning("download %s failed: %s", did, e)
    finally:
        if reader is not None:
            reader.cancel()
        if proc is not None:
            await _stop(proc)
