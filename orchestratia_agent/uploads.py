"""Uploads streamed from the relay tier — the agent's end of /ws/relay-ul.

`upload_prepare` (hub request/response) and `upload_open` (pushed by the relay through
realtime) both run dl_helper AS THE SESSION'S USER, inside that user's own 0700 upload
folder: the daemon never opens an uploaded file itself. The tier and project come from
the hub's session row; the OS user is resolved from THIS host's config, like spawn.

One link per upload, reused across its chunks. The helper's on-disk journal is the
only state that matters: a link that drops is killed, and the next one resumes from
the journal. The relay starts every link with WINDOW bytes of credit IMPLICITLY when
`ready` arrives (we never send an initial credit frame); we top it up for every
GRANT_EVERY bytes written into the helper, counted per link so a remainder carries
across chunk boundaries. A slow disk slows the browser instead of filling memory.
The relay always closes the socket, after `done` too; any close kills the helper.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys

import websockets

from orchestratia_agent import privilege, upload_dirs
from orchestratia_agent.downloads import HELPER_INSTALL_PATH, HELPER_SOURCE, _check_header, _run_as, _stop

log = logging.getLogger("orchestratia-agent.uploads")

WINDOW = 4 * 1024 * 1024
GRANT_EVERY = 256 * 1024
PREPARE_TIMEOUT = 30
READY_TIMEOUT = 30
OP_TIMEOUT = 60
REOPEN_WAIT = 5          # a dropped link may still be tearing down when the relay reopens
SWEEP_INTERVAL = 3600
MAX_LINE = 1024 * 1024
TERMINAL = ("tampered", "name_exhausted", "io")
# Link error codes the relay maps (Phase B contract note 4); anything else -> internal.
LINK_ERRORS = frozenset({"checksum_mismatch", "no_space", "helper_outdated", "tampered", "offset_mismatch",
                         "busy", "io", "internal", "unsafe_destination", "permission_denied", "privilege",
                         "invalid_name", "name_exhausted", "invalid", "protocol"})

# upload_id -> the ul-write helper of its live link (one per upload).
live_links: dict[str, asyncio.subprocess.Process] = {}


def helper_argv(run_as, tc, op: str, folder: str) -> list[str]:
    """Nothing about the upload goes in argv (ps, sudo's log): it all goes on stdin."""
    if run_as is None:
        return [sys.executable, "-I", HELPER_SOURCE, op, "--base", folder]
    return privilege.sudo_prefix(run_as, tc) + [HELPER_INSTALL_PATH, op, "--base", folder]


def _request(msg: dict) -> dict:
    return {"upload_id": str(msg.get("upload_id") or ""), "name": msg.get("name"),
            "size": msg.get("size"), "chunk_size": msg.get("chunk_size"),
            "reservation": msg.get("reservation") or 0}


def _folder(run_as) -> str:
    """The session user's upload folder (created/verified by upload_dirs)."""
    return upload_dirs.folder_for(run_as)


async def _spawn(argv):
    return await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd="/", limit=MAX_LINE)


async def _write(proc, data: bytes) -> bool:
    try:
        proc.stdin.write(data)
        await proc.stdin.drain()
        return True
    except (BrokenPipeError, ConnectionResetError):
        return False


async def _read_json_line(proc) -> dict:
    try:
        line = await proc.stdout.readline()
    except (ValueError, asyncio.LimitOverrunError):
        return {}
    try:
        obj = json.loads(line or b"{}")
    except ValueError:
        return {}
    return obj if isinstance(obj, dict) else {}


async def _stderr_text(proc) -> str:
    try:
        return (await asyncio.wait_for(proc.stderr.read(), 2)).decode("utf-8", "replace")
    except asyncio.TimeoutError:
        return ""


async def _run_once(run_as, tc, op: str, folder: str, req: dict, timeout: float = OP_TIMEOUT,
                    need_op: str | None = None) -> dict:
    """Run a one-line helper op (ul-prepare / ul-cancel / ul-sweep) and return its header,
    or an error dict ({"ok": False, "error": ...})."""
    proc = await _spawn(helper_argv(run_as, tc, op, folder))
    try:
        await _write(proc, json.dumps(req).encode() + b"\n")
        try:
            proc.stdin.close()
        except Exception:                                # noqa: BLE001
            pass
        try:
            header = await asyncio.wait_for(_read_json_line(proc), timeout)
        except asyncio.TimeoutError:
            return {"ok": False, "error": "timeout"}
        err_text = "" if header else await _stderr_text(proc)
    finally:
        await _stop(proc)
    return _check_header(header, err_text, need_op=need_op or op) or header


async def prepare_request(msg: dict, tc) -> dict:
    """Preflight AS the session user: folder safety, name, free space (minus the
    hub-supplied reservation), the journal's offset, a finished upload's done record."""
    try:
        run_as = _run_as(msg, tc)
    except privilege.PrivilegeError:
        return {"ok": False, "error": "privilege"}
    try:
        folder = _folder(run_as)
    except upload_dirs.UploadDirError as e:
        log.warning("upload %s: %s", str(msg.get("upload_id"))[:8], e)
        return {"ok": False, "error": e.code}
    header = await _run_once(run_as, tc, "ul-prepare", folder, _request(msg), PREPARE_TIMEOUT,
                             need_op="ul-write")
    out = {"ok": header.get("ok") is True}
    for key in ("error", "dir", "free_bytes", "offset", "done", "protocol"):
        if header.get(key) is not None:
            out[key] = header[key]
    if not out["ok"] and "error" not in out:
        out["error"] = "invalid"
    return out


def _sender(ws):
    lock = asyncio.Lock()

    async def send(obj) -> None:
        async with lock:
            await ws.send(obj if isinstance(obj, (str, bytes)) else json.dumps(obj))
    return send


async def _relay_to_helper(ws, proc, send) -> None:
    """Relay frames -> helper stdin, granting credit as the helper takes the bytes.
    Returns when the relay closes the socket or breaks the framing."""
    owed = 0                 # bytes the current chunk still has to deliver
    since_grant = 0
    try:
        async for m in ws:
            if isinstance(m, str):
                try:
                    f = json.loads(m)
                except ValueError:
                    continue
                if not isinstance(f, dict) or f.get("type") != "chunk":
                    continue
                length = f.get("length")
                if owed or not isinstance(length, int) or isinstance(length, bool) or length < 0:
                    log.warning("upload link: malformed chunk header")
                    return
                line = {k: f.get(k) for k in ("offset", "length", "index", "sha256", "final")}
                if not await _write(proc, json.dumps(line).encode() + b"\n"):
                    return
                owed = length
                continue
            if len(m) > owed:
                log.warning("upload link: more bytes than the chunk declared")
                return
            if not await _write(proc, m):
                return
            owed -= len(m)
            since_grant += len(m)
            if since_grant >= GRANT_EVERY:
                await send({"type": "credit", "bytes": since_grant})
                since_grant = 0
    except websockets.exceptions.ConnectionClosed:
        return


async def _helper_to_relay(proc, send) -> None:
    """Helper lines (ack / error / done) -> relay. A helper that stops without a
    terminal line is reported as error{internal}."""
    terminal = False
    try:
        while True:
            try:
                line = await proc.stdout.readline()
            except (ValueError, asyncio.LimitOverrunError):
                break
            if not line:
                break
            try:
                f = json.loads(line)
            except ValueError:
                continue
            if not isinstance(f, dict) or f.get("type") not in ("ack", "error", "done"):
                continue
            terminal = f["type"] == "done" or (f["type"] == "error" and f.get("code") in TERMINAL)
            if f["type"] == "error":
                if f.get("code") not in LINK_ERRORS:
                    f["code"] = "internal"
                f.setdefault("message", f.get("code"))
            await send(f)
    except websockets.exceptions.ConnectionClosed:
        return                                           # the relay left; the helper is killed by the caller
    rc = await proc.wait()
    if not terminal:
        err = (await _stderr_text(proc)).strip()
        if rc or err:
            log.warning("upload helper exited %s: %s", rc, err[-300:])
        try:
            await send({"type": "error", "code": "internal", "message": "the upload helper stopped"})
        except websockets.exceptions.ConnectionClosed:
            pass


async def open_upload(msg: dict, tc, api_key: str, ssl_ctx=None) -> None:
    """Dial the relay for ONE upload and bridge it to a ul-write helper until either
    side ends. Never raises."""
    uid = str(msg.get("upload_id") or "")
    target = f"{(msg.get('relay_url') or '').rstrip('/')}/ws/relay-ul"
    proc = None
    tasks: list[asyncio.Task] = []
    try:
        async with websockets.connect(target, ssl=ssl_ctx if target.startswith("wss") else None,
                                      max_size=2 ** 20, compression=None,
                                      ping_interval=20, ping_timeout=20) as ws:
            send = _sender(ws)
            await send({"type": "auth", "api_key": api_key, "upload_id": uid,
                        "request_id": msg.get("request_id")})

            async def error(code, message=None, offset=None):
                code = code if code in LINK_ERRORS else "internal"      # e.g. our own "timeout"
                frame = {"type": "error", "code": code, "message": message or code}
                if isinstance(offset, int) and not isinstance(offset, bool):
                    frame["offset"] = offset
                await send(frame)

            old = live_links.get(uid)
            if old is not None and old.returncode is None:
                try:
                    await asyncio.wait_for(old.wait(), REOPEN_WAIT)
                except asyncio.TimeoutError:
                    await error("busy", "this upload is already being received")
                    return
            try:
                run_as = _run_as(msg, tc)
            except privilege.PrivilegeError:
                await error("privilege")
                return
            try:
                folder = _folder(run_as)
            except upload_dirs.UploadDirError as e:
                await error(e.code, str(e)[:160])
                return
            proc = await _spawn(helper_argv(run_as, tc, "ul-write", folder))
            live_links[uid] = proc
            await _write(proc, json.dumps(_request(msg)).encode() + b"\n")
            try:
                header = await asyncio.wait_for(_read_json_line(proc), READY_TIMEOUT)
            except asyncio.TimeoutError:
                await error("timeout")
                return
            bad = _check_header(header, "" if header else await _stderr_text(proc), need_op="ul-write")
            if bad:
                await error(bad["error"])
                return
            if header.get("type") != "ready":
                await error(header.get("code") or header.get("error") or "internal", offset=header.get("offset"))
                return
            ready = {"type": "ready", "offset": header.get("offset", 0),
                     "finalizing": bool(header.get("finalizing")), "done": header.get("done"),
                     "protocol": header.get("protocol")}
            if header.get("reset"):
                ready["reset"] = True
            await send(ready)                    # the relay now holds WINDOW credit implicitly
            tasks = [asyncio.create_task(_relay_to_helper(ws, proc, send)),
                     asyncio.create_task(_helper_to_relay(proc, send))]
            # Either side ending ends the link. If the relay left first, the helper is
            # killed below: whatever it had not journalled is rolled back on the next open.
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except websockets.exceptions.ConnectionClosed:
        log.info("upload %s: relay closed the socket", uid[:8])
    except Exception as e:                               # noqa: BLE001
        log.warning("upload %s failed: %s", uid[:8], e)
    finally:
        for t in tasks:
            t.cancel()
        if proc is not None:
            await _stop(proc)
            if live_links.get(uid) is proc:
                live_links.pop(uid, None)


async def cancel(msg: dict, tc) -> None:
    """The hub ended this upload (cancelled / expired / denied / failed). Stop a live
    link first — its helper holds the part's lock — then remove the files. Never raises."""
    uid = str(msg.get("upload_id") or "")
    try:
        proc = live_links.get(uid)
        if proc is not None:
            await _stop(proc)
        run_as = _run_as(msg, tc)
        folder = _folder(run_as)
        res: dict = {}
        for _ in range(3):
            res = await _run_once(run_as, tc, "ul-cancel", folder, {"upload_id": uid})
            if res.get("error") != "busy":
                break
            await asyncio.sleep(1)
        if not res.get("ok"):
            log.info("upload %s: cancel left files behind (%s); the hourly sweep removes them",
                     uid[:8], res.get("error"))
    except (privilege.PrivilegeError, upload_dirs.UploadDirError) as e:
        log.info("upload %s: nothing to cancel here (%s)", uid[:8], e)
    except Exception as e:                               # noqa: BLE001
        log.warning("upload %s: cancel failed: %s", uid[:8], e)


async def sweep_all(tc) -> None:
    """ul-sweep in the daemon user's folder and, as each project user, in theirs."""
    if sys.platform == "win32":
        return
    users = [None] + sorted({pt.user for pid, pt in tc.projects.items() if pid != privilege.LEGACY_KEY})
    for run_as in users:
        try:
            folder = _folder(run_as)
        except upload_dirs.UploadDirError as e:
            log.debug("upload sweep: skipping %s: %s", run_as or "daemon user", e)
            continue
        res = await _run_once(run_as, tc, "ul-sweep", folder, {})
        if res.get("removed"):
            log.info("upload sweep: removed %d stale file(s) from %s", res["removed"], folder)
        elif not res.get("ok"):
            log.debug("upload sweep in %s: %s", folder, res.get("error"))


async def sweep_loop(state) -> None:
    """At startup, then hourly. Also creates the daemon user's own folder early."""
    if sys.platform == "win32":
        return
    while state.running:
        tc = getattr(state, "tier_config", None) or privilege.load_tier_config(getattr(state, "config", {}) or {})
        try:
            await sweep_all(tc)
        except Exception as e:                           # noqa: BLE001
            log.warning("upload sweep failed: %s", e)
        for _ in range(SWEEP_INTERVAL):
            if not state.running:
                return
            await asyncio.sleep(1)
