"""Handles scan_run / scan_cancel (spec §5, §7). The daemon only moves bytes: the
snapshot comes from dl-helper running AS THE SESSION'S USER, goes into the sandbox's
stdin, and JSON lines come back out, re-validated and re-masked before upload."""
import asyncio
import json
import logging
import os
import re

from . import catalog, masking, pack, sandbox
from . import launch as launch_codes

log = logging.getLogger("orchestratia.scan")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_KEYS = ("scan_id", "rule_id", "severity", "title", "description", "location", "evidence", "references",
         "tool", "tool_version")
_REFUSALS = {"refused_root": "the session's directory is / — refusing to scan the whole server",
             "refused_home": "the session's directory is a home directory, or contains one — refusing to scan it",
             "not_found": "the session's directory no longer exists",
             "permission_denied": "the session's user can't read its directory",
             "not_dir": "the session's directory isn't a directory",
             "refused_cred": "the session's directory is inside a credentials folder — refusing to scan it",
             "refused_system": "the session's directory is a system or Orchestratia directory — refusing to scan it"}
CHUNK = 500
# Set once the startup sweep has finished (or been skipped): no sandbox launches before then.
_SWEEP_DONE = asyncio.Event()
MAX_FINDINGS = 5000
HEADER_TIMEOUT_S = 60
RUN_GRACE_S = 120
POST_RETRIES = 3
POST_BACKOFF_S = 1.0
MAX_EXCLUDES, MAX_EXCLUDE_LEN = 50, 128
BATCH_MAX_BYTES = int(3.5 * 1024 * 1024) - 1024     # protocol: each findings POST ≤ 4 MB
KEEPALIVE_S = 60                                      # hub fails a running run after 10 min without progress
OUT_OF_TIME = "the scan ran out of time"
LAUNCHER_REFUSED = ("the root scan launcher refused this scan; it is out of date or this scan is unknown to it — "
                    "run: sudo orchestratia scanners install")
LAUNCHER_UNSAFE = ("the root scan launcher refused to run: its files aren't root-owned and protected — "
                   "run: sudo orchestratia scanners install")
_END_STATUSES = ("done", "truncated", "failed", "timed_out")
_SCOPE_MODES = ("full", "change", "nothing_to_compare", "tool")
# The bytes the runner forwards from the snapshot helper: the helper's own caps plus tar overhead
# per entry. The helper runs as the session's uid, which can hijack its stdout (M3): never forward
# an unbounded stream, and fail a body that stops arriving instead of holding a scan slot.
SNAP_MAX_BYTES, SNAP_MAX_ENTRIES = 2 * 1024 ** 3, 200_000          # mirror dl_helper's caps
STREAM_MAX = SNAP_MAX_BYTES + SNAP_MAX_ENTRIES * 8192
BODY_STALL_S = 60
# The whole snapshot must arrive within this (None: half the scan's timeout). SIGSTOP/SIGCONT or a
# trickle resets the stall timer; this doesn't reset (N4).
SNAPSHOT_DEADLINE_S = None
SLOW = "the repository snapshot took too long to arrive"
NOT_LIVE = ("the session isn't running on this server; a standard-tier scan reads the repository as the "
            "agent's own user, so it needs the live session")
TOO_LARGE = "repository too large to scan"
STALLED = "the repository snapshot stopped arriving"
UNFINISHED = "the repository snapshot didn't finish"


class HubClient:
    def __init__(self, base_url, api_key, verify=True):
        self.base, self.key, self.verify = base_url.rstrip("/"), api_key, verify

    async def post(self, path, body):
        import httpx
        async with httpx.AsyncClient(timeout=60, verify=self.verify) as c:
            r = await c.post(f"{self.base}/api/v1{path}", json=body, headers={"X-API-Key": self.key})
            return r.status_code


def _mc(v, n):
    """Mask, THEN cut (cutting first can split a secret so no pattern recognises it)."""
    return masking.mask_cut(str(v), n)


def _strs(v, n, each):
    if not isinstance(v, list):
        return []
    return [_mc(x, each) for x in [x for x in v if isinstance(x, (str, int))][:n]]


def validate_finding(obj):
    if not isinstance(obj, dict) or set(obj) != set(_KEYS) or obj.get("severity") not in _SEVERITIES:
        return None
    loc, refs = obj.get("location"), obj.get("references")
    if not isinstance(loc, dict) or loc.get("kind") != "file" or not isinstance(refs, dict):
        return None
    out = {k: obj[k] for k in _KEYS}
    for k in ("scan_id", "rule_id", "title", "description", "tool", "tool_version"):
        out[k] = _mc(out[k] or "", 512)
    out["evidence"] = _mc(out["evidence"] or "", 2048)
    line = loc.get("line")
    out["location"] = {"kind": "file", "path": _mc(loc.get("path") or "", 512),
                       "line": line if isinstance(line, int) and not isinstance(line, bool) else None}
    out["references"] = {k: _strs(refs.get(k), 20, 512) for k in ("cwe", "cve", "urls")}
    return out


def _clean_scope(sc):
    """{"mode": full|change|nothing_to_compare|tool, "history": bool}, or None when unknown/invalid."""
    if isinstance(sc, dict) and sc.get("mode") in _SCOPE_MODES and isinstance(sc.get("history"), bool):
        return {"mode": sc["mode"], "history": sc["history"]}
    return None


def _clean_dropped(d):
    """{severity: count} for findings the sandbox dropped at its cap; anything else is ignored."""
    if not isinstance(d, dict):
        return {}
    return {k: v for k, v in d.items() if k in _SEVERITIES and isinstance(v, int) and not isinstance(v, bool)
            and 0 < v < 2 ** 31}


def _clean_meta(meta):
    meta = meta if isinstance(meta, dict) else {}
    tv, asof, ms = meta.get("tool_version"), meta.get("data_as_of"), meta.get("manifests_scanned")
    return {"dropped": _clean_dropped(meta.get("dropped")),"tool_version": tv if isinstance(tv, str) and len(tv) <= 40 else "",
            "data_as_of": asof if isinstance(asof, str) and len(asof) <= 32 else None,
            "manifests_scanned": [_mc(m, 512) for m in ms if isinstance(m, str)][:200]
            if isinstance(ms, list) else [],
            "scope": _clean_scope(meta.get("scope"))}


def _plain_error(e):
    """A reason a person can act on, never a bare exception name."""
    if type(e).__name__ == "PrivilegeError":
        if "unknown privilege tier" in str(e):
            return "the session's privilege tier isn't supported on this server"
        return "this project's restricted user isn't set up on this server"
    return f"the runner hit an internal error ({type(e).__name__})"


async def _default_launch(argv):
    return await asyncio.create_subprocess_exec(*argv, stdin=asyncio.subprocess.PIPE,
                                                stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.DEVNULL, limit=1024 * 1024)


def helper_args(msg, deps_only):
    args = ["snap", "--cwd=" + msg["working_directory"]] + (["--deps-only"] if deps_only else [])
    ex = (msg.get("params") or {}).get("exclude")
    for e in (ex if isinstance(ex, list) else [])[:MAX_EXCLUDES]:
        args.append("--exclude=" + str(e)[:MAX_EXCLUDE_LEN])
    return args


def pin_to_session(msg, live):
    """The scan_run message with its identity pinned to the daemon's live session for session_id
    (L4): that session's directory, and its OS user as the floor. Private keys a hub might send are
    dropped. Without a live session (closed since) the hub's stored directory is used; dl-helper
    still refuses /, homes, credential, system and Orchestratia paths."""
    msg = {k: v for k, v in msg.items() if not str(k).startswith("_")}
    if live is not None:
        cwd = getattr(live, "working_dir", "") or ((getattr(getattr(live, "handle", None), "extra", None) or {}).get("cwd"))
        if cwd:
            msg["working_directory"] = cwd
        msg["_live"] = True
        msg["_session_run_as"] = (getattr(getattr(live, "handle", None), "extra", None) or {}).get("run_as")
    return msg


def snapshot_run_as(msg, tc, resolve=None):
    """The OS user dl-helper runs as: the live session's own user when it has one (a hub message
    can't widen it to the daemon's user), else the user the tier + project resolve to."""
    if msg.get("_live") and msg.get("_session_run_as"):
        return msg["_session_run_as"]
    if resolve is None:
        from orchestratia_agent import privilege
        resolve = privilege.resolve_user
    return resolve(msg.get("privilege_tier") or "standard", msg.get("project_id"), tc)


async def _default_snapshot(msg, tc, deps_only):
    """dl-helper snap as the session's OS user -> (header, async byte iterator, returncode(), stop()).

    The helper's stdout is one end of a socketpair, not a pipe: the helper runs as the session's
    uid, and any process of that uid could open a pipe through /proc/<pid>/fd/1 — even with the
    helper stopped at exec, before it can make itself non-dumpable — and write its own stream into
    the scan (M3). A socket can't be opened through /proc (ENXIO)."""
    import socket
    from orchestratia_agent.downloads import _stop, helper_argv
    run_as = snapshot_run_as(msg, tc)
    args = helper_args(msg, deps_only)
    ours, theirs = socket.socketpair()
    try:
        proc = await asyncio.create_subprocess_exec(*helper_argv(run_as, tc, args, msg["working_directory"]),
                                                    stdin=asyncio.subprocess.DEVNULL, stdout=theirs.fileno(),
                                                    stderr=asyncio.subprocess.DEVNULL, cwd="/")
    except BaseException:
        ours.close()
        raise
    finally:
        theirs.close()
    reader, writer = await asyncio.open_unix_connection(sock=ours, limit=1024 * 1024)

    async def stop():
        try:
            await _stop(proc)
        finally:
            writer.close()

    try:
        header = json.loads((await asyncio.wait_for(reader.readline(), HEADER_TIMEOUT_S)) or b"{}")
    except BaseException:
        await stop()
        raise

    async def body():
        while True:
            b = await reader.read(256 * 1024)
            if not b:
                break
            yield b
        await proc.wait()
    return header, body(), (lambda: proc.returncode), stop


class ScanRunner:
    def __init__(self, hub, tc, *, launch=None, snapshot=None, support=None, stop=None,
                 header_timeout=None, run_grace=None, post_backoff=None, runner_dir=None, feed_grace=5,
                 send=None, keepalive_s=None, clock=None, sessions=None, trusted_uids=(0,)):
        self.feed_grace = feed_grace
        self.hub, self.tc = hub, tc
        self.launch = launch or _default_launch
        self.snapshot = snapshot or _default_snapshot
        self.support = support or sandbox.support
        self.stop = stop or sandbox.stop
        self.header_timeout = HEADER_TIMEOUT_S if header_timeout is None else header_timeout
        self.run_grace = RUN_GRACE_S if run_grace is None else run_grace
        self.post_backoff = POST_BACKOFF_S if post_backoff is None else post_backoff
        self.runner_dir = runner_dir or sandbox.RUNNER_DIR
        # send(msg) -> awaitable: the daemon's websocket send, for scan_progress. Optional.
        self.send = send
        self.keepalive_s = KEEPALIVE_S if keepalive_s is None else keepalive_s
        self.clock = clock
        # sessions(session_id) -> the daemon's live session or None: pins the snapshot identity (L4).
        self.sessions = sessions
        # Owners the scanner tree may have: root only in production (tests pass their own uid).
        self.trusted_uids = tuple(trusted_uids)
        self.tasks = {}
        # Runs whose sandbox could not be stopped/removed: the id is never used again.
        self._unclean = set()
        self._other = asyncio.Semaphore(2)     # per runner, created inside the running loop

    def _now(self):
        return self.clock() if self.clock is not None else asyncio.get_running_loop().time()

    async def _progress(self, rid, phase, message):
        """scan_progress over the websocket; a failure here never fails the run."""
        if self.send is None:
            return
        try:
            await self.send({"type": "scan_progress", "run_id": rid, "phase": phase,
                             "message": _mc(message, 200)})
        except Exception:
            log.debug(f"scan {rid}: could not send progress", exc_info=True)

    async def _keepalive(self, rid, state):
        while True:
            await asyncio.sleep(self.keepalive_s)
            await self._progress(rid, state["phase"], state["message"])

    async def _complete(self, rid, status, error=None, meta=None, dropped=None):
        try:
            meta = _clean_meta(meta)
            for k, v in (dropped or {}).items():          # the runner's own cap, on top of the sandbox's
                meta["dropped"][k] = meta["dropped"].get(k, 0) + v
            body = {"status": status, "tool_version": meta["tool_version"], "data_as_of": meta["data_as_of"],
                    "manifests_scanned": meta["manifests_scanned"], "scope": meta["scope"], "isolation": "systemd",
                    "error": _mc(error, 200) if error else None}
            if meta["dropped"]:
                body["dropped"] = meta["dropped"]           # findings not uploaded, per severity
            await self.hub.post(f"/server/security/runs/{rid}/complete", body)
        except Exception:
            log.exception(f"scan {rid}: could not report completion ({status}) to the hub")

    async def _post_findings(self, rid, batch):
        for attempt in range(POST_RETRIES):
            try:
                if await self.hub.post(f"/server/security/runs/{rid}/findings", {"findings": batch}) == 200:
                    return True
            except Exception:
                log.warning(f"scan {rid}: findings upload raised (attempt {attempt + 1})", exc_info=True)
            if attempt + 1 < POST_RETRIES:
                await asyncio.sleep(self.post_backoff)
        return False

    async def handle(self, msg):
        rid = str(msg.get("run_id") or "")
        try:
            sandbox.unit_name(rid)
        except ValueError:
            log.warning("scan_run with a bad run id ignored")
            return
        if rid in self._unclean:
            log.error(f"scan {rid}: refused — this run's sandbox could not be cleaned up earlier")
            return
        if rid in self.tasks:
            log.warning(f"scan {rid}: duplicate scan_run ignored")
            return
        task = asyncio.current_task()
        self.tasks[rid] = task
        try:
            await self._handle(rid, msg)
        finally:
            if self.tasks.get(rid) is task:
                self.tasks.pop(rid, None)

    async def _handle(self, rid, msg):
        try:
            if await self.hub.post(f"/server/security/runs/{rid}/ack", {}) != 200:
                log.info(f"scan {rid}: hub refused the ack; not running")
                return
        except Exception:
            log.exception(f"scan {rid}: ack failed")
            return
        dropped = {}
        status, error, meta = await self._outcome(rid, msg, dropped)
        # Stop the sandbox BEFORE reporting: a run is only complete once nothing of it is left.
        try:
            stopped = await self.stop(rid) is not False
        except Exception:
            log.exception(f"scan {rid}: sandbox stop failed")
            stopped = False
        if not stopped:
            log.error(f"scan {rid}: sandbox unit could not be fully stopped/removed; this run id is retired")
            self._unclean.add(rid)
            status, error = "failed", "the scan sandbox couldn't be cleaned up"
        await self._complete(rid, status, error, meta, dropped)

    async def _outcome(self, rid, msg, dropped=None):
        """Runs the scan; returns (status, error, meta) for /complete. Posts findings, never complete."""
        live = None
        if self.sessions is not None:
            try:
                live = self.sessions(str(msg.get("session_id") or ""))
            except Exception:
                live = None
        msg = pin_to_session(msg, live)
        # L4: without the live session there is no identity to pin; a standard-tier snapshot would read
        # the hub's stored path as the daemon's own user. Only a restricted (project-user) read may fall back.
        if self.sessions is not None and live is None and (msg.get("privilege_tier") or "standard") != "restricted":
            return "failed", NOT_LIVE, None
        spec = catalog.get(str(msg.get("scan_id")))
        if spec is None:
            return "failed", f"unknown scan: {msg.get('scan_id')}", None
        try:
            ok, why = await asyncio.to_thread(self.support)
        except asyncio.CancelledError:
            return "cancelled", None, None
        if not ok:
            return "failed", f"this runner can't sandbox scans: {why}", None
        since = (msg.get("params") or {}).get("since")
        if since is not None and not _SHA.match(str(since)):
            return "failed", "the change base must be a full commit sha", None
        if not msg.get("working_directory"):
            return "failed", "the session has no working directory", None
        if not os.path.isfile(os.path.join(self.runner_dir, "shim.py")):
            return "failed", "the scanner pack isn't installed on this server", None
        # The runner files, the tool and the OSV data run in every tenant's sandbox: refuse a tree
        # anyone but root could have changed (L3).
        tool = pack.tool_paths().get(spec.tool) if spec.tool != "orchestratia" else None
        db = pack.osv_db()[0] if spec.deps_only else None
        why = await asyncio.to_thread(pack.integrity_problem, self.runner_dir, [tool] if tool else [], db,
                                      self.trusted_uids)
        if why:
            log.error(f"scan {rid}: scanner pack integrity check failed: {why}")
            return "failed", "the scanner pack's files aren't root-owned and protected on this server", None
        box = {}
        try:
            await _SWEEP_DONE.wait()
            async with self._other:
                return await asyncio.wait_for(self._run(rid, spec, msg, since, box, dropped),
                                              spec.timeout_s + self.run_grace)
        except asyncio.TimeoutError:
            return "timed_out", OUT_OF_TIME, box.get("meta")
        except asyncio.CancelledError:
            return "cancelled", None, box.get("meta")
        except Exception as e:
            log.exception(f"scan {rid} failed")
            return "failed", _plain_error(e), box.get("meta")

    async def _run(self, rid, spec, msg, since, box, dropped=None):
        dropped = {} if dropped is None else dropped
        helper_stop = None
        feeder = None
        keepalive = None
        state = {"phase": "snapshot", "message": "reading the repository"}
        try:
            await self._progress(rid, state["phase"], state["message"])
            try:
                snap = await asyncio.wait_for(self.snapshot(msg, self.tc, spec.deps_only), self.header_timeout)
            except asyncio.TimeoutError:
                return "failed", "the repository couldn't be read in time", None
            header, body, snap_rc = snap[:3]
            helper_stop = snap[3] if len(snap) > 3 else None
            if not header.get("ok"):
                return "failed", _REFUSALS.get(header.get("error"), "could not read the repository"), None
            db_path, as_of = pack.osv_db()
            hdr = {"scan_id": spec.id, "since": since, "tools": pack.tool_paths(), "osv_db": db_path,
                   "data_as_of": as_of, "known": []}
            started = self._now()
            cmd = sandbox.launch_argv(rid, spec)
            via_launcher = cmd[0] == "sudo"
            proc = await self.launch(cmd)
            state.update(phase="scanning", message=f"running {spec.id} in the sandbox")
            await self._progress(rid, state["phase"], state["message"])
            keepalive = asyncio.ensure_future(self._keepalive(rid, state))

            fed = {"error": None}

            deadline = asyncio.get_running_loop().time() + (
                SNAPSHOT_DEADLINE_S if SNAPSHOT_DEADLINE_S is not None else spec.timeout_s / 2)

            async def feed():
                sent, it = 0, body.__aiter__()
                try:
                    proc.stdin.write(json.dumps(hdr).encode() + b"\n")
                    while True:
                        left = deadline - asyncio.get_running_loop().time()
                        try:
                            chunk = await asyncio.wait_for(it.__anext__(), max(0.0, min(BODY_STALL_S, left)))
                        except StopAsyncIteration:
                            break
                        except asyncio.TimeoutError:
                            fed["error"] = SLOW if left <= BODY_STALL_S else STALLED
                            break
                        sent += len(chunk)
                        if sent > STREAM_MAX:
                            fed["error"] = TOO_LARGE
                            break
                        proc.stdin.write(chunk)
                        await proc.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    proc.stdin.close()
            feeder = asyncio.ensure_future(feed())
            batch, batch_bytes, end, total, capped, uploaded = [], 0, None, 0, False, 0

            async def flush():
                nonlocal batch, batch_bytes, uploaded
                if not batch:
                    return True
                uploaded += len(batch)
                state.update(phase="uploading", message=f"uploading findings ({uploaded} so far)")
                await self._progress(rid, state["phase"], state["message"])
                good = await self._post_findings(rid, batch)
                batch, batch_bytes = [], 0
                return good

            async def snapshot_problem():
                """Why the snapshot can't be trusted as complete, or None: the feed failed, or the helper
                hasn't exited 0 (rc None = still running or stopped: the session can SIGSTOP its helper,
                after which sudo stops too and the stream may have been cut at a file boundary)."""
                if not feeder.done():
                    await asyncio.wait({feeder}, timeout=self.feed_grace)
                if fed["error"]:
                    return fed["error"]
                rc = snap_rc()
                if rc == 3:
                    return TOO_LARGE
                return None if rc == 0 else UNFINISHED

            checked = False
            any_output = False
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                any_output = True
                try:
                    obj = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    continue
                kind = obj.get("type") if isinstance(obj, dict) else None
                if kind == "finding" and not checked:
                    checked = True                   # the sandbox read all its input before finding anything
                    why = await snapshot_problem()
                    if why:
                        return "failed", why, box.get("meta")     # nothing uploaded from a partial snapshot
                if kind == "finding":
                    if total >= MAX_FINDINGS:
                        capped = True
                        sev = (obj.get("finding") or {}).get("severity") if isinstance(obj.get("finding"), dict) else None
                        if sev in _SEVERITIES:
                            dropped[sev] = dropped.get(sev, 0) + 1
                        continue                     # keep draining; upload nothing more
                    f = validate_finding(obj.get("finding"))
                    if f:
                        size = len(json.dumps(f).encode()) + 2      # upper bound for any JSON encoding
                        if batch and batch_bytes + size > BATCH_MAX_BYTES:
                            if not await flush():
                                return "failed", "couldn't upload findings to the hub", box.get("meta")
                        batch.append(f)
                        batch_bytes += size
                        total += 1
                        if len(batch) >= CHUNK and not await flush():
                            return "failed", "couldn't upload findings to the hub", box.get("meta")
                elif kind == "meta":
                    box["meta"] = obj
                elif kind == "end":
                    end = obj
            if not feeder.done():
                await asyncio.wait({feeder}, timeout=self.feed_grace)    # sandbox exited; don't wait on a stalled helper
            if not feeder.done():
                feeder.cancel()
            await asyncio.gather(feeder, return_exceptions=True)
            feeder = None
            try:
                await asyncio.wait_for(proc.wait(), 30)
            except asyncio.TimeoutError:
                pass
            if via_launcher and not any_output:
                why = await self._launcher_failure(proc.returncode)
                if why:
                    return "failed", why, box.get("meta")
            if not await flush():
                return "failed", "couldn't upload findings to the hub", box.get("meta")
            meta = box.get("meta")
            if fed["error"]:
                return "failed", fed["error"], meta
            rc = snap_rc()
            if rc == 3:
                return "failed", TOO_LARGE, meta
            if rc != 0:                               # killed, crashed, or never exited (stopped): never done
                return "failed", UNFINISHED, meta
            if end is None:
                if self._now() - started >= spec.timeout_s - 2:          # RuntimeMaxSec stopped the unit
                    return "timed_out", OUT_OF_TIME, meta
                if proc.returncode:
                    return "failed", "the scan stopped unexpectedly (it may have run out of memory)", meta
                return "failed", "the scan stopped without a result", meta
            status = end.get("status") if end.get("status") in _END_STATUSES else "failed"
            if capped and status == "done":
                status = "truncated"
            error = end.get("error")
            return status, (str(error) if error is not None else None), meta
        finally:
            if keepalive is not None:
                keepalive.cancel()
                await asyncio.gather(keepalive, return_exceptions=True)
            if feeder is not None and not feeder.done():
                feeder.cancel()
                await asyncio.gather(feeder, return_exceptions=True)
            if helper_stop is not None:
                try:
                    await helper_stop()
                except Exception:
                    log.exception(f"scan {rid}: could not stop the snapshot helper")

    @staticmethod
    async def _launcher_failure(rc):
        """Why the root launcher (run through sudo) never started the sandbox, or None. 64/77 are the
        launcher's own refusals; sudo itself exits 1, so rc 1 is blamed on it only while sudo -l agrees."""
        if rc == launch_codes.EX_USAGE:
            return LAUNCHER_REFUSED
        if rc == launch_codes.EX_UNSAFE:
            return LAUNCHER_UNSAFE
        if rc == 1:
            ok_, why = await asyncio.to_thread(sandbox.launcher_ok, fresh=True)   # never the cached answer
            if not ok_:
                return why
        return None

    async def cancel(self, rid):
        t = self.tasks.get(rid)
        if t:
            t.cancel()


async def sweep_at_start():
    try:
        ok = (await asyncio.to_thread(sandbox.support))[0]
        if ok:
            n = await sandbox.sweep()
            if n:
                log.info(f"Stopped {n} leftover scan sandbox(es) from before the restart")
            if sandbox.as_root() and pack.tool_paths():
                pack.sync_runner_files()      # a non-root daemon can't write /opt: scanners install / update do
    except Exception:
        log.exception("scan sandbox sweep failed")
    finally:
        _SWEEP_DONE.set()
