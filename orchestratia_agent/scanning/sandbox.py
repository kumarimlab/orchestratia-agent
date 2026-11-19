"""The per-run systemd sandbox (spec §7.3, D12). Every scan runs as a transient unit
with a fresh dynamic UID, a private state dir, no home dirs, a read-only system, cgroup
limits and — for code scans — no network. No fallback: without these, no scans."""
import asyncio
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import time

RUNNER_DIR = "/opt/orchestratia/scanners/runner"
# What `pack.sync_runner_files` copies into RUNNER_DIR (root-owned; the launcher runs from it).
RUNNER_FILES = ("shim.py", "masking.py", "parsers.py", "code_agent.py", "catalog.py", "sandbox.py", "launch.py",
                "gitleaks.toml")
RUNNER_STAMP = RUNNER_DIR + "/RUNNER_SHA256"     # runner_hash of the copies, written at install
OUT_OF_DATE = "the scanner runner is out of date — run: sudo orchestratia scanners install"
STATE_ROOT = "/var/lib/private/orc-scan"
LINK_ROOT = "/var/lib/orc-scan"
_UNIT_PREFIX = "orc-scan-"
_RUN_ID = re.compile(r"[0-9a-f-]{36}")
log = logging.getLogger("orchestratia.scan")
_IO_URING = "~io_uring_setup io_uring_enter io_uring_register"
PYTHON = "/usr/bin/python3"                 # the interpreter the unit runs the shim with
_PY_PROBE = ("import sys, tarfile; "
             "sys.exit(0 if sys.version_info >= (3, 10) and hasattr(tarfile, 'data_filter') else 3)")
_py_cache = {}
LAUNCHER = "/usr/local/libexec/orchestratia/scan-launch"
SYSTEMCTL = "/usr/bin/systemctl"            # fixed paths: the launcher runs these as root
_NO_LAUNCHER = "the scan launcher isn't set up; run: sudo orchestratia scanners install"


def as_root() -> bool:
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def _root_path_problem(path):
    """Why `path` could be changed by someone other than root, or None. Every component AS GIVEN is
    lstat'ed (a symlink anywhere is refused, never resolved); each must be root-owned and not
    group/world-writable."""
    parts = os.path.abspath(path).split(os.sep)
    for i in range(1, len(parts) + 1):
        p = os.sep.join(parts[:i]) or os.sep
        try:
            st = os.lstat(p)
        except OSError:
            return f"{p} is missing"
        if os.path.islink(p) or st.st_uid != 0 or st.st_mode & 0o022:
            return f"{p} isn't root-owned and protected"
    return None


def runner_hash(directory):
    """sha256 over RUNNER_FILES in `directory`: each name, its length and its bytes."""
    h = hashlib.sha256()
    for name in RUNNER_FILES:
        with open(os.path.join(directory, name), "rb") as fh:
            data = fh.read()
        h.update(name.encode() + b"\0" + len(data).to_bytes(8, "big") + data)
    return h.hexdigest()


def runner_current():
    """Is the root-owned runner copy the same code as this agent? A non-root daemon can't refresh it, so after
    `orchestratia update` the launcher would run an older shim/catalog/sandbox than this runner expects."""
    if not os.path.isdir(os.path.dirname(RUNNER_STAMP)):
        return False, "the scanner pack isn't installed; run: sudo orchestratia scanners install"
    try:
        with open(RUNNER_STAMP) as fh:
            stamp = fh.read().strip()
        mine = runner_hash(os.path.dirname(os.path.abspath(__file__)))
    except OSError:
        return False, OUT_OF_DATE
    return (True, "ok") if stamp == mine else (False, OUT_OF_DATE)


LAUNCHER_SUDO_TTL_S = 3600
_sudo_ok = {}       # {"launcher": path, "at": monotonic time} of the last positive `sudo -n -l`


def launcher_ok(run=subprocess.run, *, fresh=False, clock=time.monotonic):
    """A non-root daemon can start sandboxes only through the root-owned launcher, which sudo must let it run
    without a password (both installed by `sudo orchestratia scanners install`).

    The path checks (lstat only) run every call. `sudo -n -l` writes an auth.log line each time and capability
    refreshes call this every minute, so a POSITIVE answer is reused for LAUNCHER_SUDO_TTL_S; a refusal is never
    cached, and the runner passes fresh=True after a launcher failure so a revoked rule is seen at once."""
    if not os.path.lexists(LAUNCHER):
        _sudo_ok.clear()
        return False, _NO_LAUNCHER
    why = _root_path_problem(LAUNCHER)
    if why:
        _sudo_ok.clear()
        return False, f"{why}; run: sudo orchestratia scanners install"
    now = clock()
    if (not fresh and _sudo_ok.get("launcher") == LAUNCHER
            and 0 <= now - _sudo_ok.get("at", float("-inf")) < LAUNCHER_SUDO_TTL_S):
        return True, "ok"
    try:
        rc = run(["sudo", "-n", "-l", LAUNCHER], capture_output=True, timeout=10).returncode
    except Exception:
        rc = None
    if rc != 0:
        _sudo_ok.clear()
        return False, "sudo doesn't let the agent run the scan launcher; run: sudo orchestratia scanners install"
    _sudo_ok.update(launcher=LAUNCHER, at=now)
    return True, "ok"


def unit_name(run_id: str) -> str:
    if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id):
        raise ValueError("bad run id")
    return _UNIT_PREFIX + run_id


def _python_ok(python=PYTHON):
    """Can `python` run the shim safely: >= 3.10 with tarfile extraction filters? Probed once
    per interpreter path and cached (an OS upgrade restarts the agent anyway)."""
    if python not in _py_cache:
        try:
            rc = subprocess.run([python, "-I", "-c", _PY_PROBE], capture_output=True, timeout=20).returncode
        except Exception:
            rc = None
        if rc == 0:
            _py_cache[python] = (True, "ok")
        elif rc is None:
            _py_cache[python] = (False, f"{python} can't be run")
        else:
            _py_cache[python] = (False, f"{python} is older than 3.10 or lacks tarfile extraction filters")
    return _py_cache[python]


def support():
    if platform.system() != "Linux":
        return False, "scans run only on Linux servers (systemd sandbox)"
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False, "this platform has no user ids to sandbox with"
    if geteuid() != 0:
        ok_, why = launcher_ok()
        if not ok_:
            return False, why
        ok_, why = runner_current()
        if not ok_:
            return False, why
    if not os.path.exists("/sys/fs/cgroup/cgroup.controllers"):
        return False, "cgroup v2 isn't available"
    try:
        out = subprocess.run(["systemctl", "--version"], capture_output=True, text=True, timeout=5).stdout
        ver = int(out.split()[1])
    except Exception:
        return False, "systemd isn't available"
    if ver < 250:
        return False, f"systemd {ver} is older than 250"
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        return False, "this Python can't remove sandbox directories safely"
    return _python_ok(PYTHON)


def argv(run_id, spec, python=PYTHON, shim=RUNNER_DIR + "/shim.py"):
    name = unit_name(run_id)
    props = [
        ("DynamicUser", "yes"), ("PrivateTmp", "yes"), ("StateDirectory", f"orc-scan/{run_id}"),
        ("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateDevices", "yes"),
        ("PrivateIPC", "yes"), ("TemporaryFileSystem", "/dev/shm"),
        ("ProtectProc", "invisible"), ("ProcSubset", "pid"),
        ("NoNewPrivileges", "yes"), ("RestrictSUIDSGID", "yes"), ("LockPersonality", "yes"),
        ("ProtectKernelTunables", "yes"), ("ProtectKernelModules", "yes"), ("ProtectKernelLogs", "yes"),
        ("ProtectControlGroups", "yes"), ("RestrictNamespaces", "yes"), ("CapabilityBoundingSet", ""),
        ("SystemCallArchitectures", "native"),
        ("SystemCallFilter", "@system-service"), ("SystemCallFilter", _IO_URING),
        ("SystemCallErrorNumber", "EPERM"),
        # AF_UNIX only. RestrictAddressFamilies=none is not accepted for transient units (systemd 255
        # systemd-run: "Failed to set unit properties: Invalid argument"). With /run hidden and
        # PrivateNetwork's own namespace for abstract sockets, there is nothing to connect to.
        ("RestrictAddressFamilies", "AF_UNIX"), ("TemporaryFileSystem", "/run:ro"),
        ("InaccessiblePaths", "-/etc/orchestratia"),
        ("MemoryMax", spec.memory_max), ("MemorySwapMax", "0"), ("CPUQuota", "200%"), ("TasksMax", "512"),
        ("RuntimeMaxSec", str(spec.timeout_s)), ("PrivateNetwork", "yes"),
        ("Environment", f"HOME=/var/lib/orc-scan/{run_id} TMPDIR=/var/lib/orc-scan/{run_id}"),
    ]
    out = ["systemd-run", "--wait", "--pipe", "--collect", "--quiet", f"--unit={name}"]
    for k, v in props:
        out += ["-p", f"{k}={v}"]
    return out + ["--", python, "-I", shim]


def launch_argv(run_id, spec):
    """What the runner executes for a run: systemd-run itself when the daemon is root, else the launcher through
    sudo with only the run id and the scan id (the launcher builds the unit from its own root-owned copy)."""
    if as_root():
        return argv(run_id, spec)
    unit_name(run_id)                                  # raises ValueError on anything but a run id
    return ["sudo", "-n", LAUNCHER, "run", run_id, spec.id]


async def _run(*cmd, capture=False):
    """Run a command; returns (returncode, stdout-text-or-'')."""
    p = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE if capture else asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL)
    out, _ = await p.communicate()
    return p.returncode, (out.decode() if capture else "")


async def _is_stopped(unit):
    """True only when systemd positively reports inactive/failed (unknown units report
    inactive). Empty output or a non-zero rc is NOT stopped."""
    rc, out = await _run(SYSTEMCTL, "show", "-p", "ActiveState", "--value", unit, capture=True)
    return rc == 0 and out.strip() in ("inactive", "failed")


def _remove_state(run_id):
    """Remove the state dir and the dangling /var/lib/orc-scan/<id> symlink. Never follows
    a symlink planted inside the dir. Raises on failure."""
    path = os.path.join(STATE_ROOT, run_id)
    if os.path.lexists(path):
        if os.path.islink(path):
            os.unlink(path)
        else:
            shutil.rmtree(path)                        # fd-based: never follows a planted symlink
    link = os.path.join(LINK_ROOT, run_id)
    if os.path.islink(link):
        os.unlink(link)


async def _stop_one(unit, run_id):
    await _run(SYSTEMCTL, "stop", unit)
    await _run(SYSTEMCTL, "reset-failed", unit)
    if not await _is_stopped(unit):
        log.error("scan unit %s is still active after stop; state kept, do not reuse run id", unit)
        return False
    try:
        await asyncio.to_thread(_remove_state, run_id)
    except Exception:
        log.error("could not remove scan state for %s; do not reuse run id", run_id, exc_info=True)
        return False
    return True


async def stop(run_id):
    """Stop the unit, then remove its state. Returns False (after logging) when the unit
    is still running or the state couldn't be removed: the caller must not reuse the id.
    A non-root daemon asks the launcher, which can only stop that run's orc-scan- unit."""
    if not as_root():
        unit_name(run_id)
        rc, _ = await _run("sudo", "-n", LAUNCHER, "stop", run_id)
        return rc == 0
    return await _stop_one(unit_name(run_id), run_id)


async def _list_units():
    _, out = await _run(SYSTEMCTL, "list-units", "--all", "--plain", "--no-legend",
                        f"{_UNIT_PREFIX}*", capture=True)
    return [ln.split()[0] for ln in out.splitlines() if ln.strip().startswith(_UNIT_PREFIX)]


async def _stop_unit(unit):
    await _run(SYSTEMCTL, "stop", unit)
    await _run(SYSTEMCTL, "reset-failed", unit)


def _leftover_ids():
    ids = set()
    for root in (STATE_ROOT, LINK_ROOT):
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            if _RUN_ID.fullmatch(name):
                ids.add(name)
    return ids


async def sweep():
    """Stop every orc-scan-* unit, then remove state and dangling links for runs whose unit
    is confirmed stopped. Returns the number of units found. A non-root daemon asks the launcher."""
    if not as_root():
        rc, out = await _run("sudo", "-n", LAUNCHER, "sweep", capture=True)
        try:
            return int(out.strip() or 0) if rc == 0 else 0
        except ValueError:
            return 0
    units = await _list_units()
    for u in units:
        await _stop_unit(u)
    for rid in sorted(await asyncio.to_thread(_leftover_ids)):
        if not await _is_stopped(unit_name(rid)):
            log.error("sweep: scan unit for %s is still active; state kept", rid)
            continue
        try:
            await asyncio.to_thread(_remove_state, rid)
        except Exception:
            log.error("sweep could not remove %s", rid, exc_info=True)
    return len(units)
