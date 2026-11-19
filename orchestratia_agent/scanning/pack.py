"""Scanner pack (spec 7.1-7.2): pinned tools verified by SHA-256 BEFORE unpacking,
installed root-owned under /opt; OSV data refreshed into a new dir and switched with an
atomic symlink swap. Opt-in, never on a hub host (D13), never without the sandbox (D12).

Everything the sandbox reads (runner files, tools, OSV data) must be readable by an
arbitrary DynamicUser UID: dirs 0755, files 0644 (binaries 0755), modes set explicitly."""
import datetime
import fcntl
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from . import catalog, sandbox

SCANNERS_ROOT = "/opt/orchestratia/scanners"
DATA_ROOT = "/var/lib/orchestratia/scan-data"
MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "manifest.json")
RUNNER_FILES = sandbox.RUNNER_FILES
OSV_ECOSYSTEMS = ("PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "Packagist", "NuGet")
OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
# osv-scanner 2.7.0 reads <dir>/osv-scalibr/<Ecosystem>/all.zip
OSV_SUBDIR = "osv-scalibr"
HUB_CONTAINERS = ("orchestratia-backend", "orchestratia-postgres")
TOOL_MAX_BYTES = 512 * 1024 * 1024
OSV_MAX_BYTES = 2 * 1024 * 1024 * 1024
CAPABILITY_TTL_S = 60


class InstallError(Exception):
    pass


def _fetch(url, dest=None, max_bytes=None):
    """Default downloader: streams to `dest` with a size cap (never holds the body in memory)."""
    total = 0
    with urllib.request.urlopen(url, timeout=120) as r, open(dest, "wb") as f:   # noqa: S310
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if max_bytes is not None and total > max_bytes:
                raise ValueError(f"download exceeds the {max_bytes // (1024 * 1024)} MiB limit")
            f.write(chunk)


def _download(fetch, url, dest, max_bytes):
    """Fetch `url` into the file `dest`. An injected fetch(url) may return bytes."""
    if fetch is _fetch:
        _fetch(url, dest, max_bytes)
        return
    blob = fetch(url)
    if len(blob) > max_bytes:
        raise ValueError(f"download exceeds the {max_bytes // (1024 * 1024)} MiB limit")
    with open(dest, "wb") as f:
        f.write(blob)


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _clean_stale(root, prefixes):
    """Remove temp dirs an earlier crash left behind (real directories only, never links)."""
    try:
        names = os.listdir(root)
    except OSError:
        return
    for n in names:
        p = os.path.join(root, n)
        if n.startswith(prefixes) and os.path.isdir(p) and not os.path.islink(p):
            shutil.rmtree(p, ignore_errors=True)


def _secure(path, mode):
    """root-owned (when we are root) and exactly `mode`, without following a symlink."""
    st_ = os.lstat(path)
    if stat.S_ISLNK(st_.st_mode):
        raise InstallError(f"{path} is a symlink; the scanner pack must be real root-owned directories")
    if os.geteuid() == 0 and (st_.st_uid, st_.st_gid) != (0, 0):
        os.lchown(path, 0, 0)
    os.chmod(path, mode)


def _mkdir(path, base=None):
    """makedirs with explicit 0755 on every directory from `base` (default: path's parent) down to
    path — created now or already there (a pre-existing group/world-writable dir is tightened)."""
    base = base or os.path.dirname(path.rstrip("/"))
    missing = []
    p = path
    while p and not os.path.isdir(p):
        missing.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    for d in reversed(missing):
        os.mkdir(d)
    p, chain = path, []
    while True:
        chain.append(p)
        if p == base or os.path.dirname(p) == p:
            break
        p = os.path.dirname(p)
    for d in reversed(chain):
        if os.path.isdir(d):
            _secure(d, 0o755)


def _path_problem(path, uids, want_dir=None):
    """Why `path` (and every directory above it) could be changed by someone outside `uids`, or None.
    Every component of the path AS GIVEN is lstat'ed — never resolved: a symlink anywhere on the way
    is refused (resolving first would vouch for the target and not for whoever can swap the link).
    Each must be owned by a trusted uid and not group/world-writable (a root-owned sticky directory
    such as /tmp is allowed above the tree)."""
    path = os.path.abspath(path)
    parts = path.split(os.sep)
    for i in range(1, len(parts) + 1):
        p = os.sep.join(parts[:i]) or os.sep
        try:
            s = os.lstat(p)
        except OSError:
            return f"{p} is missing"
        if stat.S_ISLNK(s.st_mode):
            return f"{p} is a symlink"
        if s.st_uid not in uids:
            return f"{p} is owned by uid {s.st_uid}"
        if s.st_mode & 0o022 and not (stat.S_ISDIR(s.st_mode) and s.st_mode & stat.S_ISVTX and s.st_uid == 0
                                      and p != path):
            return f"{p} is writable by group or others"
    s = os.lstat(path)
    if want_dir is True and not stat.S_ISDIR(s.st_mode) or want_dir is False and not stat.S_ISREG(s.st_mode):
        return f"{path} is not a {'directory' if want_dir else 'regular file'}"
    return None


def _osv_dir(db, uids):
    """(real data dir, problem). The OSV `current` entry is the one symlink allowed: it must be owned
    by a trusted uid and name a sibling directory (refresh_osv writes it so)."""
    db = os.path.abspath(db)
    try:
        s = os.lstat(db)
    except OSError:
        return None, f"{db} is missing"
    if not stat.S_ISLNK(s.st_mode):
        return db, None
    why = _path_problem(os.path.dirname(db), uids, True)
    if why:
        return None, why
    target = os.readlink(db)
    if s.st_uid not in uids or not target or "/" in target or target in (".", ".."):
        return None, f"{db} must be a trusted link to a sibling directory"
    return os.path.join(os.path.dirname(db), target), None


def integrity_problem(runner_dir, tools, db, uids=(0,)):
    """None when everything a scan sandbox executes or reads from the pack is root-owned and
    writable by nobody else, all the way up; else the first problem (L3). Checked at install and
    before every launch."""
    checks = [(runner_dir, True)] + [(os.path.join(runner_dir, f), False) for f in RUNNER_FILES]
    checks += [(t, False) for t in tools or ()]
    if db:
        real, why = _osv_dir(db, uids)
        if why:
            return why
        checks.append((real, True))
        for root, dirs, files in os.walk(real, followlinks=False):
            checks += [(os.path.join(root, d), True) for d in dirs]
            checks += [(os.path.join(root, f), False) for f in files]
            if len(checks) > 500:
                break
    for path, is_dir in checks:
        why = _path_problem(path, uids, is_dir)
        if why:
            return why
    return None


def is_hub_host():
    """Fails CLOSED: docker present but unqueryable counts as a hub (D13 is a safety rule).
    No docker binary at all means no hub containers."""
    try:
        r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"], capture_output=True,
                           text=True, timeout=10)
    except FileNotFoundError:
        return False
    except (OSError, subprocess.SubprocessError):
        return True
    if r.returncode != 0:
        return True
    return any(n in HUB_CONTAINERS for n in r.stdout.split())


def sync_runner_files(root=SCANNERS_ROOT):
    """Copy the runner files (launch.py, the shim, …) into the root-owned runner directory. As root it first
    refuses when this agent's own code isn't root's alone: root would copy code another user can change into the
    place the scan launcher runs as root from."""
    from orchestratia_agent import codetrust
    here = os.path.dirname(os.path.abspath(__file__))
    # The code roots AND the dir copied from: an editable (.pth) install's package lives outside the venv.
    codetrust.require_trusted("copy the scanner runner files into the root-owned runner directory",
                              roots=codetrust.code_roots() + [here])
    _mkdir(root)
    _clean_stale(root, (".runner-",))
    dest = os.path.join(root, "runner")
    tmp = tempfile.mkdtemp(prefix=".runner-", dir=root)
    try:
        for f in RUNNER_FILES:
            shutil.copyfile(os.path.join(here, f), os.path.join(tmp, f))
            os.chmod(os.path.join(tmp, f), 0o644)
        stamp = os.path.join(tmp, os.path.basename(sandbox.RUNNER_STAMP))
        with open(stamp, "w") as fh:
            fh.write(sandbox.runner_hash(tmp) + "\n")       # what was copied: a non-root daemon compares its own
        os.chmod(stamp, 0o644)
        os.chmod(tmp, 0o755)
        old = dest + ".old"
        shutil.rmtree(old, ignore_errors=True)
        if os.path.isdir(dest):
            os.rename(dest, old)
        os.rename(tmp, dest)
    except Exception:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    shutil.rmtree(dest + ".old", ignore_errors=True)


def install(root=SCANNERS_ROOT, manifest=None, arch=None, fetch=_fetch, require_root=True):
    if require_root and os.geteuid() != 0:
        raise InstallError("Run this as root: sudo orchestratia scanners install")
    if is_hub_host():
        raise InstallError("This looks like an Orchestratia hub host, or this server could not check for "
                           "hub containers (docker did not answer). Scanners are never installed on a hub.")
    ok, why = sandbox.support()
    if not ok:
        raise InstallError(f"This server can't sandbox scans: {why}.")
    if manifest is None:
        with open(MANIFEST) as f:
            manifest = json.load(f)
    arch = arch or platform.machine()
    _mkdir(root)
    _clean_stale(root, tuple(f".{n}-" for n in manifest["tools"]))
    staged = []
    try:
        for name, tool in manifest["tools"].items():
            asset = tool["assets"].get(arch)
            if asset is None:
                raise InstallError(f"No {name} build for {arch}.")
            final = os.path.join(root, name, tool["version"])
            if os.path.isfile(os.path.join(final, tool["binary"])):
                continue
            tmp = tempfile.mkdtemp(prefix=f".{name}-", dir=root)
            staged.append((tmp, final))
            dl = os.path.join(tmp, ".download")
            try:
                _download(fetch, asset["url"], dl, TOOL_MAX_BYTES)
            except Exception as e:
                raise InstallError(f"{name} {tool['version']}: download failed ({e}). Nothing was installed.")
            if _sha256_file(dl) != asset["sha256"]:
                raise InstallError(f"{name} {tool['version']}: checksum mismatch. Nothing was installed.")
            dest_bin = os.path.join(tmp, tool["binary"])
            if asset["archive"] == "tar.gz":
                with tarfile.open(dl, mode="r:gz") as tf:
                    member = tf.getmember(tool["binary"])
                    if not member.isfile():
                        raise InstallError(f"{name}: {tool['binary']} in the archive is not a regular file.")
                    src = tf.extractfile(member)
                    with open(dest_bin, "wb") as f:
                        shutil.copyfileobj(src, f)
            else:
                os.rename(dl, dest_bin)
            if os.path.exists(dl):
                os.unlink(dl)
            os.chmod(dest_bin, 0o755)
            os.chmod(tmp, 0o755)
        for tmp, final in staged:
            _mkdir(os.path.dirname(final))
            os.rename(tmp, final)
        staged = []
    finally:
        for tmp, _ in staged:
            shutil.rmtree(tmp, ignore_errors=True)
    sync_runner_files(root)
    why = integrity_problem(os.path.join(root, "runner"), list(tool_paths(root, manifest).values()), None,
                            uids=(0, os.geteuid()))          # (0, 0) as root; tests install unprivileged
    if why:
        raise InstallError(f"The scanner pack isn't protected: {why}. Scans stay off until it is root-owned.")
    return status(root)


def tool_paths(root=SCANNERS_ROOT, manifest=None):
    if manifest is None:
        with open(MANIFEST) as f:
            manifest = json.load(f)
    out = {}
    for name, tool in manifest["tools"].items():
        p = os.path.join(root, name, tool["version"], tool["binary"])
        if os.path.isfile(p):
            out[name] = p
    return out


def refresh_osv(data_root=DATA_ROOT, fetch=_fetch, ecosystems=None):
    """Download fresh OSV data and switch to it. Holds an exclusive lock on <data_root>/osv/.lock
    so the daily timer and a manual `scanners refresh` can't interleave their swaps and cleanup."""
    osv_root = os.path.join(data_root, "osv")
    _mkdir(osv_root, base=os.path.dirname(data_root.rstrip("/")))
    fd = os.open(os.path.join(osv_root, ".lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        os.fchmod(fd, 0o644)              # umask-proof, like everything else under scan-data
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise InstallError("another OSV data refresh is already running; try again when it finishes")
        return _refresh_osv_locked(osv_root, fetch, ecosystems)
    finally:
        os.close(fd)                      # closing the descriptor releases the lock


def _refresh_osv_locked(osv_root, fetch, ecosystems):
    as_of = datetime.date.today().isoformat()
    _clean_stale(osv_root, (".part-",))
    prev = None
    cur_link = os.path.join(osv_root, "current")
    if os.path.islink(cur_link):
        prev = os.path.basename(os.path.realpath(cur_link))
    new = tempfile.mkdtemp(prefix=f"{as_of}-", dir=osv_root)
    try:
        os.chmod(new, 0o755)
        base = os.path.join(new, OSV_SUBDIR)
        os.mkdir(base)
        os.chmod(base, 0o755)
        for eco in ecosystems or OSV_ECOSYSTEMS:
            d = os.path.join(base, eco)
            os.mkdir(d)
            os.chmod(d, 0o755)
            p = os.path.join(d, "all.zip")
            _download(fetch, OSV_URL.format(eco=eco), p, OSV_MAX_BYTES)
            with zipfile.ZipFile(p) as z:
                bad = z.testzip()
                if bad is not None:
                    raise ValueError(f"{eco}: corrupt entry {bad} in the OSV data")
            os.chmod(p, 0o644)
        p = os.path.join(new, "AS_OF")
        with open(p, "w") as f:
            f.write(as_of)
        os.chmod(p, 0o644)
    except Exception:
        shutil.rmtree(new, ignore_errors=True)
        raise
    link_tmp = os.path.join(osv_root, ".current.tmp")
    if os.path.lexists(link_tmp):
        os.unlink(link_tmp)
    os.symlink(os.path.basename(new), link_tmp)       # relative
    os.replace(link_tmp, os.path.join(osv_root, "current"))
    for d in os.listdir(osv_root):
        full = os.path.join(osv_root, d)
        if d not in ("current", os.path.basename(new), prev) and os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full, ignore_errors=True)
    return as_of


def osv_db(data_root=DATA_ROOT):
    cur = os.path.join(data_root, "osv", "current")
    if not os.path.isdir(cur):
        return None, None
    try:
        with open(os.path.join(cur, "AS_OF")) as f:
            return cur, f.read().strip()
    except OSError:
        return cur, None


def status(root=SCANNERS_ROOT, data_root=DATA_ROOT):
    ok, why = sandbox.support()
    return {"tools": tool_paths(root), "sandbox": {"ok": ok, "reason": why},
            "osv_as_of": osv_db(data_root)[1], "runner_files": os.path.isdir(os.path.join(root, "runner"))}


_cap_cache = {"at": 0.0, "value": None}


def capability(force=False):
    """Cached for 60 s: Task 9 calls this on every heartbeat."""
    now = time.monotonic()
    if not force and _cap_cache["value"] is not None and now - _cap_cache["at"] < CAPABILITY_TTL_S:
        return _cap_cache["value"]
    value = _capability()
    _cap_cache.update(at=now, value=value)
    return value


def _capability():
    st = status()
    have = set(st["tools"])
    scans = [s.id for s in catalog.CATALOG.values() if s.tool == "orchestratia" or s.tool in have]
    return {"catalog_version": catalog.CATALOG_VERSION, "scans": scans if st["sandbox"]["ok"] and os.path.isfile(sandbox.RUNNER_DIR + "/shim.py") else [],
            "sandbox": st["sandbox"], "data": {"osv": st["osv_as_of"]}}


TIMER = """[Unit]
Description=Orchestratia scanner data refresh (daily)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
"""


def _root_env():
    """The one environment root subprocesses get (Global Constraints: PATH, HOME=/root, LANG, set proxies)."""
    from orchestratia_agent import linux_update
    return linux_update.safe_env()


def _probe_import(python):
    """The agent package dir `python` imports when the timer runs it (-I, from /, a clean environment); else
    InstallError. Run as the timer would, so a unit that can't start is never written."""
    try:
        res = subprocess.run([python, "-I", "-c", "import os, orchestratia_agent.cli as c; "
                                                  "print(os.path.dirname(os.path.abspath(c.__file__)))"],
                             capture_output=True, text=True, cwd="/", timeout=60, env=_root_env())
    except (OSError, subprocess.SubprocessError) as e:
        raise InstallError(f"the daily refresh can't import the agent with {python}: {e}")
    if res.returncode != 0 or not res.stdout.strip():
        raise InstallError(f"the daily refresh can't import the agent with {python}: "
                           f"{(res.stderr or '').strip()[-200:]}")
    return res.stdout.strip().splitlines()[-1]


def _venv_of(python):
    """The venv `python` belongs to (`<venv>/bin/python3` beside `<venv>/pyvenv.cfg`), else None."""
    venv = os.path.dirname(os.path.dirname(python))
    return venv if os.path.isfile(os.path.join(venv, "pyvenv.cfg")) else None


def _interpreter_problem(python):
    """As root: why root running `python` could run code another user can change, or None. The name, its
    directory and what it points to; for a venv interpreter the whole venv (pyvenv.cfg, site-packages, .pth)."""
    from orchestratia_agent import codetrust
    try:
        lst = os.lstat(python)
    except OSError:
        return f"{python} is missing"
    venv = _venv_of(python)
    return (codetrust.path_problem(os.path.dirname(python))
            or codetrust.path_problem(os.path.realpath(python))
            or (None if lst.st_uid == 0 else f"{python} is owned by uid {lst.st_uid}")
            or (codetrust.tree_problem(venv) if venv else None))


def install_timer(python, unit_dir="/etc/systemd/system", systemctl=True, probe=None, euid=None):
    """The daily OSV refresh: root runs `<python> -I -m orchestratia_agent.cli scanners refresh` from /, umask 022.
    As root the interpreter (its directory, what it points to, its venv) is checked BEFORE the import probe runs it,
    and the package directory it imports from after; nothing is written unless all of it is root's alone."""
    from orchestratia_agent import codetrust
    python = os.path.abspath(str(python).replace('"', ""))
    if any(ord(c) < 32 or c in "%\\" for c in python):
        raise InstallError(f"invalid python3 path {python!r} for a systemd unit")
    as_root = (euid or os.geteuid)() == 0
    if as_root:
        why = _interpreter_problem(python)
        if why:
            raise InstallError(f"the daily refresh's python3 at {python} isn't root-owned and protected: {why}")
    pkg = (probe or _probe_import)(python)
    if as_root:
        venv = _venv_of(python)
        site = os.path.dirname(pkg)
        if not (venv and site.startswith(venv.rstrip(os.sep) + os.sep)):     # a venv's packages: checked above
            why = codetrust.tree_problem(site)
            if why:
                raise InstallError(f"the daily refresh's python3 at {python} imports the agent from {pkg}, which "
                                   f"isn't root-owned and protected: {why}")
    svc = ("[Unit]\nDescription=Orchestratia scanner data refresh\n\n[Service]\nType=oneshot\n"
           "WorkingDirectory=/\nUMask=0022\n"
           f'ExecStart="{python}" -I -m orchestratia_agent.cli scanners refresh\n')
    for name, body in (("service", svc), ("timer", TIMER)):
        path = os.path.join(unit_dir, f"orchestratia-scan-data.{name}")
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o644)
    if not systemctl:
        return
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "orchestratia-scan-data.timer"], check=True)


SCAN_SUDOERS = "/etc/sudoers.d/orchestratia-scan"
VISUDO = "/usr/sbin/visudo"


def service_user(run=subprocess.run) -> str:
    """The user the agent service runs as: its systemd User=; a loaded unit with no User= runs as root. Only
    when there is no such unit, the sudo caller, else root."""
    try:
        out = run(["systemctl", "show", "-p", "LoadState", "-p", "User", "orchestratia-agent"],
                  capture_output=True, text=True, timeout=5).stdout
        props = dict(ln.split("=", 1) for ln in (out or "").splitlines() if "=" in ln)
    except Exception:
        props = {}
    if props.get("LoadState") == "loaded":
        return props.get("User", "").strip() or "root"
    return os.environ.get("SUDO_USER") or "root"


def _visudo(path) -> bool:
    try:
        return subprocess.run([VISUDO, "-cf", path], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.SubprocessError):
        raise InstallError(f"can't validate the sudoers rule: {VISUDO} isn't available (is sudo installed?)")


def _wrapper_body(py, runner_dir):
    """The root-owned entry point sudo runs: -I (no environment, no user site, no script dir) and -S (no
    site-packages .pth code runs as root; the launcher needs the stdlib only). Before importing anything
    from the runner dir it drops the
    caller's environment and checks that the dir and launch.py are root's alone (every component, lstat);
    launch.main then checks every other file it uses."""
    return (f"#!{py} -IS\n"
            "import os, stat, sys\n"
            "sys.dont_write_bytecode = True\n"
            "os.environ.clear()\n"
            "os.environ.update({'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})\n"
            f"R = {runner_dir!r}\n"
            "def bad(path):\n"
            "    parts = path.split('/')\n"
            "    for i in range(1, len(parts) + 1):\n"
            "        p = '/'.join(parts[:i]) or '/'\n"
            "        try:\n"
            "            s = os.lstat(p)\n"
            "        except OSError:\n"
            "            return p\n"
            "        if stat.S_ISLNK(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:\n"
            "            return p\n"
            "    return None\n"
            "for f in (R, R + '/launch.py'):\n"
            "    b = bad(f)\n"
            "    if b:\n"
            "        sys.stderr.write('scan-launch: refusing: %s is not root-owned and protected\\n' % b)\n"
            "        sys.exit(77)\n"
            "sys.path.insert(0, R)\n"
            "import launch\n"
            "sys.exit(launch.main(sys.argv[1:]))\n")


def _write_new(path, data, mode):
    """Write `data` to a fresh file at `path` (never through an existing file or link), exactly `mode`,
    root-owned when we are root."""
    if os.path.lexists(path):
        os.unlink(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(data)
    _secure(path, mode)


def install_launcher(daemon_user, *, python=None, target=None, sudoers=SCAN_SUDOERS, require_root=True,
                     visudo=None):
    """The root-owned wrapper for scanning/launch.py and the one sudoers rule letting `daemon_user` run it as
    root (plan 1C Task 3). The wrapper pins this box's python3 in isolated mode and imports only from the
    root-owned runner directory; a root daemon needs no rule (any existing one is removed)."""
    from orchestratia_agent.provision import BIN_PATH_RE, ProvisionError, validate_username
    if require_root and os.geteuid() != 0:
        raise InstallError("Run this as root: sudo orchestratia scanners install")
    target = target or sandbox.LAUNCHER
    if daemon_user != "root":        # validate_username reserves "root"; a root daemon needs no rule at all
        try:
            daemon_user = validate_username(daemon_user)
        except ProvisionError as e:
            raise InstallError(f"invalid daemon user: {e}")
    py = python or shutil.which("python3") or "/usr/bin/python3"
    if not isinstance(py, str) or not BIN_PATH_RE.match(py):
        raise InstallError(f"invalid python3 path {py!r}")
    if not BIN_PATH_RE.match(target):
        raise InstallError(f"invalid launcher path {target!r}")
    trusted = (0, os.geteuid())                      # (0, 0) as root; tests install unprivileged
    # Root runs this interpreter for every scan: the name, its directory and what it points to must be root's.
    try:
        why = (_path_problem(os.path.dirname(py), trusted, True)
               or _path_problem(os.path.realpath(py), trusted, False)
               or (None if os.lstat(py).st_uid in trusted else f"{py} is owned by uid {os.lstat(py).st_uid}"))
    except OSError:
        why = f"{py} is missing"
    if why:
        raise InstallError(f"python3 at {py} isn't root-owned and protected: {why}")
    _mkdir(os.path.dirname(target), base=os.path.dirname(os.path.dirname(target)))
    tmp = os.path.join(os.path.dirname(target), "." + os.path.basename(target) + ".tmp")
    _write_new(tmp, _wrapper_body(py, sandbox.RUNNER_DIR), 0o755)
    os.replace(tmp, target)
    why = _path_problem(target, trusted, False)
    if why:
        raise InstallError(f"The scan launcher isn't protected: {why}.")
    if daemon_user == "root":
        if os.path.lexists(sudoers):
            os.unlink(sudoers)
        return
    # Never re-mode an existing sudoers dir (or /etc): only a missing one is created, the way sudo ships it.
    if not os.path.isdir(os.path.dirname(sudoers)):
        os.makedirs(os.path.dirname(sudoers), mode=0o750)
    lines = ["# Orchestratia scan launcher (sudo orchestratia scanners install). It takes only a run id and a",
             "# catalog scan id and builds the sandbox from root-owned code. Its stdin carries the repository",
             "# snapshot: never into a pty, never into sudo's I/O log. env_reset whatever the site default is.",
             f"Defaults!{target} env_reset, !use_pty, !log_input, !log_output",
             f"{daemon_user} ALL=(root) NOPASSWD: {target}", ""]
    # A name with a dot: sudo's includedir never reads it, so a half-written or invalid rule can't go live.
    tmp = os.path.join(os.path.dirname(sudoers), ".orchestratia-scan.tmp")
    _write_new(tmp, "\n".join(lines), 0o440)
    try:
        good = (visudo or _visudo)(tmp)
    except Exception:
        os.unlink(tmp)
        raise
    if not good:
        os.unlink(tmp)
        raise InstallError("refusing to install an invalid sudoers rule for the scan launcher")
    os.replace(tmp, sudoers)
