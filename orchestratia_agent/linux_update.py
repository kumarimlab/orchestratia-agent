"""`sudo orchestratia update` on Linux (hardening plan Task 2).

Root only. It never runs git or pip inside an existing tree: a planted .git/config (core.fsmonitor) or setup code
would run as root. Instead it:
- clones the source fresh (--depth 1) beside the asset tree;
- upgrades the venv in place when the venv is root's alone, else REBUILDS it from the system python3 (whatever was
  planted in it, such as a .pth, is gone);
- normalises modes and swaps the asset tree whole.

Every subprocess runs from / with python -I, pip --no-cache-dir and a clean environment. The caller
(cli._agent_update_linux) then runs the NEW entry point's `secure-install`."""
import os
import re
import shutil
import subprocess
import tempfile
import time

from orchestratia_agent import __version__, codetrust


class UpdateError(Exception):
    pass


_PROXY = ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY")
_BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,99}")
_HTTPS = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?/[A-Za-z0-9._~/-]+")
_VERSION = re.compile(r'^__version__ = "([^"]+)"', re.M)


def safe_env(environ=None):
    environ = os.environ if environ is None else environ
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
    env.update({k: environ[k] for k in _PROXY if k in environ})
    return env


def _source_url(source, uids):
    if _HTTPS.fullmatch(source or ""):
        return source
    if source and os.path.isabs(source):
        # The whole repository, not only the path to it: git reads its config and objects as root.
        why = codetrust.tree_problem(source, uids)
        if why:
            raise UpdateError(f"the source {source} isn't root's alone: {why}")
        why = _repo_problem(source)
        if why:
            raise UpdateError(f"refusing the source {source}: {why}")
        return "file://" + source
    raise UpdateError(f"the source must be an https URL or a root-owned local repository, not {source!r}")


def _repo_problem(source):
    """Why root's git could read outside a local source repo, or None: a symlink anywhere in it, a `.git` gitfile,
    objects/info/(http-)alternates, or a worktree `commondir` would point git at an object store or config another
    account may control."""
    try:
        for dirpath, dirnames, filenames in os.walk(source, onerror=codetrust._raise, followlinks=False):
            for name in dirnames + filenames:
                p = os.path.join(dirpath, name)
                if os.path.islink(p):
                    return f"{p} is a symlink"
                if name == ".git" and not os.path.isdir(p):
                    return f"{p} is a .git gitfile (it points git at another directory)"
                if name in ("alternates", "http-alternates") and dirpath.endswith(os.path.join("objects", "info")):
                    return f"{p} lists alternates (another object store)"
                if name == "commondir" and name in filenames:
                    return f"{p} is a worktree commondir (it points git at another directory)"
    except OSError as e:
        return f"{source}: {e.strerror or e}"
    return None


def _recover_stale_venv(layout):
    """An update that died between moving the venv aside and rebuilding it leaves `<venv>.old-<stamp>`. With no venv,
    the newest such copy is put back, so a failed rebuild still has a venv to return to. With a venv, the venv may be
    half-built, so the caller rebuilds it. Older copies are removed. Returns True when the venv must be rebuilt."""
    stale = codetrust.stale_venvs(layout)
    if not stale:
        return False
    rebuild = True
    if not os.path.lexists(layout.venv):
        os.rename(stale.pop(), layout.venv)
        rebuild = False                         # tree_problem decides, as for any venv
    for d in stale:
        shutil.rmtree(d, ignore_errors=True)
    return rebuild


def _run(run, argv):
    try:
        res = run(argv, capture_output=True, text=True, cwd="/", env=safe_env(), timeout=900)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise UpdateError(f"{' '.join(argv[:5])} failed: {e}")
    if res.returncode != 0:
        tail = ((res.stderr or "") + (res.stdout or "")).strip()[-300:]
        raise UpdateError(f"{' '.join(argv[:5])} failed: {tail}")
    return res


def _read_version(tree):
    try:
        with open(os.path.join(tree, "orchestratia_agent", "__init__.py")) as fh:
            m = _VERSION.search(fh.read())
    except OSError:
        m = None
    return m.group(1) if m else "unknown"


def _pip(py, *args):
    return [py, "-I", "-m", "pip", "install", "--quiet", "--no-cache-dir", *args]


def update(*, source=codetrust.REPO_URL, branch="main", layout=None, run=subprocess.run, euid=None, uids=(0,),
           clock=time.time):
    layout = layout or codetrust.Layout()
    if (euid or os.geteuid)() != 0:
        raise UpdateError("orchestratia update installs code that root runs, so it runs as root: "
                          "sudo orchestratia update")
    if not isinstance(branch, str) or not _BRANCH.fullmatch(branch):
        raise UpdateError(f"invalid branch {branch!r}")
    url = _source_url(source, uids)
    for p, what in ((layout.opt, "directory"), (os.path.realpath(layout.system_python), "python3")):
        why = codetrust.path_problem(p, uids)
        if why:
            raise UpdateError(f"{what} {p} isn't root's alone: {why}")
    force_rebuild = _recover_stale_venv(layout)
    stamp = str(int(clock()))
    clone = tempfile.mkdtemp(prefix=".orchestratia-agent.new-", dir=layout.opt)
    old_venv = old_assets = None
    try:
        _run(run, ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--depth", "1", "--no-tags",
                   "--branch", branch, url, clone])
        commit = _run(run, ["git", "-C", clone, "rev-parse", "--short", "HEAD"]).stdout.strip()
        new_version = _read_version(clone)
        py = os.path.join(layout.venv, "bin", "python3")
        rebuilt = force_rebuild or codetrust.tree_problem(layout.venv, uids) is not None
        if rebuilt:
            if os.path.lexists(layout.venv):
                old_venv = f"{layout.venv}.old-{stamp}"
                os.rename(layout.venv, old_venv)
            try:
                _run(run, [layout.system_python, "-I", "-m", "venv", layout.venv])
                _run(run, _pip(py, "--upgrade", "pip", "setuptools", "wheel"))
                _run(run, _pip(py, clone))
            except BaseException:
                shutil.rmtree(layout.venv, ignore_errors=True)
                if old_venv:
                    os.rename(old_venv, layout.venv)
                    old_venv = None
                raise
        else:
            _run(run, _pip(py, "--upgrade", clone))
        try:
            codetrust.normalize(layout.venv, uids)
            codetrust.normalize(clone, uids)
        except codetrust.CodeTrustError as e:
            raise UpdateError(str(e))
        if os.path.lexists(layout.assets):
            old_assets = f"{layout.assets}.old-{stamp}"
            os.rename(layout.assets, old_assets)
        try:
            os.rename(clone, layout.assets)
        except BaseException:
            if old_assets:                      # never leave the box without an asset tree
                os.rename(old_assets, layout.assets)
                old_assets = None
            raise
        clone = None
        return {"old": __version__, "new": new_version, "commit": commit, "venv": "rebuilt" if rebuilt else "upgraded"}
    finally:
        if clone:
            shutil.rmtree(clone, ignore_errors=True)
        for d in (old_assets, old_venv):
            if d:
                shutil.rmtree(d, ignore_errors=True)
