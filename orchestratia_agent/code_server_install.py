"""Pinned code-server, downloaded by the agent itself — no root, no package manager.

The standard editor runs code-server as the daemon user, so the binary can live in
that user's own directory. Pinning a version AND its SHA-256 in source means an
upgrade is a deliberate agent release, and a tampered or truncated download is never
executed: the hash is checked before a single byte is extracted, extraction goes to a
temp directory, and only a complete tree is renamed into place.
"""
from __future__ import annotations

import fcntl
import hashlib
import os
import platform
import shutil
import tarfile
import tempfile
import threading
import urllib.request

VERSION = "4.137.0"
# Verified 2026-09-14 against GitHub's published asset digests for v4.137.0.
SHA256 = {
    "amd64": "9303165b7fd43532091922f77e2f119ff2fa109c6b6f1c3c966fb02f3d6d9c8b",
    "arm64": "0fba760298fe06480d940e218f0873a645ba1e7e3ac4b527059af82d85a90462",
}
URL_TEMPLATE = ("https://github.com/coder/code-server/releases/download/"
                "v{v}/code-server-{v}-linux-{arch}.tar.gz")
# ~220 MB download + ~690 MB extracted + margin (measured for 4.137.0).
MIN_FREE_BYTES = 1100 * 1024 * 1024
DOWNLOAD_TIMEOUT = 60   # per socket operation, not the whole transfer

_ROOT_OVERRIDE: str | None = None
_thread_lock = threading.Lock()


class InstallError(Exception):
    """The editor could not be installed; `reason` is shown to the user."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "amd64"
    if m in ("aarch64", "arm64"):
        return "arm64"
    raise InstallError(f"the editor does not support this CPU architecture ({m})")


def install_root() -> str:
    return _ROOT_OVERRIDE or os.path.expanduser("~/.local/share/orchestratia/code-server")


def binary_path(version: str | None = None) -> str:
    # Resolve VERSION at call time, not at definition time: a default argument would
    # freeze the version this module was imported with.
    return os.path.join(install_root(), version or VERSION, "bin", "code-server")


def installed(version: str | None = None) -> bool:
    return os.access(binary_path(version), os.X_OK)


def _safe_members(tf: tarfile.TarFile, top: str):
    for m in tf.getmembers():
        name = os.path.normpath(m.name)
        if name.startswith(("/", "..")) or not (name == top or name.startswith(top + os.sep)):
            raise InstallError(f"verification failed: archive entry {m.name!r} is outside {top!r}")
        if m.issym() or m.islnk():
            target = os.path.normpath(os.path.join(os.path.dirname(name), m.linkname))
            if target.startswith(("/", "..")) or not (target == top or target.startswith(top + os.sep)):
                raise InstallError(f"verification failed: link {m.name!r} points outside the archive")
        yield m


def _download(url: str, dest: str, want_sha: str) -> None:
    h = hashlib.sha256()
    try:
        with urllib.request.urlopen(url, timeout=DOWNLOAD_TIMEOUT) as r, open(dest, "wb") as out:
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
                out.write(chunk)
    except OSError as e:
        raise InstallError(f"could not download the editor: {e}") from e
    if h.hexdigest() != want_sha:
        raise InstallError("verification failed: the downloaded editor does not match its pinned checksum")


def ensure() -> str:
    """Return the pinned code-server binary, downloading it once if needed."""
    if installed():
        return binary_path()
    root = install_root()
    try:
        os.makedirs(root, exist_ok=True)
        lockf = open(os.path.join(root, ".lock"), "w")
    except OSError as e:
        raise InstallError(f"cannot write the editor to {root}: {e.strerror or e}") from e
    with _thread_lock, lockf:
        fcntl.flock(lockf, fcntl.LOCK_EX)          # also serialises the installer CLI vs the daemon
        if installed():
            return binary_path()
        a = arch()
        want = SHA256.get(a)
        if not want or len(want) != 64:
            raise InstallError(f"no pinned checksum for {a}")
        if shutil.disk_usage(root).free < MIN_FREE_BYTES:
            raise InstallError(
                f"not enough disk space to install the editor "
                f"(needs {MIN_FREE_BYTES // (1024 * 1024)} MB free in {root})")
        part = os.path.join(root, f".code-server-{VERSION}-{a}.tar.gz.part")
        tmp = tempfile.mkdtemp(prefix=".extract-", dir=root)
        try:
            _download(URL_TEMPLATE.format(v=VERSION, arch=a), part, want)
            top = f"code-server-{VERSION}-linux-{a}"
            try:
                with tarfile.open(part, "r:gz") as tf:
                    members = list(_safe_members(tf, top))
                    tf.extractall(tmp, members=members, filter="data")
            except tarfile.TarError as e:
                raise InstallError(f"verification failed: unreadable archive ({e})") from e
            src = os.path.join(tmp, top)
            if not os.access(os.path.join(src, "bin", "code-server"), os.X_OK):
                raise InstallError("verification failed: archive has no bin/code-server")
            os.rename(src, os.path.join(root, VERSION))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            if os.path.exists(part):
                os.unlink(part)
        for name in os.listdir(root):
            if name != VERSION and not name.startswith("."):
                shutil.rmtree(os.path.join(root, name), ignore_errors=True)
        return binary_path()
