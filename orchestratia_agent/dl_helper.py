#!/usr/bin/python3 -I
"""Read a file (or zip a folder) for a download, or receive an upload — run AS THE
SESSION'S USER.

Standard library ONLY. For restricted sessions provision-tier installs this file at
/usr/local/libexec/orchestratia/dl-helper (root-owned) with the box's python3 in the
shebang, and the agent runs it via `sudo -n -u orcp-<project>`; it can import nothing
from the agent package. `-I` (isolated mode) keeps PYTHONPATH, user site-packages and
the working directory off sys.path, and every path arrives after `--`.

The daemon never opens the requested path itself: what a session can download is
exactly what its own OS user can read.

stdout: ONE JSON header line (always carrying "protocol" and "ops"), then raw bytes
for read / zip. Exit 2 when the header says ok:false.

    dl-helper stat --cwd DIR -- PATH
    dl-helper read --cwd DIR [--range R] [--if-range E] -- PATH
    dl-helper zip  --cwd DIR -- PATH
    dl-helper ul-prepare|ul-write|ul-cancel|ul-sweep --base FOLDER   (request on stdin)

Uploads write only inside FOLDER — the session user's own 0700 upload folder — through
its directory fd with O_NOFOLLOW. The upload id and file name arrive as the first stdin
line, never in argv (argv is visible in `ps` and logged by sudo).
"""
import argparse
import errno
import hashlib
import json
import os
import re
import stat as st
import sys
import time
import unicodedata
import zipfile

try:
    import fcntl
except ImportError:          # Windows imports this module for its pure helpers only
    fcntl = None

# 2 = upload ops. Downloads accept any protocol >= 1, so a host whose installed
# restricted helper has not been refreshed yet keeps downloading.
PROTOCOL = 2
OPS = ["stat", "read", "zip", "ul-prepare", "ul-write", "ul-cancel", "ul-sweep"]
CHUNK = 256 * 1024
WALK_SECONDS = 5.0
WALK_MAX_ENTRIES = 200_000
SKIPPED_NAME = "ORCHESTRATIA-SKIPPED.txt"
_ZIP_EPOCH = 315532800          # 1980-01-01, the earliest time a ZIP header can hold


def etag(size, mtime_ns):
    return f'"{size}-{mtime_ns}"'


def parse_range(header, size):
    """(start, end_inclusive), None (serve full), or 'unsatisfiable'. Single ranges
    only; anything else is ignored, which RFC 9110 permits."""
    if not header or not header.startswith("bytes=") or "," in header:
        return None
    first, sep, last = header[6:].strip().partition("-")
    if not sep:
        return None
    try:
        if first == "":
            n = int(last)
            if n <= 0:
                return None
            return (max(0, size - n), size - 1) if size else "unsatisfiable"
        start = int(first)
        end = int(last) if last else size - 1
    except ValueError:
        return None
    if start < 0 or (last and end < start):
        return None
    if start >= size:
        return "unsatisfiable"
    return start, min(end, size - 1)


def decide_range(range_h, if_range, size, etag_):
    """(status, start, length). An If-Range that doesn't match means 'send it all' —
    never splice bytes from two versions of a file into one download."""
    if if_range and if_range.strip() != etag_:
        range_h = None
    r = parse_range(range_h, size)
    if r is None:
        return 200, 0, size
    if r == "unsatisfiable":
        return 416, 0, 0
    return 206, r[0], r[1] - r[0] + 1


def _resolve(path, cwd):
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.path.expanduser("~"), p)
    return os.path.abspath(p)


def _emit(obj):
    sys.stdout.buffer.write(json.dumps(obj).encode() + b"\n")
    sys.stdout.buffer.flush()


def _header(obj):
    _emit(dict(obj, protocol=PROTOCOL, ops=OPS))


def _fail(error, **extra):
    _header(dict({"ok": False, "error": error}, **extra))
    sys.exit(2)


def _err_code(e):
    if isinstance(e, (FileNotFoundError, NotADirectoryError)):
        return "not_found"
    if isinstance(e, PermissionError):
        return "permission_denied"
    return "invalid"


def _open_regular(path):
    """Open without blocking (a FIFO would hang a plain open) and refuse anything
    that isn't a regular file — judged on the OPENED fd, not a racing path."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    s = os.fstat(fd)
    if not st.S_ISREG(s.st_mode):
        os.close(fd)
        raise IsADirectoryError(path)
    return os.fdopen(fd, "rb", buffering=0), s


def cmd_stat(path, cwd):
    p = _resolve(path, cwd)
    try:
        s = os.stat(p)
    except OSError as e:
        _fail(_err_code(e))
    name = os.path.basename(p.rstrip("/")) or "download"
    if st.S_ISREG(s.st_mode):
        if not os.access(p, os.R_OK):
            _fail("permission_denied")
        _header({"ok": True, "kind": "file", "name": name, "size": s.st_size, "mtime_ns": s.st_mtime_ns})
        return
    if not st.S_ISDIR(s.st_mode):
        _fail("not_regular")
    if not os.access(p, os.R_OK | os.X_OK):
        _fail("permission_denied")
    total, entries, truncated = 0, 0, False
    deadline = time.monotonic() + WALK_SECONDS
    for root, dirs, files in os.walk(p, followlinks=False):
        entries += len(dirs) + len(files)
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
        if entries >= WALK_MAX_ENTRIES or time.monotonic() > deadline:
            truncated = True
            break
    _header({"ok": True, "kind": "dir", "name": name, "approx_size": total, "entries": entries,
             "truncated": truncated})


def cmd_read(path, cwd, range_h, if_range):
    p = _resolve(path, cwd)
    try:
        f, s = _open_regular(p)
    except IsADirectoryError:
        _fail("not_regular")
    except OSError as e:
        _fail(_err_code(e))
    with f:
        tag = etag(s.st_size, s.st_mtime_ns)
        status, start, length = decide_range(range_h, if_range, s.st_size, tag)
        if status == 416:
            _fail("range_not_satisfiable", size=s.st_size)
        _header({"ok": True, "status": status, "offset": start, "length": length, "size": s.st_size,
                 "etag": tag, "mtime_ns": s.st_mtime_ns, "name": os.path.basename(p)})
        f.seek(start)
        left, out = length, sys.stdout.buffer
        while left > 0:
            chunk = f.read(min(CHUNK, left))
            if not chunk:
                break          # file shrank: exit 0 with a short body; the relay sees it short
            out.write(chunk)
            left -= len(chunk)
        out.flush()
        if left > 0:
            sys.exit(3)        # short read -> the agent reports an error, not success


class _Counting:
    """zipfile on an unseekable pipe: tell() without seek() makes it use data
    descriptors."""
    def __init__(self, raw):
        self.raw, self.pos = raw, 0

    def write(self, b):
        self.raw.write(b)
        self.pos += len(b)
        return len(b)

    def tell(self):
        return self.pos

    def flush(self):
        self.raw.flush()

    def seekable(self):
        return False


def cmd_zip(path, cwd):
    p = _resolve(path, cwd)
    try:
        s = os.stat(p)
    except OSError as e:
        _fail(_err_code(e))
    if not st.S_ISDIR(s.st_mode):
        _fail("not_regular")
    if not os.access(p, os.R_OK | os.X_OK):
        _fail("permission_denied")
    top = os.path.basename(p.rstrip("/")) or "download"
    _header({"ok": True, "status": 200, "name": top + ".zip"})
    skipped = []
    out = _Counting(sys.stdout.buffer)
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1, allowZip64=True) as zf:
        for root, dirs, files in os.walk(p, followlinks=False,
                                         onerror=lambda e: skipped.append(str(getattr(e, "filename", "?")))):
            rel_root = os.path.relpath(root, os.path.dirname(p))
            if not files and not dirs:
                try:
                    zi = zipfile.ZipInfo(rel_root.rstrip("/") + "/")
                    zi.external_attr = (0o40755 << 16) | 0x10
                    zf.writestr(zi, b"")
                except ValueError:
                    skipped.append(rel_root)
            for name in sorted(dirs):
                if os.path.islink(os.path.join(root, name)):
                    files.append(name)           # a symlinked dir: store the link itself
            for name in sorted(files):
                full = os.path.join(root, name)
                arc = os.path.join(rel_root, name)
                try:
                    ls = os.lstat(full)
                    if st.S_ISLNK(ls.st_mode):
                        zi = zipfile.ZipInfo(arc, time.localtime(max(ls.st_mtime, _ZIP_EPOCH))[:6])
                        zi.external_attr = (st.S_IFLNK | 0o777) << 16
                        zf.writestr(zi, os.readlink(full))
                        continue
                    if not st.S_ISREG(ls.st_mode):
                        continue                 # sockets, FIFOs, devices: never opened
                    src, _ = _open_regular(full)
                    with src:
                        zi = zipfile.ZipInfo.from_file(full, arc, strict_timestamps=False)
                        zi.compress_type = zipfile.ZIP_DEFLATED
                        with zf.open(zi, "w", force_zip64=True) as dst:
                            while True:
                                chunk = src.read(CHUNK)
                                if not chunk:
                                    break
                                dst.write(chunk)
                except (OSError, ValueError):
                    # Unreadable, vanished, or a name a ZIP header can't encode. The
                    # header is built before any bytes are written, so skipping is safe.
                    skipped.append(arc.encode("utf-8", "backslashreplace").decode("utf-8"))
        if skipped:
            zf.writestr(os.path.join(top, SKIPPED_NAME),
                        "These entries could not be read by this session's user and were left out:\n"
                        + "\n".join(sorted(skipped)) + "\n")
    out.flush()


# ── Uploads ──────────────────────────────────────────────────────────────────
# FOLDER (--base) is the session user's own upload folder. It is opened once with
# O_DIRECTORY|O_NOFOLLOW and refused unless this euid owns it and nobody else can
# write it; every later access is relative to that fd with O_NOFOLLOW, so nothing can
# be redirected through a symlink planted after the check.
#
# Per upload, three files sit in the folder: the part (.orchestratia-<id>.part), the
# journal (committed offset + the relay-forwarded digest of every committed chunk,
# replaced atomically) and, from the moment finalize has verified the file, the done
# record (the name being published + the whole-file SHA-256). The journal is the only
# rollback: an abort is a kill, and the next ul-write truncates the part back to it.

UL_PREFIX = ".orchestratia-"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
SWEEP_RE = re.compile(r"^\.orchestratia-([0-9a-f-]{36})\.(?:part|journal|done)(?:\.tmp)?$")
NAME_MAX_BYTES = 200
MAX_COPIES = 999
MAX_CHUNK_SIZE = 64 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_JSON = 64 * 1024 * 1024
SWEEP_AGE = 24 * 3600
GIB = 1024 ** 3
COMPOUND_EXTS = (".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar.lz", ".tar.lzma", ".tar.z")
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_QUOTA = (errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC))


def valid_name(name):
    """A plain file name we will publish as-is. The hub's sanitize_name runs first; this
    is a second CHECK, not a second sanitiser: anything the hub would have changed
    (surrounding whitespace, Cc/Cf/Cs characters, the reserved prefix, > 200 bytes) is
    refused, never repaired. A leading '-' is fine: names never reach argv or a shell."""
    if not isinstance(name, str) or not name or name in (".", "..") or name != name.strip():
        return False
    if "\x00" in name or "/" in name or name.startswith(UL_PREFIX):
        return False
    if any(unicodedata.category(c) in ("Cc", "Cf") for c in name):     # incl. U+202E
        return False
    try:
        return len(name.encode("utf-8")) <= NAME_MAX_BYTES
    except UnicodeEncodeError:                                          # a lone surrogate
        return False


def split_ext(name):
    """('a', '.tar.gz') for 'a.tar.gz'; ('.bashrc', '') for a dotfile."""
    low = name.lower()
    for ext in COMPOUND_EXTS:
        if low.endswith(ext) and len(name) > len(ext):
            return name[:-len(ext)], name[-len(ext):]
    stem, ext = os.path.splitext(name)
    if not stem or len(ext) > 20 or ext == ".":
        return name, ""
    return stem, ext


def candidate_names(name, limit=MAX_COPIES):
    """name, 'name (1).ext', … 'name (limit).ext' — the no-clobber publish order."""
    yield name
    stem, ext = split_ext(name)
    for i in range(1, limit + 1):
        yield f"{stem} ({i}){ext}"


def chunks_digest(digests):
    """SHA-256 over the ordered hex chunk digests (ASCII, concatenated)."""
    return hashlib.sha256("".join(digests).encode("ascii")).hexdigest()


def _chunk_count(size, chunk_size):
    return max(1, -(-size // chunk_size))


def _is_int(v, lo=0, hi=None):
    return isinstance(v, int) and not isinstance(v, bool) and v >= lo and (hi is None or v <= hi)


def _names(upload_id):
    p = UL_PREFIX + upload_id
    return p + ".part", p + ".journal", p + ".done"


class _Refuse(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _read_request():
    try:
        req = json.loads(sys.stdin.buffer.readline(MAX_LINE) or b"{}")
    except ValueError:
        return None
    return req if isinstance(req, dict) else None


def _upload_request(need_name=True):
    """(request, None) or (None, error code)."""
    req = _read_request()
    if req is None or not isinstance(req.get("upload_id"), str) or not UUID_RE.match(req["upload_id"]):
        return None, "invalid"
    if not need_name:
        return req, None
    req.setdefault("reservation", 0)
    if not (_is_int(req.get("size")) and _is_int(req.get("chunk_size"), 1, MAX_CHUNK_SIZE)
            and _is_int(req.get("reservation"))):
        return None, "invalid"
    if not valid_name(req.get("name")):
        return None, "invalid_name"
    return req, None


def _open_dir(base):
    """(fd, None) or (None, error code). Owned by us, nobody else can write, no symlink."""
    if not isinstance(base, str) or not os.path.isabs(base) or "\x00" in base:
        return None, "invalid"
    try:
        fd = os.open(base, os.O_RDONLY | _DIRECTORY | os.O_NOFOLLOW)
    except PermissionError:
        return None, "permission_denied"
    except OSError:
        return None, "unsafe_destination"          # missing, a symlink, or not a directory
    s = os.fstat(fd)
    if not st.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or s.st_mode & 0o022:
        os.close(fd)
        return None, "unsafe_destination"
    return fd, None


def _free(fd):
    """(bytes free to us, the margin we always leave: max(1 GiB, 5 % of the fs))."""
    v = os.fstatvfs(fd)
    return v.f_bavail * v.f_frsize, max(GIB, (v.f_blocks * v.f_frsize) // 20)


def _unlink(dfd, name):
    try:
        os.unlink(name, dir_fd=dfd)            # never follows: removes a symlink, not its target
        return 1
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return 0


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _read_json(dfd, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | _NONBLOCK, dir_fd=dfd)
    except OSError:
        return None
    try:
        if not st.S_ISREG(os.fstat(fd).st_mode):
            return None
        parts, total = [], 0
        while total <= MAX_JSON:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            parts.append(b)
            total += len(b)
    finally:
        os.close(fd)
    try:
        obj = json.loads(b"".join(parts))
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def _write_json(dfd, name, obj):
    """temp + fsync + rename, all relative to the folder fd."""
    tmp = name + ".tmp"
    _unlink(dfd, tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        _write_all(fd, json.dumps(obj).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)


def _load_journal(dfd, name, req):
    j = _read_json(dfd, name)
    if (not j or j.get("upload_id") != req["upload_id"] or j.get("size") != req["size"]
            or j.get("chunk_size") != req["chunk_size"]):
        return None
    off, digests, final = j.get("offset"), j.get("digests"), j.get("final") is True
    if not _is_int(off, 0, req["size"]) or not isinstance(digests, list):
        return None
    if not all(isinstance(d, str) and HEX64_RE.match(d) for d in digests):
        return None
    if final:
        ok = off == req["size"] and len(digests) == _chunk_count(req["size"], req["chunk_size"])
    else:
        ok = off == len(digests) * req["chunk_size"] and (off < req["size"] or req["size"] == 0)
    return {"offset": off, "digests": digests, "final": final} if ok else None


def _load_done(dfd, name, upload_id):
    d = _read_json(dfd, name)
    if not d or d.get("upload_id") != upload_id:
        return None
    path, sha = d.get("path"), d.get("sha256")
    if not isinstance(path, str) or not isinstance(sha, str) or not HEX64_RE.match(sha):
        return None
    out = {"path": path, "sha256": sha}
    if isinstance(d.get("chunks_digest"), str) and HEX64_RE.match(d["chunks_digest"]):
        out["chunks_digest"] = d["chunks_digest"]
    return out


def _lock(fd):
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def cmd_ul_prepare(base):
    """Read-only: reports, never truncates or deletes. A refused prepare (no_space, ...)
    leaves the part and journal for a later resume; only ul-write's start reconciles."""
    req, err = _upload_request()
    if err:
        _fail(err)
    dfd, err = _open_dir(base)
    if err:
        _fail(err)
    try:
        part, jname, dname = _names(req["upload_id"])
        free, margin = _free(dfd)
        info = {"dir": base, "free_bytes": free}
        done = _load_done(dfd, dname, req["upload_id"])
        if done:
            _header(dict(info, ok=True, offset=req["size"], done=done))
            return
        j = _load_journal(dfd, jname, req)
        offset = j["offset"] if j else 0
        if offset:
            try:
                if os.stat(part, dir_fd=dfd, follow_symlinks=False).st_size < offset:
                    offset = 0                     # ul-write will reset it
            except OSError:
                offset = 0
        if free - req["reservation"] - margin < req["size"] - offset:
            _fail("no_space", offset=offset, **info)
        _header(dict(info, ok=True, offset=offset, done=None))
    finally:
        os.close(dfd)


class _Upload:
    """One ul-write: owns the part's lock for its whole life."""

    def __init__(self, dfd, base, req):
        self.dfd, self.base, self.req = dfd, base, req
        self.id, self.size, self.cs = req["upload_id"], req["size"], req["chunk_size"]
        self.part, self.jname, self.dname = _names(self.id)
        self.pfd = None
        self.offset, self.digests, self.final = 0, [], False

    # ── start ─────────────────────────────────────────────────────────────
    def _open_part(self, create):
        flags = os.O_RDWR | os.O_NOFOLLOW | _NONBLOCK
        try:
            try:
                fd = os.open(self.part, flags, dir_fd=self.dfd)
            except FileNotFoundError:
                if not create:
                    return None
                try:
                    fd = os.open(self.part, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self.dfd)
                except FileExistsError:            # another helper created it a moment ago
                    fd = os.open(self.part, flags, dir_fd=self.dfd)
        except OSError as e:
            raise _Refuse("unsafe_destination" if e.errno == errno.ELOOP else "io")
        s = os.fstat(fd)
        if not st.S_ISREG(s.st_mode) or s.st_uid != os.geteuid():
            os.close(fd)
            raise _Refuse("unsafe_destination")
        if not _lock(fd):
            os.close(fd)
            raise _Refuse("busy")
        return fd

    def _journal(self):
        _write_json(self.dfd, self.jname, {"upload_id": self.id, "size": self.size, "chunk_size": self.cs,
                                           "offset": self.offset, "digests": self.digests,
                                           "final": self.final})

    def _recover(self):
        """Truncate the part back to the journal. A part SHORTER than the journal was
        lost or tampered with: start again from 0 and say so."""
        j = _load_journal(self.dfd, self.jname, self.req)
        if j is not None and os.fstat(self.pfd).st_size >= j["offset"]:
            os.ftruncate(self.pfd, j["offset"])
            self.offset, self.digests, self.final = j["offset"], list(j["digests"]), j["final"]
            return False
        reset = j is not None and j["offset"] > 0
        os.ftruncate(self.pfd, 0)
        self.offset, self.digests, self.final = 0, [], False
        self._journal()
        return reset

    def _ready(self, reset=False, done=None):
        _header({"type": "ready", "offset": self.size if done else self.offset,
                 "finalizing": self.final and not done, "done": done, "reset": reset})

    def run(self):
        try:
            self.pfd = self._open_part(create=False)
            done = _load_done(self.dfd, self.dname, self.id)
            if done is not None:
                return self._resume_done(done)
            if self.pfd is None:
                self.pfd = self._open_part(create=True)
            try:
                reset = self._recover()
            except OSError as e:
                raise _Refuse("no_space" if e.errno in _QUOTA else "io")
        except _Refuse as e:
            _header({"type": "error", "ok": False, "code": e.code, "error": e.code})
            sys.exit(2)
        self._ready(reset)
        if self.final:
            return self._finalize()
        self._serve()

    def _resume_done(self, done):
        """Finalize had verified the file and written the done record. Either the link
        happened (report it — never publish a second copy) or it did not (publish now)."""
        public = {"path": done["path"], "sha256": done["sha256"]}
        if "chunks_digest" in done:
            public["chunks_digest"] = done["chunks_digest"]
        if self.pfd is None:                         # published, and the part already removed
            _unlink(self.dfd, self.jname)
            self._ready(done=public)
            _emit(dict(public, type="done"))
            return
        pst = os.fstat(self.pfd)
        try:
            got = os.stat(os.path.basename(done["path"]), dir_fd=self.dfd, follow_symlinks=False)
        except FileNotFoundError:
            got = None
        if got is not None and (got.st_dev, got.st_ino) == (pst.st_dev, pst.st_ino):
            self._after_publish()
            self._ready(done=public)
            _emit(dict(public, type="done"))
            return
        # Not published yet: verify again from the journal (the part may have been
        # touched while nothing held it), then publish.
        j = _load_journal(self.dfd, self.jname, self.req)
        self.offset, self.final = self.size, True
        self.digests = list(j["digests"]) if j and j["final"] else []
        self._ready()
        if not (j and j["final"]):
            _unlink(self.dfd, self.dname)
            _emit({"type": "error", "code": "tampered", "offset": self.offset})
            return
        self._finalize()

    # ── chunks ────────────────────────────────────────────────────────────
    def _frame_error(self, offset, length, index, final):
        if offset != self.offset or index != len(self.digests):
            return "offset_mismatch"
        end = offset + length
        if final:
            return None if end == self.size else "offset_mismatch"
        return None if length == self.cs and end < self.size else "offset_mismatch"

    @staticmethod
    def _discard(inp, length):
        while length:
            b = inp.read(min(CHUNK, length))
            if not b:
                return False
            length -= len(b)
        return True

    def _write_chunk(self, inp, length):
        """(hex digest, error code | None); error 'eof' = the link went away mid-chunk."""
        h = hashlib.sha256()
        os.lseek(self.pfd, self.offset, os.SEEK_SET)
        left, err = length, None
        while left:
            b = inp.read(min(CHUNK, left))
            if not b:
                os.ftruncate(self.pfd, self.offset)
                return None, "eof"
            left -= len(b)
            h.update(b)
            if err is None:
                try:
                    _write_all(self.pfd, b)
                except OSError as e:
                    err = "no_space" if e.errno in _QUOTA else "io"
        if err is not None:
            os.ftruncate(self.pfd, self.offset)
        return h.hexdigest(), err

    def _serve(self):
        inp = sys.stdin.buffer
        while True:
            line = inp.readline(MAX_LINE)
            if not line:
                return                               # the link closed; the journal is the state
            try:
                f = json.loads(line)
            except ValueError:
                f = None
            if (not isinstance(f, dict) or not _is_int(f.get("offset")) or not _is_int(f.get("index"))
                    or not _is_int(f.get("length"), 0, self.cs)
                    or not (isinstance(f.get("sha256"), str) and HEX64_RE.match(f["sha256"]))):
                _emit({"type": "error", "code": "invalid", "offset": self.offset})
                return                               # framing is lost: stop, never guess
            length, final = f["length"], f.get("final") is True
            code = self._frame_error(f["offset"], length, f["index"], final)
            if code is None:
                free, margin = _free(self.pfd)
                if free - margin < length:
                    code = "no_space"                # checked BEFORE writing a byte
            if code is not None:
                if not self._discard(inp, length):
                    return
                _emit({"type": "error", "code": code, "offset": self.offset})
                continue
            digest, err = self._write_chunk(inp, length)
            if err == "eof":
                return
            if err is None and digest != f["sha256"]:
                os.ftruncate(self.pfd, self.offset)
                err = "checksum_mismatch"
            if err is None:
                try:
                    os.fsync(self.pfd)
                    self.digests.append(digest)
                    self.offset += length
                    self.final = final
                    self._journal()
                except OSError as e:
                    if len(self.digests) > f["index"]:
                        self.digests.pop()
                        self.offset -= length
                    self.final = False
                    os.ftruncate(self.pfd, self.offset)
                    err = "no_space" if e.errno in _QUOTA else "io"
            if err is not None:
                _emit({"type": "error", "code": err, "offset": self.offset})
                continue
            _emit({"type": "ack", "offset": self.offset, "index": f["index"], "sha256": digest})
            if final:
                return self._finalize()

    # ── finalize ──────────────────────────────────────────────────────────
    def _verify(self):
        """Whole-file SHA-256 read back THROUGH THE OPEN FD, or None if any chunk no
        longer matches the digest the relay forwarded for it."""
        if (os.fstat(self.pfd).st_size != self.size
                or len(self.digests) != _chunk_count(self.size, self.cs)):
            return None
        whole, pos = hashlib.sha256(), 0
        for want in self.digests:
            h, left = hashlib.sha256(), min(self.cs, self.size - pos)
            while left:
                b = os.pread(self.pfd, min(1 << 20, left), pos)
                if not b:
                    return None
                h.update(b)
                whole.update(b)
                pos += len(b)
                left -= len(b)
            if h.hexdigest() != want:
                return None
        return whole.hexdigest()

    def _finalize(self):
        try:
            os.fsync(self.pfd)
            sha = self._verify()
            if sha is None:
                _emit({"type": "error", "code": "tampered", "offset": self.offset})
                return
            self._publish(sha)
        except OSError:
            _emit({"type": "error", "code": "io", "offset": self.offset})

    def _publish(self, sha):
        """The done record names the candidate BEFORE it is linked, so a restart at any
        point finds it: linked (same inode) → report it; not linked → link it."""
        pst = os.fstat(self.pfd)
        cdig = chunks_digest(self.digests)
        for cand in candidate_names(self.req["name"]):
            path = os.path.join(self.base, cand)
            _write_json(self.dfd, self.dname, {"upload_id": self.id, "path": path, "sha256": sha,
                                               "chunks_digest": cdig})
            try:
                os.link(self.part, cand, src_dir_fd=self.dfd, dst_dir_fd=self.dfd, follow_symlinks=False)
            except FileExistsError:
                continue
            got = os.stat(cand, dir_fd=self.dfd, follow_symlinks=False)
            if (got.st_dev, got.st_ino) != (pst.st_dev, pst.st_ino):
                _unlink(self.dfd, cand)              # the part's name was swapped under us
                _unlink(self.dfd, self.dname)
                _emit({"type": "error", "code": "tampered", "offset": self.offset})
                return
            self._after_publish()
            _emit({"type": "done", "path": path, "sha256": sha, "chunks_digest": cdig})
            return
        _unlink(self.dfd, self.dname)
        _emit({"type": "error", "code": "name_exhausted", "offset": self.offset})

    def _after_publish(self):
        os.fsync(self.dfd)
        for n in (self.part, self.jname, self.jname + ".tmp"):
            _unlink(self.dfd, n)
        os.fsync(self.dfd)


def cmd_ul_write(base):
    req, err = _upload_request()
    if err:
        _header({"type": "error", "ok": False, "code": err, "error": err})
        sys.exit(2)
    dfd, err = _open_dir(base)
    if err:
        _header({"type": "error", "ok": False, "code": err, "error": err})
        sys.exit(2)
    _Upload(dfd, base, req).run()


def cmd_ul_cancel(base):
    req, err = _upload_request(need_name=False)
    if err:
        _fail(err)
    dfd, err = _open_dir(base)
    if err:
        _fail(err)
    try:
        part, jname, dname = _names(req["upload_id"])
        fd = None
        try:
            fd = os.open(part, os.O_RDWR | os.O_NOFOLLOW | _NONBLOCK, dir_fd=dfd)
        except OSError:
            fd = None                                # absent, or a symlink: just unlink the name
        if fd is not None and not _lock(fd):
            os.close(fd)
            _fail("busy")
        removed = sum(_unlink(dfd, n) for n in (part, jname, jname + ".tmp", dname, dname + ".tmp"))
        if fd is not None:
            os.close(fd)
        _header({"ok": True, "removed": removed})
    finally:
        os.close(dfd)


def cmd_ul_sweep(base):
    _read_request()                                  # "{}" — nothing to read, but keep the framing
    dfd, err = _open_dir(base)
    if err:
        _fail(err)
    try:
        cutoff = time.time() - SWEEP_AGE
        groups, loose = {}, []
        for name in os.listdir(dfd):
            if not name.startswith(UL_PREFIX):
                continue
            try:
                s = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            except OSError:
                continue
            if st.S_ISDIR(s.st_mode):
                continue
            m = SWEEP_RE.match(name)
            if m:
                groups.setdefault(m.group(1), []).append((name, s.st_mtime))
            elif s.st_mtime < cutoff:
                loose.append(name)
        removed = sum(_unlink(dfd, n) for n in loose)
        for uid, items in groups.items():
            if max(t for _, t in items) >= cutoff:
                continue                             # touched within a day: still somebody's upload
            part = UL_PREFIX + uid + ".part"
            fd = None
            if any(n == part for n, _ in items):
                try:
                    fd = os.open(part, os.O_RDWR | os.O_NOFOLLOW | _NONBLOCK, dir_fd=dfd)
                except OSError:
                    fd = None
                if fd is not None and not _lock(fd):
                    os.close(fd)
                    continue                         # a live ul-write holds it
            removed += sum(_unlink(dfd, n) for n, _ in items)
            if fd is not None:
                os.close(fd)
        _header({"ok": True, "removed": removed})
    finally:
        os.close(dfd)


UPLOAD_OPS = {"ul-prepare": cmd_ul_prepare, "ul-write": cmd_ul_write,
              "ul-cancel": cmd_ul_cancel, "ul-sweep": cmd_ul_sweep}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dl-helper")
    sub = ap.add_subparsers(dest="op", required=True)
    for op in ("stat", "read", "zip"):
        p = sub.add_parser(op)
        p.add_argument("--cwd", default="")
        p.add_argument("--range", default=None)
        p.add_argument("--if-range", default=None)
        p.add_argument("path")
    for op in UPLOAD_OPS:
        sub.add_parser(op).add_argument("--base", required=True)
    a = ap.parse_args(argv)
    if a.op in UPLOAD_OPS:
        if fcntl is None:
            _fail("invalid")
        UPLOAD_OPS[a.op](a.base)
        return
    if "\x00" in a.path:
        _fail("invalid")
    if a.op == "stat":
        cmd_stat(a.path, a.cwd)
    elif a.op == "read":
        cmd_read(a.path, a.cwd, a.range, a.if_range)
    else:
        cmd_zip(a.path, a.cwd)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        os._exit(0)          # the agent closed our stdout: the browser went away
