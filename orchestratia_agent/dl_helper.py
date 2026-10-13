#!/usr/bin/python3 -I
"""Read a file (or zip a folder) for a download — run AS THE SESSION'S USER.

Standard library ONLY. For restricted sessions provision-tier installs this file at
/usr/local/libexec/orchestratia/dl-helper (root-owned) with the box's python3 in the
shebang, and the agent runs it via `sudo -n -u orcp-<project>`; it can import nothing
from the agent package. `-I` (isolated mode) keeps PYTHONPATH, user site-packages and
the working directory off sys.path, and every path arrives after `--`.

The daemon never opens the requested path itself: what a session can download is
exactly what its own OS user can read.

stdout: ONE JSON header line (always carrying "protocol"), then raw bytes for read /
zip. Exit 2 when the header says ok:false.

    dl-helper stat --cwd DIR -- PATH
    dl-helper read --cwd DIR [--range R] [--if-range E] -- PATH
    dl-helper zip  --cwd DIR -- PATH
"""
import argparse
import json
import os
import stat as st
import sys
import time
import zipfile

PROTOCOL = 1
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


def _header(obj):
    sys.stdout.buffer.write(json.dumps(dict(obj, protocol=PROTOCOL)).encode() + b"\n")
    sys.stdout.buffer.flush()


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


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dl-helper")
    ap.add_argument("op", choices=("stat", "read", "zip"))
    ap.add_argument("--cwd", default="")
    ap.add_argument("--range", default=None)
    ap.add_argument("--if-range", default=None)
    ap.add_argument("path")
    a = ap.parse_args(argv)
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
