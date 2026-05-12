"""Filesystem operations exposed to the hub for the editor side panel.

Every operation is scoped to a session's working_directory. Paths supplied
by the hub are treated as relative; absolute paths are rejected. The
resolved real path must remain inside the session's root — symlink escape
returns 403-equivalent {ok: false, error: 'access_denied'}.

Read/write size limits, binary detection, and entry-count caps protect
the agent from being asked to ship a 4GB file over the WebSocket.
"""

from __future__ import annotations

import hashlib
import logging
import os
import stat as stat_mod
from pathlib import Path

log = logging.getLogger("orchestratia.fs")

# ── Limits ─────────────────────────────────────────────────────────────
MAX_READ_BYTES = 5 * 1024 * 1024          # 5 MB
MAX_WRITE_BYTES = 5 * 1024 * 1024         # 5 MB
MAX_DIR_ENTRIES = 5000                    # refuse listings larger than this
BINARY_SNIFF_BYTES = 8192                 # bytes inspected for NUL detection


# ── Path safety ────────────────────────────────────────────────────────


def _safe_resolve(root: str, rel_path: str) -> Path | None:
    """Resolve rel_path under root. Return None on any safety violation.

    Rejects absolute paths, parent-escape via .., and symlink targets
    that point outside the root after resolution.
    """
    if rel_path is None:
        rel_path = ""

    # Strip leading slashes — treat all paths as relative
    rel = rel_path.lstrip("/\\")

    try:
        root_real = Path(root).resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError):
        return None

    try:
        candidate = (root_real / rel).resolve(strict=False)
    except (RuntimeError, OSError):
        return None

    # Must be the root itself or descend from it
    try:
        candidate.relative_to(root_real)
    except ValueError:
        return None

    return candidate


def _looks_binary(blob: bytes) -> bool:
    """Heuristic: any NUL in the sniff window means binary."""
    if not blob:
        return False
    return b"\x00" in blob[:BINARY_SNIFF_BYTES]


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Operations ─────────────────────────────────────────────────────────


def list_dir(root: str, rel_path: str) -> dict:
    """Return entries in a directory.

    Result shape:
      {ok: true, entries: [{name, type, size, mtime}, ...], truncated: bool}
      {ok: false, error: 'access_denied' | 'not_found' | 'not_a_directory'}
    """
    target = _safe_resolve(root, rel_path)
    if target is None:
        return {"ok": False, "error": "access_denied"}
    if not target.exists():
        return {"ok": False, "error": "not_found"}
    if not target.is_dir():
        return {"ok": False, "error": "not_a_directory"}

    entries: list[dict] = []
    truncated = False
    try:
        with os.scandir(target) as it:
            for i, entry in enumerate(it):
                if i >= MAX_DIR_ENTRIES:
                    truncated = True
                    break
                # Skip dotfiles only if .git? Keep dotfiles visible — devs need them.
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                kind = (
                    "dir" if stat_mod.S_ISDIR(st.st_mode)
                    else "symlink" if stat_mod.S_ISLNK(st.st_mode)
                    else "file"
                )
                entries.append({
                    "name": entry.name,
                    "type": kind,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                })
    except PermissionError:
        return {"ok": False, "error": "access_denied"}
    except OSError as e:
        log.warning(f"list_dir failed for {target}: {e}")
        return {"ok": False, "error": "io_error"}

    # Sort: dirs first, then files, alphabetical within each group
    entries.sort(key=lambda e: (e["type"] != "dir", e["name"].lower()))

    return {"ok": True, "entries": entries, "truncated": truncated}


def read_file(root: str, rel_path: str) -> dict:
    """Return file contents with metadata.

    Result:
      {ok: true, content, mtime, sha256, size, encoding, binary: false}
      {ok: true, binary: true, size, mtime, sha256, content: null}  -- skip preview
      {ok: false, error: ...}
    """
    target = _safe_resolve(root, rel_path)
    if target is None:
        return {"ok": False, "error": "access_denied"}
    if not target.exists():
        return {"ok": False, "error": "not_found"}
    if target.is_dir():
        return {"ok": False, "error": "is_a_directory"}

    try:
        st = target.stat()
    except OSError:
        return {"ok": False, "error": "io_error"}

    if st.st_size > MAX_READ_BYTES:
        return {
            "ok": False,
            "error": "too_large",
            "size": st.st_size,
            "limit": MAX_READ_BYTES,
        }

    try:
        raw = target.read_bytes()
    except PermissionError:
        return {"ok": False, "error": "access_denied"}
    except OSError as e:
        log.warning(f"read_file failed for {target}: {e}")
        return {"ok": False, "error": "io_error"}

    sha = hashlib.sha256(raw).hexdigest()

    if _looks_binary(raw):
        return {
            "ok": True,
            "binary": True,
            "content": None,
            "size": st.st_size,
            "mtime": int(st.st_mtime),
            "sha256": sha,
            "encoding": "binary",
        }

    # Try UTF-8 first; fall back to latin-1 (lossless byte mapping)
    try:
        text = raw.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
        encoding = "latin-1"

    return {
        "ok": True,
        "binary": False,
        "content": text,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "sha256": sha,
        "encoding": encoding,
    }


def write_file(root: str, rel_path: str, content: str, expected_sha256: str | None) -> dict:
    """Write content to a file, with optimistic-lock check.

    If expected_sha256 is provided and the current file's hash differs,
    returns a conflict with the current hash so the client can resolve.

    Result:
      {ok: true, sha256, mtime, size}
      {ok: false, error: 'conflict', current_sha256, current_mtime}
      {ok: false, error: ...}
    """
    target = _safe_resolve(root, rel_path)
    if target is None:
        return {"ok": False, "error": "access_denied"}

    payload = content.encode("utf-8")
    if len(payload) > MAX_WRITE_BYTES:
        return {"ok": False, "error": "too_large", "limit": MAX_WRITE_BYTES}

    # Conflict check (only meaningful if file already exists)
    if target.exists():
        if target.is_dir():
            return {"ok": False, "error": "is_a_directory"}
        try:
            current_sha = _file_sha256(target)
            current_mtime = int(target.stat().st_mtime)
        except OSError:
            return {"ok": False, "error": "io_error"}

        if expected_sha256 and expected_sha256 != current_sha:
            return {
                "ok": False,
                "error": "conflict",
                "current_sha256": current_sha,
                "current_mtime": current_mtime,
            }
    else:
        # New file — only allow if expected_sha256 is None or empty
        if expected_sha256:
            return {
                "ok": False,
                "error": "conflict",
                "current_sha256": None,
                "current_mtime": None,
            }
        # Ensure parent exists (don't auto-create deep paths — refuse if missing)
        if not target.parent.exists():
            return {"ok": False, "error": "parent_not_found"}

    # Atomic write: write to .tmp sibling, then rename
    tmp_path = target.with_suffix(target.suffix + ".orcswp")
    try:
        with open(tmp_path, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    except PermissionError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return {"ok": False, "error": "access_denied"}
    except OSError as e:
        log.warning(f"write_file failed for {target}: {e}")
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return {"ok": False, "error": "io_error"}

    new_sha = hashlib.sha256(payload).hexdigest()
    new_mtime = int(target.stat().st_mtime)

    return {
        "ok": True,
        "sha256": new_sha,
        "mtime": new_mtime,
        "size": len(payload),
    }


def stat(root: str, rel_path: str) -> dict:
    """Return file metadata without content.

    Result:
      {ok: true, exists, type, size, mtime, sha256?}
      {ok: false, error: ...}
    """
    target = _safe_resolve(root, rel_path)
    if target is None:
        return {"ok": False, "error": "access_denied"}

    if not target.exists():
        return {"ok": True, "exists": False}

    try:
        st = target.stat()
    except OSError:
        return {"ok": False, "error": "io_error"}

    kind = (
        "dir" if stat_mod.S_ISDIR(st.st_mode)
        else "symlink" if stat_mod.S_ISLNK(st.st_mode)
        else "file"
    )

    result = {
        "ok": True,
        "exists": True,
        "type": kind,
        "size": st.st_size,
        "mtime": int(st.st_mtime),
    }

    # Compute sha256 only for files under the read cap (otherwise too expensive)
    if kind == "file" and st.st_size <= MAX_READ_BYTES:
        try:
            result["sha256"] = _file_sha256(target)
        except OSError:
            pass

    return result
