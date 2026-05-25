"""Orchestrator persistent memory (Phase 2.5, plan §8.5.2).

Project knowledge belongs to the user, not the platform. Memories are plain
markdown files under `<working_dir>/.orchestratia/memory/<uuid>.md` with a
tiny frontmatter block — git-versionable, grep-able, and fully readable even
if Orchestratia is removed. The hub's `orchestrator_memory_index` table is a
rebuildable pointer index; these files are the system of record.

Frontmatter is a deliberately minimal, dependency-free format (no YAML lib):
a `---` fence, `key: value` lines (`tags` is comma-separated), a closing
`---`, then the fact body. We both write and parse it, so it round-trips.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone

log = logging.getLogger("orchestratia-agent.memory")

MEMORY_SUBDIR = os.path.join(".orchestratia", "memory")
_SUMMARY_LEN = 200


def _memory_dir(working_dir: str) -> str:
    return os.path.join(working_dir, MEMORY_SUBDIR)


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _summary_of(body: str) -> str:
    return " ".join(body.split())[:_SUMMARY_LEN]


def write_memory(
    working_dir: str,
    fact: str,
    tags: list[str] | None = None,
    related_task_id: str | None = None,
) -> dict:
    """Write a new memory file. Returns the index payload (relative file_path,
    content_hash, tags, summary, related_task_id)."""
    tags = [t.strip() for t in (tags or []) if t and t.strip()]
    mem_dir = _memory_dir(working_dir)
    os.makedirs(mem_dir, exist_ok=True)
    mem_id = str(uuid.uuid4())
    rel_path = os.path.join(MEMORY_SUBDIR, f"{mem_id}.md")
    abs_path = os.path.join(working_dir, rel_path)

    front = [
        "---",
        f"id: {mem_id}",
        f"created_at: {datetime.now(timezone.utc).isoformat()}",
        f"tags: {', '.join(tags)}",
        f"related_task_id: {related_task_id or ''}",
        "---",
        "",
    ]
    content = "\n".join(front) + fact.rstrip() + "\n"
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(content)

    return {
        "file_path": rel_path,
        "content_hash": _sha256(content),
        "tags": tags,
        "summary": _summary_of(fact),
        "related_task_id": related_task_id or None,
    }


def parse_memory(text: str) -> tuple[dict, str]:
    """Split a memory file into (frontmatter dict, body). Tolerant of files a
    user hand-wrote without frontmatter (returns empty meta + whole text)."""
    meta: dict = {}
    lines = text.splitlines()
    if lines and lines[0].strip() == "---":
        end = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                end = i
                break
        if end is not None:
            for line in lines[1:end]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    meta[k.strip()] = v.strip()
            body = "\n".join(lines[end + 1:]).lstrip("\n")
            return meta, body
    return meta, text


def _tags_from_meta(meta: dict) -> list[str]:
    raw = meta.get("tags", "")
    return [t.strip() for t in raw.split(",") if t.strip()]


def read_memory(working_dir: str, rel_path: str) -> str | None:
    """Return a memory file's body (frontmatter stripped). None if missing or
    if the path escapes the memory dir."""
    abs_path = os.path.normpath(os.path.join(working_dir, rel_path))
    mem_dir = os.path.normpath(_memory_dir(working_dir))
    if not abs_path.startswith(mem_dir + os.sep):
        log.warning(f"memory: refusing to read outside memory dir: {rel_path}")
        return None
    if not os.path.isfile(abs_path):
        return None
    try:
        with open(abs_path, "r", encoding="utf-8") as f:
            _, body = parse_memory(f.read())
        return body
    except Exception:
        log.exception(f"memory: failed to read {rel_path}")
        return None


def scan_memory(working_dir: str) -> list[dict]:
    """Walk the memory dir and return an index payload per file. Used by the
    reindex sync — handles user-created/edited/deleted files."""
    mem_dir = _memory_dir(working_dir)
    if not os.path.isdir(mem_dir):
        return []
    entries: list[dict] = []
    for name in os.listdir(mem_dir):
        if not name.endswith(".md"):
            continue
        abs_path = os.path.join(mem_dir, name)
        try:
            with open(abs_path, "r", encoding="utf-8") as f:
                raw = f.read()
        except Exception:
            continue
        meta, body = parse_memory(raw)
        rel_path = os.path.join(MEMORY_SUBDIR, name)
        related = meta.get("related_task_id") or None
        entries.append({
            "file_path": rel_path,
            "content_hash": _sha256(raw),
            "tags": _tags_from_meta(meta),
            "summary": _summary_of(body or raw),
            "related_task_id": related,
        })
    return entries
