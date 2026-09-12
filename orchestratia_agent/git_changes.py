"""What did the agent actually change?

A terminal recording proves what happened; it is useless for judging code. The
artifact a developer wants is the diff — "these 12 files changed, here is what
was done to them" — and nothing in the product captured it.

Collection is split from transport so it can be tested without a daemon, a
websocket, or a hub. Every function here takes a path and returns data.
"""

from __future__ import annotations

import os
import subprocess

# A diff is for human review, not archival. Past a few hundred KB nobody reads
# it and we are just moving bytes through a websocket, so it is truncated with
# an explicit marker rather than silently clipped.
MAX_DIFF_BYTES = 400_000
MAX_FILES = 500


def _git(repo: str, args: list[str], timeout: int = 15) -> tuple[int, str]:
    """Run a git command in `repo`. Returns (returncode, stdout)."""
    try:
        r = subprocess.run(
            ["git", "-C", repo] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return r.returncode, r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return 1, ""


def is_git_repo(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    rc, out = _git(path, ["rev-parse", "--is-inside-work-tree"])
    return rc == 0 and out.strip() == "true"


def head_sha(path: str) -> str:
    """Current HEAD, or '' — an empty repo with no commits has no HEAD."""
    rc, out = _git(path, ["rev-parse", "HEAD"])
    return out.strip() if rc == 0 else ""


def current_branch(path: str) -> str:
    rc, out = _git(path, ["rev-parse", "--abbrev-ref", "HEAD"])
    return out.strip() if rc == 0 else ""


def baseline(path: str) -> dict:
    """Snapshot taken when a session starts, so later diffs have an anchor.

    Records whether the tree was ALREADY dirty: without that, pre-existing
    uncommitted work gets attributed to the agent, which is exactly the kind of
    quiet inaccuracy that makes a review surface untrustworthy.
    """
    if not is_git_repo(path):
        return {"is_repo": False}
    rc, status = _git(path, ["status", "--porcelain"])
    return {
        "is_repo": True,
        "head": head_sha(path),
        "branch": current_branch(path),
        "dirty_at_start": bool(status.strip()),
    }


def _parse_porcelain(status_out: str) -> list[dict]:
    """Parse `git status --porcelain` into {path, index, worktree, untracked}."""
    files = []
    for line in status_out.splitlines():
        if len(line) < 4:
            continue
        index, worktree, rest = line[0], line[1], line[3:]
        # Renames arrive as "old -> new"; report the destination.
        if " -> " in rest:
            rest = rest.split(" -> ", 1)[1]
        files.append({
            "path": rest.strip('"'),
            "index": index.strip(),
            "worktree": worktree.strip(),
            "untracked": index == "?" and worktree == "?",
        })
    return files


def collect(path: str, since_sha: str = "") -> dict:
    """Everything that changed in `path`, optionally since `since_sha`.

    Covers all three places work hides: commits made during the session,
    modifications in the working tree, and untracked new files. Reporting only
    `git diff` would miss the first and last — and "the agent committed its
    work" is the common case, so that omission would make the feature look
    broken precisely when it worked.
    """
    if not is_git_repo(path):
        return {"is_repo": False, "error": "not a git repository"}

    result: dict = {
        "is_repo": True,
        "path": path,
        "branch": current_branch(path),
        "head": head_sha(path),
        "since": since_sha,
        "commits": [],
        "files": [],
        "diff": "",
        "diff_truncated": False,
        "stat": {"files_changed": 0, "insertions": 0, "deletions": 0},
    }

    # Commits made since the baseline.
    if since_sha:
        rc, out = _git(path, ["log", "--format=%H%x1f%s%x1f%an%x1f%aI",
                              f"{since_sha}..HEAD"])
        if rc == 0:
            for line in out.strip().splitlines():
                parts = line.split("\x1f")
                if len(parts) == 4:
                    result["commits"].append({
                        "sha": parts[0][:12], "subject": parts[1],
                        "author": parts[2], "date": parts[3],
                    })

    rc, status = _git(path, ["status", "--porcelain"])
    if rc == 0:
        result["files"] = _parse_porcelain(status)[:MAX_FILES]

    # Diff range: since the baseline if we have one, else the working tree.
    diff_args = ["diff", "--no-color"]
    stat_args = ["diff", "--numstat"]
    if since_sha:
        diff_args.append(since_sha)
        stat_args.append(since_sha)

    rc, diff = _git(path, diff_args, timeout=30)
    if rc == 0:
        encoded = diff.encode("utf-8", errors="replace")
        if len(encoded) > MAX_DIFF_BYTES:
            result["diff"] = encoded[:MAX_DIFF_BYTES].decode("utf-8", errors="ignore")
            result["diff_truncated"] = True
        else:
            result["diff"] = diff

    rc, numstat = _git(path, stat_args)
    if rc == 0:
        ins = dels = changed = 0
        for line in numstat.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                changed += 1
                # "-" for binary files; count the file, not the lines.
                if parts[0].isdigit():
                    ins += int(parts[0])
                if parts[1].isdigit():
                    dels += int(parts[1])
        result["stat"] = {"files_changed": changed, "insertions": ins,
                          "deletions": dels}

    return result
