"""Git history analyzer using subprocess. Zero external dependencies."""

import os
import subprocess
from collections import Counter
from pathlib import Path


def analyze_git_history(repo_path: str, days: int = 30) -> dict:
    """Analyze git history for churn metrics.

    Returns file change frequencies, recent commit count, and hotspot data.
    Falls back gracefully if not a git repo or git not available.
    """
    result = {
        "is_git_repo": False,
        "current_commit": None,
        "branch": None,
        "total_commits_in_period": 0,
        "file_churn": {},   # path -> change count
        "hotspots": [],     # top 10 most-changed files
        "recent_authors": [],
    }

    if not _is_git_repo(repo_path):
        return result

    result["is_git_repo"] = True
    result["current_commit"] = _git_cmd(repo_path, ["rev-parse", "--short", "HEAD"])
    result["branch"] = _git_cmd(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])

    # Get file change counts in the last N days
    log_output = _git_cmd(repo_path, [
        "log", f"--since={days} days ago",
        "--pretty=format:", "--name-only",
    ])

    if log_output:
        files = [f.strip() for f in log_output.split("\n") if f.strip()]
        churn = Counter(files)
        result["file_churn"] = dict(churn.most_common(100))
        result["hotspots"] = [
            {"path": path, "changes": count}
            for path, count in churn.most_common(10)
        ]

    # Total commits in period
    count_output = _git_cmd(repo_path, [
        "rev-list", "--count", f"--since={days} days ago", "HEAD",
    ])
    if count_output and count_output.isdigit():
        result["total_commits_in_period"] = int(count_output)

    # Recent authors
    authors_output = _git_cmd(repo_path, [
        "log", f"--since={days} days ago",
        "--pretty=format:%an", "--no-merges",
    ])
    if authors_output:
        author_counts = Counter(a.strip() for a in authors_output.split("\n") if a.strip())
        result["recent_authors"] = [
            {"name": name, "commits": count}
            for name, count in author_counts.most_common(10)
        ]

    return result


def _is_git_repo(path: str) -> bool:
    """Check if path is inside a git repository."""
    try:
        result = subprocess.run(
            ["git", "-C", path, "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _git_cmd(repo_path: str, args: list[str]) -> str | None:
    """Run a git command and return stdout, or None on error."""
    try:
        result = subprocess.run(
            ["git", "-C", repo_path] + args,
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None
