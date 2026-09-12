#!/usr/bin/env python3
"""Tests for git_changes — run against REAL git repos in temp dirs.

Mocking git here would test my idea of git's output rather than git's actual
output, which is the failure mode that let two bugs through earlier today.

Dependency-free — run:  python3 tests/test_git_changes.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import git_changes as gc  # noqa: E402


def _run(repo, *args):
    subprocess.run(["git", "-C", repo] + list(args), capture_output=True, check=False)


def _repo():
    """A real git repo with one commit."""
    d = tempfile.mkdtemp(prefix="gcx-")
    _run(d, "init", "-q")
    _run(d, "config", "user.email", "t@t.t")
    _run(d, "config", "user.name", "T")
    _run(d, "config", "commit.gpgsign", "false")
    with open(os.path.join(d, "a.txt"), "w") as f:
        f.write("one\n")
    _run(d, "add", "."); _run(d, "commit", "-qm", "init")
    return d


def test_non_repo_is_reported_not_crashed():
    d = tempfile.mkdtemp(prefix="gcx-")
    assert gc.is_git_repo(d) is False
    r = gc.collect(d)
    assert r["is_repo"] is False and "error" in r


def test_missing_path_is_safe():
    assert gc.is_git_repo("/definitely/not/here") is False


def test_detects_a_real_repo():
    d = _repo()
    assert gc.is_git_repo(d) is True
    assert len(gc.head_sha(d)) == 40


def test_baseline_records_clean_start():
    d = _repo()
    b = gc.baseline(d)
    assert b["is_repo"] and b["dirty_at_start"] is False and len(b["head"]) == 40


def test_baseline_records_dirty_start():
    """Pre-existing uncommitted work must not later be blamed on the agent."""
    d = _repo()
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("edited before the session\n")
    assert gc.baseline(d)["dirty_at_start"] is True


def test_working_tree_modification_is_seen():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("agent wrote this\n")
    r = gc.collect(d, base["head"])
    assert any(f["path"] == "a.txt" for f in r["files"]), r["files"]
    assert "agent wrote this" in r["diff"]
    assert r["stat"]["insertions"] >= 1


def test_untracked_new_file_is_seen():
    """A brand-new file is the most common agent output and `git diff` alone
    would miss it entirely."""
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "brand_new.py"), "w") as f:
        f.write("print('hi')\n")
    r = gc.collect(d, base["head"])
    newf = [f for f in r["files"] if f["path"] == "brand_new.py"]
    assert newf and newf[0]["untracked"] is True, r["files"]


def test_commits_made_during_the_session_are_seen():
    """If the agent commits its work, `git diff` shows nothing — the change is
    in history. Reporting only the working tree would look broken exactly when
    the agent did the right thing."""
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "b.txt"), "w") as f:
        f.write("committed by agent\n")
    _run(d, "add", "."); _run(d, "commit", "-qm", "agent work")
    r = gc.collect(d, base["head"])
    assert len(r["commits"]) == 1, r["commits"]
    assert r["commits"][0]["subject"] == "agent work"
    assert "committed by agent" in r["diff"], "diff must span the commit"


def test_renames_report_the_destination():
    d = _repo()
    base = gc.baseline(d)
    _run(d, "mv", "a.txt", "renamed.txt")
    r = gc.collect(d, base["head"])
    paths = [f["path"] for f in r["files"]]
    assert any("renamed.txt" in p for p in paths), paths


def test_large_diff_is_truncated_and_says_so():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "big.txt"), "w") as f:
        f.write("x" * (gc.MAX_DIFF_BYTES + 50_000))
    _run(d, "add", "."); _run(d, "commit", "-qm", "big")
    r = gc.collect(d, base["head"])
    assert r["diff_truncated"] is True
    assert len(r["diff"].encode()) <= gc.MAX_DIFF_BYTES


def test_no_baseline_still_returns_working_tree():
    d = _repo()
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("no baseline\n")
    r = gc.collect(d)
    assert "no baseline" in r["diff"]


def test_branch_is_reported():
    d = _repo()
    assert gc.collect(d)["branch"] in ("main", "master")


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
        except AssertionError as e:
            failures.append((fn.__name__, str(e) or "assertion failed"))
        except Exception as e:  # noqa: BLE001
            failures.append((fn.__name__, f"{type(e).__name__}: {e}"))
    if failures:
        for name, msg in failures:
            print(f"FAIL  {name}: {msg}")
        print(f"\n{len(failures)}/{len(CASES)} failed")
        raise SystemExit(1)
    print(f"ok  {len(CASES)} passed")


if __name__ == "__main__":
    main()
