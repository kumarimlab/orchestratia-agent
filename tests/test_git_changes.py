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


# ── Security: a repo must never be able to execute code during review ────────
# Reviewing a diff is a read-only act. git honours several repo-controlled config
# keys by running an external program — diff.external, a textconv/filter driver
# named in .gitattributes, core.fsmonitor. Since collect() runs in the daemon
# (root-equivalent) process, any of these is a "view the diff -> RCE" primitive,
# and an escalation the moment a restricted session's workspace is the repo.
# Each test arms one vector with a sentinel-writing script and asserts collect()
# did NOT run it. They FAIL against pre-fix code (the sentinel appears).

def _arm(repo, sentinel):
    """Write a script that touches `sentinel`, return its path. cat keeps git happy
    when the vector is a filter/textconv (it must still emit content)."""
    script = os.path.join(repo, "..", f"bomb_{os.path.basename(sentinel)}.sh")
    script = os.path.abspath(script)
    with open(script, "w") as f:
        f.write(f'#!/bin/sh\ntouch {sentinel}\ncat\n')
    os.chmod(script, 0o755)
    return script


def _sentinel():
    d = tempfile.mkdtemp(prefix="gcx-sentinel-")
    return os.path.join(d, "FIRED")


def test_diff_external_is_not_executed():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("change\n")
    s = _sentinel()
    _run(d, "config", "diff.external", _arm(d, s))
    gc.collect(d, base["head"])
    assert not os.path.exists(s), "diff.external was executed during review — RCE"


def test_textconv_driver_is_not_executed():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("change\n")
    with open(os.path.join(d, ".gitattributes"), "w") as f:
        f.write("*.txt diff=pwn\n")
    s = _sentinel()
    _run(d, "config", "diff.pwn.textconv", _arm(d, s))
    gc.collect(d, base["head"])
    assert not os.path.exists(s), "textconv driver was executed during review — RCE"


def test_filter_clean_driver_is_not_executed():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("change\n")
    with open(os.path.join(d, ".gitattributes"), "w") as f:
        f.write("*.txt filter=pwn\n")
    s = _sentinel()
    _run(d, "config", "filter.pwn.clean", _arm(d, s))
    gc.collect(d, base["head"])
    assert not os.path.exists(s), "filter.clean driver was executed during review — RCE"


def test_fsmonitor_hook_is_not_executed():
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("change\n")
    s = _sentinel()
    _run(d, "config", "core.fsmonitor", _arm(d, s))
    gc.collect(d, base["head"])
    assert not os.path.exists(s), "core.fsmonitor hook was executed during review — RCE"


def test_real_diff_survives_the_hardening():
    """The neutralization must not blind the feature: a genuine change with a
    benign .gitattributes present must still show up in the diff."""
    d = _repo()
    base = gc.baseline(d)
    with open(os.path.join(d, ".gitattributes"), "w") as f:
        f.write("*.md text\n")
    with open(os.path.join(d, "a.txt"), "a") as f:
        f.write("genuine agent edit\n")
    r = gc.collect(d, base["head"])
    assert "genuine agent edit" in r["diff"], "hardening blinded the real diff"
    assert any(f["path"] == "a.txt" for f in r["files"]), r["files"]


# ── run git as the session's project user (Spec A backstop) ──────────────────
# The version-agnostic containment for the repo-config code-exec class: run git
# AS the session's unprivileged project user, so even a vector the flags miss
# executes as that contained user, not the daemon.

def test_git_argv_wraps_in_sudo_when_run_as_set():
    argv = gc._git_argv("/srv/a", ["status", "--porcelain"], run_as="orcp-aaaaaaaaaaaa")
    assert argv[:5] == ["sudo", "-n", "-u", "orcp-aaaaaaaaaaaa", "-H"], argv
    assert "git" in argv and "-C" in argv and "/srv/a" in argv


def test_git_argv_no_sudo_when_run_as_none():
    argv = gc._git_argv("/srv/a", ["status", "--porcelain"], run_as=None)
    assert argv[0] != "sudo"
    assert argv[0] == "git"


def test_diff_flags_still_applied_under_sudo():
    argv = gc._git_argv("/srv/a", ["diff", "HEAD"], run_as="orcp-aaaaaaaaaaaa")
    assert "--no-ext-diff" in argv and "--no-textconv" in argv
    assert argv[:4] == ["sudo", "-n", "-u", "orcp-aaaaaaaaaaaa"], argv


def test_old_git_filter_refusal_lifts_only_when_run_as_set():
    orig = gc._supports_attr_source
    gc._supports_attr_source = lambda: False   # simulate git < 2.40
    try:
        assert gc._should_refuse_filter(run_as=None) is True
        assert gc._should_refuse_filter(run_as="orcp-aaaaaaaaaaaa") is False
    finally:
        gc._supports_attr_source = orig


def test_modern_git_never_refuses_filter():
    orig = gc._supports_attr_source
    gc._supports_attr_source = lambda: True    # git >= 2.40 neutralizes attributes
    try:
        assert gc._should_refuse_filter(run_as=None) is False
        assert gc._should_refuse_filter(run_as="orcp-aaaaaaaaaaaa") is False
    finally:
        gc._supports_attr_source = orig


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
