"""What did the agent actually change?

A terminal recording proves what happened; it is useless for judging code. The
artifact a developer wants is the diff — "these 12 files changed, here is what
was done to them" — and nothing in the product captured it.

Collection is split from transport so it can be tested without a daemon, a
websocket, or a hub. Every function here takes a path and returns data.
"""

from __future__ import annotations

import functools
import os
import subprocess

# A diff is for human review, not archival. Past a few hundred KB nobody reads
# it and we are just moving bytes through a websocket, so it is truncated with
# an explicit marker rather than silently clipped.
MAX_DIFF_BYTES = 400_000
MAX_FILES = 500

# ── Reviewing a diff must never execute code ─────────────────────────────────
# `git diff`/`status` will run an external program if the repository asks it to:
# diff.external, a textconv or filter driver named in .gitattributes, or
# core.fsmonitor. collect() runs inside the daemon — root-equivalent — so every
# one of those is a "open the review pane → arbitrary code as the daemon user"
# primitive, and a straight privilege escalation once a restricted session's own
# workspace is the repo under review. The repo is attacker-controlled input;
# treat it as such. (Proven with a PoC before this guard existed.)
#
# The containment has three parts, chosen to hold on the git versions agents
# actually run (Ubuntu 22.04 ships 2.34, 24.04 ships 2.43):
#   * env — refuse global/system config and any credential/pager subprocess.
#   * per-command flags — --no-ext-diff and --no-textconv kill the two
#     config-only / diff-driver vectors on every git version; -c core.fsmonitor=
#     disables the fsmonitor hook.
#   * --attr-source=<empty tree> — makes .gitattributes resolve to nothing, so no
#     path can be assigned a filter/diff driver at all. This is what closes the
#     filter.clean vector, which the flags alone do NOT (proven). It needs git
#     ≥ 2.40; on older git the filter vector is handled by refusing to inspect a
#     repo that arms it (see collect()), never by executing it.
#
# The real version-agnostic backstop — running git as the session's own
# unprivileged user — is deferred to the per-project-OS-user work, because the
# tier sudoers rule currently permits only tmux.
_HARDEN_ENV = {
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_SYSTEM": os.devnull,   # git ≥ 2.32; harmlessly ignored below it
    "GIT_CONFIG_GLOBAL": os.devnull,   # git ≥ 2.32; ""
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat",
    "GIT_EXTERNAL_DIFF": "",           # neutralize the env-set external differ
}

# Empty-tree hashes; --attr-source=<this> means "no attributes at all". Both
# object formats are covered so a rare SHA-256 repo degrades safely rather than
# erroring the whole diff into a misleading "no changes".
_EMPTY_TREE = {
    "sha1": "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
    "sha256": "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321",
}


@functools.lru_cache(maxsize=1)
def _git_version() -> tuple[int, int]:
    """(major, minor) of the git on PATH, or (0, 0) if it cannot be determined."""
    try:
        r = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=5)
        parts = r.stdout.split()[2].split(".")
        return int(parts[0]), int(parts[1])
    except Exception:  # noqa: BLE001
        return (0, 0)


def _supports_attr_source() -> bool:
    return _git_version() >= (2, 40)


def _hardened_env() -> dict:
    env = os.environ.copy()
    env.update(_HARDEN_ENV)
    return env


def _empty_tree(repo: str) -> str:
    """The empty-tree hash for this repo's object format (SHA-1 unless told)."""
    try:
        r = subprocess.run(
            ["git", "-C", repo, "rev-parse", "--show-object-format"],
            capture_output=True, text=True, timeout=5, env=_hardened_env(),
        )
        fmt = r.stdout.strip() or "sha1"
    except Exception:  # noqa: BLE001
        fmt = "sha1"
    return _EMPTY_TREE.get(fmt, _EMPTY_TREE["sha1"])


def _git(repo: str, args: list[str], timeout: int = 15) -> tuple[int, str]:
    """Run a git command in `repo`, hardened against repo-controlled code exec.

    `args` begins with the git subcommand. Diff subcommands additionally get
    --no-ext-diff/--no-textconv; every command runs with fsmonitor disabled,
    attributes neutralized (where git supports it), and a locked-down env.
    """
    pre: list[str] = ["-c", "core.fsmonitor="]
    if _supports_attr_source():
        pre += [f"--attr-source={_empty_tree(repo)}"]

    cmd = list(args)
    if cmd and cmd[0] == "diff":
        # After the subcommand: these are diff options, not top-level git options.
        cmd = [cmd[0], "--no-ext-diff", "--no-textconv"] + cmd[1:]

    try:
        r = subprocess.run(
            ["git", "-C", repo] + pre + cmd,
            capture_output=True, text=True, timeout=timeout, env=_hardened_env(),
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
    # rev-parse (head/branch) never runs a filter; status can. On a git too old
    # to neutralize attributes, refuse the status probe if a filter is armed.
    if not _supports_attr_source() and _armed_filter_driver(path):
        return {
            "is_repo": True,
            "head": head_sha(path),
            "branch": current_branch(path),
            "dirty_at_start": False,
            "inspection_limited": "repo defines content filters and this host's "
                                  "git (<2.40) cannot inspect it without running them",
        }
    rc, status = _git(path, ["status", "--porcelain"])
    return {
        "is_repo": True,
        "head": head_sha(path),
        "branch": current_branch(path),
        "dirty_at_start": bool(status.strip()),
    }


def _armed_filter_driver(path: str) -> bool:
    """Does the repo define a filter.*.(clean|smudge|process) exec driver?

    On git ≥ 2.40 the answer is irrelevant — --attr-source neutralizes the
    .gitattributes that would select any such driver, so we never ask. Below
    2.40 there is no way to disable in-tree attributes, and `git status`/`diff`
    will run the driver to clean working-tree content. Reading config does NOT
    run the driver (verified), so this check is a safe pre-flight: if a driver
    is armed we refuse to inspect rather than execute it.

    Errs toward refusal — a repo using git-lfs also matches, and loses the diff
    on a pre-2.40 host until git is upgraded or per-user isolation lands. That is
    the safe direction: a missing diff is visible and honest; silent code
    execution is neither.
    """
    rc, out = _git(path, ["config", "--get-regexp",
                          r"^filter\..*\.(clean|smudge|process)$"])
    return rc == 0 and bool(out.strip())


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

    # status and diff below can run a repo-defined filter driver. On a git too
    # old for --attr-source we cannot stop that, so refuse rather than execute —
    # commits (from log, above) are still reported, only the working-tree
    # inspection is withheld, with the reason stated.
    if not _supports_attr_source() and _armed_filter_driver(path):
        result["inspection_limited"] = (
            "repo defines content filters and this host's git (<2.40) cannot "
            "inspect the working tree without running them; showing commits only"
        )
        return result

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
