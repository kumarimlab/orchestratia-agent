#!/usr/bin/python3 -I
"""Runs INSIDE the per-run systemd sandbox (spec §7.3). Stdlib only.

stdin: one JSON header line, then the snapshot tar stream. stdout: JSON lines (finding /
meta / one end). Unpacks with tarfile's `data` filter (no absolute paths, no `..`, no
links leaving the tree), runs one pinned tool, parses, masks, caps. Never prints raw
tool output; errors are masked and cut to 200 chars."""
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # -I drops the script dir
try:                                                                  # installed layout
    import catalog, code_agent, masking, parsers                      # noqa: E401
except ImportError:                                                   # package layout (tests)
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from orchestratia_agent.scanning import catalog, code_agent, masking, parsers  # noqa: E401

MAX_FINDINGS, HEADER_MAX = 5000, 64 * 1024
SEVERITY_RANK = {s: i for i, s in enumerate(("critical", "high", "medium", "low", "info"))}
# The pinned gitleaks config ships next to this file (pack.RUNNER_FILES): repo config never applies.
GITLEAKS_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gitleaks.toml")
# --ignore-gitleaks-allow: an inline `gitleaks:allow` comment is repo content, so it can't silence a scan.
# The history pass: gitleaks' own `git log` options plus --text, so a file git would call binary (one
# NUL byte) is still diffed and read; and without gitleaks' default `t` in the filter, so a type change
# (a symlink or gitlink replaced by a file holding a secret) is diffed too. Deletions (d) stay out: a
# deleted file's content was added in an earlier commit. gitleaks runs `git -C <src> log -p -U0 <these>`.
GITLEAKS_LOG_OPTS = ["--full-history", "--all", "--diff-filter=uxdb", "--text"]
TOOL_ARGV = {
    "code.secrets": [["{bin}", "dir", "--no-banner", "--redact", "--ignore-gitleaks-allow", "--config={cfg}",
                      "--report-format", "json", "--report-path", "{out}", "{src}"],
                     ["{bin}", "git", "--no-banner", "--redact", "--ignore-gitleaks-allow", "--config={cfg}",
                      "--log-opts=" + " ".join(GITLEAKS_LOG_OPTS),
                      "--report-format", "json", "--report-path", "{out}", "{src}"]],
    "code.deps": [["{bin}", "scan", "source", "--offline", "--offline-vulnerabilities", "--format", "json", "-r", "{src}"]],
}


ended = False
MAX_READ = 64 * 1024 * 1024
TOOL_TIMEOUT_MIN = 60
OUT_OF_TIME = "the scan ran out of time"
WORKTREE = "this repository is a git worktree; history isn't available to the scan"
OSV_NO_PACKAGES = 128      # osv-scanner v2.7.0: "No package sources found" (verified on the pinned binary)
HISTORY_UNREAD = "gitleaks didn't read the whole git history"
# gitleaks reports "N commits scanned": the commits its `git log` shows at least one hunk for.
# history_commits() counts the same set from the same options' --numstat.
GITLEAKS_LOG = ["log", *GITLEAKS_LOG_OPTS, "--numstat", "--format=%x00%H"]
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_COMMITS_SCANNED = re.compile(r"\b(\d+) commits scanned")
_LOG_ERROR = re.compile(r"(?m)^(?:\S+ )?(?:ERR|FTL)\b")
# osv-scanner 2.7.0 logs every manifest it extracted, vulnerable or not, even with 0 packages
# (verified on the pinned binary). Its JSON lists only sources with a vulnerable package, so a
# manifest cleaned by an upgrade would drop out of manifests_scanned and its issues never auto-fix.
_OSV_SCANNED = re.compile(r"^Scanned (.+) file and found \d+ packages?$")


def osv_scanned(stderr_path, root):
    """Every manifest path osv-scanner says it read, relative to root, in order."""
    out = []
    try:
        with open(stderr_path, "rb") as f:
            text = f.read(16 * 1024 * 1024).decode(errors="replace")
    except OSError:
        return out
    for line in text.split("\n"):
        m = _OSV_SCANNED.match(line.rstrip("\r"))
        if m:
            path = m.group(1)
            rel = os.path.relpath(path, root) if os.path.isabs(path) else path
            if not rel.startswith("..") and rel not in out:
                out.append(rel)
    return out


class Done(Exception):
    """end() already emitted; unwind to the top."""


def emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def end(status, error=None, known=()):
    global ended
    if ended:
        raise Done()
    ended = True
    if error:
        error = masking.mask_cut(str(error), 200, known)          # mask first, then cut
    emit({"type": "end", "status": status, "error": error})
    raise Done()


# The snapshot's own caps (dl_helper SNAP_MAX_*). The stream comes from a helper running as the
# session's uid, which can hijack it (M3): unpacking is capped independently, so it can't fill the
# host's disk past what a real snapshot could.
UNPACK_MAX_ENTRIES, UNPACK_MAX_BYTES = 200_000, 2 * 1024 ** 3
TOO_LARGE = "repository too large to scan"


def _lowered(name, cap):
    """Test hook: a positive integer below the cap (the unit's environment is set by the daemon)."""
    try:
        v = int(os.environ.get(name, ""))
        return v if 0 < v < cap else cap
    except ValueError:
        return cap


def _member_filter(member, dest):
    """tarfile's `data` filter, then fixed modes: dirs 0700, files 0600. A 000-mode directory would
    otherwise be applied before its children are extracted and silently hide them."""
    member = tarfile.data_filter(member, dest)
    if member.isdir():
        return member.replace(mode=0o700, deep=False)
    if member.isfile():
        return member.replace(mode=0o600, deep=False)
    return member


CUT_OFF = "the repository snapshot was cut off before its end"


class _EndAware(tarfile.TarInfo):
    """Records whether the stream ended with tar's end-of-archive marker (two zero blocks). tarfile
    stops at the first zero block AND at a plain end of input, so without this a stream cut off at a
    file boundary (a stopped-then-killed helper) unpacks as a complete, smaller repository."""

    @classmethod
    def fromtarfile(cls, tf):
        try:
            return super().fromtarfile(tf)
        except tarfile.EOFHeaderError:
            if tf.fileobj.read(tarfile.BLOCKSIZE) == tarfile.NUL * tarfile.BLOCKSIZE:
                tf.orc_ended = True               # the second zero block
            raise


def unpack(dest, known=()):
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("python without tarfile extraction filters")
    max_entries = _lowered("ORC_UNPACK_MAX_ENTRIES_FOR_TEST", UNPACK_MAX_ENTRIES)
    max_bytes = _lowered("ORC_UNPACK_MAX_BYTES_FOR_TEST", UNPACK_MAX_BYTES)
    entries = total = 0
    with tarfile.open(fileobj=sys.stdin.buffer, mode="r|", tarinfo=_EndAware) as tf:
        tf.orc_ended = False
        for member in tf:
            entries += 1
            total += max(member.size, 0)
            if entries > max_entries or total > max_bytes:
                end("failed", TOO_LARGE, known)
            if member.issparse():
                continue                           # a sparse member can claim any size: never extracted
            try:
                tf.extract(member, dest, filter=_member_filter)
            except (tarfile.FilterError, OSError):
                continue                           # refused member (escaping link, odd type): skip it
        if not tf.orc_ended:
            end("failed", CUT_OFF, known)          # before any scan runs: no findings from a partial tree


VERSION_ARGV = {"gitleaks": ["version"], "osv-scanner": ["--version"]}   # verified against v8.30.1 / v2.7.0


def tool_version(binary, tool=None):
    try:
        args = VERSION_ARGV.get(tool or os.path.basename(binary).split("_")[0], ["version"])
        out = subprocess.run([binary, *args], capture_output=True, text=True, timeout=20).stdout.strip()
        first = out.splitlines()[0].split() if out else []
        return (first[-1] if first else "unknown")[:40]
    except Exception:
        return "unknown"


def _rm(path):
    """Remove whatever is at path without following links."""
    if os.path.islink(path) or os.path.isfile(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def git_kind(src):
    """What src/.git is: "dir" (a real directory), "gitfile" (a `gitdir:` file — a git worktree or
    submodule, whose history lives outside the snapshot), "none", or "other" (symlink, odd type)."""
    git = os.path.join(src, ".git")
    if not os.path.lexists(git):
        return "none"
    if os.path.islink(git):
        return "other"
    if os.path.isdir(git):
        return "dir"
    if os.path.isfile(git):
        try:
            with open(git, "rb") as f:
                if f.read(8) == b"gitdir: ":
                    return "gitfile"
        except OSError:
            pass
    return "other"


def strip_scanner_config(src):
    """Delete every gitleaks config/ignore file from the unpacked snapshot (any depth, never
    following links): a planted allowlist or ignore list must not silence code.secrets."""
    for rel in code_agent.scanner_config_files(src):
        _rm(os.path.join(src, rel))


def neutralise_git(src):
    """Returns True when src/.git is a usable, neutralised real directory."""
    git = os.path.join(src, ".git")
    if not os.path.lexists(git):
        return False
    if os.path.islink(git) or not os.path.isdir(git):
        _rm(git)                                          # symlink / gitdir: file / odd: no history
        return False
    _rm(os.path.join(git, "config"))
    with open(os.path.join(git, "config"), "w") as f:
        f.write("[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
    _rm(os.path.join(git, "hooks"))
    os.makedirs(os.path.join(git, "hooks"))
    _rm(os.path.join(git, "commondir"))
    _rm(os.path.join(git, "info", "attributes"))
    _rm(os.path.join(git, "info", "grafts"))             # grafts rewrite parents: they can cut history off
    # Caches git trusts over the objects themselves (also disabled by config in GIT_ENV).
    _rm(os.path.join(git, "objects", "info", "commit-graph"))
    _rm(os.path.join(git, "objects", "info", "commit-graphs"))
    pack = os.path.join(git, "objects", "pack")
    if os.path.isdir(pack) and not os.path.islink(pack):
        for name in os.listdir(pack):
            if name.startswith("multi-pack-index"):
                _rm(os.path.join(pack, name))
    return True


def is_shallow(src):
    """A shallow clone (or a planted .git/shallow): history stops at the boundary, so a run can't
    claim to have read all of it."""
    return os.path.lexists(os.path.join(src, ".git", "shallow"))


def _git_run(env, *args, stdout=subprocess.DEVNULL, timeout=120):
    try:
        return subprocess.run(["git", *args], stdout=stdout, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
                              env=env, timeout=timeout).returncode
    except (OSError, subprocess.SubprocessError):
        return None


def history_readable(env):
    """True when git can walk every ref (a ref to a missing object makes gitleaks' `git log` die
    early while gitleaks still reports "no leaks found")."""
    return history_state(env, None)[0]


HISTORY_NOTES = {"unreadable": "git couldn't read every ref; only the files were scanned",
                 "corrupt": "the git object store failed an integrity check (git fsck); only the files were scanned",
                 "slow": "the git object store was too large to verify in time; only the files were scanned",
                 "empty": "no commits are reachable from any ref; only the files were scanned",
                 "noncommit": "a ref points at something other than a commit; only the files were scanned",
                 "shallow": "this is a shallow clone; history before its boundary wasn't scanned"}


def history_state(env, fsck_timeout):
    """(trusted, reason) for the history. Trusted needs: every ref walks (`rev-list --all`), at least
    one commit is reachable (an unborn HEAD over a full object store would otherwise "read" 0 commits
    as complete history), and — when fsck_timeout is given — `git fsck --full` passes: git doesn't
    re-hash objects on read, so an object rewritten under the same id silently changes history."""
    try:
        p = subprocess.run(["git", "rev-list", "--all", "--count"], capture_output=True, text=True,
                           stdin=subprocess.DEVNULL, env=env, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return False, "unreadable"
    if p.returncode != 0:
        return False, "unreadable"
    try:
        empty = int(p.stdout.strip() or "0") == 0
    except ValueError:
        return False, "unreadable"
    if _non_commit_ref(env):
        return False, "noncommit"
    if fsck_timeout is not None:             # also when empty: code.agent may still diff against `since`
        rc = _git_run(env, "fsck", "--full", "--no-dangling", "--no-progress", timeout=fsck_timeout)
        if rc is None:
            return False, "slow"
        if rc != 0:
            return False, "corrupt"
    return (False, "empty") if empty else (True, None)


def history_commits(env, work, timeout):
    """How many commits gitleaks' own `git log` shows a hunk for, or None when git fails. Streamed
    from a file: the numstat of a long history can be large."""
    out = os.path.join(work, "history.numstat")
    with open(out, "wb") as f:
        if _git_run(env, *GITLEAKS_LOG, stdout=f, timeout=timeout) != 0:
            return None
    n, counted = 0, True
    with open(out, "rb") as f:
        for line in f:
            if line.startswith(b"\0"):
                counted = False
                continue
            if not counted:
                added, _, rest = line.partition(b"\t")
                deleted = rest.partition(b"\t")[0]
                # "-" = a file git calls binary: --text diffs it, so it has a hunk (numstat ignores --text)
                if added == b"-" or (added.isdigit() and int(added)) or (deleted.isdigit() and int(deleted)):
                    n, counted = n + 1, True
    os.unlink(out)
    return n


def strip_attributes(src):
    """Remove every .gitattributes file and the index (attributes fall back to the index): on git
    older than 2.40 GIT_ATTR_SOURCE is ignored, and `* -diff` would hide every patch. Run only after
    the files pass, so those files are still scanned as files."""
    for root, dirs, files in os.walk(src, followlinks=False):
        if root == src:
            dirs[:] = [d for d in dirs if d != ".git"]
        if ".gitattributes" in files or ".gitattributes" in dirs:
            _rm(os.path.join(root, ".gitattributes"))
    _rm(os.path.join(src, ".git", "index"))


def defeat_sniffing(src):
    """Put one newline in front of every regular file (not .git). gitleaks skips a file whose first
    bytes look like a binary format (zip, gzip, tar, pdf, exe ...) however much text follows — a .env
    starting with PK\\x03\\x04 hid its token. Every magic number those sniffers know sits at a fixed
    offset, so one leading byte defeats all of them; the parser takes the line back off."""
    for root, dirs, files in os.walk(src, followlinks=False):
        if root == src:
            dirs[:] = [d for d in dirs if d != ".git"]
        try:
            os.chmod(root, 0o700)                       # ours; data-filter modes may lack u+w
        except OSError:
            continue
        for name in files:
            path = os.path.join(root, name)
            try:
                if not stat.S_ISREG(os.lstat(path).st_mode):
                    continue
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                continue
            tfd, tmp = tempfile.mkstemp(dir=root, prefix=".orc-sniff-")
            with os.fdopen(fd, "rb") as fin, os.fdopen(tfd, "wb") as fout:
                fout.write(b"\n")
                shutil.copyfileobj(fin, fout, 1 << 20)
            os.replace(tmp, path)


def _non_commit_ref(env):
    """True when any ref (or HEAD), fully peeled, is a blob or a tree. `rev-list --all` and gitleaks'
    `git log` skip those silently, so a secret parked in a ref->blob or tag->tree is never read."""
    try:
        refs = subprocess.run(["git", "for-each-ref", "--format=%(refname)"], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, env=env, timeout=120)
        if refs.returncode != 0:
            return True
        names = [r for r in refs.stdout.split("\n") if r] + ["HEAD"]
        p = subprocess.run(["git", "cat-file", "--batch-check=%(objecttype)"], input="".join(f"{n}^{{}}\n" for n in names),
                           capture_output=True, text=True, env=env, timeout=120)
    except (OSError, subprocess.SubprocessError):
        return True
    if p.returncode != 0:
        return True
    types = p.stdout.split("\n")
    for name, t in zip(names, types):
        t = t.strip()
        if t == "commit" or (name == "HEAD" and t.endswith("missing")):   # unborn HEAD is checked elsewhere
            continue
        return True
    return False


def check_history_pass(stderr_path, expected, known):
    """gitleaks exits 0 with "no leaks found" even when git died; trust the pass only when it logged
    no error and read every commit."""
    with open(stderr_path, "rb") as f:
        text = _ANSI.sub("", f.read(16 * 1024 * 1024).decode(errors="replace"))
    m = _COMMITS_SCANNED.findall(text)
    if _LOG_ERROR.search(text) or not m or int(m[-1]) != expected:
        end("failed", HISTORY_UNREAD, known)


def _read_capped(path, known):
    if not os.path.exists(path):
        return b""
    with open(path, "rb") as f:
        data = f.read(MAX_READ + 1)
    if len(data) > MAX_READ:
        end("failed", "tool output too large", known)
    return data


def run_tool(spec, binary, src, work, env, has_git, known, ran=None):
    """Runs the tool's passes -> [(pass name, report)]; `ran` (a list) collects the names of the passes
    that ran. The git pass runs only when git can read every ref, and is checked against what gitleaks
    says it read. Before the files pass of code.secrets every file is un-sniffed (defeat_sniffing)."""
    reports = []
    timeout = max(TOOL_TIMEOUT_MIN, spec.timeout_s - 30)
    for i, tmpl in enumerate(TOOL_ARGV[spec.id]):
        expected = None
        if "git" in tmpl:
            if not has_git:
                continue
            strip_attributes(src)
            expected = history_commits(env, work, timeout)
            if expected is None:
                end("failed", HISTORY_UNREAD, known)
            if expected == 0:
                continue                                  # nothing read: history is not claimed
        if spec.id == "code.secrets" and "dir" in tmpl:
            defeat_sniffing(src)
        out = os.path.join(work, f"report{i}.json")
        so, se = os.path.join(work, f"stdout{i}"), os.path.join(work, f"stderr{i}")
        argv = [a.format(bin=binary, out=out, src=src, cfg=GITLEAKS_CONFIG) for a in tmpl]
        try:
            with open(so, "wb") as fo, open(se, "wb") as fe:
                p = subprocess.run(argv, stdout=fo, stderr=fe, stdin=subprocess.DEVNULL, timeout=timeout,
                                   env=env, cwd=work)
        except subprocess.TimeoutExpired:
            end("timed_out", OUT_OF_TIME, known)
        if ran is not None:
            ran.append("git" if "git" in tmpl else "files")
        if spec.id == "code.deps" and p.returncode == OSV_NO_PACKAGES:
            continue                                      # nothing to scan: a clean run, no findings
        if p.returncode not in (0, 1):
            with open(se, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 64 * 1024))
                err = f.read().decode(errors="replace")
            msg = masking.mask_tail(err, 300, known)          # mask first, then cut
            end("failed", f"{os.path.basename(binary)} exited {p.returncode}: {msg}", known)
        if expected is not None:
            check_history_pass(se, expected, known)
        raw = _read_capped(out, known) or _read_capped(so, known)
        reports.append(("git" if "git" in tmpl else "files", json.loads(raw or b"null")))
    return reports


def _str_or_none(v):
    return v if isinstance(v, str) else None


def clean_header(hdr):
    if not isinstance(hdr, dict):
        return None
    tools = hdr.get("tools")
    tools = {k: v for k, v in tools.items() if isinstance(k, str) and isinstance(v, str)} if isinstance(tools, dict) else {}
    known = hdr.get("known")
    return {"scan_id": hdr.get("scan_id"), "since": _str_or_none(hdr.get("since")), "tools": tools,
            "osv_db": _str_or_none(hdr.get("osv_db")), "data_as_of": _str_or_none(hdr.get("data_as_of")),
            "known": [k for k in known if isinstance(k, str)] if isinstance(known, list) else []}


def main():
    line = sys.stdin.buffer.readline(HEADER_MAX + 1)
    try:
        hdr = clean_header(json.loads(line))
    except Exception:
        hdr = None
    if hdr is None:
        end("failed", "bad header")
    known = hdr["known"]
    spec = catalog.get(str(hdr["scan_id"]))
    if spec is None:
        end("failed", f"unknown scan: {hdr['scan_id']}", known)
    work = tempfile.mkdtemp(prefix="scan-", dir=os.environ.get("TMPDIR") or None)
    src = os.path.join(work, "src")
    os.makedirs(src)
    try:
        unpack(src, known)
    except Done:
        raise
    except Exception:
        end("failed", "the repository snapshot couldn't be read", known)
    kind = git_kind(src)
    has_git = neutralise_git(src)
    env = dict(code_agent.GIT_ENV, PATH="/usr/bin:/bin", HOME=os.environ.get("HOME", work), TMPDIR=work)
    if has_git:
        env["GIT_DIR"] = os.path.join(src, ".git")
        env["GIT_WORK_TREE"] = src
    # History counts as read only when git can walk every ref, commits were reachable, the object store
    # passes fsck, and the clone isn't shallow. Otherwise the files are scanned and the run says why.
    readable, why = history_state(env, max(TOOL_TIMEOUT_MIN, spec.timeout_s // 3)) if has_git else (False, None)
    if readable and is_shallow(src):
        why = "shallow"
    full_history = readable and why is None
    note = HISTORY_NOTES.get(why) if why else None
    if spec.id == "code.secrets":
        has_git = readable                             # untrusted history: scan the files, say history:false
    findings, manifests, version, dropped = [], [], catalog.CATALOG_VERSION, {}
    if spec.id == "code.agent":
        if hdr["since"] and not (has_git and (readable or why == "empty")):   # no trustworthy base: fail
            emit({"type": "meta", "tool_version": version, "data_as_of": hdr["data_as_of"], "manifests_scanned": [],
                  "scope": {"mode": "change", "history": False}})
            end("failed", WORKTREE if kind == "gitfile" else (HISTORY_NOTES.get(why) if why in ("corrupt", "slow")
                                                              else code_agent.GitError().args[0]), known)
        try:
            findings, run_meta = code_agent.run(src, hdr["since"])
        except code_agent.GitError as e:
            end("failed", str(e), known)
        scope = {"mode": run_meta.get("mode"), "history": full_history}
        dropped = dict(run_meta.get("dropped") or {})
    else:
        binary = hdr["tools"].get(spec.tool)
        if not binary or not os.path.isfile(binary):
            end("failed", f"{spec.tool} is not installed on this runner")
        if spec.id == "code.secrets":
            if not os.path.isfile(GITLEAKS_CONFIG):
                end("failed", "the scanner pack is incomplete (gitleaks.toml is missing)")
            strip_scanner_config(src)
        if spec.id == "code.deps" and hdr["osv_db"]:
            env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = hdr["osv_db"]
        version = tool_version(binary, spec.tool)
        ran = []
        for name, report in run_tool(spec, binary, src, work, env, has_git, known, ran):
            if spec.id == "code.secrets":       # the files pass read every file one line down (defeat_sniffing)
                findings += parsers.gitleaks(report, version, root=src, known=known,
                                             line_offset=-1 if name == "files" else 0)
            else:
                f, m = parsers.osv(report, version, root=src, known=known)
                findings += f
                manifests += [x for x in m if x not in manifests]
        if spec.id == "code.deps":                     # every manifest osv read, not only vulnerable ones
            manifests += [x for x in osv_scanned(os.path.join(work, "stderr0"), src) if x not in manifests]
        scope = {"mode": "tool", "history": "git" in ran and full_history}
    # Most severe first, so the cap (here and in the runner) drops the least severe (L2); count it.
    findings.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity"), len(SEVERITY_RANK)))
    for f in findings[MAX_FINDINGS:]:
        dropped[f.get("severity")] = dropped.get(f.get("severity"), 0) + 1
    meta = {"type": "meta", "tool_version": version, "data_as_of": hdr["data_as_of"],
            "manifests_scanned": [masking.mask_cut(m, 512, known) for m in manifests[:200]], "scope": scope}
    if dropped:
        meta["dropped"] = dropped
    emit(meta)
    for f in findings[:MAX_FINDINGS]:
        masking.mask_finding(f, known)
        emit({"type": "finding", "finding": f})
    end("truncated" if len(findings) > MAX_FINDINGS or dropped else "done", note)


def safe_main():
    try:
        main()
    except Done:
        pass
    except BaseException as e:                       # noqa: BLE001 — the contract: always exactly one end
        try:
            end("failed", f"the scanner hit an internal error ({type(e).__name__})")
        except Done:
            pass
    sys.exit(0)


if __name__ == "__main__":
    safe_main()
