"""code.agent (spec §6.4). Stdlib only; runs inside the sandbox on a snapshot copy.

Git is hardened like git_changes.py: no system/global config, no external diff,
no textconv, no fsmonitor, no hooks, no pager — repo config can't make git run code."""
import os
import re
import stat
import subprocess
import unicodedata

try:
    from . import catalog, masking
except ImportError:          # installed layout: /opt/orchestratia/scanners/runner/*.py, no package
    import catalog
    import masking

GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
           "GIT_CONFIG_COUNT": "11",
           "GIT_CONFIG_KEY_0": "core.fsmonitor", "GIT_CONFIG_VALUE_0": "",
           "GIT_CONFIG_KEY_1": "core.hooksPath", "GIT_CONFIG_VALUE_1": "/dev/null",
           "GIT_CONFIG_KEY_2": "diff.external", "GIT_CONFIG_VALUE_2": "",
           "GIT_CONFIG_KEY_3": "core.pager", "GIT_CONFIG_VALUE_3": "cat",
           "GIT_CONFIG_KEY_4": "safe.directory", "GIT_CONFIG_VALUE_4": "*",
           "GIT_CONFIG_KEY_5": "core.quotePath", "GIT_CONFIG_VALUE_5": "false",
           "GIT_CONFIG_KEY_6": "diff.noprefix", "GIT_CONFIG_VALUE_6": "false",
           "GIT_CONFIG_KEY_7": "diff.mnemonicPrefix", "GIT_CONFIG_VALUE_7": "false",
           "GIT_CONFIG_KEY_8": "diff.renames", "GIT_CONFIG_VALUE_8": "false",
           # The commit-graph and multi-pack-index are caches git TRUSTS for parents and root trees: a
           # forged one cut history off (gitleaks) or swapped the base tree (code.agent). Never read them.
           "GIT_CONFIG_KEY_9": "core.commitGraph", "GIT_CONFIG_VALUE_9": "false",
           "GIT_CONFIG_KEY_10": "core.multiPackIndex", "GIT_CONFIG_VALUE_10": "false",
           # Repo content must not change what git shows: no refs/replace objects (a replace ref on the
           # base commit made a change look like nothing), no attributes from the work tree, the index,
           # info/attributes or the system file (`* -diff` hid every patch from gitleaks). The empty
           # tree as the attribute source needs git >= 2.40; older git ignores it, so the shim also
           # removes every attributes file before reading history.
           "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
           "GIT_ATTR_SOURCE": "4b825dc642cb6eb9a060e54bf8d69288fbee4904"}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TEST_FILE = re.compile(r"(^|/)(test_[^/]+\.py|[^/]+_test\.(py|go)|[^/]+\.(test|spec)\.(js|jsx|ts|tsx))$")
_TEST_DIRS = {"tests", "test", "__tests__"}
# (marker regex, style, file_wide). The text AFTER the marker decides whether a reason was given.
# Case-insensitive (`# NOQA`, `# NOSEC`). File-wide forms switch a checker off for a whole file and
# are reported high. Earlier entries win, so the file-wide `# flake8: noqa` is matched before `# noqa`.
_I = re.I
_SUPPRESS = [
    (re.compile(r"#\s*(?:flake8|ruff)\s*:\s*noqa\b(?!\s*:)", _I), "hash", True),
    (re.compile(r"#\s*(?:flake8|ruff)\s*:\s*noqa\s*:", _I), "ids", True),
    (re.compile(r"@ts-nocheck\b", _I), "text", True),
    (re.compile(r"#\s*mypy\s*:\s*ignore-errors\b", _I), "hash", True),
    (re.compile(r"#\s*pylint\s*:\s*(?:disable\s*=\s*all\b|skip-file\b)", _I), "hash", True),
    (re.compile(r"/\*\s*eslint-disable(?![-\w])", _I), "dashdash", True),
    (re.compile(r"#\s*nosec\b", _I), "ids", False), (re.compile(r"#\s*noqa\b", _I), "ids", False),
    (re.compile(r"#\s*type:\s*ignore\b", _I), "typeignore", False),
    (re.compile(r"@ts-(?:ignore|expect-error)\b", _I), "text", False),
    (re.compile(r"eslint-disable(?:-next-line|-line)?\b", _I), "dashdash", False),
    (re.compile(r"@SuppressWarnings\("), "comment", False),
    (re.compile(r"#\s*pylint\s*:\s*disable(?:-next)?\s*=", _I), "hash", False),
    (re.compile(r"//\s*nolint\b", _I), "slashes", False),
    (re.compile(r"#\s*rubocop\s*:\s*disable\b", _I), "hash", False),
    (re.compile(r"\bNOSONAR\b", _I), "text", False),
]
_ID = re.compile(r"^[A-Za-z]{1,4}\d{2,4}$")
_TOKEN_SEP = re.compile(r"[\s:\[\](),;]+")
_SKIP = re.compile(r"\b(?:it|describe|test)\.(?:skip|only)\(|(?<![.\w])(?:xit|xdescribe|fit|fdescribe)\(|"
                   r"@pytest\.mark\.(?:skip|xfail)\b|skipIf\(\s*True|@unittest\.skip\b")
_ASSERT = re.compile(r"\bassert\b|\bexpect\(|\.assert\w*\(|\bassert_\w+\(")
_PLACEHOLDER = re.compile(r"TODO\(human\)|\braise\s+NotImplemented(?:Error)?\b")
_TODO = re.compile(r"\b(?:TODO|FIXME)\b")
_CI = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.yml)$")
_CI_STEP = re.compile(r"^\s*-\s*(?:name|uses|run)\s*:")
_STEERING_NAMES = {"CLAUDE.md", "AGENTS.md", ".cursorrules", ".mcp.json"}
_STEERING_SETTINGS = {"settings.json", "settings.local.json"}
_STUBS = {"pass", "...", "return None"}
_HIDDEN = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\U000e0000-\U000e007f]")
_TEXT_MAX = 1024 * 1024
_BINARY_SNIFF = 8000
_LINE_MAX = 4096
_MAX_FINDINGS = 5001
_HEAVY = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build", "target", ".mypy_cache"}
_EVIDENCE_MAX = 2048
# Repo files that steer gitleaks (an allowlist or ignore list planted next to the code silences it).
SCANNER_CONFIG_NAMES = {".gitleaks.toml", ".gitleaksignore"}
SCANNER_CONFIG_ROOT_NAMES = {"gitleaks.toml"}
_SCANNER_CONFIG_MAX = 50
# A string literal: the opening quote, everything up to the matching unescaped quote, and the
# closing quote — or the end of the text when it never closes (that is blanked too). The loop
# can consume any character except the closing quote, so the match never fails: linear time.
_LITERAL = re.compile(r"""(["'`])((?:(?!\1)[^\\]|\\[\s\S]?)*)(\1|\Z)""")
# Token-like runs: keys, hashes, base64 blobs. No trailing condition, so linear time.
_TOKENISH = re.compile(r"[A-Za-z0-9+/_=-]{20,}")
_BLANK = "\u2026"


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


class _Out:
    """Findings, bounded PER SEVERITY: a flood of low findings (repo content controls their order)
    can't push a high one out of the cap (L2). What doesn't fit is counted."""

    def __init__(self):
        self.by = {s: [] for s in SEVERITY_ORDER}
        self.dropped = {}

    def append(self, f):
        bucket = self.by.get(f["severity"], self.by["info"])
        if len(bucket) < _MAX_FINDINGS:
            bucket.append(f)
        else:
            self.dropped[f["severity"]] = self.dropped.get(f["severity"], 0) + 1

    def __iadd__(self, fs):
        for f in fs:
            self.append(f)
        return self

    def full(self):
        return all(len(b) >= _MAX_FINDINGS for b in self.by.values())

    def result(self, meta):
        out = [f for s in SEVERITY_ORDER for f in self.by[s]]
        if self.dropped:
            meta["dropped"] = dict(self.dropped)
        return out, meta


class GitError(RuntimeError):
    """git couldn't read the history; the message is plain and safe to show."""

    def __init__(self):
        super().__init__("git couldn't read this repository's history")


def _display(path):
    """Valid str for output; undecodable bytes (surrogateescape) become U+FFFD for display only."""
    return path.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _views(text):
    """Regex-checked windows of a line: all of it, or its first and last _LINE_MAX chars (bounded cost,
    and trailing-space padding cannot push a marker out of view)."""
    return [text] if len(text) <= _LINE_MAX else [text[:_LINE_MAX], text[-_LINE_MAX:]]


def _finding(rule, severity, title, path, line, evidence):
    """`evidence` is either a fixed sentence or the output of _evidence(); it is masked, then cut."""
    return {"scan_id": "code.agent", "rule_id": f"agent:{rule}", "severity": severity, "title": title,
            "description": "", "location": {"kind": "file", "path": _display(path), "line": line},
            "evidence": masking.mask_cut(evidence, _EVIDENCE_MAX), "references": {"cwe": [], "cve": [], "urls": []},
            "tool": "orchestratia", "tool_version": catalog.CATALOG_VERSION}


def _blank(text):
    """String-literal contents and token-like runs become …; the line's shape stays readable."""
    text = _LITERAL.sub(lambda m: m.group(1) + (_BLANK if m.group(2) else "") + m.group(3), text)
    return _TOKENISH.sub(_BLANK, text)


def _outside_literals(matches, spans):
    """The first match that overlaps no literal span (both in text order; linear time)."""
    i = 0
    for m in matches:
        while i < len(spans) and spans[i][1] <= m.start():
            i += 1
        if i == len(spans) or spans[i][0] >= m.end():
            return m
    return None


def _evidence(text, marker=None):
    """A source line made safe to upload: literals, token-like runs and URL userinfo blanked, then
    masked, then cut. The detector's own marker (e.g. `# nosec`) is kept verbatim — only where it
    sits outside every literal of the whole line: splitting inside one would flip quote parity and
    upload the next literal as code."""
    text = text.strip()
    m = None
    if marker is not None:
        m = _outside_literals(marker.finditer(text), [lit.span() for lit in _LITERAL.finditer(text)])
    if m:
        text = _blank(text[:m.start()]) + m.group(0) + _blank(text[m.end():])
    else:
        text = _blank(text)
    return masking.mask_cut(text, _EVIDENCE_MAX)


def _marker(rxs, text):
    for rx in rxs:
        if rx.search(text):
            return rx
    return None


def scanner_config_files(src):
    """Relative paths of gitleaks config/ignore files anywhere in src (never following links)."""
    out = []
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        rel_root = os.path.relpath(root, src)
        for name in sorted(dirs + files):
            if name in SCANNER_CONFIG_NAMES or (rel_root == "." and name in SCANNER_CONFIG_ROOT_NAMES):
                out.append(name if rel_root == "." else os.path.join(rel_root, name))
                if len(out) >= _SCANNER_CONFIG_MAX:
                    return out
    return out


def _scanner_config_findings(src):
    return [_finding("scanner-config-in-repo", "medium", "Scanner configuration in the repository", p, None,
                     "a gitleaks config or ignore file here could silence secret scanning; the scan ignored it")
            for p in scanner_config_files(src)]


def _git(src, git, *args):
    env = dict(GIT_ENV, PATH=os.environ.get("PATH", "/usr/bin:/bin"), HOME=os.environ.get("HOME", "/tmp"))
    try:
        return subprocess.run([git, "-C", src, *args], capture_output=True, text=True, env=env,
                              encoding="utf-8", errors="replace", timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        raise GitError()


def _git_bytes(src, git, *args):
    env = dict(GIT_ENV, PATH=os.environ.get("PATH", "/usr/bin:/bin"), HOME=os.environ.get("HOME", "/tmp"))
    try:
        return subprocess.run([git, "-C", src, *args], capture_output=True, env=env, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        raise GitError()


def _split(text):
    """Split on "\n" only (str.splitlines also breaks on U+2028, \x0b, \x0c, \x85 ... which hides line tails)."""
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts.pop()
    return [p[:-1] if p.endswith("\r") else p for p in parts]


def _read_bytes(path, limit):
    """Up to `limit` bytes of a regular, non-symlink file, else None. Never opens a FIFO/device/symlink."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return None


def _binary(data):
    """git's test: a NUL in the first 8000 bytes. A PNG's or PDF's bytes can decode to bidi controls."""
    return b"\0" in data[:_BINARY_SNIFF]


def _is_binary_file(path):
    data = _read_bytes(path, _BINARY_SNIFF)
    return data is not None and _binary(data)


def _read_regular(path):
    """Text of a regular, non-symlink, non-binary file <= _TEXT_MAX, else None."""
    try:
        if os.lstat(path).st_size > _TEXT_MAX:
            return None
    except OSError:
        return None
    data = _read_bytes(path, _TEXT_MAX + 1)
    if data is None or _binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def _reasonless(line):
    """True when a suppression marker on this line has no reason (any marker without one counts)."""
    return _reasonless_kind(line) is not None


def _reasonless_kind(line):
    """"file" or "line" for the first reason-less suppression marker on this line, else None."""
    seen = set()
    for rx, style, file_wide in _SUPPRESS:
        m = rx.search(line)
        if not m or m.start() in seen:
            continue
        seen.add(m.start())
        rest = line[m.end():]
        kind = "file" if file_wide else "line"
        if style == "comment":                       # @SuppressWarnings("x") // reason
            i = rest.find(")")
            if "//" not in (rest[i + 1:] if i >= 0 else ""):
                return kind
        elif style == "dashdash":                    # eslint-disable-line x -- reason
            if "--" not in rest or not rest.split("--", 1)[1].strip(" */"):
                return kind
        elif style == "text":
            if not rest.strip(" :-*/"):
                return kind
        elif style in ("hash", "slashes"):           # `# pylint: disable=x  # reason`, `//nolint:x // reason`
            seps = ("//",) if style == "slashes" else ("#", "//", "--")
            if not any(sep in rest and rest.split(sep, 1)[1].strip() for sep in seps):
                return kind
        else:                                        # ids / typeignore: tokens beyond rule ids are a reason
            if style == "typeignore":
                lb = rest.find("[")
                rb = rest.find("]", lb + 1) if lb >= 0 else -1
                if lb >= 0 and rb >= 0 and not rest[:lb].strip(" :"):
                    rest = rest[rb + 1:]
            if not any(t and t != "-" and not _ID.match(t) for t in _TOKEN_SEP.split(rest)):
                return kind
    return None


def _suppression_kind(line):
    return any(rx.search(line) for rx, _, _ in _SUPPRESS)


def _suppression_finding(path, line_no, text, line_severity):
    """The suppression-no-reason finding for this line, or None. File-wide forms are high."""
    kinds = {_reasonless_kind(v) for v in _views(text) if _suppression_kind(v)} - {None}
    if not kinds:
        return None
    if "file" in kinds:
        return _finding("suppression-no-reason", "high", "File-wide suppression without a reason", path, line_no,
                        _evidence(text, _marker([rx for rx, _, _ in _SUPPRESS], text)))
    return _finding("suppression-no-reason", line_severity, "Suppression without a reason", path, line_no,
                    _evidence(text, _marker([rx for rx, _, _ in _SUPPRESS], text)))


def _hpath(raw):
    raw = raw[:-1] if raw.endswith("\t") else raw
    if raw == "/dev/null":
        return None
    return raw[2:] if raw.startswith(("a/", "b/")) else raw


def _parse_diff(text):
    """{path: {"added": [(line_no, text)], "removed": [text], "deleted": bool}}.
    File headers are recognised only before a section's first @@; afterwards every +/- line is content."""
    files, cur, in_hunk, old, new_line = {}, None, False, None, 0
    for raw in _split(text):
        if raw.startswith("diff --git "):
            cur, in_hunk, old = None, False, None
        elif not in_hunk and raw.startswith("--- "):
            old = _hpath(raw[4:])
        elif not in_hunk and raw.startswith("+++ "):
            new = _hpath(raw[4:])
            path = new or old
            if path is not None:
                cur = files.setdefault(path, {"added": [], "removed": [], "deleted": new is None})
        elif raw.startswith("@@") and cur is not None:
            in_hunk = True
            m = re.search(r"\+(\d+)", raw)
            new_line = int(m.group(1)) if m else 0
        elif cur is not None and in_hunk:
            if raw.startswith("+"):
                cur["added"].append((new_line, raw[1:]))
                new_line += 1
            elif raw.startswith("-"):
                cur["removed"].append(raw[1:])
            elif raw.startswith(" "):
                new_line += 1
    return files


def _hidden(path, line_no, text):
    if not _HIDDEN.search(text):
        return None
    names = sorted({unicodedata.name(c, f"U+{ord(c):04X}") for c in set(_HIDDEN.findall(text))})
    return _finding("hidden-unicode", "high", "Hidden Unicode characters", path, line_no,
                    "Contains " + ", ".join(names))


def _is_test_path(path):
    return bool(_TEST_FILE.search(path)) or any(c in _TEST_DIRS for c in path.split("/")[:-1])


def _steering(path):
    parts = path.split("/")
    if parts[-1] in _STEERING_NAMES:
        return (True, False)
    if len(parts) >= 2 and parts[-2] == ".claude" and parts[-1] in _STEERING_SETTINGS:
        return (True, True)
    return (False, False)


def _file_names(src):
    names = set()
    for _root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d not in _HEAVY]
        names.update(files)
    return names


def _change(src, since, git):
    p = _git(src, git, "diff", "--no-ext-diff", "--no-textconv", "--text", "--no-renames", "--src-prefix=a/",
             "--dst-prefix=b/", "--no-color", "-U0", "--end-of-options", since, "--")
    if p.returncode != 0:
        raise GitError()
    ls = _git_bytes(src, git, "ls-files", "--others", "-z")      # no --exclude-standard: a new .gitignore must not hide files
    if ls.returncode != 0:
        raise GitError()
    files = {path: d for path, d in _parse_diff(p.stdout).items()     # diff --text shows binaries as lines
             if not _is_binary_file(os.path.join(src, path))}
    for raw in filter(None, ls.stdout.split(b"\0")):
        rel = os.fsdecode(raw)                      # surrogateescape: round-trips to the filesystem
        text = _read_regular(os.path.join(src, rel))
        if text is not None:
            files[rel] = {"added": list(enumerate(_split(text), 1)), "removed": [], "deleted": False}
    out, names = _Out(), None
    out += _scanner_config_findings(src)
    if not files:
        return out.result({"mode": "nothing_to_compare"})
    for path, d in files.items():
        if out.full():
            break
        is_test, test_path = bool(_TEST_FILE.search(path)), _is_test_path(path)
        is_py_edit = path.endswith(".py") and bool(d["removed"])
        for line_no, text in d["added"]:
            if out.full():
                break
            h = _hidden(path, line_no, text)
            if h:
                out.append(h)
            vs = _views(text)
            sup = _suppression_finding(path, line_no, text, "medium")
            if sup:
                out.append(sup)
            if test_path and any(_SKIP.search(v) for v in vs):
                out.append(_finding("test-skipped", "medium", "Test skipped or focused", path, line_no,
                                    _evidence(text, _SKIP)))
            if any(_PLACEHOLDER.search(v) for v in vs):
                out.append(_finding("placeholder", "medium", "Placeholder left in", path, line_no,
                                    _evidence(text, _PLACEHOLDER)))
            elif any(_TODO.search(v) for v in vs):
                out.append(_finding("todo-added", "low", "TODO or FIXME added", path, line_no, _evidence(text, _TODO)))
            if is_py_edit and text.strip() in _STUBS:
                out.append(_finding("placeholder", "medium", "Body replaced with a stub", path, line_no, _evidence(text)))
        if is_test and not d["deleted"]:
            removed = sum(bool(_ASSERT.search(t[:_LINE_MAX])) for t in d["removed"])
            added = sum(bool(_ASSERT.search(t[:_LINE_MAX])) for _, t in d["added"])
            if removed > added:
                out.append(_finding("assertions-removed", "high", "Assertions removed from a test", path, None,
                                    f"{removed - added} fewer assertions"))
        if is_test and d["deleted"]:
            subject = re.sub(r"^test_|_test(?=\.)|\.(test|spec)(?=\.)", "", os.path.basename(path))
            if names is None:
                names = _file_names(src)
            if subject in names:
                out.append(_finding("test-deleted", "high", "Test file deleted while its code remains", path, None,
                                    f"{subject} still exists"))
        if _CI.search(path):
            gone = (sum(bool(_CI_STEP.match(t[:_LINE_MAX])) for t in d["removed"])
                    - sum(bool(_CI_STEP.match(t[:_LINE_MAX])) for _, t in d["added"]))
            if gone > 0:
                out.append(_finding("ci-step-removed", "medium", "CI step removed", path, None, f"{gone} step(s) removed"))
        steering, is_settings = _steering(path)
        if steering:
            hooks = is_settings and any(('"hooks"' in t or '"command"' in t) for _, t in d["added"])
            out.append(_finding("steering-file-changed", "high" if hooks else "medium",
                                "Agent-steering file changed" + (" (hooks)" if hooks else ""), path, None,
                                "hooks or commands added" if hooks else "edited in this change"))
    return out.result({"mode": "change"})


def _full(src):
    out = _Out()
    out += _scanner_config_findings(src)
    for root, dirs, files in os.walk(src, followlinks=False):
        dirs[:] = [d for d in dirs if d != ".git"]
        for name in files:
            if out.full():
                return out.result({"mode": "full"})
            full = os.path.join(root, name)
            rel = os.path.relpath(full, src)
            text = _read_regular(full)
            if text is None:
                continue
            for i, line in enumerate(_split(text), 1):
                h = _hidden(rel, i, line)
                if h:
                    out.append(h)
                sup = _suppression_finding(rel, i, line, "low")
                if sup:
                    out.append(sup)
                if out.full():
                    break
    return out.result({"mode": "full"})


def run(src, since, git="git"):
    if since is not None and not _SHA.match(since):
        raise ValueError("since must be a full hex sha")
    return _change(src, since, git) if since else _full(src)
