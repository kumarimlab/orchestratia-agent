#!/usr/bin/env python3
"""Adversarial review (2026-11-17): repository content must not silence a scan while the run
still reports done with full scope. Real dl-helper snap -> real shim -> pinned gitleaks 8.30.1
(/tmp/orc-pin/gitleaks; the real-binary checks are skipped when it is missing).

Run:  python3 tests/test_scan_evasion.py
"""
import io
import json
import os
import random
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import code_agent, pack  # noqa: E402

HELPER = os.path.join(HERE, "orchestratia_agent", "dl_helper.py")
GITLEAKS = "/tmp/orc-pin/gitleaks"
GENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t",
            GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
random.seed(7)
TOKEN = "ghp" + "_" + "".join(random.choice(string.ascii_letters + string.digits) for _ in range(36))
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True, env=GENV).stdout.strip()


def write(repo, rel, data):
    os.makedirs(os.path.dirname(os.path.join(repo, rel)) or repo, exist_ok=True)
    with open(os.path.join(repo, rel), "wb" if isinstance(data, bytes) else "w") as f:
        f.write(data)


def snap_tar(repo):
    p = subprocess.run([sys.executable, "-I", HELPER, "snap", "--", repo], capture_output=True, timeout=60)
    head, _, body = p.stdout.partition(b"\n")
    assert p.returncode == 0 and json.loads(head)["ok"], (p.returncode, head)
    return body


FLAT = tempfile.mkdtemp(prefix="orc-flat-")
for name in pack.RUNNER_FILES:
    shutil.copy(os.path.join(HERE, "orchestratia_agent", "scanning", name), FLAT)
FLAT_SHIM = os.path.join(FLAT, "shim.py")


def run_flat(header, body, tmp):
    env = {"PATH": "/usr/bin:/bin", "HOME": tmp, "TMPDIR": tmp}
    p = subprocess.run([sys.executable, "-I", FLAT_SHIM], input=json.dumps(header).encode() + b"\n" + body,
                       capture_output=True, timeout=300, env=env, cwd="/")
    lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    return lines, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")


def H(scan_id, since=None, **kw):
    return dict({"scan_id": scan_id, "since": since, "tools": {}, "osv_db": None, "data_as_of": None, "known": []}, **kw)


def summary(lines):
    fs = [x["finding"] for x in lines if x.get("type") == "finding"]
    meta = next((x for x in lines if x.get("type") == "meta"), {})
    end = next((x for x in lines if x.get("type") == "end"), {})
    return fs, meta.get("scope"), end


def fresh(tmp, name):
    d = os.path.join(tmp, name)
    os.makedirs(d)
    git(d, "init", "-q", "-b", "main")
    write(d, "app.py", "print('hi')\n")
    git(d, "add", "-A")
    git(d, "commit", "-qm", "base")
    return d


def history_secret(d):
    """Commit a secret, then delete it: only the git-history pass can find it."""
    write(d, "config.py", f'GITHUB_TOKEN = "{TOKEN}"\n')
    git(d, "add", "-A")
    git(d, "commit", "-qm", "add config")
    os.unlink(os.path.join(d, "config.py"))
    git(d, "add", "-A")
    git(d, "commit", "-qm", "remove config")


def secrets_run(repo, tmp):
    return run_flat(H("code.secrets", tools={"gitleaks": GITLEAKS}), snap_tar(repo), tmp)


def gh(fs):
    return [f for f in fs if f["rule_id"] == "gitleaks:github-pat"]


if os.path.exists(GITLEAKS):
    with tempfile.TemporaryDirectory() as tmp:
        # ---- H1: each trick alone must not turn 1 finding into 0 with a clean done/history:true
        d = fresh(tmp, "baseline")
        history_secret(d)
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 baseline: the history secret is found", len(gh(fs)) == 1 and end.get("status") == "done"
           and scope == {"mode": "tool", "history": True}, (len(fs), scope, end))

        d = fresh(tmp, "attr_untracked")
        history_secret(d)
        write(d, ".gitattributes", "* -diff\n")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 work-tree .gitattributes '* -diff' (untracked) doesn't hide the history secret",
           len(gh(fs)) == 1 and end.get("status") == "done", (len(fs), scope, end))

        d = fresh(tmp, "attr_committed")
        write(d, ".gitattributes", "*.py -diff\n")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "attrs")
        history_secret(d)
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 committed .gitattributes '-diff' doesn't hide the history secret",
           len(gh(fs)) == 1 and end.get("status") == "done", (len(fs), scope, end))

        d = fresh(tmp, "shallow")
        history_secret(d)
        write(d, ".git/shallow", git(d, "rev-parse", "HEAD") + "\n")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 .git/shallow: the run says history:false (it can't see past the boundary)",
           scope == {"mode": "tool", "history": False}, (len(fs), scope, end))

        d = fresh(tmp, "grafts")
        history_secret(d)
        write(d, ".git/info/grafts", git(d, "rev-parse", "HEAD") + "\n")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 .git/info/grafts is ignored: the history secret is found",
           len(gh(fs)) == 1 and end.get("status") == "done" and scope == {"mode": "tool", "history": True},
           (len(fs), scope, end))

        d = fresh(tmp, "replace")
        history_secret(d)
        git(d, "replace", git(d, "rev-parse", "HEAD~1"), git(d, "rev-parse", "HEAD~2"))
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 refs/replace over the secret commit doesn't hide it", len(gh(fs)) == 1 and end.get("status") == "done",
           (len(fs), scope, end))

        d = fresh(tmp, "inline_allow")
        write(d, "config.py", f'GITHUB_TOKEN = "{TOKEN}"  # gitleaks:allow\n')
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 inline 'gitleaks:allow' is ignored", len(gh(fs)) >= 1 and end.get("status") == "done", (len(fs), scope, end))

        d = fresh(tmp, "broken_ref")
        history_secret(d)
        write(d, "live.py", f'TOKEN2 = "{TOKEN[:-4]}abcd"\n')
        write(d, ".git/refs/heads/zz", "1" * 40 + "\n")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 a broken ref: history can't be read, so the run says history:false (not a clean full scan)",
           scope == {"mode": "tool", "history": False} and len(gh(fs)) >= 1, (len(fs), scope, end))

        # control: a varied, honest history (merges, renames, binary, symlink, type change, empty and
        # deleted files, a submodule link, a non-UTF-8 name, CRLF) passes the commit-count check
        d = fresh(tmp, "varied")
        git(d, "checkout", "-qb", "side")
        write(d, "s.txt", "side\r\nline\r\n")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "side")
        git(d, "checkout", "-q", "main")
        write(d, "m.txt", "main\n")
        write(d, "b.bin", b"\0\1\2\3")
        write(d, "empty", "")
        os.symlink("m.txt", os.path.join(d, "ln"))
        write(d, os.fsdecode(b"caf\xe9.txt"), "x\n")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "main")
        git(d, "merge", "-q", "--no-edit", "side")
        git(d, "mv", "m.txt", "moved.txt")
        git(d, "commit", "-qm", "rename")
        os.unlink(os.path.join(d, "ln"))
        write(d, "ln", "now a file\n")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "typechange")
        os.unlink(os.path.join(d, "empty"))
        git(d, "add", "-A")
        git(d, "commit", "-qm", "delete")
        git(d, "update-index", "--add", "--cacheinfo", "160000," + git(d, "rev-parse", "HEAD") + ",sub")
        git(d, "commit", "-qm", "gitlink")
        git(d, "commit", "-q", "--allow-empty", "-m", "empty")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("H1 control: a varied honest history passes the commit-count check",
           end.get("status") == "done" and scope == {"mode": "tool", "history": True}, (scope, end))

        # ---- M5: no file is skipped by name (the upstream global allowlist), nor by a binary sniff
        d = fresh(tmp, "names")
        for rel in ("settings.svg", "settings.pdf", "x/@octokit/auth-token/README.md", "vendor/github.com/a/b/c.go",
                    "yarn.lock", "go.sum", "Pipfile.lock", "lib/python3.12/site-packages/k.py"):
            write(d, rel, f'GITHUB_TOKEN = "{TOKEN}"\n')
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        paths = sorted(f["location"]["path"] for f in gh(fs) if "commit" not in f["evidence"])
        ok("M5 a secret in a name the upstream allowlist skipped (svg, pdf, vendor, lockfiles, ...) is reported",
           len(paths) == 8 and end.get("status") == "done", paths)

        d = fresh(tmp, "magic")
        write(d, ".env", b"PK\x03\x04\n" + f"GITHUB_TOKEN={TOKEN}\n".encode())
        write(d, "padded.env", b"PK\x03\x04\x14\x00\x00" + bytes(range(256)) * 256 + f"\nGITHUB_TOKEN={TOKEN}\n".encode())
        write(d, "first.py", f'T = "{TOKEN}"\n')
        write(d, "tar_magic.txt", "x" * 257 + "ustar\x0000\n" + f'T = "{TOKEN}"\n')
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        lines = {f["location"]["path"]: f["location"]["line"] for f in gh(fs) if "commit" not in f["evidence"]}
        ok("M5 a file sniffed as binary (zip/tar magic, binary padding) is still scanned",
           {".env", "padded.env", "tar_magic.txt"} <= set(lines), lines)
        ok("M5 line numbers are the file's own (the sniff defeat doesn't shift them)",
           lines.get("first.py") == 1 and lines.get(".env") == 2 and lines.get("tar_magic.txt") == 2, lines)

        d = fresh(tmp, "hist_binary")
        write(d, "blob.dat", b"\x00\x01binary\x00\n" + f"GITHUB_TOKEN={TOKEN}\n".encode())
        git(d, "add", "-A")
        git(d, "commit", "-qm", "add blob")
        os.unlink(os.path.join(d, "blob.dat"))
        git(d, "add", "-A")
        git(d, "commit", "-qm", "rm blob")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("M5 a secret in a file git calls binary is found in history",
           len(gh(fs)) == 1 and end.get("status") == "done" and scope == {"mode": "tool", "history": True},
           (len(fs), scope, end))

    # ---- H1 item 6: gitleaks' own report of what it read is checked (fake gitleaks)
    with tempfile.TemporaryDirectory() as tmp:
        d = fresh(tmp, "count")
        history_secret(d)
        body = snap_tar(d)

        def fake(name, stderr_text):
            p = os.path.join(tmp, name)
            with open(p, "w") as f:
                f.write("#!/bin/sh\n"
                        'for a in "$@"; do case "$prev" in --report-path) printf "[]" > "$a";; esac; prev="$a"; done\n'
                        'case "$1" in version) echo "8.30.1"; exit 0;; esac\n'
                        f"printf '%s\\n' '{stderr_text}' >&2\nexit 0\n")
            os.chmod(p, 0o755)
            return p
        lines, raw, err = run_flat(H("code.secrets", tools={"gitleaks": fake("gl_zero", "INF 0 commits scanned.")}), body, tmp)
        fs, scope, end = summary(lines)
        ok("H1 gitleaks reading fewer commits than the history holds fails the run",
           end.get("status") == "failed", (scope, end))
        lines, raw, err = run_flat(H("code.secrets", tools={"gitleaks": fake("gl_err", "ERR [git] fatal: bad object x")}), body, tmp)
        fs, scope, end = summary(lines)
        ok("H1 a gitleaks ERR line fails the run", end.get("status") == "failed", (scope, end))
        lines, raw, err = run_flat(H("code.secrets", tools={"gitleaks": fake("gl_ok", "INF 2 commits scanned.")}), body, tmp)
        fs, scope, end = summary(lines)
        ok("H1 control: a matching commit count passes", end.get("status") == "done"
           and scope == {"mode": "tool", "history": True}, (scope, end, err[-300:]))
else:
    print("[SKIP] real-gitleaks evasion checks: /tmp/orc-pin/gitleaks missing")

# ---- M1: code.agent change mode can't be blinded by a replace ref (or graft) on `since`
with tempfile.TemporaryDirectory() as tmp:
    for trick in ("none", "replace", "graft"):
        d = os.path.join(tmp, "agent_" + trick)
        os.makedirs(os.path.join(d, "tests"))
        git(d, "init", "-q", "-b", "main")
        write(d, "calc.py", "def add(a, b):\n    return a + b\n")
        write(d, "tests/test_calc.py", "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"
              "    assert add(0, 0) == 0\n")
        git(d, "add", "-A")
        git(d, "commit", "-qm", "base")
        since = git(d, "rev-parse", "HEAD")
        write(d, "calc.py", "def add(a, b):  # noqa\n    pass\n")
        write(d, "tests/test_calc.py", "import pytest\nfrom calc import add\n\n@pytest.mark.skip\ndef test_add():\n    pass\n")
        if trick != "none":
            git(d, "add", "-A")
            git(d, "commit", "-qm", "wip")
            if trick == "replace":
                git(d, "replace", "-f", since, git(d, "rev-parse", "HEAD"))
            else:
                write(d, ".git/info/grafts", f"{git(d, 'rev-parse', 'HEAD')} {since}\n")
        lines, raw, err = run_flat(H("code.agent", since), snap_tar(d), tmp)
        fs, scope, end = summary(lines)
        rules = sorted(f["rule_id"] for f in fs)
        ok(f"M1 code.agent change mode, trick={trick}: all 5 shortcuts reported",
           len(rules) == 5 and scope == {"mode": "change", "history": True} and end.get("status") == "done",
           (rules, scope, end))

ok("M1 code_agent.GIT_ENV disables replace objects", code_agent.GIT_ENV.get("GIT_NO_REPLACE_OBJECTS") == "1")

# ---- H1 on git < 2.40 (GIT_ATTR_SOURCE ignored): strip_attributes alone must un-hide the patch
sys.path.insert(0, os.path.join(HERE, "orchestratia_agent", "scanning"))
import shim  # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    d = fresh(tmp, "oldgit")
    write(d, ".gitattributes", "* -diff\n")
    write(d, "sub/.gitattributes", "* -diff\n")
    git(d, "add", "-A")
    git(d, "commit", "-qm", "attrs")
    write(d, "sub/k.py", "SECRET_MARKER = 1\n")
    git(d, "add", "-A")
    git(d, "commit", "-qm", "k")
    env = dict(GENV, GIT_DIR=os.path.join(d, ".git"), GIT_WORK_TREE=d)
    env.pop("GIT_ATTR_SOURCE", None)
    before = subprocess.run(["git", "-C", d, "log", "-p", "-U0"], capture_output=True, text=True, env=env).stdout
    shim.strip_attributes(d)
    after = subprocess.run(["git", "-C", d, "log", "-p", "-U0"], capture_output=True, text=True, env=env).stdout
    ok("H1 old-git fallback: removing every .gitattributes and the index un-hides the patch",
       "SECRET_MARKER" not in before and "+SECRET_MARKER" in after
       and not os.path.exists(os.path.join(d, "sub", ".gitattributes")),
       ("SECRET_MARKER" in before, "+SECRET_MARKER" in after, os.listdir(d)))


# ---------------------------------------------------------------- round 2: object-store forgeries (N1, N2, N5)
import hashlib  # noqa: E402
import struct  # noqa: E402
import zlib  # noqa: E402


def _cg_load(path):
    b = bytearray(open(path, "rb").read())
    n = b[6]
    ch = [(bytes(b[8 + 12 * i:12 + 12 * i]), struct.unpack(">Q", b[12 + 12 * i:20 + 12 * i])[0]) for i in range(n + 1)]
    tab = {ch[i][0]: (ch[i][1], ch[i + 1][1]) for i in range(n)}
    s0, e0 = tab[b"OIDL"]
    return b, tab, [bytes(b[x:x + 20]).hex() for x in range(s0, e0, 20)]


def _cg_save(path, b):
    b[-20:] = hashlib.sha1(bytes(b[:-20])).digest()
    os.chmod(path, 0o644)
    open(path, "wb").write(bytes(b))


def cg_set_parent(path, commit, parent):
    b, tab, L = _cg_load(path)
    off = tab[b"CDAT"][0] + 36 * L.index(commit)
    b[off + 20:off + 24] = struct.pack(">I", L.index(parent))
    _cg_save(path, b)


def cg_set_tree(path, commit, tree):
    b, tab, L = _cg_load(path)
    off = tab[b"CDAT"][0] + 36 * L.index(commit)
    b[off:off + 20] = bytes.fromhex(tree)
    _cg_save(path, b)


if os.path.exists(GITLEAKS):
    with tempfile.TemporaryDirectory() as tmp:
        d = fresh(tmp, "cg_parent")
        history_secret(d)
        git(d, "commit-graph", "write", "--reachable")
        cg_set_parent(os.path.join(d, ".git/objects/info/commit-graph"), git(d, "rev-parse", "HEAD"), git(d, "rev-parse", "HEAD~2"))
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("N1 a forged commit-graph (parent cut) doesn't hide the history secret", len(gh(fs)) == 1
           and end.get("status") == "done" and scope == {"mode": "tool", "history": True}, (len(fs), scope, end))

        d = fresh(tmp, "cg_tree")
        history_secret(d)
        git(d, "commit-graph", "write", "--reachable")
        cg_set_tree(os.path.join(d, ".git/objects/info/commit-graph"), git(d, "rev-parse", "HEAD~1"),
                    git(d, "rev-parse", "HEAD~2^{tree}"))
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("N1 a forged commit-graph (tree swap) doesn't hide the history secret", len(gh(fs)) == 1
           and end.get("status") == "done", (len(fs), scope, end))

        d = fresh(tmp, "cg_chain")
        history_secret(d)
        git(d, "commit-graph", "write", "--reachable", "--split")
        chd = os.path.join(d, ".git/objects/info/commit-graphs")
        f = [x for x in os.listdir(chd) if x.endswith(".graph")][0]
        cg_set_parent(os.path.join(chd, f), git(d, "rev-parse", "HEAD"), git(d, "rev-parse", "HEAD~2"))
        newsum = open(os.path.join(chd, f), "rb").read()[-20:].hex()
        os.rename(os.path.join(chd, f), os.path.join(chd, f"graph-{newsum}.graph"))
        os.chmod(os.path.join(chd, "commit-graph-chain"), 0o644)
        open(os.path.join(chd, "commit-graph-chain"), "w").write(newsum + "\n")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("N1 a forged split commit-graph chain doesn't hide the history secret", len(gh(fs)) == 1
           and end.get("status") == "done", (len(fs), scope, end))

        d = fresh(tmp, "objswap")
        history_secret(d)
        blob = git(d, "rev-parse", "HEAD~1:config.py")
        pth = os.path.join(d, ".git/objects", blob[:2], blob[2:])
        body = b"print('nothing here')\n"
        os.chmod(pth, 0o644)
        open(pth, "wb").write(zlib.compress(b"blob %d\0" % len(body) + body))
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("N2 an object rewritten under the same id: history can't be trusted → history:false, and the run says why",
           scope == {"mode": "tool", "history": False} and end.get("status") == "done" and end.get("error"),
           (len(fs), scope, end))

        d = fresh(tmp, "unborn")
        history_secret(d)
        os.unlink(os.path.join(d, ".git/refs/heads/main"))
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("N5 an unborn HEAD with commits in the store: no commit read → history:false",
           scope == {"mode": "tool", "history": False}, (len(fs), scope, end))

with tempfile.TemporaryDirectory() as tmp:
    d = os.path.join(tmp, "agent_cg")
    os.makedirs(os.path.join(d, "tests"))
    git(d, "init", "-q", "-b", "main")
    write(d, "calc.py", "def add(a, b):\n    return a + b\n")
    write(d, "tests/test_calc.py", "from calc import add\n\ndef test_add():\n    assert add(1, 2) == 3\n"
          "    assert add(0, 0) == 0\n")
    git(d, "add", "-A")
    git(d, "commit", "-qm", "base")
    since = git(d, "rev-parse", "HEAD")
    write(d, "calc.py", "def add(a, b):  # noqa\n    pass\n")
    write(d, "tests/test_calc.py", "import pytest\nfrom calc import add\n\n@pytest.mark.skip\ndef test_add():\n    pass\n")
    git(d, "add", "-A")
    git(d, "commit", "-qm", "wip")
    git(d, "commit-graph", "write", "--reachable")
    cg_set_tree(os.path.join(d, ".git/objects/info/commit-graph"), since, git(d, "rev-parse", "HEAD^{tree}"))
    lines, raw, err = run_flat(H("code.agent", since), snap_tar(d), tmp)
    fs, scope, end = summary(lines)
    ok("N1 code.agent: a commit-graph tree swap on `since` doesn't hide the 5 shortcuts",
       len(fs) == 5 and scope == {"mode": "change", "history": True}, ([f["rule_id"] for f in fs], scope, end))

# ---------------------------------------------------------------- round 3: type changes, refs to non-commits
if os.path.exists(GITLEAKS):
    with tempfile.TemporaryDirectory() as tmp:
        d = fresh(tmp, "tc_symlink")
        os.symlink("app.py", os.path.join(d, "config.py"))
        git(d, "add", "-A")
        git(d, "commit", "-qm", "link")
        os.unlink(os.path.join(d, "config.py"))
        write(d, "config.py", f'GITHUB_TOKEN = "{TOKEN}"\n')
        git(d, "add", "-A")
        git(d, "commit", "-qm", "typechange")
        os.unlink(os.path.join(d, "config.py"))
        git(d, "add", "-A")
        git(d, "commit", "-qm", "rm")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("R3 a symlink replaced by a file holding a secret (then deleted) is found in history",
           len(gh(fs)) == 1 and end.get("status") == "done" and scope == {"mode": "tool", "history": True},
           (len(fs), scope, end))

        d = fresh(tmp, "tc_gitlink")
        git(d, "update-index", "--add", "--cacheinfo", "160000," + git(d, "rev-parse", "HEAD") + ",vendor/lib")
        git(d, "commit", "-qm", "sub")
        git(d, "rm", "-q", "--cached", "vendor/lib")
        write(d, "vendor/lib", f'GITHUB_TOKEN = "{TOKEN}"\n')
        git(d, "add", "-A")
        git(d, "commit", "-qm", "tc")
        git(d, "rm", "-q", "vendor/lib")
        git(d, "commit", "-qm", "rm")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("R3 a gitlink replaced by a file holding a secret (then deleted) is found in history",
           len(gh(fs)) == 1 and end.get("status") == "done" and scope == {"mode": "tool", "history": True},
           (len(fs), scope, end))

        d = fresh(tmp, "ref_blob")
        blob = subprocess.run(["git", "-C", d, "hash-object", "-w", "--stdin"], input=f'T = "{TOKEN}"\n',
                              capture_output=True, text=True, env=GENV, check=True).stdout.strip()
        git(d, "update-ref", "refs/tags/v0-notes", blob)
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("R3 a ref straight at a blob: history isn't claimed (history:false, with a reason)",
           scope == {"mode": "tool", "history": False} and end.get("error"), (scope, end))

        d = fresh(tmp, "tag_tree")
        blob2 = subprocess.run(["git", "-C", d, "hash-object", "-w", "--stdin"], input=f'T = "{TOKEN}"\n',
                               capture_output=True, text=True, env=GENV, check=True).stdout.strip()
        tree = subprocess.run(["git", "-C", d, "mktree"], input=f"100644 blob {blob2}\tconfig.py\n",
                              capture_output=True, text=True, env=GENV, check=True).stdout.strip()
        git(d, "tag", "-a", "-m", "x", "v1-tree", tree)
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("R3 an annotated tag at a tree: history isn't claimed (history:false, with a reason)",
           scope == {"mode": "tool", "history": False} and end.get("error"), (scope, end))

        d = fresh(tmp, "tag_commit")
        git(d, "tag", "-a", "-m", "release", "v1")
        fs, scope, end = summary(secrets_run(d, tmp)[0])
        ok("R3 control: an annotated tag at a commit keeps history:true", scope == {"mode": "tool", "history": True}
           and not end.get("error"), (scope, end))
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
