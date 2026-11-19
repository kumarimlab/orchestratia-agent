#!/usr/bin/env python3
"""dl-helper snap: what a scan sees of a repo, read as the session user.

Run:  python3 tests/test_scan_snapshot.py
"""
import io
import json
import os
import pwd
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER = os.path.join(HERE, "orchestratia_agent", "dl_helper.py")
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def snap(path, *extra, env=None):
    p = subprocess.run([sys.executable, "-I", HELPER, "snap", *extra, "--", path],
                       capture_output=True, timeout=60, env=env)
    head, _, body = p.stdout.partition(b"\n")
    return p.returncode, json.loads(head or b"{}"), body


def names(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode="r|") as tf:
        return {m.name: m for m in tf}


with tempfile.TemporaryDirectory() as td:
    repo = os.path.join(td, "repo")
    os.makedirs(os.path.join(repo, "src"))
    os.makedirs(os.path.join(repo, ".git"))
    os.makedirs(os.path.join(repo, "node_modules", "x"))
    os.makedirs(os.path.join(repo, ".ssh"))
    os.makedirs(os.path.join(repo, ".config", "orchestratia"))
    os.makedirs(os.path.join(repo, "fixtures"))
    for rel, data in {"src/app.py": "print(1)\n", ".env": "KEY=1\n", ".git/HEAD": "ref\n",
                      "node_modules/x/i.js": "x", ".ssh/id_rsa": "PRIVATE", "requirements.txt": "flask==2\n",
                      ".config/orchestratia/config.yaml": "api_key: orc_x", "fixtures/big.json": "{}",
                      "src/package.json": "{}"}.items():
        with open(os.path.join(repo, rel), "w") as f:
            f.write(data)
    secret = os.path.join(td, "secret.txt")
    with open(secret, "w") as f:
        f.write("TOP SECRET CONTENT")
    os.symlink(secret, os.path.join(repo, "src", "link_out"))
    os.mkfifo(os.path.join(repo, "src", "pipe"))

    rc, head, body = snap(repo)
    got = names(body) if rc == 0 else {}
    ok("snapshot succeeds with a header", rc == 0 and head.get("ok") is True, (rc, head))
    ok("includes source, .env and .git", {"src/app.py", ".env", ".git/HEAD"} <= set(got), sorted(got))
    ok("skips node_modules", not any(n.startswith("node_modules") for n in got))
    ok("never includes .config/orchestratia", not any(n.startswith(".config/orchestratia") for n in got))
    ok("a credential-named dir INSIDE a repo is archived (only home-level ones are excluded)",
       ".ssh/id_rsa" in got, sorted(got))
    link = got.get("src/link_out")
    ok("a symlink is stored as a link, never its target's content",
       link is not None and link.issym() and b"TOP SECRET" not in body, link and link.linkname)
    ok("special files are skipped", "src/pipe" not in got)

    rc, head, body = snap(repo, "--exclude", "fixtures")
    ok("--exclude drops a directory by name", rc == 0 and "fixtures/big.json" not in names(body))

    rc, head, body = snap(repo, "--deps-only")
    ok("--deps-only keeps only manifests and lockfiles",
       rc == 0 and set(names(body)) == {"requirements.txt", "src/package.json"}, sorted(names(body)))

    rc, head, _ = snap("/")
    ok("/ is refused", rc == 2 and head.get("error") == "refused_root", head)
    home = pwd.getpwuid(os.getuid()).pw_dir
    rc, head, _ = snap(home)
    ok("the user's home directory itself is refused", rc == 2 and head.get("error") == "refused_home", head)
    rc, head, _ = snap(os.path.join(td, "missing"))
    ok("a missing directory is not_found", rc == 2 and head.get("error") == "not_found", head)

    many = os.path.join(td, "many")
    os.makedirs(many)
    for i in range(30):
        open(os.path.join(many, f"f{i}"), "w").close()
    env = dict(os.environ, ORC_SNAP_MAX_ENTRIES_FOR_TEST="10")
    p = subprocess.run([sys.executable, HELPER, "snap", "--", many], capture_output=True, timeout=60, env=env)
    ok("exceeding the entry cap exits 3", p.returncode == 3, p.returncode)

    for label, rel in (("a .config/orchestratia dir", "x/.config/orchestratia"),
                       ("a dir inside .config/orchestratia", "y/.config/orchestratia/sub")):
        d = os.path.join(td, "cred", rel)
        os.makedirs(d)
        rc, head, _ = snap(d)
        ok(f"PATH = {label} is refused_cred", rc == 2 and head.get("error") == "refused_cred", head)
    os.makedirs(os.path.join(td, "cred", ".ssh"))
    rc, head, _ = snap(os.path.join(td, "cred", ".ssh"))
    ok("PATH = a .ssh dir that is NOT directly in a home dir is scanned", rc == 0 and head.get("ok") is True, head)

    os.makedirs(os.path.join(repo, "foo.config", "orchestratia"))
    with open(os.path.join(repo, "foo.config", "orchestratia", "k.txt"), "w") as f:
        f.write("x")
    rc, head, body = snap(repo)
    ok("foo.config/orchestratia is not mistaken for a credential dir",
       rc == 0 and "foo.config/orchestratia/k.txt" in names(body))


# ---------------------------------------------------------------- final fix wave
sys.path.insert(0, os.path.dirname(HELPER))
import dl_helper  # noqa: E402


def snap_home(path, homes, *extra):
    """snap with _home_dirs() replaced by `homes` (a fake home directory for the test)."""
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import dl_helper as h; "
            "h._home_dirs = lambda: set(sys.argv[2].split(':')); h.main(sys.argv[3:])")
    p = subprocess.run([sys.executable, "-I", "-c", code, os.path.dirname(HELPER),
                        ":".join(os.path.realpath(h) for h in homes), "snap", *extra, "--", path],
                       capture_output=True, timeout=60)
    head, _, body = p.stdout.partition(b"\n")
    return p.returncode, json.loads(head or b"{}"), body


with tempfile.TemporaryDirectory() as td:
    home = os.path.join(td, "users", "alice")
    proj = os.path.join(home, "proj")
    for rel, data in {".claude/settings.json": '{"hooks": {}}', ".claude/.credentials.json": "HOME-CRED",
                      ".ssh/id_rsa": "HOME-KEY", "proj/app.py": "x", "proj/.claude/settings.json": '{"hooks": {}}',
                      "proj/.claude/.credentials.json": "REPO-CRED", "proj/.credentials.json": "ROOT-CRED",
                      "proj/sub/.netrc": "machine x password NETRC", "proj/.git-credentials": "https://u:GITCRED@h",
                      "proj/.aws/config": "[default]", "proj/a/.config/orchestratia": "FILE-CFG",
                      "proj/b/.config/orchestratia/config.yaml": "api_key: DIR-CFG"}.items():
        os.makedirs(os.path.dirname(os.path.join(home, rel)), exist_ok=True)
        with open(os.path.join(home, rel), "w") as f:
            f.write(data)

    rc, head, body = snap_home(proj, [home])
    got = names(body) if rc == 0 else {}
    ok("repo/.claude/settings.json is archived", rc == 0 and ".claude/settings.json" in got, (rc, head, sorted(got)))
    ok("repo/.aws inside a repo is archived", ".aws/config" in got, sorted(got))
    ok(".credentials.json is never archived (repo root or inside .claude)",
       not any(n.endswith(".credentials.json") for n in got) and b"REPO-CRED" not in body and b"ROOT-CRED" not in body)
    ok(".netrc and .git-credentials files are never archived", b"NETRC" not in body and b"GITCRED" not in body, sorted(got))
    ok(".config/orchestratia is excluded anywhere, file or dir", b"FILE-CFG" not in body and b"DIR-CFG" not in body, sorted(got))

    for label, path in (("~/.claude", os.path.join(home, ".claude")), ("~/.ssh", os.path.join(home, ".ssh")),
                        ("a dir inside ~/.claude", os.path.join(home, ".claude"))):
        rc, head, _ = snap_home(path, [home])
        ok(f"PATH = {label} (directly in a home dir) is refused_cred", rc == 2 and head.get("error") == "refused_cred", head)
    os.makedirs(os.path.join(home, ".claude", "projects"))
    rc, head, _ = snap_home(os.path.join(home, ".claude", "projects"), [home])
    ok("PATH inside ~/.claude/… is refused_cred", rc == 2 and head.get("error") == "refused_cred", head)
    rc, head, _ = snap_home(os.path.join(td, "users"), [home])
    ok("M10 a proper ancestor of a home dir is refused_home", rc == 2 and head.get("error") == "refused_home", head)
    rc, head, _ = snap_home(home, [home])
    ok("the home dir itself is still refused_home", rc == 2 and head.get("error") == "refused_home", head)

    hr = os.path.realpath(home)
    ok("walk predicate: a credential dir sitting directly in a home dir is skipped",
       dl_helper._snap_skip_dir(hr, "", ".claude", set(), {hr}) and dl_helper._snap_skip_dir(hr, "", ".ssh", set(), {hr}))
    ok("walk predicate: the same name inside a repo is kept",
       not dl_helper._snap_skip_dir(os.path.join(hr, "proj"), "", ".claude", set(), {hr}))
    ok("walk predicate: .config/orchestratia skipped anywhere",
       dl_helper._snap_skip_dir("/x", ".config", "orchestratia", set(), {hr}))

real_home = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
if os.path.dirname(real_home) != "/":
    rc, head, _ = snap(os.path.dirname(real_home))
    ok("M10 the parent of a real home dir is refused_home", rc == 2 and head.get("error") == "refused_home", head)

with tempfile.TemporaryDirectory() as td:
    open(os.path.join(td, "f"), "w").close()
    for bad in ("abc", "", "1e9", "-"):
        env = dict(os.environ, ORC_SNAP_MAX_ENTRIES_FOR_TEST=bad)
        p = subprocess.run([sys.executable, HELPER, "snap", "--", td], capture_output=True, timeout=60, env=env)
        ok(f"M4 a non-int ORC_SNAP_MAX_ENTRIES_FOR_TEST={bad!r} is ignored", p.returncode == 0, (p.returncode, p.stderr[-200:]))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
