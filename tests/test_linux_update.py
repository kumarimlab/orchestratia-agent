#!/usr/bin/env python3
"""`sudo orchestratia update` on Linux (hardening plan Task 2): root only; a fresh clone, never git or pip inside an
existing tree; an untrusted venv is rebuilt, a trusted one upgraded; every root subprocess isolated. Plus the CLI
wiring and `secure-install`'s tree step.

Dependency-free — run:  python3 tests/test_linux_update.py
"""
import contextlib
import io
import os
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import cli, codetrust, linux_update, secure_install  # noqa: E402

results = []
os.umask(0o022)
ME = (0, os.geteuid())


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class FakeRun:
    """Stands in for subprocess.run: records (argv, kwargs) and plays git / venv / pip."""

    def __init__(self, fail=()):
        self.calls, self.fail = [], fail

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append((argv, kw))

        def res(rc=0, out="", err=""):
            return subprocess.CompletedProcess(argv, rc, out, err)
        for f in self.fail:
            if f in argv:
                return res(1, "", f"{f} broke")
        if argv[0] == "git" and "clone" in argv:
            dest = argv[-1]
            os.makedirs(os.path.join(dest, ".git"), exist_ok=True)
            os.makedirs(os.path.join(dest, "orchestratia_agent"), exist_ok=True)
            with open(os.path.join(dest, "orchestratia_agent", "__init__.py"), "w") as fh:
                fh.write('__version__ = "9.9.9"\n')
            with open(os.path.join(dest, "NEW"), "w") as fh:
                fh.write("new\n")
            return res()
        if argv[0] == "git" and "rev-parse" in argv:
            return res(0, "abc1234\n")
        if argv[1:4] == ["-I", "-m", "venv"]:
            venv = argv[4]
            os.makedirs(os.path.join(venv, "bin"))
            os.makedirs(os.path.join(venv, "lib"))
            os.symlink(sys.executable, os.path.join(venv, "bin", "python3"))
            return res()
        if "pip" in argv:
            p = os.path.join(os.path.dirname(os.path.dirname(argv[0])), "lib", "installed.txt")
            with open(p, "w") as fh:
                fh.write("pip\n")
            os.chmod(p, 0o600)                      # a root umask of 077; update must normalise it
            return res()
        return res(1, "", "unexpected command")


def layout():
    opt = tempfile.mkdtemp()
    os.chmod(opt, 0o755)
    venv = os.path.join(opt, "orchestratia-venv")
    os.makedirs(os.path.join(venv, "bin"))
    os.makedirs(os.path.join(venv, "lib"))
    os.symlink(sys.executable, os.path.join(venv, "bin", "python3"))
    assets = os.path.join(opt, "orchestratia-agent")
    os.makedirs(os.path.join(assets, ".git"))
    with open(os.path.join(assets, "OLD"), "w") as fh:
        fh.write("old\n")
    return codetrust.Layout(venv=venv, assets=assets, opt=opt, system_python=sys.executable)


def leftovers(L):
    return [n for n in os.listdir(L.opt) if ".new-" in n or ".old-" in n]


def attempt(**kw):
    try:
        return linux_update.update(**kw), None
    except linux_update.UpdateError as e:
        return None, str(e)


# ── refusals: nothing runs ──
L, fr = layout(), FakeRun()
_, err = attempt(layout=L, run=fr, euid=lambda: 1000, uids=ME)
ok("not root -> refused, says sudo", err is not None and "sudo orchestratia update" in err and fr.calls == [], err)
for bad in ("--upload-pack=touch /tmp/x", "main;rm -rf /", "", "-x"):
    _, err = attempt(branch=bad, layout=L, run=fr, euid=lambda: 0, uids=ME)
    ok(f"branch {bad!r} refused", err is not None and fr.calls == [], err)
for src in ("http://github.com/x.git", "relative/repo", "/tmp", "ssh://git@github.com/x.git"):
    _, err = attempt(source=src, layout=L, run=fr, euid=lambda: 0, uids=ME)
    ok(f"source {src!r} refused", err is not None and fr.calls == [], err)

# ── a trusted venv: upgraded in place; isolated root subprocesses ──
saved_env = dict(os.environ)
for k in linux_update._PROXY:
    os.environ.pop(k, None)
os.environ.update({"PYTHONPATH": "/home/attacker", "PIP_INDEX_URL": "https://evil", "GIT_DIR": "/home/attacker/.git",
                   "HOME": "/home/attacker", "https_proxy": "http://proxy:3128"})
try:
    L, fr = layout(), FakeRun()
    info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
finally:
    os.environ.clear()
    os.environ.update(saved_env)
ok("trusted venv -> upgraded", err is None and info["venv"] == "upgraded" and info["new"] == "9.9.9"
   and info["commit"] == "abc1234", (info, err))
argvs = [a for a, _ in fr.calls]
clone = argvs[0]
ok("fresh shallow clone of GitHub main, no hooks, no tags",
   clone[:-1] == ["git", "-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--depth", "1", "--no-tags",
                  "--branch", "main", codetrust.REPO_URL]
   and os.path.basename(clone[-1]).startswith(".orchestratia-agent.new-"), clone)
ok("pip: the venv's python, isolated, no cache, from the fresh clone",
   argvs[2] == [os.path.join(L.venv, "bin", "python3"), "-I", "-m", "pip", "install", "--quiet", "--no-cache-dir",
                "--upgrade", clone[-1]], argvs[2])
ok("git never runs inside the existing asset tree", not any("-C" in a and L.assets in a for a in argvs), argvs)
envs = [kw.get("env") for _, kw in fr.calls]
ok("every root subprocess: cwd / and a clean env (PATH, HOME=/root, LANG, proxy only)",
   all(kw.get("cwd") == "/" for _, kw in fr.calls)
   and all(e == {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                 "https_proxy": "http://proxy:3128"} for e in envs), envs[0])
ok("asset tree swapped whole", os.path.exists(os.path.join(L.assets, "NEW"))
   and not os.path.exists(os.path.join(L.assets, "OLD")))
ok("no .new-/.old- dirs left", leftovers(L) == [], leftovers(L))
ok("a file pip wrote 0600 is normalised to 0644",
   stat.S_IMODE(os.lstat(os.path.join(L.venv, "lib", "installed.txt")).st_mode) == 0o644)
ok("both trees are clean afterwards", codetrust.tree_problem(L.venv, ME) is None
   and codetrust.tree_problem(L.assets, ME) is None)

# ── a local source: must be root-owned (here: ours), cloned over file:// ──
L, fr = layout(), FakeRun()
repo = tempfile.mkdtemp()
os.chmod(repo, 0o755)
info, err = attempt(source=repo, branch="rc", layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("a trusted local repo is cloned over file://", err is None and fr.calls[0][0][-2] == "file://" + repo
   and "rc" in fr.calls[0][0], (err, fr.calls[:1]))

# ── an untrusted venv (migration): rebuilt from scratch; anything planted is gone ──
L, fr = layout(), FakeRun()
planted = os.path.join(L.venv, "lib", "zz-planted.pth")
with open(planted, "w") as fh:
    fh.write("import os\n")
os.chmod(planted, 0o664)                          # group-writable -> untrusted
info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
argvs = [a for a, _ in fr.calls]
ok("untrusted venv -> rebuilt", err is None and info["venv"] == "rebuilt", (info, err))
ok("…with the system python, isolated", [sys.executable, "-I", "-m", "venv", L.venv] in argvs, argvs)
ok("…bootstrapping pip without a cache", any(a[1:] == ["-I", "-m", "pip", "install", "--quiet", "--no-cache-dir",
                                                    "--upgrade", "pip", "setuptools", "wheel"] for a in argvs), argvs)
ok("…and the planted .pth is gone", not os.path.exists(planted))
ok("…no old venv left", leftovers(L) == [], leftovers(L))

# ── venv creation fails: the old venv comes back exactly, the asset tree is untouched ──
L, fr = layout(), FakeRun(fail=("venv",))
marker = os.path.join(L.venv, "lib", "marker")
with open(marker, "w") as fh:
    fh.write("m\n")
os.chmod(marker, 0o666)
info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("venv creation fails -> error naming it", err is not None and "venv" in err, err)
ok("…old venv restored as it was", os.path.exists(marker) and stat.S_IMODE(os.lstat(marker).st_mode) == 0o666)
ok("…asset tree untouched", os.path.exists(os.path.join(L.assets, "OLD")))
ok("…no leftovers", leftovers(L) == [], leftovers(L))

# ── clone fails: nothing changes ──
L, fr = layout(), FakeRun(fail=("clone",))
info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("clone fails -> error, nothing changed", err is not None and os.path.exists(os.path.join(L.assets, "OLD"))
   and leftovers(L) == [], (err, leftovers(L)))

# ── a local source with a group-writable file inside: refused (git reads the whole repo as root) ──
L, fr = layout(), FakeRun()
repo = tempfile.mkdtemp()
os.chmod(repo, 0o755)
with open(os.path.join(repo, "config"), "w") as fh:
    fh.write("[core]\n")
os.chmod(os.path.join(repo, "config"), 0o666)
_, err = attempt(source=repo, layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("a local repo with a writable file inside is refused, nothing runs",
   err is not None and "writable by group or others" in err and fr.calls == [], err)

# ── a subprocess that can't start or times out is an UpdateError, and nothing changes ──
L = layout()


def timing_out(argv, **kw):
    raise subprocess.TimeoutExpired(argv, 900)


_, err = attempt(layout=L, run=timing_out, euid=lambda: 0, uids=ME)
ok("a timeout is an UpdateError naming the step; nothing changed",
   err is not None and "clone" in err and os.path.exists(os.path.join(L.assets, "OLD")) and leftovers(L) == [], err)

# ── the asset swap fails: the old asset tree comes back ──
L, fr = layout(), FakeRun()
real_rename = os.rename


def flaky_rename(src, dst, *a, **k):
    if ".orchestratia-agent.new-" in os.path.basename(str(src)) and dst == L.assets:
        raise OSError(28, "No space left on device")
    return real_rename(src, dst, *a, **k)


os.rename = flaky_rename
try:
    _, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
except OSError as e:
    err = f"OSError: {e}"
finally:
    os.rename = real_rename
ok("asset swap fails -> the old asset tree is back, no leftovers",
   err is not None and os.path.exists(os.path.join(L.assets, "OLD")) and leftovers(L) == [], (err, leftovers(L)))

# ── CLI wiring ──
calls = []


def fake_update(**kw):
    calls.append(kw)
    return {"old": "0.34.0", "new": "9.9.9", "commit": "abc1234", "venv": "upgraded"}


buf = io.StringIO()
with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
    try:
        cli._agent_update_linux(SimpleNamespace(source=None, branch=None), update=fake_update, euid=lambda: 1000)
        code = 0
    except SystemExit as e:
        code = e.code
ok("CLI: not root -> exit 1 with the sudo command, nothing updated",
   code == 1 and "sudo orchestratia update" in buf.getvalue() and calls == [], buf.getvalue())
saved = (cli._service_user, cli._after_update_refresh)
cli._service_user = lambda *a, **k: "svc"
cli._after_update_refresh = lambda *a, **k: "skip"
fr = FakeRun()
fr_calls = []
try:
    with contextlib.redirect_stdout(io.StringIO()):
        cli._agent_update_linux(SimpleNamespace(source=None, branch=None), update=fake_update, euid=lambda: 0,
                                run=lambda argv, **kw: fr_calls.append((argv, kw))
                                or subprocess.CompletedProcess(argv, 0, "ok", ""))
finally:
    cli._service_user, cli._after_update_refresh = saved
ok("CLI: root -> update from GitHub main", calls == [{"source": codetrust.REPO_URL, "branch": "main"}], calls)
ok("CLI: then the NEW entry point's secure-install for the unit's user, from /",
   len(fr_calls) == 1 and fr_calls[0][0][1:] == ["secure-install", "--daemon-user", "svc"]
   and fr_calls[0][1].get("cwd") == "/", fr_calls)

# ── secure-install: the tree step ──
try:
    secure_install.run("svc", euid=lambda: 1000, steps=[secure_install.secure_trees])
    res = "ran"
except secure_install.SecureInstallError as e:
    res = str(e)
ok("secure-install: not root -> refused", "as root" in res, res)
L = layout()
loose = os.path.join(L.assets, "OLD")
os.chmod(loose, 0o600)
out = secure_install.run("svc", layout=L, euid=lambda: 0, uids=ME, steps=[secure_install.secure_trees])
ok("secure-install: trusted trees normalised", stat.S_IMODE(os.lstat(loose).st_mode) == 0o644 and "root-owned" in out[0], out)
try:
    secure_install.run("svc", layout=L, euid=lambda: 0, uids=(0,), steps=[secure_install.secure_trees])
    res = "ran"
except secure_install.SecureInstallError as e:
    res = str(e)
ok("secure-install: a foreign-owned tree is refused (never blessed), says what to run",
   "owned by uid" in res and codetrust.FIX_HINT in res, res)

# ══ fix round 1 ══

# ── the entry point root runs is always the venv's, never whatever PATH finds (a legacy ~/.local symlink) ──
VENV_BIN = os.path.join(codetrust.VENV_DIR, "bin", "orchestratia-agent")
ok("_agent_bin is the venv's entry point even when sys.executable isn't the venv's",
   cli._agent_bin() == VENV_BIN, cli._agent_bin())
ok("…so update's secure-install runs the venv's entry point", fr_calls and fr_calls[0][0][0] == VENV_BIN, fr_calls)

# ── a local source: no alternates, no gitfile, no symlinks (root's git would read or follow them) ──


def local_repo(kind):
    r = tempfile.mkdtemp()
    os.chmod(r, 0o755)
    os.makedirs(os.path.join(r, "objects", "info"))
    with open(os.path.join(r, "HEAD"), "w") as fh:
        fh.write("ref: refs/heads/rc\n")
    if kind == "alternates":
        with open(os.path.join(r, "objects", "info", "alternates"), "w") as fh:
            fh.write("/home/attacker/objects\n")
    elif kind == "gitfile":
        with open(os.path.join(r, ".git"), "w") as fh:
            fh.write("gitdir: /home/attacker/repo.git\n")
    elif kind == "symlink":
        os.symlink("/usr", os.path.join(r, "objects", "pack"))
    elif kind == "commondir":
        with open(os.path.join(r, "commondir"), "w") as fh:
            fh.write("/home/attacker/repo.git\n")
    return r


for kind, why in (("alternates", "alternates"), ("gitfile", ".git"), ("symlink", "symlink"),
                  ("commondir", "commondir")):
    L, fr = layout(), FakeRun()
    _, err = attempt(source=local_repo(kind), branch="rc", layout=L, run=fr, euid=lambda: 0, uids=ME)
    ok(f"a local source with {kind} is refused before git runs", err is not None and why in err and fr.calls == [],
       err)
L, fr = layout(), FakeRun()
_, err = attempt(source=local_repo("plain"), branch="rc", layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("a plain bare-shaped local repo is still accepted", err is None, err)

# ── an update that died between moving the venv aside and rebuilding it ──
L, fr = layout(), FakeRun(fail=("venv",))
stale = f"{L.venv}.old-1700000000"
os.rename(L.venv, stale)
marker = os.path.join(stale, "lib", "marker")
with open(marker, "w") as fh:
    fh.write("m\n")
os.chmod(marker, 0o666)                           # untrusted -> update rebuilds, which fails here
_, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("venv missing + venv.old-*: update restores it first, so a failed rebuild still leaves the old venv",
   err is not None and os.path.exists(os.path.join(L.venv, "lib", "marker")) and leftovers(L) == [],
   (err, leftovers(L)))
L, fr = layout(), FakeRun()
stale = f"{L.venv}.old-1700000000"
os.rename(L.venv, stale)
info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("venv missing + venv.old-*: restored and updated, nothing left over",
   err is None and os.path.isdir(L.venv) and leftovers(L) == [], (info, err, leftovers(L)))
L, fr = layout(), FakeRun()
os.makedirs(os.path.join(f"{L.venv}.old-1700000000", "lib"))
info, err = attempt(layout=L, run=fr, euid=lambda: 0, uids=ME)
ok("venv present + a stale venv.old-*: the venv may be half-built, so it is rebuilt; the stale copy goes",
   err is None and info["venv"] == "rebuilt" and leftovers(L) == [], (info, err, leftovers(L)))

L = layout()
stale = f"{L.venv}.old-1700000000"
os.rename(L.venv, stale)
try:
    secure_install.run("svc", layout=L, euid=lambda: 0, uids=ME, steps=[secure_install.secure_trees])
    res = "ran"
except secure_install.SecureInstallError as e:
    res = str(e)
ok("secure-install: venv missing + venv.old-* -> refused with the exact recovery command",
   f"sudo mv {stale} {L.venv}" in res, res)

# ── secure-install rewrites the /usr/local/bin wrappers when they aren't root's and pointing at the venv ──


def wrapper_layout():
    L = layout()
    bindir = os.path.join(L.opt, "bin")
    os.mkdir(bindir)
    os.chmod(bindir, 0o755)
    return codetrust.Layout(venv=L.venv, assets=L.assets, opt=L.opt, system_python=L.system_python, bindir=bindir)


def want(L, name):
    return f'#!/bin/sh\nexec "{L.venv}/bin/{name}" "$@"\n'


L = wrapper_layout()
home_local = os.path.join(tempfile.mkdtemp(), "orchestratia-agent")
with open(home_local, "w") as fh:
    fh.write("#!/bin/sh\necho daemon-writable\n")
os.symlink(home_local, os.path.join(L.bindir, "orchestratia-agent"))         # legacy: a link into ~/.local
with open(os.path.join(L.bindir, "orchestratia"), "w") as fh:
    fh.write("#!/bin/sh\nexec /home/u/.local/bin/orchestratia \"$@\"\n")
os.chmod(os.path.join(L.bindir, "orchestratia"), 0o775)
out = secure_install.secure_wrappers("svc", SimpleNamespace(layout=L, uids=ME, elevated=None))
good = True
for name in ("orchestratia-agent", "orchestratia"):
    p = os.path.join(L.bindir, name)
    st = os.lstat(p)
    good = good and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o755 and open(p).read() == want(L, name)
ok("wrappers: a symlink into ~/.local and a foreign wrapper are rewritten as 0755 files exec'ing the venv", good, out)
ok("…the symlink's old target is untouched", open(home_local).read() == "#!/bin/sh\necho daemon-writable\n")
ok("…and it says so", "rewrote" in out, out)
ok("wrappers: a second run changes nothing",
   "rewrote" not in secure_install.secure_wrappers("svc", SimpleNamespace(layout=L, uids=ME, elevated=None)))
os.chmod(L.bindir, 0o775)
try:
    secure_install.secure_wrappers("svc", SimpleNamespace(layout=L, uids=ME, elevated=None))
    res = "ran"
except secure_install.SecureInstallError as e:
    res = str(e)
ok("wrappers: a bin dir others can write is refused", "writable by group or others" in res, res)
ok("wrappers are a default secure-install step", secure_install.secure_wrappers in secure_install.DEFAULT_STEPS)

# ══ Task 4 fold-in: a failed secure-install is never reported as a green "Update complete." ══
saved = (cli._service_user, cli._after_update_refresh)
cli._service_user = lambda *a, **k: "svc"
cli._after_update_refresh = lambda *a, **k: "skip"
buf = io.StringIO()
try:
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            cli._agent_update_linux(
                SimpleNamespace(source=None, branch=None), update=fake_update, euid=lambda: 0,
                run=lambda argv, **kw: subprocess.CompletedProcess(
                    argv, 1, "root-owned: /opt/orchestratia-venv\naccess-grant helper installed; elevated grants: deny\n",
                    "secure-install: scanner pack: boom\n"))
            code = 0
        except SystemExit as e:
            code = e.code
finally:
    cli._service_user, cli._after_update_refresh = saved
out = buf.getvalue()
ok("CLI: secure-install failed -> exit 1 and no 'Update complete.'", code == 1 and "Update complete." not in out, out)
ok("…an honest failure line that says what to do", "secure-install failed" in out and "sudo orchestratia update" in out,
   out)
ok("…and the steps that did run are shown with the failure", "root-owned: /opt/orchestratia-venv" in out
   and "access-grant helper installed" in out and "boom" in out, out)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
