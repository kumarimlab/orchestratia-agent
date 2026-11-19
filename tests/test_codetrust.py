#!/usr/bin/env python3
"""Root-owned agent code (hardening plan Task 2): ownership checks, the mode normaliser and the root gate.

Dependency-free — run:  python3 tests/test_codetrust.py
"""
import os
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import codetrust  # noqa: E402

results = []
os.umask(0o022)
ME = (0, os.geteuid())          # / and /tmp are root's; the temp tree is ours — production passes (0,)


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def mode(p):
    return stat.S_IMODE(os.lstat(p).st_mode)


def tree():
    base = tempfile.mkdtemp()
    os.chmod(base, 0o755)
    root = os.path.join(base, "venv")
    os.makedirs(os.path.join(root, "lib", "pkg"))
    os.makedirs(os.path.join(root, "bin"))
    with open(os.path.join(root, "lib", "pkg", "mod.py"), "w") as fh:
        fh.write("x = 1\n")
    os.symlink(sys.executable, os.path.join(root, "bin", "python3"))
    return base, root


base, root = tree()
mod = os.path.join(root, "lib", "pkg", "mod.py")
ok("a clean tree has no problem", codetrust.tree_problem(root, ME) is None, codetrust.tree_problem(root, ME))
ok("root-only uids: our own tree is foreign", "owned by uid" in (codetrust.tree_problem(root, (0,)) or ""))
ok("first_foreign names the tree root first", codetrust.first_foreign(root, (0,)) == f"{root} is owned by uid {os.geteuid()}")
ok("first_foreign: none when every entry is trusted", codetrust.first_foreign(root, ME) is None)
os.chmod(mod, 0o664)
ok("a group-writable file is a problem", codetrust.tree_problem(root, ME) == f"{mod} is writable by group or others",
   codetrust.tree_problem(root, ME))
os.chmod(mod, 0o644)
ww = tempfile.mkdtemp()
os.chmod(ww, 0o777)
link = os.path.join(root, "lib", "out")
os.symlink(ww, link)
ok("a link inside the tree to a world-writable dir is a problem",
   (codetrust.tree_problem(root, ME) or "").startswith(f"{link} points at"), codetrust.tree_problem(root, ME))
os.unlink(link)
ok("path_problem refuses a symlink component", "is a symlink" in (codetrust.path_problem(
    os.path.join(root, "bin", "python3", "x"), ME) or ""))
ok("path_problem allows the root-owned sticky /tmp above the tree", codetrust.path_problem(root, ME) is None)

# normalize: modes from a restrictive/loose umask become 0755 / 0644 / 0755(exec); links untouched
outside = os.path.join(base, "outside.txt")
open(outside, "w").close()
os.chmod(outside, 0o600)
os.symlink(outside, os.path.join(root, "lib", "to-outside"))
exe = os.path.join(root, "bin", "tool")
open(exe, "w").close()
os.chmod(exe, 0o700)
os.chmod(mod, 0o600)
os.chmod(os.path.join(root, "lib"), 0o775)
os.chmod(os.path.join(root, "lib", "pkg"), 0o700)
n = codetrust.normalize(root, ME)
ok("normalize: dirs 0755", mode(os.path.join(root, "lib")) == 0o755 and mode(os.path.join(root, "lib", "pkg")) == 0o755)
ok("normalize: plain files 0644, executables 0755", mode(mod) == 0o644 and mode(exe) == 0o755, (oct(mode(mod)), oct(mode(exe))))
ok("normalize: a link's target is never touched", mode(outside) == 0o600)
ok("normalize counts every entry", n >= 7, n)
ok("after normalize the tree is clean", codetrust.tree_problem(root, ME) is None, codetrust.tree_problem(root, ME))

os.chmod(mod, 0o600)
hard = os.path.join(root, "lib", "hard")
os.link(mod, hard)
try:
    codetrust.normalize(root, ME)
    res = "normalized"
except codetrust.CodeTrustError as e:
    res = str(e)
ok("normalize refuses a hard-linked file", "hard links" in res, res)
ok("…and changes nothing (checks every entry before the first chmod)", mode(mod) == 0o600)
os.unlink(hard)
fifo = os.path.join(root, "lib", "fifo")
os.mkfifo(fifo)
try:
    codetrust.normalize(root, ME)
    res = "normalized"
except codetrust.CodeTrustError as e:
    res = str(e)
ok("normalize refuses a fifo", "not a file, directory or symlink" in res, res)
os.unlink(fifo)
try:
    codetrust.normalize(root, (0,))
    res = "normalized"
except codetrust.CodeTrustError as e:
    res = str(e)
ok("normalize refuses a tree that isn't wholly trusted, before any chmod", "owned by uid" in res and mode(mod) == 0o600, res)

# code_roots / install_problem / require_trusted
assets = os.path.join(base, "assets")
os.mkdir(assets)
ok("code_roots in a venv: the venv prefix and the asset tree",
   codetrust.code_roots(pkg_dir="/p", prefix="/v", base_prefix="/usr", assets=assets) == ["/v", assets])
ok("code_roots outside a venv: the package dir",
   codetrust.code_roots(pkg_dir="/p", prefix="/usr", base_prefix="/usr", assets=os.path.join(base, "nope")) == ["/p"])
codetrust.normalize(root, ME)
ok("install_problem: none for trusted roots", codetrust.install_problem([root, assets], ME) is None)
ok("require_trusted is a no-op for a non-root caller",
   codetrust.require_trusted("x", roots=[root], uids=(0,), euid=lambda: 1000) is None)
try:
    codetrust.require_trusted("install the scanner pack", roots=[root], uids=(0,), euid=lambda: 0)
    res = "passed"
except codetrust.CodeTrustError as e:
    res = str(e)
ok("require_trusted as root refuses code it doesn't own, says what to run",
   res.startswith("refusing to install the scanner pack: ") and codetrust.FIX_HINT in res, res)
ok("require_trusted as root passes a trusted tree",
   codetrust.require_trusted("x", roots=[root], uids=ME, euid=lambda: 0) is None)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
