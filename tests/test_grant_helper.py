#!/usr/bin/env python3
"""The root-owned access-grant helper (hardening plan Task 4) — run unprivileged against a temp home, with the root
checks injected. Plus its installer.

Dependency-free — run:  python3 tests/test_grant_helper.py
"""
import base64
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import grant_helper as gh, grant_install as gi  # noqa: E402

results = []
os.umask(0o022)
G1 = "a1111111-2222-3333-4444-55555555555c"     # hex letters, so G1.upper() is a different (refused) id
G2 = "a1111111-2222-3333-4444-66666666666d"


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def key(kt="ssh-ed25519", body=b"\x01" * 32, declared=None):
    blob = len(kt.encode()).to_bytes(4, "big") + kt.encode() + len(body).to_bytes(4, "big") + body
    return f"{declared or kt} {base64.b64encode(blob).decode()}"


K1, K2 = key(), key(body=b"\x02" * 32)

# ── parse_key ──
ok("a key with a comment -> type + base64 only", gh.parse_key(K1 + " user@host\n") == K1)
for name, bad in (("an options prefix", 'command="sh" ' + K1), ("two lines", K1 + "\n" + K2),
                  ("an unknown type", key(kt="ssh-dss")), ("a type mismatch", key(declared="ssh-rsa")),
                  ("bad base64", "ssh-ed25519 AAAA!!!!"), ("a CR", K1 + "\r"), ("a NUL", K1 + "\0"),
                  ("oversize", "ssh-ed25519 " + "A" * 20000), ("empty", "")):
    try:
        gh.parse_key(bad)
        res = "accepted"
    except ValueError:
        res = "refused"
    ok(f"parse_key refuses {name}", res == "refused")

# ── main, against a temp home ──
base = tempfile.mkdtemp()
os.chmod(base, 0o755)
home = os.path.join(base, "orchestratia")
etc = os.path.join(base, "etc")
os.makedirs(os.path.join(etc, "sudoers.d"))
users = {"exists": False}
ran = []


def getpw():
    if not users["exists"]:
        raise KeyError("orchestratia")
    return SimpleNamespace(pw_dir=home, pw_uid=os.getuid(), pw_gid=os.getgid())


def fake_run(argv, **kw):
    ran.append(argv)
    if argv[0] == gh.USERADD:
        os.makedirs(home, exist_ok=True)
        os.chmod(home, 0o755)
        users["exists"] = True
    return subprocess.CompletedProcess(argv, 0 if "bad" not in str(argv) else 1, "", "")


ctx = gh.Ctx(home=home, sudoers=os.path.join(etc, "sudoers.d", "orchestratia"),
             policy=os.path.join(etc, "orchestratia-grants.conf"), trusted_uids=(os.getuid(),), getpw=getpw, run=fake_run)


def call(argv, stdin="", **kw):
    out, err = io.StringIO(), io.StringIO()
    rc = gh.main(argv, stdin=io.StringIO(stdin), out=out, err=err, euid=kw.get("euid", lambda: 0), ctx=ctx,
                 integrity=kw.get("integrity", lambda: None))
    return rc, out.getvalue().strip(), err.getvalue().strip()


ak = os.path.join(home, ".ssh", "authorized_keys")
ok("not root -> 64", call(["status"], euid=lambda: 1000)[0] == 64)
ok("integrity problem -> 77", call(["status"], integrity=lambda: "x is not root-owned")[0] == 77)
for argv in (["add-key", "../../etc/x"], ["add-key", G1.upper()], ["add-key", G1, "extra"], ["remove-key"],
             ["chown", G1], [], ["set-elevated", "now"]):
    ok(f"argv {argv} -> 64", call(argv, K1)[0] == 64)
ok("a bad key -> 64, nothing created", call(["add-key", G1], 'command="sh" ' + K1)[0] == 64 and not os.path.exists(home))
rc, out, _ = call(["add-key", G1], K1 + " comment\n")
ok("add-key creates the user (useradd, fixed argv) and adds the key", rc == 0 and out == "added"
   and ran[0] == [gh.USERADD, "--system", "--create-home", "--home-dir", home, "--shell", "/bin/bash", gh.USER], (rc, out, ran))
ok("….ssh 0700, authorized_keys 0600, the tagged line", stat.S_IMODE(os.stat(os.path.dirname(ak)).st_mode) == 0o700
   and stat.S_IMODE(os.stat(ak).st_mode) == 0o600 and open(ak).read() == f"{K1} {gh.TAG}{G1}\n", open(ak).read())
with open(ak, "a") as fh:
    fh.write("ssh-ed25519 AAAAmanual admin@laptop\n")
ino = os.stat(ak).st_ino
ok("the same key again -> unchanged, file untouched", call(["add-key", G1], K1)[1] == "unchanged" and os.stat(ak).st_ino == ino)
ok("a new key for the grant -> replaced", call(["add-key", G1], K2)[1] == "replaced")
call(["add-key", G2], K1)
text = open(ak).read()
ok("…one line per grant, the manual key kept", text.count(gh.TAG + G1) == 1 and f"{K2} {gh.TAG}{G1}" in text
   and "admin@laptop" in text, text)
rc, out, _ = call(["status"])
st = json.loads(out)
ok("status: user, keys by grant id, elevated flags", rc == 0 and st == {"user": True, "keys": {G1: K2, G2: K1},
   "elevated": False, "elevated_allowed": False}, st)
ok("remove-key drops only that grant", call(["remove-key", G1])[1] == "removed" and gh.TAG + G1 not in open(ak).read()
   and gh.TAG + G2 in open(ak).read())
ok("remove-key again -> absent", call(["remove-key", G1])[1] == "absent")

# a link or a hard link where authorized_keys should be: refused, the target untouched
victim = os.path.join(base, "victim")
with open(victim, "w") as fh:
    fh.write("root:secret\n")
os.unlink(ak)
os.symlink(victim, ak)
ok("authorized_keys is a symlink -> 77", call(["add-key", G1], K1)[0] == 77 and open(victim).read() == "root:secret\n")
os.unlink(ak)
os.link(victim, ak)
ok("authorized_keys is a hard link -> 77", call(["add-key", G1], K1)[0] == 77 and open(victim).read() == "root:secret\n")
os.unlink(ak)
sshd = os.path.dirname(ak)
os.rmdir(sshd)
os.symlink(base, sshd)
ok(".ssh is a symlink -> 77", call(["add-key", G1], K1)[0] == 77 and not os.path.exists(os.path.join(base, "authorized_keys")))
os.unlink(sshd)

# elevated: only with the policy, only the fixed rule, visudo-checked
ok("set-elevated without a policy -> 3, no file", call(["set-elevated"])[0] == 3 and not os.path.exists(ctx.sudoers))
with open(ctx.policy, "w") as fh:
    fh.write("elevated=deny\n")
ok("set-elevated with elevated=deny -> 3", call(["set-elevated"])[0] == 3)
with open(ctx.policy, "w") as fh:
    fh.write("elevated=allow\n")
os.chmod(ctx.policy, 0o666)
ok("a policy file others can write counts as no policy -> 3", call(["set-elevated"])[0] == 3)
os.chmod(ctx.policy, 0o644)
ran.clear()
rc, out, _ = call(["set-elevated"])
ok("set-elevated with elevated=allow -> the fixed rule, 0440, visudo -cf on a dot-named temp file",
   rc == 0 and out == "set" and open(ctx.sudoers).read() == gh.SUDOERS_RULE
   and stat.S_IMODE(os.stat(ctx.sudoers).st_mode) == 0o440
   and ran and ran[-1][:2] == [gh.VISUDO, "-cf"] and os.path.basename(ran[-1][2]).startswith("."), (rc, out, ran))
ran.clear()
ok("set-elevated again -> unchanged, no visudo", call(["set-elevated"])[1] == "unchanged" and ran == [])
ok("clear-elevated -> cleared, then absent", call(["clear-elevated"])[1] == "cleared" and call(["clear-elevated"])[1] == "absent")
ok("status reports the policy", json.loads(call(["status"])[1])["elevated_allowed"] is True)

# ── installer ──
lib = os.path.join(base, "libexec", "orchestratia")
os.makedirs(lib)
target, rule = os.path.join(lib, "grant-helper"), os.path.join(etc, "sudoers.d", "orchestratia-grant")
checked = []
gi.install_grant_helper("svc", python=sys.executable, target=target, sudoers=rule, require_root=False,
                        visudo=lambda p: checked.append(p) or True, check=lambda action: None)
ok("helper installed 0755 with an isolated, site-free shebang", stat.S_IMODE(os.stat(target).st_mode) == 0o755
   and open(target).readline() == f"#!{sys.executable} -IS\n")
r = subprocess.run([target, "status"], capture_output=True, text=True, cwd="/")
ok("the installed file runs on its own (stdlib only) and refuses a non-root caller", r.returncode == 64
   and "runs as root" in r.stderr, (r.returncode, r.stderr))
ok("its rule: one user, one command, env_reset, 0440, validated first",
   open(rule).read().splitlines()[2:4] == [f"Defaults!{target} env_reset, !use_pty", f"svc ALL=(root) NOPASSWD: {target}"]
   and stat.S_IMODE(os.stat(rule).st_mode) == 0o440 and len(checked) == 1, open(rule).read())
try:
    gi.install_grant_helper("svc", python=sys.executable, target=target, sudoers=rule, require_root=False,
                            visudo=lambda p: False, check=lambda action: None)
    res = "installed"
except gi.GrantInstallError as e:
    res = str(e)
ok("visudo refuses -> no new rule", "invalid sudoers" in res, res)
try:
    gi.install_grant_helper("bad user;", python=sys.executable, target=target, sudoers=rule, require_root=False,
                            visudo=lambda p: True, check=lambda action: None)
    res = "installed"
except gi.GrantInstallError as e:
    res = str(e)
ok("an invalid daemon user is refused", "invalid daemon user" in res, res)
legacy = os.path.join(etc, "sudoers.d", "orchestratia-agent")
open(legacy, "w").close()
ok("the legacy broad rules are removed", gi.remove_legacy_sudoers(legacy) is True and not os.path.exists(legacy))
ok("…and removing them twice is fine", gi.remove_legacy_sudoers(legacy) is False)
pol, elev = os.path.join(etc, "pol.conf"), os.path.join(etc, "elev")
# fix round 2 (user decision, Option A): no file -> deny; an existing file is never changed; only flags change it
ok("policy: a flag wins", gi.decide_policy("allow", policy=pol) == "allow" and gi.decide_policy("deny", policy=pol) == "deny")
ok("policy: no flag, no policy file -> deny (also where an elevated grant is live)", gi.decide_policy(None, policy=pol) == "deny")
open(pol, "w").close()
ok("policy: no flag, a policy file exists -> None: it is never changed automatically", gi.decide_policy(None, policy=pol) is None)
os.unlink(pol)
ok("the hub is never asked: hub_elevated_live and _hub_base are gone",
   not hasattr(gi, "hub_elevated_live") and not hasattr(gi, "_hub_base"))
open(elev, "w").close()
gi.write_policy("deny", policy=pol, elevated=elev)
ok("write_policy deny: the file says so (0644) and the elevated rule goes", "elevated=deny" in open(pol).read()
   and stat.S_IMODE(os.stat(pol).st_mode) == 0o644 and not os.path.exists(elev))


# ══ beyond the brief: the installer's own gate, secure-install wiring (ruling H2), the CLI flags ══
from orchestratia_agent import codetrust, secure_install as si  # noqa: E402

# the helper is copied from the agent package: as root the gate also checks that source dir (an editable install's
# package lives outside the venv, so the venv check alone wouldn't cover it)
got = []


def record(action, **kw):
    got.append((action, kw.get("roots")))
    raise codetrust.CodeTrustError(f"refusing to {action}: test")


real_gate = codetrust.require_trusted
codetrust.require_trusted = record
try:
    try:
        gi.install_grant_helper("svc", python=sys.executable, target=os.path.join(lib, "gh2"), sudoers=rule + "2",
                                require_root=False, visudo=lambda p: True)
        res = "installed"
    except codetrust.CodeTrustError as e:
        res = str(e)
finally:
    codetrust.require_trusted = real_gate
pkg_dir = os.path.dirname(os.path.abspath(gh.__file__))
ok("the default gate refuses before anything is written, and checks the package dir it copies from",
   res.startswith("refusing to install the access-grant helper") and not os.path.exists(os.path.join(lib, "gh2"))
   and got and pkg_dir in (got[0][1] or []) and all(r in got[0][1] for r in codetrust.code_roots()), (res, got))

# policy writes are check-before-write, and a policy file root didn't write isn't believed
pol3 = os.path.join(etc, "pol3.conf")
gi.write_policy("allow", policy=pol3, elevated=elev)
ino = os.stat(pol3).st_ino
gi.write_policy("allow", policy=pol3, elevated=elev)
ok("write_policy: the same value again leaves the file alone", os.stat(pol3).st_ino == ino)
try:
    gi.write_policy("maybe", policy=pol3, elevated=elev)
    res = "written"
except gi.GrantInstallError as e:
    res = str(e)
ok("write_policy refuses a value other than allow/deny", "invalid elevated-grant policy" in res, res)

# final review M2: the elevated rule goes BEFORE the deny policy is written, so a failed write can't leave it live
elev_m2 = os.path.join(etc, "elev-m2")
open(elev_m2, "w").close()
try:
    gi.write_policy("deny", policy=os.path.join(etc, "no-such-dir", "pol.conf"), elevated=elev_m2)
    res = "written"
except Exception as e:  # noqa: BLE001
    res = f"{type(e).__name__}: {e}"
ok("M2: the deny policy can't be written -> it fails, and the elevated rule is gone anyway",
   res != "written" and not os.path.exists(elev_m2), (res, os.path.exists(elev_m2)))

# secure-install: the order, and what a failing step does
names = [s.__name__ for s in si.DEFAULT_STEPS]
ok("secure-install: the old broad rules go first; the grant helper is set up before the scanner refresh",
   names[0] == "remove_legacy_grant_rules" and "grant_setup" in names
   and names.index("grant_setup") < names.index("refresh_scanner_pieces"), names)
ok("…the grant, wrapper and scanner steps continue on error; the tree step stops the run",
   all(getattr(getattr(si, n), "continue_on_error", False)
       for n in ("remove_legacy_grant_rules", "secure_wrappers", "grant_setup", "refresh_scanner_pieces"))
   and not getattr(si.secure_trees, "continue_on_error", False))

# final review M1: a wrappers failure (a group-writable /usr/local/bin, e.g. Debian's setgid staff) must not skip the
# grant setup: the run still fails, but the helper and the policy are in place and the elevated rule is gone
gw_bin = tempfile.mkdtemp()
os.chmod(gw_bin, 0o2775)
m1_seen = []


def m1_grant(u, c):
    m1_seen.append("grant_setup ran")
    return "grant"


try:
    si.run("svc", euid=lambda: 0, uids=(0, os.geteuid()), layout=codetrust.Layout(venv="/nonexistent/v", bindir=gw_bin),
           steps=[si.secure_wrappers, m1_grant])
    err = None
except si.SecureInstallError as e:
    err = e
ok("M1: a failing wrappers step (group-writable bindir) -> grant setup still runs; the run fails and says why",
   err is not None and m1_seen == ["grant_setup ran"] and any("FAILED" in ln and gw_bin in ln for ln in err.lines),
   (err, getattr(err, "lines", None), m1_seen))

seen = []


def good(u, c):
    return "good"


def boom(u, c):
    raise RuntimeError("scanner broke")


boom.continue_on_error = True


def after(u, c):
    seen.append("after ran")
    return "after"


def stop(u, c):
    raise si.SecureInstallError("a foreign tree")


reported = []
try:
    si.run("svc", euid=lambda: 0, steps=[good, boom, after], report=reported.append)
    err = None
except si.SecureInstallError as e:
    err = e
ok("a continue-on-error step's failure doesn't skip the steps after it; the run still fails",
   err is not None and "scanner broke" in str(err) and seen == ["after ran"], (err, seen))
ok("…every step's line is kept (and reported as it happens), the failure among them",
   err is not None and err.lines[0] == "good" and err.lines[-1] == "after" and "scanner broke" in err.lines[1]
   and reported == err.lines, (getattr(err, "lines", None), reported))
seen.clear()
try:
    si.run("svc", euid=lambda: 0, steps=[good, stop, after])
    err = None
except si.SecureInstallError as e:
    err = e
ok("a stopping step's failure keeps the earlier steps' lines and runs nothing after it",
   err is not None and err.lines == ["good"] and "a foreign tree" in str(err) and seen == [], (err, seen))

# remove_legacy_grant_rules / grant_setup against temp paths (fix round 2: Option A)
legacy2, pol2, elev2 = (os.path.join(etc, n) for n in ("legacy2", "pol2.conf", "elev2"))
saved = (gi.POLICY, gi.ELEVATED, gi.LEGACY_SUDOERS, gi.install_grant_helper)
gi.POLICY, gi.ELEVATED, gi.LEGACY_SUDOERS = pol2, elev2, legacy2
helper_for = []
gi.install_grant_helper = lambda user, **kw: helper_for.append(user)
WARN = "while elevated grants are allowed, any process running as svc can become root"
HOWTO = "sudo orchestratia-agent secure-install --allow-elevated-grants"
try:
    open(legacy2, "w").close()
    line1 = si.remove_legacy_grant_rules("svc", SimpleNamespace(elevated=None))
    line2 = si.remove_legacy_grant_rules("svc", SimpleNamespace(elevated=None))
    open(elev2, "w").close()                       # elevated in use before 0.35: a legacy rule, no policy file
    line3 = si.grant_setup("svc", SimpleNamespace(elevated=None))
    pol3, elev3 = gi.read_policy(pol2), os.path.exists(elev2)
    line3b = si.grant_setup("svc", SimpleNamespace(elevated=None))
    line4 = si.grant_setup("svc", SimpleNamespace(elevated="allow"))
    pol4 = gi.read_policy(pol2)
    open(elev2, "w").close()                       # the helper set it while allowed
    line5 = si.grant_setup("svc", SimpleNamespace(elevated=None))
    pol5, elev5 = gi.read_policy(pol2), os.path.exists(elev2)
    line6 = si.grant_setup("svc", SimpleNamespace(elevated="deny"))
    pol6, elev6 = gi.read_policy(pol2), os.path.exists(elev2)
    with open(pol2, "w") as fh:
        fh.write("something an admin wrote\n")
    open(elev2, "w").close()
    line7 = si.grant_setup("svc", SimpleNamespace(elevated=None))
    pol7_text, elev7 = open(pol2).read(), os.path.exists(elev2)
finally:
    gi.POLICY, gi.ELEVATED, gi.LEGACY_SUDOERS, gi.install_grant_helper = saved
ok("remove_legacy_grant_rules removes them and says so; nothing to do the second time",
   "removed" in line1 and not os.path.exists(legacy2) and "removed" not in line2, (line1, line2))
ok("upgrade of a server that used elevated grants: policy deny, the legacy elevated rule removed, the helper installed",
   "elevated grants: deny" in line3 and pol3 == "deny" and not elev3 and helper_for[0] == "svc", line3)
ok("…with a clear notice: off now, the command to allow, and what allowing means",
   "now off" in line3 and HOWTO in line3 and WARN in line3, line3)
ok("…the next update: deny kept, no notice (nothing was removed)", "elevated grants: deny" in line3b
   and "now off" not in line3b and "kept" in line3b, line3b)
ok("--allow-elevated-grants: allow, with the warning", "elevated grants: allow" in line4 and pol4 == "allow"
   and WARN in line4, line4)
ok("an update after allow: allow kept (never lapses), the live rule kept, the warning repeated",
   "elevated grants: allow" in line5 and pol5 == "allow" and elev5 and WARN in line5, line5)
ok("--deny-elevated-grants: deny, the live rule removed, the notice says how to allow again",
   "elevated grants: deny" in line6 and pol6 == "deny" and not elev6 and HOWTO in line6, line6)
ok("a policy file without elevated=allow is left exactly as it is, but a rule without allow can't stay",
   pol7_text == "something an admin wrote\n" and not elev7 and "elevated grants: deny" in line7 and "now off" in line7,
   line7)

# the CLI flags (non-root here: they parse, then secure-install refuses without root)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
r = subprocess.run([sys.executable, "-m", "orchestratia_agent", "secure-install", "--allow-elevated-grants"],
                   capture_output=True, text=True, cwd=ROOT)
ok("secure-install --allow-elevated-grants parses (then asks for root)",
   r.returncode == 1 and "run it as root" in r.stderr, (r.returncode, r.stderr[-300:]))
r = subprocess.run([sys.executable, "-m", "orchestratia_agent", "secure-install", "--allow-elevated-grants",
                    "--deny-elevated-grants"], capture_output=True, text=True, cwd=ROOT)
ok("…and the two flags exclude each other", r.returncode == 2 and "not allowed with" in r.stderr, r.stderr[-300:])

# ══ fix round 1 ══
# fix round 2: the helper never writes the policy file; clear-elevated only removes the rule
with open(ctx.policy, "w") as fh:
    fh.write("elevated=allow\n")
os.chmod(ctx.policy, 0o644)
pol_before = (open(ctx.policy).read(), os.stat(ctx.policy).st_ino)
ok("set-elevated (policy allows) -> set", call(["set-elevated"])[1] == "set")
rc, out, _ = call(["clear-elevated"])
ok("clear-elevated -> the rule goes, the policy file untouched",
   (rc, out) == (0, "cleared") and not os.path.exists(ctx.sudoers)
   and (open(ctx.policy).read(), os.stat(ctx.policy).st_ino) == pol_before, out)
ok("…so set-elevated works again without root's help", call(["set-elevated"])[1] == "set")
call(["clear-elevated"])
for argv in (["clear-elevated", "last"], ["clear-elevated", "allow"], ["set-policy", "allow"], ["allow-elevated"],
             ["set-policy", "deny"]):
    ok(f"argv {argv} -> 64 (the helper has no way to write the policy)", call(argv)[0] == 64)
ok("the helper's code never opens the policy for writing",
   "_deny_policy" not in open(gh.__file__).read() and "policy_text(" not in open(gh.__file__).read().split("def policy_text")[1].split("\n", 1)[1])
ok("the helper's subprocess environment has HOME=/root", gh.CLEAN_ENV.get("HOME") == "/root", gh.CLEAN_ENV)

# set-elevated's temp file is unique: a planted fixed name is neither followed nor removed
with open(ctx.policy, "w") as fh:
    fh.write("elevated=allow\n")
planted = os.path.join(os.path.dirname(ctx.sudoers), ".orchestratia.grant-tmp")
os.symlink(victim, planted)
ran.clear()
rc, out, _ = call(["set-elevated"])
ok("set-elevated: a unique dot-named temp (mkstemp), the planted name untouched",
   rc == 0 and os.path.islink(planted) and open(victim).read() == "root:secret\n" and ran
   and os.path.basename(ran[-1][2]).startswith(".") and ran[-1][2] != planted
   and not [n for n in os.listdir(os.path.dirname(ctx.sudoers)) if n.startswith(".orchestratia.grant-") and n != ".orchestratia.grant-tmp"],
   (rc, out, ran[-1:] if ran else ran))
call(["clear-elevated"])

# authorized_keys lines are split on b"\n" only: a manual line holding \x1c, \u2028 or \x0b survives a rewrite byte for byte
manual = "ssh-ed25519 AAAAmanual a\x1cb\u2028c\x0bd admin@laptop".encode()
os.makedirs(os.path.dirname(ak), mode=0o700, exist_ok=True)
with open(ak, "wb") as fh:
    fh.write(manual + b"\n")
os.chmod(ak, 0o600)
call(["add-key", G2], K2)
data = open(ak, "rb").read()
ok("a manual key with odd separators is kept byte for byte when a grant key is added",
   data.split(b"\n")[0] == manual and data.count(b"\n") == 2 and data.endswith(f"{K2} {gh.TAG}{G2}\n".encode()), data)
call(["remove-key", G2])
ok("…and when one is removed", open(ak, "rb").read() == manual + b"\n", open(ak, "rb").read())

# --allow-elevated-grants says plainly what it means
r = subprocess.run([sys.executable, "-m", "orchestratia_agent", "--help"], capture_output=True, text=True, cwd=ROOT)
ok("--allow-elevated-grants help: any process running as the agent's user can become root",
   "can become root" in " ".join(r.stdout.split()), r.stdout[-800:])

# install_launcher leaves an existing sudoers dir (and its parent) exactly as it was
from orchestratia_agent.scanning import pack  # noqa: E402
d = tempfile.mkdtemp()
sd = os.path.join(d, "sudoers.d")
os.mkdir(sd, 0o750)
os.chmod(sd, 0o750)
os.chmod(d, 0o711)
pack.install_launcher("ubuntu", python="/usr/bin/python3", target=os.path.join(tempfile.mkdtemp(), "libexec", "scan-launch"),
                      sudoers=os.path.join(sd, "orchestratia-scan"), require_root=False, visudo=lambda p: True)
ok("install_launcher doesn't chmod an existing sudoers dir or its parent",
   stat.S_IMODE(os.stat(sd).st_mode) == 0o750 and stat.S_IMODE(os.stat(d).st_mode) == 0o711,
   (oct(os.stat(sd).st_mode), oct(os.stat(d).st_mode)))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
