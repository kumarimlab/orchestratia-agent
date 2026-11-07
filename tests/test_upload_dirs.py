#!/usr/bin/env python3
"""upload_dirs: tmpfs detection, the root-owned shared parent, per-user 0700 folders,
the mkdtemp fallback, and the tmpfiles.d content.

Every case runs in a sandbox `root` — never the real /tmp/orchestratia-uploads.
Dependency-free — run directly:  python3 tests/test_upload_dirs.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import upload_dirs as ud  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


ME = ud.own_user()

# ── mountinfo ────────────────────────────────────────────────────────────────
TMPFS = """\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
25 22 0:23 / /proc rw,nosuid shared:12 - proc proc rw
30 22 0:26 / /tmp rw,nosuid,nodev shared:14 - tmpfs tmpfs rw,size=4G,inode64
31 22 0:27 / /tmpdata rw shared:15 - ext4 /dev/sdb1 rw
"""
EXT4 = """\
22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
28 22 0:25 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,size=793728k,mode=755
"""
STACKED = TMPFS + "40 30 8:3 / /tmp rw shared:20 - xfs /dev/sdc1 rw\n"
ESCAPED = EXT4 + "41 22 0:30 / /mnt/my\\040disk rw shared:21 - tmpfs tmpfs rw\n"
ok("tmpfs /tmp detected", ud.fstype_of("/tmp", TMPFS) == "tmpfs")
ok("ext4 root holds /tmp", ud.fstype_of("/tmp", EXT4) == "ext4")
ok("/tmpdata is not /tmp (prefix match is by path component)", ud.fstype_of("/tmpdata/x", TMPFS) == "ext4"
   and ud.fstype_of("/tmp/x", TMPFS) == "tmpfs")
ok("a later mount on the same point wins", ud.fstype_of("/tmp", STACKED) == "xfs")
ok("octal escapes in mount points", ud.fstype_of("/mnt/my disk/f", ESCAPED) == "tmpfs")
ok("garbage lines are skipped", ud.fstype_of("/tmp", "nonsense\n\n" + EXT4) == "ext4")
if sys.platform.startswith("linux"):
    ok("tmpfs /tmp -> /var/tmp", ud.temp_root(TMPFS) == "/var/tmp")
    ok("disk /tmp -> /tmp", ud.temp_root(EXT4) == "/tmp")
    ok("the real box resolves without error", ud.temp_root() in ("/tmp", "/var/tmp"))
ok("magic constant kept for reference", ud.TMPFS_MAGIC == 0x01021994)

# ── ensure_base ──────────────────────────────────────────────────────────────
root = tempfile.mkdtemp(prefix="ud-root-")
base = ud.ensure_base(root=root)
s = os.lstat(base)
ok("base created at <root>/orchestratia-uploads", base == os.path.join(root, ud.BASE_NAME))
ok("base is 0755 and ours (root when the daemon is root)", s.st_mode & 0o777 == 0o755
   and s.st_uid == os.geteuid(), oct(s.st_mode))
ok("second call reuses it", ud.ensure_base(root=root) == base)
old_umask = os.umask(0o077)
try:
    r2 = tempfile.mkdtemp(prefix="ud-umask-")
    ok("0755 regardless of umask", os.lstat(ud.ensure_base(root=r2)).st_mode & 0o777 == 0o755)
finally:
    os.umask(old_umask)

sym_root = tempfile.mkdtemp(prefix="ud-sym-")
elsewhere = tempfile.mkdtemp(prefix="ud-elsewhere-")
os.symlink(elsewhere, os.path.join(sym_root, ud.BASE_NAME))
fb = ud.ensure_base(root=sym_root)
ok("symlinked base -> mkdtemp fallback", fb != os.path.join(sym_root, ud.BASE_NAME)
   and os.path.basename(fb).startswith(ud.BASE_NAME + "-") and os.path.dirname(fb) == sym_root, fb)
ok("fallback is a real 0755 dir", not os.path.islink(fb) and os.lstat(fb).st_mode & 0o777 == 0o755)
ok("fallback is cached for the process", ud.ensure_base(root=sym_root) == fb)
ok("the symlink target was never touched", os.listdir(elsewhere) == [])
ud._cache.pop(sym_root, None)
try:
    ud.ensure_base(root=sym_root, fallback=False)
    ok("fallback=False refuses a squatted base", False)
except ud.UploadDirError as e:
    ok("fallback=False refuses a squatted base", e.code == "unsafe_destination", str(e))

gw_root = tempfile.mkdtemp(prefix="ud-gw-")
os.mkdir(os.path.join(gw_root, ud.BASE_NAME))
os.chmod(os.path.join(gw_root, ud.BASE_NAME), 0o777)
ok("world-writable base -> fallback", ud.ensure_base(root=gw_root) != os.path.join(gw_root, ud.BASE_NAME))

if os.geteuid() == 0:
    sq_root = tempfile.mkdtemp(prefix="ud-squat-")
    sq = os.path.join(sq_root, ud.BASE_NAME)
    os.mkdir(sq, 0o755)
    os.chown(sq, 65534, 65534)
    got = ud.ensure_base(root=sq_root)
    ok("base owned by another user -> fallback, owned by root", got != sq and os.lstat(got).st_uid == 0, got)
    ud._cache.pop(sq_root, None)
    ok("trusted_uids accepts a base the daemon user owns",
       ud.ensure_base(root=sq_root, trusted_uids=(65534,)) == sq)
else:
    print("[SKIP] base squatted by another uid (needs root to chown)")

# ── ensure_user_dir ──────────────────────────────────────────────────────────
root = tempfile.mkdtemp(prefix="ud-user-")
base = ud.ensure_base(root=root)
mine = ud.ensure_user_dir(base, ME)
s = os.lstat(mine)
ok("own folder created 0700", mine == os.path.join(base, ME) and s.st_mode & 0o777 == 0o700
   and s.st_uid == os.geteuid(), oct(s.st_mode))
os.chmod(mine, 0o755)
ud.ensure_user_dir(base, ME)
ok("loose mode on our own folder is tightened to 0700", os.lstat(mine).st_mode & 0o777 == 0o700)
os.rmdir(mine)
os.symlink(tempfile.mkdtemp(), mine)
try:
    ud.ensure_user_dir(base, ME)
    ok("symlinked user folder refused", False)
except ud.UploadDirError as e:
    ok("symlinked user folder refused", e.code == "unsafe_destination", str(e))
try:
    ud.ensure_user_dir(base, "no-such-user-xyz")
    ok("unknown user -> privilege", False)
except ud.UploadDirError as e:
    ok("unknown user -> privilege", e.code == "privilege")
if os.geteuid() != 0:
    try:
        ud.ensure_user_dir(base, "nobody")
        ok("another user's missing folder is not ours to create", False)
    except ud.UploadDirError as e:
        ok("another user's missing folder is not ours to create", e.code == "unsafe_destination"
           and ud.FIX_HINT in str(e), str(e))
else:
    theirs = ud.ensure_user_dir(base, "nobody")
    s = os.lstat(theirs)
    ok("root creates another user's folder, owned by them, 0700", s.st_uid == 65534 and s.st_mode & 0o777 == 0o700)

# ── tmpfiles.d ───────────────────────────────────────────────────────────────
conf = ud.tmpfiles_conf([("ubuntu", "ubuntu"), ("orcp-0123456789ab", "orcp-0123456789ab")], root="/tmp")
lines = [ln for ln in conf.splitlines() if ln and not ln.startswith("#")]
ok("tmpfiles: both parents root 0755", "d /tmp/orchestratia-uploads 0755 root root -" in lines
   and "d /var/tmp/orchestratia-uploads 0755 root root -" in lines, lines)
ok("tmpfiles: a private folder per user", "d /tmp/orchestratia-uploads/ubuntu 0700 ubuntu ubuntu -" in lines
   and "d /tmp/orchestratia-uploads/orcp-0123456789ab 0700 orcp-0123456789ab orcp-0123456789ab -" in lines, lines)
ok("tmpfiles: bare call is the parents only", len([ln for ln in ud.tmpfiles_conf().splitlines()
                                                   if ln.startswith("d ")]) == 2)
for bad in (("a\nd /etc 0777 root root -", "x"), ("ubuntu", "g p"), ("../x", "x")):
    try:
        ud.tmpfiles_conf([bad], root="/tmp")
        ok(f"tmpfiles refuses {bad[0][:10]!r}", False)
    except ValueError:
        ok(f"tmpfiles refuses {bad[0][:10]!r}", True)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
