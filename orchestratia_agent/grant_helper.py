"""Root-owned access-grant helper (hardening plan Task 4).

A server that is the TARGET of an access grant lets the grant's key log in as `orchestratia`; an elevated grant gives
that user sudo. The agent daemon isn't root, so it asks this helper, through ONE sudoers rule:

    grant-helper status                 JSON {"user", "keys": {grant id: key}, "elevated", "elevated_allowed"}
    grant-helper ensure-user            create the orchestratia system user (home /home/orchestratia) if missing
    grant-helper add-key <grant_id>     stdin: one public key line, written as "<type> <base64> orchestratia-grant:<id>"
    grant-helper remove-key <grant_id>  drop that grant's key
    grant-helper set-elevated           /etc/sudoers.d/orchestratia = SUDOERS_RULE, only when POLICY says elevated=allow
    grant-helper clear-elevated         remove /etc/sudoers.d/orchestratia (the agent calls it when no elevated grant is
                                        left)

It never takes a path, a user name or sudoers text from its caller. It writes into a home another user owns, so it
never follows a link there: every file is opened relative to a directory fd with O_NOFOLLOW, refused unless it is a
single-link regular file, and replaced by rename. The policy is root's: without it the daemon user could add its own
key, set elevated and log in as orchestratia (plan ruling 2). The helper NEVER writes the policy: only root's
`secure-install --allow-elevated-grants` / `--deny-elevated-grants` does (user decision, Option A).

`secure-install` installs this file as /usr/local/libexec/orchestratia/grant-helper behind a `#!/usr/bin/python3 -IS`
line (no environment, no site-packages). Stdlib only; `pwd` is imported lazily so the package imports on Windows."""
import base64
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass

USER = "orchestratia"
HOME = "/home/orchestratia"
TAG = "orchestratia-grant:"
SUDOERS = "/etc/sudoers.d/orchestratia"
SUDOERS_RULE = "orchestratia ALL=(ALL) NOPASSWD: ALL\n"
POLICY = "/etc/orchestratia-grants.conf"
USERADD = "/usr/sbin/useradd"
VISUDO = "/usr/sbin/visudo"
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}
EX_OK, EX_FAIL, EX_DENIED, EX_USAGE, EX_UNSAFE = 0, 1, 3, 64, 77
GRANT_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
KEY_TYPES = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa",
             "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
MAX_KEY = 16 * 1024
MAX_FILE = 1024 * 1024


class Unsafe(Exception):
    pass


class Denied(Exception):
    pass


def parse_key(text):
    """'<type> <base64>' from one OpenSSH public key line (a trailing comment is dropped), else ValueError. No
    options (the line must start with a key type), one line only, and the blob must name the declared type."""
    if not isinstance(text, str) or len(text) > MAX_KEY or "\0" in text or "\r" in text:
        raise ValueError("not a single public key line")
    lines = [ln for ln in text.split("\n") if ln.strip()]
    if len(lines) != 1:
        raise ValueError("expected exactly one public key line")
    parts = lines[0].split()
    if len(parts) not in (2, 3) or parts[0] not in KEY_TYPES or not _B64.fullmatch(parts[1]):
        raise ValueError("not an allowed public key")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except ValueError:
        raise ValueError("bad key data")
    n = int.from_bytes(blob[:4], "big")
    if len(blob) < 4 + n or blob[4:4 + n] != parts[0].encode():
        raise ValueError("the key data doesn't match its type")
    return f"{parts[0]} {parts[1]}"


def policy_text(value):
    """The policy file's content, as root's `secure-install` writes it (this helper only reads the policy)."""
    return ("# Orchestratia: may access grants give the orchestratia user sudo? Change with\n"
            "# sudo orchestratia-agent secure-install --allow-elevated-grants | --deny-elevated-grants\n"
            "# While elevated grants are allowed, any process running as the agent's user can become root.\n"
            f"elevated={value}\n")


@dataclass
class Ctx:
    home: str = HOME
    sudoers: str = SUDOERS
    policy: str = POLICY
    trusted_uids: tuple = (0,)
    getpw: object = None
    run: object = subprocess.run

    def pw(self):
        if self.getpw is not None:
            return self.getpw()
        import pwd
        return pwd.getpwnam(USER)


def _user(ctx):
    try:
        pw = ctx.pw()
    except KeyError:
        return None
    if pw.pw_dir != ctx.home:
        raise Unsafe(f"{USER}'s home is {pw.pw_dir}, not {ctx.home}")
    return pw


def ensure_user(ctx):
    if _user(ctx) is not None:
        return "exists"
    res = ctx.run([USERADD, "--system", "--create-home", "--home-dir", ctx.home, "--shell", "/bin/bash", USER],
                  capture_output=True, text=True, env=dict(CLEAN_ENV), timeout=30, cwd="/")
    if _user(ctx) is None:
        raise RuntimeError(f"useradd failed: {(res.stderr or '').strip()[:200]}")
    return "created"


def _ssh_dir(pw, create):
    """fd of <home>/.ssh, a real directory owned by the user (or root); with `create`, made 0700 and the user's."""
    home = os.open(pw.pw_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(home).st_uid not in (pw.pw_uid, 0):
            raise Unsafe(f"{pw.pw_dir} isn't owned by {USER}")
        try:
            fd = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        except FileNotFoundError:
            if not create:
                return None
            os.mkdir(".ssh", 0o700, dir_fd=home)
            fd = os.open(".ssh", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home)
        except OSError as e:
            raise Unsafe(f"{pw.pw_dir}/.ssh is not a directory ({e.strerror})")
    finally:
        os.close(home)
    if os.fstat(fd).st_uid not in (pw.pw_uid, 0):
        os.close(fd)
        raise Unsafe(f"{pw.pw_dir}/.ssh isn't owned by {USER}")
    if create:
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
        os.fchmod(fd, 0o700)
    return fd


def _read_keys(dfd, pw):
    try:
        fd = os.open("authorized_keys", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
    except FileNotFoundError:
        return []
    except OSError as e:
        raise Unsafe(f"authorized_keys can't be opened safely ({e.strerror})")
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid not in (pw.pw_uid, 0)
                or st.st_size > MAX_FILE):
            raise Unsafe("authorized_keys isn't a single-link regular file of the orchestratia user")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE:
                raise Unsafe("authorized_keys is too large")
            chunks.append(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    lines = data.split(b"\n")              # only "\n" separates lines for sshd; keep every other byte as it is
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def _write_keys(dfd, pw, lines):
    tmp = f".authorized_keys.orc-{os.getpid()}"
    try:
        os.unlink(tmp, dir_fd=dfd)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dfd)
    try:
        data = b"\n".join(lines) + b"\n" if lines else b""
        while data:
            data = data[os.write(fd, data):]
        os.fsync(fd)
        os.fchown(fd, pw.pw_uid, pw.pw_gid)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.rename(tmp, "authorized_keys", src_dir_fd=dfd, dst_dir_fd=dfd)


def _tagged(line, gid):
    return line.endswith(f" {TAG}{gid}".encode())


def add_key(ctx, gid, text):
    key = parse_key(text)                       # before anything is created: a bad key changes nothing
    ensure_user(ctx)
    pw = _user(ctx)
    dfd = _ssh_dir(pw, create=True)
    try:
        lines = _read_keys(dfd, pw)
        want = f"{key} {TAG}{gid}".encode()
        mine = [ln for ln in lines if _tagged(ln, gid)]
        if mine == [want]:
            return "unchanged"
        _write_keys(dfd, pw, [ln for ln in lines if not _tagged(ln, gid)] + [want])
        return "replaced" if mine else "added"
    finally:
        os.close(dfd)


def remove_key(ctx, gid):
    pw = _user(ctx)
    dfd = _ssh_dir(pw, create=False) if pw is not None else None
    if dfd is None:
        return "absent"
    try:
        lines = _read_keys(dfd, pw)
        keep = [ln for ln in lines if not _tagged(ln, gid)]
        if len(keep) == len(lines):
            return "absent"
        _write_keys(dfd, pw, keep)
        return "removed"
    finally:
        os.close(dfd)


def _policy_allows(ctx):
    """True only when the policy file is a regular file owned by root (trusted_uids), writable by nobody else,
    with an `elevated=allow` line."""
    try:
        fd = os.open(ctx.policy, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid not in ctx.trusted_uids or st.st_mode & 0o022:
            return False
        text = os.read(fd, 4096).decode("utf-8", "replace")
    finally:
        os.close(fd)
    return any(ln.strip() == "elevated=allow" for ln in text.splitlines())


def set_elevated(ctx):
    if not _policy_allows(ctx):
        raise Denied("elevated grants are off on this server; its owner turns them on with: "
                     "sudo orchestratia-agent secure-install --allow-elevated-grants")
    ensure_user(ctx)
    try:
        st = os.lstat(ctx.sudoers)
        if stat.S_ISREG(st.st_mode) and st.st_uid in ctx.trusted_uids and stat.S_IMODE(st.st_mode) == 0o440:
            with open(ctx.sudoers) as fh:
                if fh.read() == SUDOERS_RULE:
                    return "unchanged"
    except FileNotFoundError:
        pass
    # A unique dot-named temp (sudo's includedir never reads a name with a dot), 0440, checked, then renamed.
    tmp = _new_temp(os.path.dirname(ctx.sudoers), ".orchestratia.grant-", SUDOERS_RULE, 0o440)
    try:
        res = ctx.run([VISUDO, "-cf", tmp], capture_output=True, text=True, env=dict(CLEAN_ENV), timeout=30, cwd="/")
        if res.returncode != 0:
            raise RuntimeError("visudo refused the elevated rule")
        os.replace(tmp, ctx.sudoers)
    except BaseException:
        if os.path.lexists(tmp):
            os.unlink(tmp)
        raise
    return "set"


def _new_temp(directory, prefix, text, mode):
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=directory)       # O_EXCL, a fresh name: nothing planted is reused
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
            os.fchmod(fh.fileno(), mode)
    except BaseException:
        os.unlink(tmp)
        raise
    return tmp


def clear_elevated(ctx):
    if not os.path.lexists(ctx.sudoers):
        return "absent"
    os.unlink(ctx.sudoers)
    return "cleared"


def status(ctx):
    pw = _user(ctx)
    keys = {}
    dfd = _ssh_dir(pw, create=False) if pw is not None else None
    if dfd is not None:
        try:
            for raw in _read_keys(dfd, pw):
                parts = raw.decode("utf-8", "replace").split()
                if len(parts) == 3 and parts[2].startswith(TAG) and GRANT_ID.fullmatch(parts[2][len(TAG):]):
                    keys[parts[2][len(TAG):]] = f"{parts[0]} {parts[1]}"
        finally:
            os.close(dfd)
    return {"user": pw is not None, "keys": keys, "elevated": os.path.lexists(ctx.sudoers),
            "elevated_allowed": _policy_allows(ctx)}


def _root_path_problem(path):
    parts = os.path.abspath(path).split(os.sep)
    for i in range(1, len(parts) + 1):
        p = os.sep.join(parts[:i]) or os.sep
        try:
            st = os.lstat(p)
        except OSError:
            return f"{p} is missing"
        if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            return f"{p} isn't root-owned and protected"
    return None


def _integrity():
    """This file, the interpreter running it and the two programs it runs: root's alone along their whole path."""
    for p in (os.path.abspath(sys.argv[0]), os.path.realpath(sys.executable), USERADD, VISUDO):
        why = _root_path_problem(p)
        if why:
            return why
    return None


def main(argv, *, stdin=None, out=None, err=None, euid=None, ctx=None, integrity=None):
    stdin, out, err = stdin or sys.stdin, out or sys.stdout, err or sys.stderr
    if (euid or os.geteuid)() != 0:
        err.write("grant-helper runs as root, through sudo\n")
        return EX_USAGE
    why = (integrity or _integrity)()
    if why:
        err.write(f"grant-helper: refusing: {why}\n")
        return EX_UNSAFE
    ctx = ctx or Ctx()
    try:
        if argv == ["status"]:
            result = json.dumps(status(ctx), sort_keys=True)
        elif argv == ["ensure-user"]:
            result = ensure_user(ctx)
        elif len(argv) == 2 and argv[0] == "add-key" and GRANT_ID.fullmatch(argv[1]):
            result = add_key(ctx, argv[1], stdin.read(MAX_KEY + 1))
        elif len(argv) == 2 and argv[0] == "remove-key" and GRANT_ID.fullmatch(argv[1]):
            result = remove_key(ctx, argv[1])
        elif argv == ["set-elevated"]:
            result = set_elevated(ctx)
        elif argv == ["clear-elevated"]:
            result = clear_elevated(ctx)
        else:
            err.write("usage: grant-helper status|ensure-user|add-key ID|remove-key ID|set-elevated|clear-elevated\n")
            return EX_USAGE
    except ValueError as e:
        err.write(f"grant-helper: {e}\n")
        return EX_USAGE
    except Denied as e:
        err.write(f"grant-helper: {e}\n")
        return EX_DENIED
    except Unsafe as e:
        err.write(f"grant-helper: refusing: {e}\n")
        return EX_UNSAFE
    except (OSError, RuntimeError, subprocess.SubprocessError) as e:
        err.write(f"grant-helper: {e}\n")
        return EX_FAIL
    out.write(result + "\n")
    return EX_OK


if __name__ == "__main__":
    os.environ.clear()
    os.environ.update(CLEAN_ENV)
    os.umask(0o022)
    sys.exit(main(sys.argv[1:]))
