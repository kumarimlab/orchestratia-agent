"""Root-owned scan launcher (plan 1C Task 3; spec §7.3, D12).

The agent daemon is not root (the restricted tier requires that), but a scan sandbox is a transient SYSTEM unit
with DynamicUser, which only root can start. `sudo orchestratia scanners install` copies this file into the
root-owned runner directory, installs a root-owned wrapper at /usr/local/libexec/orchestratia/scan-launch, and
adds one sudoers rule that lets the daemon's user run that wrapper, and nothing else, as root.

The caller passes only a run id and a catalog scan id. Every unit property comes from the root-owned copies of
sandbox.py and catalog.py beside this file (python3 -I: no user site, no PYTHONPATH). So nothing the caller
controls becomes a property, a path or an argument of systemd-run. Its standard input is the only data channel.

    scan-launch run <run_id> <scan_id>   exec systemd-run for that run (stdin/stdout pass straight through)
    scan-launch stop <run_id>            stop that run's orc-scan- unit and remove its state (0 when gone)
    scan-launch sweep                    stop every orc-scan-* unit and remove leftover state (prints the count)

A standard session runs as the daemon's user, so it can call this too: it gets nothing the daemon couldn't
already do (start a sandbox that has less access than itself, or stop scans on this server).

Stdlib only."""
import asyncio
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EX_USAGE, EX_UNSAFE = 64, 77
SYSTEMD_RUN = "/usr/bin/systemd-run"
SYSTEMCTL = "/usr/bin/systemctl"
CLEAN_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
# Everything `pack.sync_runner_files` puts beside this file (pack.RUNNER_FILES): all of it reaches root or the
# sandbox, so all of it must be root's alone.
_CHECKED = ("launch.py", "sandbox.py", "catalog.py", "shim.py", "masking.py", "parsers.py", "code_agent.py",
            "gitleaks.toml")


def _safe_tree(paths):
    """None when every component of every path, AS GIVEN (lstat, never resolved), is owned by root, writable
    by nobody else and not a symlink, and each path itself is a regular file or a directory; else why not."""
    for path in paths:
        path = os.path.abspath(path)
        parts = path.split(os.sep)
        for i in range(1, len(parts) + 1):
            p = os.sep.join(parts[:i]) or os.sep
            try:
                st = os.lstat(p)
            except OSError:
                return f"{p} is missing"
            if stat.S_ISLNK(st.st_mode):
                return f"{p} is a symlink"
            if st.st_uid != 0 or st.st_mode & 0o022:
                return f"{p} is not root-owned and protected"
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
            return f"{path} is not a regular file or directory"
    return None


def _exec(path, argv):
    """Replace this process with `path` (absolute), with a fixed environment: nothing the caller set survives."""
    os.execve(path, argv, dict(CLEAN_ENV))


def main(argv, *, execvp=_exec, euid=os.geteuid):
    if euid() != 0:
        print("scan-launch runs as root, through sudo", file=sys.stderr)
        return EX_USAGE
    bad = _safe_tree([HERE] + [os.path.join(HERE, f) for f in _CHECKED] + [SYSTEMD_RUN, SYSTEMCTL])
    if bad:
        print(f"scan-launch: refusing: {bad}", file=sys.stderr)
        return EX_UNSAFE
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import catalog
    import sandbox
    if len(argv) == 3 and argv[0] == "run":
        run_id, scan_id = argv[1], argv[2]
        try:
            sandbox.unit_name(run_id)
        except ValueError:
            return EX_USAGE
        spec = catalog.CATALOG.get(scan_id)
        if spec is None:
            return EX_USAGE
        cmd = sandbox.argv(run_id, spec, shim=os.path.join(HERE, "shim.py"))
        execvp(SYSTEMD_RUN, cmd)
        return 0
    if len(argv) == 2 and argv[0] == "stop":
        try:
            sandbox.unit_name(argv[1])
        except ValueError:
            return EX_USAGE
        return 0 if asyncio.run(sandbox.stop(argv[1])) else 1
    if argv == ["sweep"]:
        print(asyncio.run(sandbox.sweep()))
        return 0
    return EX_USAGE
