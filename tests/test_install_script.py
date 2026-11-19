#!/usr/bin/env python3
"""The Linux installer leaves no daemon-writable code for root (hardening plan Task 2; Task 4 adds the sudo rules).
Static: reads the scripts, never runs them.

Dependency-free — run:  python3 tests/test_install_script.py
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def read(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return fh.read()


inst = read("scripts/install-linux.sh")
ok("install-linux.sh parses", subprocess.run(["bash", "-n", os.path.join(ROOT, "scripts/install-linux.sh")]).returncode == 0)
ok("the venv is never handed to the daemon user", 'chown -R "${RUN_USER}:${RUN_USER}" "$VENV_DIR"' not in inst)
ok("the asset tree is never handed to the daemon user", 'chown -R "${RUN_USER}:${RUN_USER}" "$INSTALL_DIR"' not in inst)
ok("root never runs git inside an existing asset tree", 'git -C "$INSTALL_DIR"' not in inst and "safe.directory" not in inst)
ok("the asset tree is a fresh clone swapped in whole", "/opt/.orchestratia-agent.new-" in inst
   and 'sudo mv "$NEW_TREE" "$INSTALL_DIR"' in inst)
ok("the installer secures the install", 'secure-install --daemon-user "$RUN_USER"' in inst)
ok("root parts run with umask 022", re.search(r"^umask 022$", inst, re.M) is not None)

# ── fix round 1: root never imports from the caller's cwd ──
lines = inst.splitlines()
cd_at = next((i for i, ln in enumerate(lines) if re.fullmatch(r"cd / \|\| exit 1", ln.strip())), None)
first_py = next((i for i, ln in enumerate(lines) if re.search(r"\bpython3 -", ln) and not ln.lstrip().startswith("#")),
                None)
run_home = next((i for i, ln in enumerate(lines) if ln.startswith("RUN_HOME=")), None)
ok("the installer cd's to / after resolving the user, before any python runs",
   cd_at is not None and run_home is not None and run_home < cd_at < (first_py or 10 ** 9), (run_home, cd_at, first_py))
ok("a relative ORCHESTRATIA_INSTALL_SOURCE is made absolute before the cd",
   (src_at := next((i for i, ln in enumerate(lines) if 'INSTALL_SOURCE="$(cd' in ln), None)) is not None
   and cd_at is not None and src_at < cd_at, src_at)
loose = [ln.strip() for ln in lines if not ln.lstrip().startswith("#")
         and re.search(r'(?<!-u "\$RUN_USER" )\bpython3 (?!-I )-[cm]\b', ln)]
ok("every python3 -c / -m the installer runs itself is isolated (-I)", loose == [], loose)
ok("venv pip runs as the venv's python -I -m pip, never the bin/pip script",
   '"$VENV_DIR/bin/pip"' not in inst and "$VENV_DIR/bin/pip " not in inst
   and '"$VENV_DIR/bin/python3" -I -m pip install' in inst)
pip_installs = [ln.strip() for ln in lines if "-m pip install" in ln and not ln.lstrip().startswith("#")]
ok("every root pip install uses --no-cache-dir", pip_installs and all("--no-cache-dir" in ln for ln in pip_installs),
   pip_installs)
ok("root-context pip uninstall/show is python3 -I -m pip",
   re.search(r"^\s*pip3 (uninstall|show)", inst, re.M) is None and "python3 -I -m pip uninstall" in inst)
ok("leftover venv.old-* dirs from an interrupted update are removed", '"${VENV_DIR}".old-*' in inst)
ok("no comment claims Step 6 refreshes /opt via git pull", "git pull" not in inst)

# ══ Task 4: no broad grant sudo rules; uninstall cleans up ══
for name in ("scripts/install-linux.sh", "install.sh"):
    s = read(name)
    ok(f"{name}: no sudo rule for tee/chmod/chown/rm/mkdir/cat/useradd",
       not re.search(r"NOPASSWD:\s*/usr/(s?bin)/(tee|chmod|chown|rm|mkdir|cat|useradd)\b", s),
       re.findall(r"NOPASSWD:.*", s))
ok("install-linux.sh removes the old broad rules", 'sudo rm -f "/etc/sudoers.d/${SERVICE_NAME}"' in inst)
un = read("uninstall.sh")
for f in ("/etc/sudoers.d/orchestratia-grant", "/usr/local/libexec/orchestratia/grant-helper",
          "/etc/sudoers.d/orchestratia-agent", "/etc/sudoers.d/orchestratia ", "/etc/orchestratia-grants.conf"):
    ok(f"uninstall.sh removes {f.strip()}", f in un.replace("\n", " ") + " ")
ok("uninstall.sh parses", subprocess.run(["bash", "-n", os.path.join(ROOT, "uninstall.sh")]).returncode == 0)

# the legacy repo-root install.sh pip-installs into the daemon user's ~/.local and hands it /opt/orchestratia-agent:
# root would run code that account can change. On Linux it refuses and points at the supported installer.
legacy = read("install.sh")
ok("install.sh parses", subprocess.run(["bash", "-n", os.path.join(ROOT, "install.sh")]).returncode == 0)
llines = legacy.splitlines()
guard = next((i for i, ln in enumerate(llines) if re.match(r'\s*if \[ "\$OS_TYPE" = "linux" \]; then', ln)), None)
first_sudo = next((i for i, ln in enumerate(llines) if re.match(r"\s*sudo ", ln)), None)
ok("install.sh refuses on Linux before it does anything, pointing at install.orchestratia.com/linux",
   guard is not None and first_sudo is not None and guard < first_sudo
   and "install.orchestratia.com/linux" in "\n".join(llines[guard:guard + 15])
   and re.search(r"^\s*exit 1$", "\n".join(llines[guard:guard + 15]), re.M) is not None, (guard, first_sudo))

# ══ Task 4 fix round 1: uninstall revokes every grant key through the helper and locks the account ══
import tempfile  # noqa: E402
un_lines = un.splitlines()
rm_loop = next((i for i, ln in enumerate(un_lines) if ln.startswith("for f in /etc/sudoers.d/orchestratia-scan")), None)
revoke_call = next((i for i, ln in enumerate(un_lines) if "revoke_grant_keys \"$GRANT_HELPER\"" in ln), None)
lock = next((i for i, ln in enumerate(un_lines) if re.search(r"usermod -e 1 orchestratia\b", ln)), None)
ok("uninstall.sh revokes the grant keys and expires the orchestratia account BEFORE removing the helper",
   rm_loop is not None and revoke_call is not None and lock is not None and revoke_call < lock < rm_loop,
   (revoke_call, lock, rm_loop))
ok("uninstall.sh: root never rm's anything under /home/orchestratia",
   not re.search(r"\brm\b[^\n]*(/home/orchestratia|ORCH_HOME|~orchestratia)", un), re.findall(r".*rm.*orchestratia.*", un))
m = re.search(r"# >>> revoke_grant_keys\n(.*?)# <<< revoke_grant_keys", un, re.S)
ok("uninstall.sh defines revoke_grant_keys between markers", m is not None)
if m:
    d = tempfile.mkdtemp()
    log = os.path.join(d, "calls")
    fake = os.path.join(d, "grant-helper")
    with open(fake, "w") as fh:
        fh.write("#!/bin/sh\n"
                 f'echo "$@" >> "{log}"\n'
                 'case "$1" in\n'
                 '  status) [ -n "$FAIL_STATUS" ] && exit 1; echo \'{"elevated": false, "elevated_allowed": false, '
                 '"keys": {"11111111-2222-3333-4444-555555555555": "ssh-ed25519 AAAA", '
                 '"11111111-2222-3333-4444-666666666666": "ssh-ed25519 BBBB"}, "user": true}\' ;;\n'
                 '  remove-key) echo removed ;;\n'
                 '  *) exit 64 ;;\n'
                 'esac\n')
    os.chmod(fake, 0o755)
    script = "set -euo pipefail\nsudo() { \"$@\"; }\n" + m.group(1) + 'revoke_grant_keys "$1"\n'
    r = subprocess.run(["bash", "-c", script, "x", fake], capture_output=True, text=True, cwd=d)
    calls = open(log).read().splitlines() if os.path.exists(log) else []
    ok("revoke_grant_keys: status, then remove-key for each tagged grant; prints how many",
       r.returncode == 0 and r.stdout.strip() == "2" and calls == [
           "status", "remove-key 11111111-2222-3333-4444-555555555555",
           "remove-key 11111111-2222-3333-4444-666666666666"], (r.returncode, r.stdout, r.stderr, calls))
    os.unlink(log)
    r = subprocess.run(["bash", "-c", "set -euo pipefail\nsudo() { \"$@\"; }\n" + m.group(1)
                        + 'if revoke_grant_keys "$1"; then echo OK; else echo FAILED; fi\n', "x", fake],
                       capture_output=True, text=True, cwd=d, env={**os.environ, "FAIL_STATUS": "1"})
    ok("…a helper that can't list the keys -> the function fails (uninstall warns, still expires the account)",
       r.stdout.strip() == "FAILED", (r.stdout, r.stderr))
    r = subprocess.run(["bash", "-c", "sudo() { \"$@\"; }\n" + m.group(1)
                        + 'if revoke_grant_keys /nonexistent/grant-helper; then echo OK; else echo FAILED; fi\n'],
                       capture_output=True, text=True, cwd=d)
    ok("…no helper installed -> fails without running anything", r.stdout.strip() == "FAILED", (r.stdout, r.stderr))
ok("install-linux.sh lifts only uninstall's expiry marker (1) on the orchestratia account",
   re.search(r'getent shadow orchestratia \| cut -d: -f8\)" = "1"', inst) is not None
   and 'usermod -e "" orchestratia' in inst)
ok("install.sh (macOS only now) doesn't tell users to run a Linux-only step",
   "run sudo orchestratia update after install" not in legacy)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
