"""SSH key and sudoers management for access grants.

Target role (Server B): manages authorized_keys for SSH access.
  - Linux/macOS: 'orchestratia' system user + ~/.ssh/authorized_keys
  - Windows: OpenSSH server + administrators_authorized_keys or user authorized_keys

Source role (Server A): stores/removes private keys for SSH client use.

Linux target role (hardening plan Task 4): every change goes through ONE root-owned helper
(/usr/local/libexec/orchestratia/grant-helper) behind one sudoers rule, never through broad sudo rules, and only for
what differs from what this process last saw (converge_target): no change, no sudo.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

from orchestratia_agent.grant_helper import GRANT_ID, POLICY as _GRANT_POLICY, parse_key

log = logging.getLogger("orchestratia-agent.ssh_setup")

_IS_WINDOWS = sys.platform == "win32"

# ── Platform-specific constants ───────────────────────────────────────────────

if _IS_WINDOWS:
    _SSHD_CONFIG_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ssh"
    # Windows OpenSSH: admin users use a shared authorized_keys file
    _ADMIN_AUTH_KEYS = _SSHD_CONFIG_DIR / "administrators_authorized_keys"
    # Standard users use per-user authorized_keys
    _USER_AUTH_KEYS = Path.home() / ".ssh" / "authorized_keys"
    _GRANT_TAG = "orchestratia-grant:"
else:
    _ORCHESTRATIA_USER = "orchestratia"
    _ORCHESTRATIA_HOME = Path(f"/home/{_ORCHESTRATIA_USER}")
    _AUTH_KEYS_PATH = _ORCHESTRATIA_HOME / ".ssh" / "authorized_keys"
    _SUDOERS_PATH = Path(f"/etc/sudoers.d/{_ORCHESTRATIA_USER}")
    _GRANT_TAG = "orchestratia-grant:"

GRANT_HELPER = "/usr/local/libexec/orchestratia/grant-helper"
_NO_HELPER = "the access-grant helper isn't installed; run: sudo orchestratia update"
HELPER_PLATFORM = sys.platform.startswith("linux")   # macOS and Windows keep their existing paths
POLICY_PATH = _GRANT_POLICY          # root-owned, world-readable: a change is noticed without sudo
STATUS_TTL = 3600.0                  # re-read the helper's status hourly where there is something to verify
_clock = time.monotonic


# ── Windows helpers ───────────────────────────────────────────────────────────


def _win_is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    if not _IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


_CREATE_NO_WINDOW = 0x08000000


def _win_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command on Windows, capturing output."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=15,
        creationflags=_CREATE_NO_WINDOW,
        **kwargs,
    )


def _win_get_sshd_status() -> str | None:
    """Check if OpenSSH Server (sshd) is installed and return its status.

    Returns: 'Running', 'Stopped', or None if not installed.
    """
    try:
        result = _win_run(["powershell", "-NoProfile", "-Command",
                           "(Get-Service sshd -ErrorAction SilentlyContinue).Status"])
        status = result.stdout.strip()
        return status if status else None
    except Exception:
        return None


def _win_ensure_sshd() -> bool:
    """Ensure OpenSSH Server is installed and running on Windows.

    Returns True if sshd is running (or was started), False otherwise.
    """
    status = _win_get_sshd_status()

    if status == "Running":
        return True

    if status == "Stopped":
        # Try to start it
        try:
            result = _win_run(["powershell", "-NoProfile", "-Command",
                               "Start-Service sshd -ErrorAction Stop"])
            if result.returncode == 0:
                log.info("Started OpenSSH Server (sshd)")
                # Also set it to auto-start
                _win_run(["powershell", "-NoProfile", "-Command",
                          "Set-Service sshd -StartupType Automatic"])
                return True
            else:
                log.error(f"Failed to start sshd: {result.stderr}")
                return False
        except Exception as e:
            log.exception(f"Failed to start sshd")
            return False

    # Not installed — try Add-WindowsCapability first (requires Windows Update)
    log.info("OpenSSH Server not found, attempting to install via Windows capability...")
    try:
        result = _win_run([
            "powershell", "-NoProfile", "-Command",
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        ], timeout=120)
        if result.returncode == 0:
            _win_run(["powershell", "-NoProfile", "-Command",
                      "Start-Service sshd; Set-Service sshd -StartupType Automatic"])
            log.info("Installed and started OpenSSH Server via Windows capability")
            return True
        log.warning(f"Add-WindowsCapability failed: {result.stderr.strip()}")
    except Exception as e:
        log.warning(f"Add-WindowsCapability failed: {e}")

    # Fallback: download Win32-OpenSSH from GitHub
    return _win_install_sshd_from_github()


def _win_install_sshd_from_github() -> bool:
    """Download and install Win32-OpenSSH from GitHub releases (fallback)."""
    import shutil
    import tempfile
    import urllib.request
    import zipfile

    OPENSSH_URL = (
        "https://github.com/PowerShell/Win32-OpenSSH/releases/latest/"
        "download/OpenSSH-Win64.zip"
    )
    INSTALL_DIR = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "OpenSSH"

    log.info("Attempting Win32-OpenSSH install from GitHub...")
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            zip_path = Path(tmpdir) / "OpenSSH-Win64.zip"
            log.info(f"Downloading {OPENSSH_URL}...")
            urllib.request.urlretrieve(OPENSSH_URL, str(zip_path))

            with zipfile.ZipFile(str(zip_path), "r") as zf:
                zf.extractall(tmpdir)

            # ZIP contains an "OpenSSH-Win64" subfolder
            extracted = Path(tmpdir) / "OpenSSH-Win64"
            if not extracted.exists():
                log.error("Unexpected ZIP structure: OpenSSH-Win64 folder not found")
                return False

            if INSTALL_DIR.exists():
                shutil.rmtree(str(INSTALL_DIR))
            shutil.copytree(str(extracted), str(INSTALL_DIR))

        # Run the bundled install-sshd.ps1
        install_script = INSTALL_DIR / "install-sshd.ps1"
        if not install_script.exists():
            log.error(f"install-sshd.ps1 not found at {install_script}")
            return False

        result = _win_run([
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(install_script),
        ], timeout=60)
        if result.returncode != 0:
            log.error(f"install-sshd.ps1 failed: {result.stderr}")
            return False

        # Add to system PATH
        _win_run([
            "powershell", "-NoProfile", "-Command",
            f"$p = [Environment]::GetEnvironmentVariable('PATH','Machine'); "
            f"if ($p -notlike '*OpenSSH*') {{ "
            f"[Environment]::SetEnvironmentVariable('PATH', $p + ';{INSTALL_DIR}', 'Machine') }}"
        ])

        # Firewall rule for SSH
        _win_run([
            "powershell", "-NoProfile", "-Command",
            "New-NetFirewallRule -Name 'OpenSSH-Server' -DisplayName 'OpenSSH Server (sshd)' "
            "-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 "
            "-ErrorAction SilentlyContinue"
        ])

        # Start and enable
        _win_run(["powershell", "-NoProfile", "-Command",
                  "Start-Service sshd; Set-Service sshd -StartupType Automatic"])

        if _win_get_sshd_status() == "Running":
            log.info("Installed and started OpenSSH Server from GitHub release")
            return True

        log.error("sshd not running after GitHub install")
        return False

    except Exception as e:
        log.exception(f"Failed to install OpenSSH from GitHub")
        return False


def _win_set_auth_keys_acl(path: Path, admin_keys: bool = False) -> bool:
    """Set correct NTFS ACLs on an authorized_keys file.

    Windows OpenSSH is very strict about file permissions:
    - administrators_authorized_keys: owned by Administrators, readable by SYSTEM
      and Administrators only, no inheritance.
    - User authorized_keys: owned by the user, no inheritance.
    """
    try:
        path_str = str(path)

        if admin_keys:
            # administrators_authorized_keys: SYSTEM + Administrators only
            cmds = [
                # Remove inheritance and clear existing ACLs
                ["icacls", path_str, "/inheritance:r"],
                # Grant SYSTEM full control
                ["icacls", path_str, "/grant", "SYSTEM:(F)"],
                # Grant Administrators full control
                ["icacls", path_str, "/grant", "*S-1-5-32-544:(F)"],
            ]
        else:
            # User authorized_keys: current user only
            username = os.environ.get("USERNAME", "")
            if not username:
                log.error("Cannot determine USERNAME for ACL")
                return False
            cmds = [
                ["icacls", path_str, "/inheritance:r"],
                ["icacls", path_str, "/grant", f"{username}:(F)"],
                ["icacls", path_str, "/grant", "SYSTEM:(R)"],
            ]

        for cmd in cmds:
            result = _win_run(cmd)
            if result.returncode != 0:
                log.warning(f"icacls command failed: {' '.join(cmd)} — {result.stderr}")

        return True
    except Exception as e:
        log.exception(f"Failed to set ACLs on {path}")
        return False


def _win_user_is_in_administrators() -> bool:
    """Check if the current user is a member of the Administrators group.

    This is different from _win_is_admin() which checks if the process has
    elevated privileges. A user can be in Administrators but running a
    non-elevated process.
    """
    try:
        username = os.environ.get("USERNAME", "")
        if not username:
            return False
        result = _win_run([
            "powershell", "-NoProfile", "-Command",
            "(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name"
        ])
        return any(username.lower() in line.lower() for line in result.stdout.splitlines())
    except Exception:
        return False


def _win_get_auth_keys_path(privilege_level: str = "standard") -> Path:
    """Determine the correct authorized_keys path for Windows.

    Windows OpenSSH has a special rule: if the user is in the Administrators
    group, sshd IGNORES ~/.ssh/authorized_keys and ONLY checks
    %ProgramData%/ssh/administrators_authorized_keys. This is enforced by
    the default 'Match Group administrators' block in sshd_config.

    So we must write to administrators_authorized_keys for ANY admin user,
    regardless of grant privilege level.
    """
    if _win_is_admin() or _win_user_is_in_administrators():
        return _ADMIN_AUTH_KEYS
    return _USER_AUTH_KEYS


# ── Target role (runs on Server B) ────────────────────────────────────────────


def _sudo_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with sudo, suppressing password prompts (Linux/macOS).

    Avoids subprocess.run(timeout=...) because of a subtle masking bug:
    when timeout fires, subprocess.run calls proc.kill() to terminate
    the still-running child. If the child has by then execve'd into
    setuid-root (which sudo always does), our uid-1000 process can't
    SIGKILL it — the kernel returns EPERM. That PermissionError
    propagates *up the same stack* as the original TimeoutExpired and
    masks it entirely, leaving '[Errno 1] Operation not permitted'
    in the log with no hint that the real problem was a timeout.

    Bug that exposed this masking: a VMware-provisioned host with a
    missing /etc/hosts entry made sudo block 15s on getaddrinfo() of
    its own hostname; the 10s subprocess timeout fired, kill() returned
    EPERM, and the agent reported a permissions error when the real
    problem was DNS. (Diagnosed 2026-05-23 by a Claude task running
    on the affected server — see dogfood-claude-diagnoses-bug.md.)

    Design choice: we deliberately keep the 10s timeout (NOT increase
    it). A healthy sudo invocation finishes in milliseconds. If sudo
    takes >10s the host environment is broken (slow DNS, PAM hanging,
    audit subsystem under load) and the agent should fail loudly, not
    paper over it. The install-time hostname check + diag.sh's
    hostname-timing section surface that class of issue at the right
    layer. The fix here is purely diagnostic: surface the real
    TimeoutExpired instead of letting the kill-EPERM mask it.
    """
    timeout = kwargs.pop("timeout", 10)
    input_data = kwargs.pop("input", None)

    proc = subprocess.Popen(
        ["sudo", "-n"] + cmd,
        stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        **kwargs,
    )
    try:
        stdout, stderr = proc.communicate(input=input_data, timeout=timeout)
        return subprocess.CompletedProcess(
            proc.args, proc.returncode, stdout, stderr,
        )
    except subprocess.TimeoutExpired:
        # Child is still alive (possibly now setuid root via sudo's
        # execve). Try to kill it but tolerate EPERM — the kernel will
        # reap it eventually when sudo's auth path completes.
        try:
            proc.kill()
        except PermissionError:
            log.warning(
                f"sudo timeout: cannot SIGKILL setuid-root child pid={proc.pid} "
                f"(cmd={cmd[:3]}). System will reap when sudo's auth completes. "
                f"Likely cause: slow DNS/PAM. Check 'time hostname -f' and /etc/hosts."
            )
        # Drain pipes so they don't leak (best-effort, brief deadline).
        try:
            proc.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            pass
        raise  # Re-raise the original TimeoutExpired so caller sees the real cause.


def _posix_ensure_orchestratia_user() -> bool:
    """Create the `orchestratia` system user on first grant, if missing.

    The install script doesn't create this user — it's only needed when a
    server becomes the *target* of an access grant, which most installs
    never do. Earlier versions of `_posix_setup_authorized_key` assumed
    the user already existed and silently failed (chown to a non-existent
    user is a no-op) — sshd then rejected the grant's key because there
    was no user to authenticate as.

    Created as a system account with a real shell so SSH login works.
    `--system` reserves a UID below 1000 (out of the way of human users)
    and the home dir gets created with sensible defaults.

    Returns True if the user exists (or was created), False if creation
    failed — caller should not proceed with key install in that case.
    """
    # Fast path: user already exists.
    if subprocess.run(["id", _ORCHESTRATIA_USER], capture_output=True).returncode == 0:
        return True

    log.info(f"Creating system user '{_ORCHESTRATIA_USER}' for SSH access grants")
    if sys.platform == "darwin":
        log.error(
            f"macOS user creation not yet automated — create manually: "
            f"sudo sysadminctl -addUser {_ORCHESTRATIA_USER}"
        )
        return False

    # Linux: useradd with explicit shell. Default --system would pick
    # /bin/false which prevents SSH login — opposite of what we want.
    result = _sudo_run([
        "useradd",
        "--system",
        "--create-home",
        "--shell", "/bin/bash",
        _ORCHESTRATIA_USER,
    ])
    if result.returncode == 0:
        log.info(f"Created system user '{_ORCHESTRATIA_USER}'")
        return True
    # Race-safe: another grant install may have just created the user;
    # re-check before treating this as a failure.
    if subprocess.run(["id", _ORCHESTRATIA_USER], capture_output=True).returncode == 0:
        return True
    log.error(
        f"Failed to create user '{_ORCHESTRATIA_USER}': "
        f"{(result.stderr or '').strip() or 'unknown error'} "
        f"(rc={result.returncode}). "
        f"If sudo NOPASSWD isn't configured for useradd, run manually: "
        f"sudo useradd --system --create-home --shell /bin/bash {_ORCHESTRATIA_USER}"
    )
    return False


def setup_authorized_key(public_key: str, grant_id: str,
                         privilege_level: str = "standard") -> bool:
    """Add a public key to authorized_keys with grant tag.

    On Linux/macOS: manages /home/orchestratia/.ssh/authorized_keys
    On Windows: manages OpenSSH authorized_keys (admin or user level)
    """
    tagged_key = f"{public_key} {_GRANT_TAG}{grant_id}"

    if _IS_WINDOWS:
        return _win_setup_authorized_key(tagged_key, grant_id, privilege_level)
    if HELPER_PLATFORM:
        return _linux_add_key(public_key, grant_id)
    return _posix_setup_authorized_key(tagged_key, grant_id)


def _win_setup_authorized_key(tagged_key: str, grant_id: str,
                              privilege_level: str) -> bool:
    """Windows: add public key to OpenSSH authorized_keys."""
    try:
        # Ensure sshd is running
        if not _win_ensure_sshd():
            log.error("Cannot setup SSH access: OpenSSH Server not available")
            return False

        auth_keys_path = _win_get_auth_keys_path(privilege_level)
        is_admin_keys = (auth_keys_path == _ADMIN_AUTH_KEYS)

        # Ensure parent directory exists
        auth_keys_path.parent.mkdir(parents=True, exist_ok=True)

        # Read existing keys
        existing = ""
        if auth_keys_path.exists():
            try:
                existing = auth_keys_path.read_text(encoding="utf-8")
            except PermissionError:
                # Try via powershell for admin keys
                result = _win_run([
                    "powershell", "-NoProfile", "-Command",
                    f"Get-Content '{auth_keys_path}' -Raw -ErrorAction SilentlyContinue"
                ])
                existing = result.stdout if result.returncode == 0 else ""

        # Check if grant already exists
        if f"{_GRANT_TAG}{grant_id}" in existing:
            log.info(f"Grant {grant_id[:8]}: key already in authorized_keys")
            return True

        # Append new key
        new_content = (
            existing.rstrip("\n") + "\n" + tagged_key + "\n"
            if existing.strip() else tagged_key + "\n"
        )

        try:
            auth_keys_path.write_text(new_content, encoding="utf-8")
        except PermissionError:
            # Write via powershell for admin keys
            # Escape single quotes in content for PowerShell
            escaped = new_content.replace("'", "''")
            result = _win_run([
                "powershell", "-NoProfile", "-Command",
                f"Set-Content -Path '{auth_keys_path}' -Value '{escaped}' -NoNewline"
            ])
            if result.returncode != 0:
                log.error(f"Failed to write authorized_keys: {result.stderr}")
                return False

        # Set correct ACLs
        _win_set_auth_keys_acl(auth_keys_path, admin_keys=is_admin_keys)

        log.info(f"Grant {grant_id[:8]}: SSH access configured (key added to {auth_keys_path})")
        return True

    except Exception as e:
        log.exception(f"Failed to setup authorized key for grant {grant_id[:8]}")
        return False


def _posix_setup_authorized_key(tagged_key: str, grant_id: str) -> bool:
    """Linux/macOS: add public key to orchestratia user's authorized_keys."""
    try:
        # Ensure the orchestratia user exists before we touch its home
        # directory. Pre-v0.13.4 the install script assumed the user
        # existed and the agent silently no-op'd the chown — leaving a
        # file owned by root that sshd couldn't use, with no diagnostic.
        if not _posix_ensure_orchestratia_user():
            return False

        ssh_dir = _ORCHESTRATIA_HOME / ".ssh"
        _sudo_run(["mkdir", "-p", str(ssh_dir)])
        _sudo_run(["chmod", "700", str(ssh_dir)])
        _sudo_run(["chown", f"{_ORCHESTRATIA_USER}:{_ORCHESTRATIA_USER}", str(ssh_dir)])

        result = _sudo_run(["cat", str(_AUTH_KEYS_PATH)])
        existing = result.stdout if result.returncode == 0 else ""

        if f"{_GRANT_TAG}{grant_id}" in existing:
            log.info(f"Grant {grant_id[:8]}: key already in authorized_keys")
            return True

        new_content = (
            existing.rstrip("\n") + "\n" + tagged_key + "\n"
            if existing.strip() else tagged_key + "\n"
        )
        # Use _sudo_run (which handles the setuid-root-can't-kill EPERM
        # masking — see its docstring). subprocess.run with timeout=10
        # was the original failure path on the kritis box.
        proc = _sudo_run(["tee", str(_AUTH_KEYS_PATH)], input=new_content)
        if proc.returncode != 0:
            log.error(f"Failed to write authorized_keys: {proc.stderr}")
            return False

        _sudo_run(["chmod", "600", str(_AUTH_KEYS_PATH)])
        _sudo_run(["chown", f"{_ORCHESTRATIA_USER}:{_ORCHESTRATIA_USER}", str(_AUTH_KEYS_PATH)])

        log.info(f"Grant {grant_id[:8]}: SSH access configured (key added)")
        return True

    except Exception:
        # log.exception (not log.error) captures the full traceback in
        # journalctl. Critical for debugging — pre-v0.13.5 the only
        # diagnostic on failure was the exception's str(), which hides
        # *where* in the function the error happened.
        log.exception(f"Failed to setup authorized key for grant {grant_id[:8]}")
        return False


def remove_authorized_key(grant_id: str) -> bool:
    """Remove the key tagged with grant_id from authorized_keys."""
    if _IS_WINDOWS:
        return _win_remove_authorized_key(grant_id)
    if HELPER_PLATFORM:
        return _linux_remove_key(grant_id)
    return _posix_remove_authorized_key(grant_id)


def _win_remove_authorized_key(grant_id: str) -> bool:
    """Windows: remove a grant's key from authorized_keys."""
    try:
        # Check both admin and user authorized_keys files
        for auth_path in [_ADMIN_AUTH_KEYS, _USER_AUTH_KEYS]:
            if not auth_path.exists():
                continue

            try:
                content = auth_path.read_text(encoding="utf-8")
            except PermissionError:
                result = _win_run([
                    "powershell", "-NoProfile", "-Command",
                    f"Get-Content '{auth_path}' -Raw -ErrorAction SilentlyContinue"
                ])
                content = result.stdout if result.returncode == 0 else ""

            if f"{_GRANT_TAG}{grant_id}" not in content:
                continue

            lines = content.splitlines()
            filtered = [l for l in lines if f"{_GRANT_TAG}{grant_id}" not in l]
            new_content = "\n".join(filtered) + "\n" if filtered else ""

            try:
                auth_path.write_text(new_content, encoding="utf-8")
            except PermissionError:
                escaped = new_content.replace("'", "''")
                _win_run([
                    "powershell", "-NoProfile", "-Command",
                    f"Set-Content -Path '{auth_path}' -Value '{escaped}' -NoNewline"
                ])

            log.info(f"Grant {grant_id[:8]}: key removed from {auth_path}")

        return True
    except Exception as e:
        log.exception(f"Failed to remove authorized key for grant {grant_id[:8]}")
        return False


def _posix_remove_authorized_key(grant_id: str) -> bool:
    """Linux/macOS: remove a grant's key from authorized_keys."""
    try:
        result = _sudo_run(["cat", str(_AUTH_KEYS_PATH)])
        if result.returncode != 0:
            return True  # No file = nothing to remove

        lines = result.stdout.splitlines()
        filtered = [line for line in lines if f"{_GRANT_TAG}{grant_id}" not in line]

        if len(filtered) == len(lines):
            return True  # Key wasn't there

        new_content = "\n".join(filtered) + "\n" if filtered else ""
        proc = _sudo_run(["tee", str(_AUTH_KEYS_PATH)], input=new_content)
        if proc.returncode != 0:
            log.error(f"Failed to update authorized_keys: {proc.stderr}")
            return False

        log.info(f"Grant {grant_id[:8]}: key removed from authorized_keys")
        return True

    except Exception as e:
        log.exception(f"Failed to remove authorized key for grant {grant_id[:8]}")
        return False


def setup_sudoers(privilege_level: str) -> bool:
    """Setup elevated privileges for the orchestratia user.

    On Linux/macOS: creates sudoers drop-in.
    On Windows: adds user to local Administrators group.
    """
    if privilege_level != "elevated":
        return True

    if _IS_WINDOWS:
        return _win_setup_elevated()
    if HELPER_PLATFORM:
        return _linux_elevated(True)
    return _posix_setup_sudoers()


def _win_setup_elevated() -> bool:
    """Windows: add current user to Administrators group for elevated access."""
    try:
        username = os.environ.get("USERNAME", "")
        if not username:
            log.error("Cannot determine USERNAME for elevated access")
            return False

        # Check if already in Administrators
        result = _win_run([
            "powershell", "-NoProfile", "-Command",
            f"(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue).Name -match '{username}'"
        ])
        if "True" in result.stdout:
            log.info("User already in Administrators group")
            return True

        # Add to Administrators group
        result = _win_run([
            "powershell", "-NoProfile", "-Command",
            f"Add-LocalGroupMember -Group 'Administrators' -Member '{username}' -ErrorAction Stop"
        ])
        if result.returncode != 0:
            log.error(f"Failed to add user to Administrators: {result.stderr}")
            return False

        log.info(f"Elevated: added {username} to Administrators group")
        return True

    except Exception as e:
        log.exception(f"Failed to setup elevated access")
        return False


def _posix_setup_sudoers() -> bool:
    """Linux/macOS: create sudoers drop-in for orchestratia user."""
    try:
        # Defensive — sudoers for a user that doesn't exist is a no-op
        # waiting to confuse the next debugger. If install order ever
        # changes, this catches it.
        if not _posix_ensure_orchestratia_user():
            return False
        content = f"{_ORCHESTRATIA_USER} ALL=(ALL) NOPASSWD: ALL\n"
        proc = _sudo_run(["tee", str(_SUDOERS_PATH)], input=content)
        if proc.returncode != 0:
            log.error(f"Failed to write sudoers: {proc.stderr}")
            return False

        _sudo_run(["chmod", "440", str(_SUDOERS_PATH)])
        log.info("Elevated sudoers configured for orchestratia user")
        return True

    except Exception as e:
        log.exception(f"Failed to setup sudoers")
        return False


def remove_sudoers() -> bool:
    """Remove elevated privileges.

    On Linux/macOS: removes sudoers drop-in.
    On Windows: no-op (we don't remove from Administrators — too dangerous).
    """
    if _IS_WINDOWS:
        # Intentionally no-op on Windows. Removing a user from Administrators
        # mid-session could lock them out. Grants are revoked via authorized_keys
        # removal instead.
        log.info("Windows: elevated privilege removal is a no-op (revoke keys instead)")
        return True
    if HELPER_PLATFORM:
        return _linux_elevated(False)

    try:
        result = _sudo_run(["rm", "-f", str(_SUDOERS_PATH)])
        if result.returncode == 0:
            log.info("Removed orchestratia sudoers")
        return result.returncode == 0
    except Exception as e:
        log.exception(f"Failed to remove sudoers")
        return False


# ── Linux target role: the root-owned grant helper ────────────────────────────


_missing_logged = False


def _helper(args, input_data=None):
    """Run the grant helper through its one sudoers rule. Never raises: a missing helper or a sudo that fails or
    hangs comes back as a failed CompletedProcess. A missing helper costs no grant sudo call, only an hourly probe
    for the old rules: on a half-upgraded server (below) removals go through those instead."""
    global _missing_logged
    if not os.path.exists(GRANT_HELPER):
        if _legacy_rules_present():
            if not _legacy["logged"]:
                log.error(_HALF_UPGRADED)
                _legacy["logged"] = True
            return _legacy_helper(args, input_data)
        if not _missing_logged:              # once per process: the reconcile runs every minute
            log.error(_NO_HELPER)
            _missing_logged = True
        return subprocess.CompletedProcess(args, 127, "", _NO_HELPER)
    try:
        return _sudo_run([GRANT_HELPER, *args], input=input_data)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 1, "", "sudo grant-helper timed out")
    except OSError as e:
        return subprocess.CompletedProcess(args, 1, "", f"sudo grant-helper failed to run: {e}")


# ── A half-upgraded Linux server: removals only, through the 0.34 rules ──────────
# 0.35 code running where `secure-install` never ran (a 0.34 host updated once, or without sudo, then restarted): no
# helper, and the old broad rules in /etc/sudoers.d/orchestratia-agent are still there. Without this, a revoke on such
# a server would leave the grant's key working. Those rules exist on that server anyway; this uses them only to TAKE
# access away (remove a key, remove the elevated rule) and never to add a key or elevate. Once the update finishes
# (the helper is installed, the rules are gone) none of this runs.

_HALF_UPGRADED = ("this server is half-upgraded: the access-grant helper isn't installed and the old broad grant sudo "
                  "rules are still here. Revokes still go through the old rules; new grants and elevated access "
                  "don't work. Finish the upgrade: sudo orchestratia update, then sudo systemctl restart "
                  "orchestratia-agent")
_legacy = {"present": None, "at": 0.0, "logged": False}


def _legacy_reset():
    _legacy.update(present=None, at=0.0, logged=False)


def _legacy_sudo(cmd, input_data=None):
    try:
        return _sudo_run(cmd, input=input_data)
    except (subprocess.TimeoutExpired, OSError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", f"sudo failed: {e}")


def _legacy_rules_present():
    """Whether the 0.34 rule that writes authorized_keys is live (`sudo -n -l <cmd>` exits 0 only for a command the
    policy allows without a password). Probed at most hourly; a refused legacy command re-probes."""
    if _legacy["present"] is None or _clock() - _legacy["at"] >= STATUS_TTL:
        res = _legacy_sudo(["-l", "tee", str(_AUTH_KEYS_PATH)])
        _legacy.update(present=res.returncode == 0, at=_clock())
    return _legacy["present"]


def _legacy_failed(args, res):
    _legacy["present"] = None
    return subprocess.CompletedProcess(args, 1, "", f"old sudo rules: {(res.stderr or '').strip()}")


def _legacy_read_keys():
    """(text, None) or (None, the failed call). A missing file is no keys; a refused cat is a failure, never 'empty'."""
    res = _legacy_sudo(["cat", str(_AUTH_KEYS_PATH)])
    if res.returncode == 0:
        return res.stdout or "", None
    if "No such file" in (res.stderr or "") and "sudo:" not in (res.stderr or ""):
        return "", None
    return None, res


def _legacy_helper(args, input_data=None):
    """The helper's verbs a half-upgraded server can still do: status, remove-key, clear-elevated. add-key and
    ensure-user answer 127 (the helper is missing) and set-elevated answers 3 (refused): nothing is ever added or
    elevated this way. Status reports elevated as on (the rule can't be read without root), so the first reconcile
    without an elevated grant removes it."""
    op = args[0] if args else ""
    if op == "status":
        text, bad = _legacy_read_keys()
        if text is None:
            return _legacy_failed(args, bad)
        keys = {}
        for line in text.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[-1].startswith(_GRANT_TAG) and GRANT_ID.fullmatch(parts[-1][len(_GRANT_TAG):]):
                keys[parts[-1][len(_GRANT_TAG):]] = f"{parts[0]} {parts[1]}"
        return subprocess.CompletedProcess(args, 0, json.dumps({"user": True, "keys": keys, "elevated": True,
                                                                "elevated_allowed": False}), "")
    if op == "remove-key" and len(args) == 2 and GRANT_ID.fullmatch(args[1]):
        text, bad = _legacy_read_keys()
        if text is None:
            return _legacy_failed(args, bad)
        lines = text.splitlines()
        keep = [ln for ln in lines if f"{_GRANT_TAG}{args[1]}" not in ln]
        if len(keep) == len(lines):
            return subprocess.CompletedProcess(args, 0, "absent (old sudo rules)", "")
        res = _legacy_sudo(["tee", str(_AUTH_KEYS_PATH)], "\n".join(keep) + "\n" if keep else "")
        if res.returncode != 0:
            return _legacy_failed(args, res)
        return subprocess.CompletedProcess(args, 0, "removed (old sudo rules)", "")
    if op == "clear-elevated":
        res = _legacy_sudo(["rm", "-f", str(_SUDOERS_PATH)])
        if res.returncode != 0:
            return _legacy_failed(args, res)
        return subprocess.CompletedProcess(args, 0, "cleared (old sudo rules)", "")
    if op == "set-elevated":
        return subprocess.CompletedProcess(args, 3, "", _HALF_UPGRADED)
    return subprocess.CompletedProcess(args, 127, "", _HALF_UPGRADED)


class _TargetCache:
    """This server's grant-target state as this process last read (`grant-helper status`) or applied it, plus the
    grants revoked here (a revoked grant id is never re-added from a list fetched before the revoke)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.known, self.keys, self.elevated, self.elevated_allowed = False, {}, False, True
        self.revoked = set()
        self.read_at = 0.0
        self.policy_sig = None


_target = _TargetCache()


def _policy_sig():
    try:
        st = os.stat(POLICY_PATH)
    except OSError:
        return None
    return (st.st_ino, st.st_mtime_ns, st.st_size, st.st_ctime_ns)


def target_status(helper=None):
    res = (helper or _helper)(["status"])
    if res.returncode != 0:
        log.error(f"grant-helper status failed: {(res.stderr or '').strip()}")
        return None
    try:
        st = json.loads(res.stdout)
    except ValueError:
        return None
    return st if isinstance(st, dict) else None


def converge_target(desired, helper=None):
    """Make this server's grant-target state match `desired` ({grant_id: (public key, privilege level)}): the hub's
    COMPLETE list of target grants, from a successful (HTTP 200) fetch; the caller never passes a partial list. Calls
    the helper only for what differs from what it last reported or applied, so nothing changed means no sudo at all.
    - A tagged key whose grant the hub no longer lists is removed: a lost revoke push must not leave a working login
      (a source-side session may have copied the private key). The helper's status lists only orchestratia-grant
      tagged keys, so a key someone added by hand is never touched.
    - A grant revoked here is never re-added from a list fetched before the revoke.
    - Elevated is on while any listed (unrevoked) grant is elevated, and only where root's policy allows it; when none
      is left the rule goes. The policy itself is never changed here (only root's secure-install flags change it).
    The state is re-read when the owner changes the elevated-grant policy file (no sudo to notice) and hourly while
    there is something to verify. Returns how many helper calls it made."""
    if not HELPER_PLATFORM:
        return _legacy_converge(desired)
    helper = helper or _helper
    with _target.lock:
        return _converge_locked(desired, helper)


def _converge_locked(desired, helper):
    calls = 0
    desired = {gid: v for gid, v in desired.items() if gid not in _target.revoked}
    if _target.known:
        stale = (desired or _target.keys or _target.elevated) and _clock() - _target.read_at >= STATUS_TTL
        if stale or _policy_sig() != _target.policy_sig:
            _target.known = False
    if not _target.known:
        calls += 1
        sig = _policy_sig()
        st = target_status(helper)
        if st is None:
            return calls
        _target.keys = {k: v for k, v in (st.get("keys") or {}).items() if isinstance(k, str) and isinstance(v, str)}
        _target.elevated, _target.elevated_allowed = bool(st.get("elevated")), bool(st.get("elevated_allowed"))
        _target.known, _target.read_at, _target.policy_sig = True, _clock(), sig
    for gid in sorted(set(_target.keys) - set(desired)):        # revoked here, or no longer listed by the hub
        calls += 1
        res = helper(["remove-key", gid])
        if res.returncode == 0:
            _target.keys.pop(gid, None)
        else:
            _target.known = False
            log.error(f"Grant {gid[:8]}: grant-helper remove-key failed: {(res.stderr or '').strip()}")
    for gid, (key, _level) in sorted(desired.items()):
        try:
            norm = parse_key(key)
        except ValueError:
            norm = None
        if norm is None or not GRANT_ID.fullmatch(gid or ""):
            log.warning(f"Grant {str(gid)[:8]}: the hub sent a key or id this server won't install")
            continue
        if _target.keys.get(gid) == norm:
            continue
        calls += 1
        res = helper(["add-key", gid], norm + "\n")
        if res.returncode == 0:
            _target.keys[gid] = norm
        elif res.returncode == 127:
            pass                             # no helper (logged once): status still holds, retrying costs no sudo
        else:
            _target.known = False
            log.error(f"Grant {gid[:8]}: grant-helper add-key failed: {(res.stderr or '').strip()}")
    want = any(level == "elevated" for _key, level in desired.values())
    if want != _target.elevated and (_target.elevated_allowed or not want):
        calls += 1
        res = helper(["set-elevated" if want else "clear-elevated"])
        if res.returncode == 0:
            _target.elevated = want
        elif res.returncode == 3:
            _target.elevated_allowed = False
            log.error(f"Elevated grant not applied: {(res.stderr or '').strip()}")
        else:
            _target.known = False
            log.error(f"grant-helper elevated change failed: {(res.stderr or '').strip()}")
    return calls


def _legacy_converge(desired):
    """macOS / Windows: the per-grant calls the reconcile made before (unchanged behaviour)."""
    for gid, (key, level) in desired.items():
        setup_authorized_key(key, gid, level)
        if level == "elevated":
            setup_sudoers(level)
    return len(desired)


def _linux_add_key(public_key, grant_id):
    try:
        norm = parse_key(public_key)
    except ValueError as e:
        log.error(f"Grant {grant_id[:8]}: refusing the key: {e}")
        return False
    if not GRANT_ID.fullmatch(grant_id or ""):
        log.error(f"Grant {str(grant_id)[:8]}: refusing an invalid grant id")
        return False
    with _target.lock:
        res = _helper(["add-key", grant_id], norm + "\n")
        if res.returncode != 0:
            _target.known = False
            log.error(f"Grant {grant_id[:8]}: grant-helper add-key failed: {(res.stderr or '').strip()}")
            return False
        _target.keys[grant_id] = norm
    log.info(f"Grant {grant_id[:8]}: SSH access configured ({(res.stdout or '').strip()})")
    return True


def _linux_remove_key(grant_id):
    with _target.lock:
        _target.revoked.add(grant_id)
        res = _helper(["remove-key", grant_id])
        if res.returncode != 0:
            _target.known = False            # the next reconcile re-reads status and removes it again
            log.error(f"Grant {grant_id[:8]}: grant-helper remove-key failed: {(res.stderr or '').strip()}")
            return False
        _target.keys.pop(grant_id, None)
    log.info(f"Grant {grant_id[:8]}: SSH access removed ({(res.stdout or '').strip()})")
    return True


def _linux_elevated(on):
    with _target.lock:
        res = _helper(["set-elevated" if on else "clear-elevated"])
        if res.returncode == 0:
            _target.elevated = on
            return True
        if res.returncode == 3:
            _target.elevated_allowed = False
        else:
            _target.known = False
    log.error(f"Elevated grant {'set' if on else 'clear'} failed: {(res.stderr or '').strip()}")
    return False


# ── Source role (runs on Server A) ────────────────────────────────────────────

_KEY_DIR = Path.home() / ".orchestratia" / "ssh_keys"


def _win_restrict_file_acl(path: Path) -> None:
    """Windows: restrict a file to current user only (equivalent of chmod 600)."""
    try:
        path_str = str(path)
        username = os.environ.get("USERNAME", "")
        if not username:
            return
        # Remove inheritance and clear, then grant only current user
        _win_run(["icacls", path_str, "/inheritance:r"])
        _win_run(["icacls", path_str, "/grant:r", f"{username}:(F)"])
    except Exception as e:
        log.warning(f"Could not restrict ACLs on {path}: {e}")


def store_private_key(grant_id: str, pem: str) -> Path:
    """Store a private key PEM for SSH client use. Returns key file path."""
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    key_path = _KEY_DIR / f"grant_{grant_id}"
    key_path.write_text(pem)

    if _IS_WINDOWS:
        # Path.chmod on Windows only toggles read-only — use icacls for real ACLs
        _win_restrict_file_acl(key_path)
    else:
        key_path.chmod(0o600)

    log.info(f"Grant {grant_id[:8]}: private key stored at {key_path}")
    return key_path


def clean_known_hosts(port: int) -> None:
    """Remove stale SSH known_hosts entries for a tunnel port.

    When grants are recreated, the remote host key changes but the local port
    stays the same. SSH blocks the connection with REMOTE HOST IDENTIFICATION
    HAS CHANGED. This cleans the stale entry so the next connection succeeds.

    Uses `ssh-keygen -R`, which also matches HASHED entries (`|1|...`,
    Ubuntu's default HashKnownHosts) — a plain text match never did.
    """
    known_hosts = Path.home() / ".ssh" / "known_hosts"
    if not known_hosts.exists():
        return
    host = f"[localhost]:{port}"
    backup = Path(f"{known_hosts}.old")
    # ssh-keygen -R writes its backup to known_hosts.old — keep the user's own.
    users_backup = backup.read_bytes() if backup.exists() else None
    try:
        result = subprocess.run(
            ["ssh-keygen", "-R", host, "-f", str(known_hosts)],
            capture_output=True, text=True, timeout=10,
            **({"creationflags": subprocess.CREATE_NO_WINDOW} if _IS_WINDOWS else {}),
        )
        if result.returncode != 0:
            log.warning(f"Could not clean known_hosts for port {port}: {result.stderr.strip()}")
        elif "updated" in result.stdout or "updated" in result.stderr:
            log.info(f"Cleaned stale known_hosts entry for port {port}")
        if users_backup is None:
            backup.unlink(missing_ok=True)
        else:
            backup.write_bytes(users_backup)
    except FileNotFoundError:
        # No ssh-keygen (optional on Windows). Plain-text match: enough for
        # unhashed entries, which is what Windows OpenSSH writes by default.
        try:
            lines = known_hosts.read_text().splitlines()
            filtered = [l for l in lines if host not in l]
            if len(filtered) < len(lines):
                known_hosts.write_text("\n".join(filtered) + "\n")
                log.info(f"Cleaned {len(lines) - len(filtered)} stale known_hosts entry(s) for port {port}")
        except Exception as e:
            log.warning(f"Could not clean known_hosts for port {port}: {e}")
    except Exception as e:
        log.warning(f"Could not clean known_hosts for port {port}: {e}")


def remove_private_key(grant_id: str) -> bool:
    """Remove a stored private key."""
    key_path = _KEY_DIR / f"grant_{grant_id}"
    try:
        if key_path.exists():
            key_path.unlink()
            log.info(f"Grant {grant_id[:8]}: private key removed")
        return True
    except Exception as e:
        log.exception(f"Failed to remove private key for grant {grant_id[:8]}")
        return False
