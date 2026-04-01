"""SSH key and sudoers management for access grants.

Target role (Server B): manages authorized_keys for SSH access.
  - Linux/macOS: 'orchestratia' system user + ~/.ssh/authorized_keys
  - Windows: OpenSSH server + administrators_authorized_keys or user authorized_keys

Source role (Server A): stores/removes private keys for SSH client use.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

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


def _win_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command on Windows, capturing output."""
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=15,
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
            log.error(f"Failed to start sshd: {e}")
            return False

    # Not installed — try to install the OpenSSH Server optional feature
    log.info("OpenSSH Server not found, attempting to install...")
    try:
        result = _win_run([
            "powershell", "-NoProfile", "-Command",
            "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"
        ], timeout=120)
        if result.returncode != 0:
            log.error(f"Failed to install OpenSSH Server: {result.stderr}")
            return False

        # Start and enable
        _win_run(["powershell", "-NoProfile", "-Command",
                  "Start-Service sshd; Set-Service sshd -StartupType Automatic"])
        log.info("Installed and started OpenSSH Server")
        return True
    except Exception as e:
        log.error(f"Failed to install OpenSSH Server: {e}")
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
        log.error(f"Failed to set ACLs on {path}: {e}")
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
    """Run a command with sudo, suppressing password prompts (Linux/macOS)."""
    return subprocess.run(
        ["sudo", "-n"] + cmd,
        capture_output=True, text=True, timeout=10,
        **kwargs,
    )


def setup_authorized_key(public_key: str, grant_id: str,
                         privilege_level: str = "standard") -> bool:
    """Add a public key to authorized_keys with grant tag.

    On Linux/macOS: manages /home/orchestratia/.ssh/authorized_keys
    On Windows: manages OpenSSH authorized_keys (admin or user level)
    """
    tagged_key = f"{public_key} {_GRANT_TAG}{grant_id}"

    if _IS_WINDOWS:
        return _win_setup_authorized_key(tagged_key, grant_id, privilege_level)
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
        log.error(f"Failed to setup authorized key for grant {grant_id[:8]}: {e}")
        return False


def _posix_setup_authorized_key(tagged_key: str, grant_id: str) -> bool:
    """Linux/macOS: add public key to orchestratia user's authorized_keys."""
    try:
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
        proc = subprocess.run(
            ["sudo", "-n", "tee", str(_AUTH_KEYS_PATH)],
            input=new_content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log.error(f"Failed to write authorized_keys: {proc.stderr}")
            return False

        _sudo_run(["chmod", "600", str(_AUTH_KEYS_PATH)])
        _sudo_run(["chown", f"{_ORCHESTRATIA_USER}:{_ORCHESTRATIA_USER}", str(_AUTH_KEYS_PATH)])

        log.info(f"Grant {grant_id[:8]}: SSH access configured (key added)")
        return True

    except Exception as e:
        log.error(f"Failed to setup authorized key for grant {grant_id[:8]}: {e}")
        return False


def remove_authorized_key(grant_id: str) -> bool:
    """Remove the key tagged with grant_id from authorized_keys."""
    if _IS_WINDOWS:
        return _win_remove_authorized_key(grant_id)
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
        log.error(f"Failed to remove authorized key for grant {grant_id[:8]}: {e}")
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
        proc = subprocess.run(
            ["sudo", "-n", "tee", str(_AUTH_KEYS_PATH)],
            input=new_content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log.error(f"Failed to update authorized_keys: {proc.stderr}")
            return False

        log.info(f"Grant {grant_id[:8]}: key removed from authorized_keys")
        return True

    except Exception as e:
        log.error(f"Failed to remove authorized key for grant {grant_id[:8]}: {e}")
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
        log.error(f"Failed to setup elevated access: {e}")
        return False


def _posix_setup_sudoers() -> bool:
    """Linux/macOS: create sudoers drop-in for orchestratia user."""
    try:
        content = f"{_ORCHESTRATIA_USER} ALL=(ALL) NOPASSWD: ALL\n"
        proc = subprocess.run(
            ["sudo", "-n", "tee", str(_SUDOERS_PATH)],
            input=content, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            log.error(f"Failed to write sudoers: {proc.stderr}")
            return False

        _sudo_run(["chmod", "440", str(_SUDOERS_PATH)])
        log.info("Elevated sudoers configured for orchestratia user")
        return True

    except Exception as e:
        log.error(f"Failed to setup sudoers: {e}")
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

    try:
        result = _sudo_run(["rm", "-f", str(_SUDOERS_PATH)])
        if result.returncode == 0:
            log.info("Removed orchestratia sudoers")
        return result.returncode == 0
    except Exception as e:
        log.error(f"Failed to remove sudoers: {e}")
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


def remove_private_key(grant_id: str) -> bool:
    """Remove a stored private key."""
    key_path = _KEY_DIR / f"grant_{grant_id}"
    try:
        if key_path.exists():
            key_path.unlink()
            log.info(f"Grant {grant_id[:8]}: private key removed")
        return True
    except Exception as e:
        log.error(f"Failed to remove private key for grant {grant_id[:8]}: {e}")
        return False
