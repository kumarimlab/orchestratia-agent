"""SSH key and sudoers management for access grants.

Target role (Server B): manages authorized_keys for the 'orchestratia' system user.
Source role (Server A): stores/removes private keys for SSH client use.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

log = logging.getLogger("orchestratia-agent.ssh_setup")

_ORCHESTRATIA_USER = "orchestratia"
_ORCHESTRATIA_HOME = Path(f"/home/{_ORCHESTRATIA_USER}")
_AUTH_KEYS_PATH = _ORCHESTRATIA_HOME / ".ssh" / "authorized_keys"
_SUDOERS_PATH = Path(f"/etc/sudoers.d/{_ORCHESTRATIA_USER}")
_GRANT_TAG = "orchestratia-grant:"


# ── Target role (runs on Server B) ──────────────────────────────────────────


def _sudo_run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a command with sudo, suppressing password prompts."""
    return subprocess.run(
        ["sudo", "-n"] + cmd,
        capture_output=True, text=True, timeout=10,
        **kwargs,
    )


def setup_authorized_key(public_key: str, grant_id: str) -> bool:
    """Add a public key to orchestratia user's authorized_keys with grant tag."""
    if sys.platform == "win32":
        log.warning("SSH access setup not supported on Windows")
        return False

    tagged_key = f"{public_key} {_GRANT_TAG}{grant_id}"

    try:
        # Ensure .ssh directory exists
        ssh_dir = _ORCHESTRATIA_HOME / ".ssh"
        _sudo_run(["mkdir", "-p", str(ssh_dir)])
        _sudo_run(["chmod", "700", str(ssh_dir)])
        _sudo_run(["chown", f"{_ORCHESTRATIA_USER}:{_ORCHESTRATIA_USER}", str(ssh_dir)])

        # Read existing keys (if any)
        result = _sudo_run(["cat", str(_AUTH_KEYS_PATH)])
        existing = result.stdout if result.returncode == 0 else ""

        # Check if grant already exists
        if f"{_GRANT_TAG}{grant_id}" in existing:
            log.info(f"Grant {grant_id[:8]}: key already in authorized_keys")
            return True

        # Append new key
        new_content = existing.rstrip("\n") + "\n" + tagged_key + "\n" if existing.strip() else tagged_key + "\n"
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
    if sys.platform == "win32":
        return False

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
    """Setup sudoers for orchestratia user if privilege_level is 'elevated'."""
    if privilege_level != "elevated":
        return True

    if sys.platform == "win32":
        return False

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
    """Remove sudoers file for orchestratia user."""
    if sys.platform == "win32":
        return False

    try:
        result = _sudo_run(["rm", "-f", str(_SUDOERS_PATH)])
        if result.returncode == 0:
            log.info("Removed orchestratia sudoers")
        return result.returncode == 0
    except Exception as e:
        log.error(f"Failed to remove sudoers: {e}")
        return False


# ── Source role (runs on Server A) ──────────────────────────────────────────

_KEY_DIR = Path.home() / ".orchestratia" / "ssh_keys"


def store_private_key(grant_id: str, pem: str) -> Path:
    """Store a private key PEM for SSH client use. Returns key file path."""
    _KEY_DIR.mkdir(parents=True, exist_ok=True)
    key_path = _KEY_DIR / f"grant_{grant_id}"
    key_path.write_text(pem)
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
