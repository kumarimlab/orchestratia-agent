"""Configuration loading, saving, and platform-aware path defaults."""

import base64
import logging
import os
import platform
import sys

import yaml

log = logging.getLogger("orchestratia-agent")


def default_config_path() -> str:
    """Return the platform-appropriate default config file path.

    On Linux: /etc/orchestratia/ when running as root (system service),
    ~/.config/orchestratia/ when running as regular user.
    """
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/Orchestratia/config.yaml")
    elif sys.platform == "win32":
        appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        return os.path.join(appdata, "Orchestratia", "config.yaml")
    else:
        if os.geteuid() == 0:
            return "/etc/orchestratia/config.yaml"
        # User-level first, fall back to system-level (install.sh puts config there)
        user_path = os.path.expanduser("~/.config/orchestratia/config.yaml")
        if os.path.exists(user_path):
            return user_path
        system_path = "/etc/orchestratia/config.yaml"
        if os.path.exists(system_path):
            return system_path
        return user_path  # default for new installs


def default_log_dir() -> str:
    """Return the platform-appropriate default log directory."""
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Logs/Orchestratia")
    elif sys.platform == "win32":
        appdata = os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        return os.path.join(appdata, "Orchestratia", "logs")
    else:
        if os.geteuid() == 0:
            return "/var/log/orchestratia"
        return os.path.expanduser("~/.local/share/orchestratia/logs")


def load_config(path: str) -> dict:
    """Load YAML config file."""
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _config_owner(existing, directory) -> tuple[int, int]:
    """Who a config written by root should belong to: an existing non-root owner, else
    the owner of its directory (the installer gives /etc/orchestratia to the daemon
    user). Root-owned 0600 would lock the daemon out of its own config."""
    if existing is not None and existing.st_uid != 0:
        return existing.st_uid, existing.st_gid
    return directory.st_uid, directory.st_gid


def save_config(path: str, data: dict) -> None:
    """Write config atomically, readable by its owner only.

    It holds the server API key. Written 0644 (root-owned, since the installer
    registers as root), a locked-down project user could read the key and act as the
    server against the hub. Found on staging, 2026-09-14.
    """
    directory = os.path.dirname(os.path.abspath(path))
    try:
        existing = os.stat(path)
    except FileNotFoundError:
        existing = None
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        if hasattr(os, "fchown") and os.geteuid() == 0:
            os.fchown(fd, *_config_owner(existing, os.stat(directory)))
        with os.fdopen(fd, "w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def secure_config_file(path: str) -> str:
    """Make sure nobody but the owner can read the config: "ok", "fixed", or "exposed"
    (readable by others and not ours to chmod — e.g. root-owned from an old install)."""
    if sys.platform == "win32":
        return "ok"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "ok"
    if not st.st_mode & 0o077:
        return "ok"
    if st.st_uid == os.getuid():
        os.chmod(path, 0o600)
        return "fixed"
    return "exposed"


def config_permission_warning(path: str, has_restricted_tier: bool) -> str | None:
    """Repair the config's mode if we can; otherwise say exactly how, louder when a
    locked-down tier makes other local users part of the threat model."""
    if secure_config_file(path) != "exposed":
        return None
    fix = f"sudo chown $(whoami) {path} && sudo chmod 600 {path}"
    if has_restricted_tier:
        return (f"{path} holds this server's API key and is readable by other users, including "
                f"the locked-down project users — they can act as this server. Fix now: {fix}")
    return f"{path} holds this server's API key and is readable by other users. Fix: {fix}"


def parse_token_hub_url(token: str) -> str | None:
    """Extract the hub URL from a self-contained registration token."""
    if not token.startswith("orcreg_"):
        return None
    payload = token[7:]
    parts = payload.split(".", 1)
    if len(parts) != 2:
        return None
    url_b64 = parts[0]
    padding = 4 - len(url_b64) % 4
    if padding != 4:
        url_b64 += "=" * padding
    try:
        return base64.urlsafe_b64decode(url_b64).decode()
    except Exception:
        return None


def ensure_config_for_register(config_path: str, token: str) -> dict:
    """Create or update config for --register mode."""
    hub = parse_token_hub_url(token)
    if not hub:
        log.error("Invalid token format — cannot extract hub URL")
        log.error("  Remediation:")
        log.error("    1. Verify the token starts with 'orcreg_'")
        log.error("    2. Copy the full token from the dashboard (Servers -> Register Server)")
        log.error("    3. Ensure no whitespace or line breaks in the token")
        sys.exit(1)

    if os.path.exists(config_path):
        cfg = load_config(config_path)
    else:
        cfg = {
            "server_name": platform.node(),
            "repos": {},
            "claude": {
                "binary": "claude",
            },
        }

    cfg["hub_url"] = hub
    cfg["registration_token"] = token
    cfg.pop("api_key", None)

    os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
    save_config(config_path, cfg)
    log.info(f"Config written to {config_path}")
    return cfg


def persist_api_key(config_path: str, key: str) -> None:
    """After registration, save the API key and remove the consumed token."""
    if not os.path.exists(config_path):
        return
    cfg = load_config(config_path)
    cfg["api_key"] = key
    cfg.pop("registration_token", None)
    cfg.pop("server_id", None)  # Legacy field, no longer used
    save_config(config_path, cfg)
    log.info(f"API key saved to {config_path} (registration_token removed)")
