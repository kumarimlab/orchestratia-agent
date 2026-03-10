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


def save_config(path: str, data: dict) -> None:
    """Write config back to YAML file."""
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


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


def persist_api_key(config_path: str, key: str, server_id: str | None = None) -> None:
    """After registration, save the API key, server_id, and remove the consumed token."""
    if not os.path.exists(config_path):
        return
    cfg = load_config(config_path)
    cfg["api_key"] = key
    if server_id:
        cfg["server_id"] = server_id
    cfg.pop("registration_token", None)
    save_config(config_path, cfg)
    log.info(f"API key saved to {config_path} (registration_token removed)")
