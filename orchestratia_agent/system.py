"""Cross-platform system information gathering."""

import getpass
import os
import platform
import sys

import psutil


def get_system_info() -> dict:
    """Gather current system stats (cross-platform)."""
    mem = psutil.virtual_memory()

    # Disk path: "/" on POSIX, "C:\\" on Windows
    disk_path = "C:\\" if sys.platform == "win32" else "/"
    disk = psutil.disk_usage(disk_path)

    # OS-level username (used by hub to auto-resolve SSH usernames)
    if sys.platform == "win32":
        os_username = os.environ.get("USERNAME", "")
    else:
        try:
            os_username = getpass.getuser()
        except Exception:
            os_username = ""

    return {
        "cpu_count": psutil.cpu_count(),
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_total_gb": round(mem.total / (1024**3), 1),
        "memory_used_gb": round(mem.used / (1024**3), 1),
        "memory_percent": mem.percent,
        "disk_total_gb": round(disk.total / (1024**3), 1),
        "disk_used_gb": round(disk.used / (1024**3), 1),
        "disk_percent": round(disk.used / disk.total * 100, 1),
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": platform.python_version(),
        "uptime_seconds": int(psutil.boot_time()),
        "os_username": os_username,
    }


def get_repos_info(config: dict) -> dict:
    """Get repo paths from config."""
    repos = {}
    for name, repo_config in config.get("repos", {}).items():
        path = repo_config.get("path", "") if isinstance(repo_config, dict) else repo_config
        repos[name] = path
    return repos
