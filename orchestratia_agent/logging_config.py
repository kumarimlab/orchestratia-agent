"""Logging configuration with color support, debug modes, and file logging."""

import logging
import logging.handlers
import os
import sys


class ColorFormatter(logging.Formatter):
    """Log formatter that adds ANSI color codes when outputting to a TTY."""

    COLORS = {
        logging.DEBUG: "\033[2m",       # dim
        logging.INFO: "\033[0m",        # default
        logging.WARNING: "\033[33m",    # yellow
        logging.ERROR: "\033[31m",      # red
        logging.CRITICAL: "\033[1;31m", # bold red
    }
    RESET = "\033[0m"

    def __init__(self, fmt: str, datefmt: str | None = None, use_color: bool = True):
        super().__init__(fmt, datefmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        if self.use_color:
            color = self.COLORS.get(record.levelno, self.RESET)
            return f"{color}{msg}{self.RESET}"
        return msg


def _get_log_dir() -> str | None:
    """Get platform-appropriate log directory."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", "")
        if base:
            return os.path.join(base, "Orchestratia", "logs")
    else:
        # Linux/macOS: use /var/log for root, ~/.local/state for user
        if os.getuid() == 0:
            return "/var/log/orchestratia"
        return os.path.expanduser("~/.local/state/orchestratia/logs")
    return None


def setup_logging(debug: bool = False, verbose: bool = False) -> None:
    """Configure logging based on CLI flags.

    --debug:   DEBUG level, includes function:line in format
    --verbose: INFO level, but noisy libraries stay at INFO
    (default):  INFO level, noisy libraries quieted to WARNING

    On Windows, always adds a file handler (agent.log) since the exe
    runs with console=False and stderr goes to devnull.
    """
    if debug:
        level = logging.DEBUG
        fmt = "%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d %(message)s"
    else:
        level = logging.INFO
        fmt = "%(asctime)s [%(levelname)s] %(message)s"

    datefmt = "%Y-%m-%d %H:%M:%S"

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    # Console handler (useful when running interactively)
    use_color = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(ColorFormatter(fmt, datefmt, use_color=use_color))
    root.addHandler(console_handler)

    # File handler — essential on Windows where console=False
    log_dir = _get_log_dir()
    if log_dir:
        try:
            os.makedirs(log_dir, exist_ok=True)
            log_path = os.path.join(log_dir, "agent.log")
            file_handler = logging.handlers.RotatingFileHandler(
                log_path, maxBytes=5 * 1024 * 1024, backupCount=3,
            )
            file_handler.setFormatter(logging.Formatter(fmt, datefmt))
            root.addHandler(file_handler)
        except OSError:
            pass  # Can't create log dir — continue with console only

    # Quiet noisy libraries unless --debug
    if not debug:
        for lib in ("httpx", "httpcore", "websockets", "asyncio"):
            logging.getLogger(lib).setLevel(logging.WARNING)
    elif not verbose and not debug:
        for lib in ("httpx", "httpcore", "websockets"):
            logging.getLogger(lib).setLevel(logging.WARNING)
