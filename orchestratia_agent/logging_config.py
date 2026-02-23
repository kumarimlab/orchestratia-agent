"""Logging configuration with color support and debug/verbose modes."""

import logging
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


def setup_logging(debug: bool = False, verbose: bool = False) -> None:
    """Configure logging based on CLI flags.

    --debug:   DEBUG level, includes function:line in format
    --verbose: INFO level, but noisy libraries stay at INFO
    (default):  INFO level, noisy libraries quieted to WARNING
    """
    if debug:
        level = logging.DEBUG
        fmt = "%(asctime)s [%(levelname)s] %(name)s:%(funcName)s:%(lineno)d %(message)s"
    else:
        level = logging.INFO
        fmt = "%(asctime)s [%(levelname)s] %(message)s"

    datefmt = "%Y-%m-%d %H:%M:%S"
    use_color = hasattr(sys.stderr, "isatty") and sys.stderr.isatty()

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ColorFormatter(fmt, datefmt, use_color=use_color))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Quiet noisy libraries unless --debug
    if not debug:
        for lib in ("httpx", "httpcore", "websockets", "asyncio"):
            logging.getLogger(lib).setLevel(logging.WARNING)
    elif not verbose and not debug:
        for lib in ("httpx", "httpcore", "websockets"):
            logging.getLogger(lib).setLevel(logging.WARNING)
