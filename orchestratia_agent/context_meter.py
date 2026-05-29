"""Context-window usage meter — shared, dependency-free helper.

Core principle: MEASURE AT THE WORKER. Only a worker's own agent process
knows its real context-window usage; the hub and orchestrator are
consumers of the reading the worker reports.

This module turns a raw `(used_tokens, window_size)` pair into a small,
JSON-serializable reading `{used, window, pct, ts}`. It is intentionally
free of third-party dependencies and side effects so it can be unit
tested in isolation and imported from anywhere (daemon endpoint, CLI,
tests).
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass

# Claude Code's default context window. Overridable per reading because
# different models / agents expose different window sizes.
DEFAULT_WINDOW_SIZE = 200_000


@dataclass
class ContextReading:
    """A single context-usage sample for one session.

    `pct` is the percentage (0–100, rounded to one decimal) of the window
    consumed. `ts` is a unix timestamp (seconds) of when the reading was
    computed.
    """

    used: int
    window: int
    pct: float
    ts: float

    def to_dict(self) -> dict:
        return asdict(self)


def compute_pct(used_tokens: int, window_size: int = DEFAULT_WINDOW_SIZE) -> float:
    """Return the percentage of the context window consumed (0–100).

    Defensive: negative/garbage inputs are coerced; a non-positive window
    yields 0.0 rather than dividing by zero. The result is clamped to
    [0, 100] and rounded to one decimal place.
    """
    try:
        used = max(0, int(used_tokens))
    except (TypeError, ValueError):
        used = 0
    try:
        window = int(window_size)
    except (TypeError, ValueError):
        window = DEFAULT_WINDOW_SIZE
    if window <= 0:
        return 0.0
    pct = (used / window) * 100.0
    if pct < 0.0:
        pct = 0.0
    elif pct > 100.0:
        pct = 100.0
    return round(pct, 1)


def make_reading(
    used_tokens: int,
    window_size: int = DEFAULT_WINDOW_SIZE,
    ts: float | None = None,
) -> ContextReading:
    """Build a `ContextReading` from raw counters.

    `window_size` falls back to `DEFAULT_WINDOW_SIZE` when not positive.
    `ts` defaults to the current time when omitted.
    """
    try:
        used = max(0, int(used_tokens))
    except (TypeError, ValueError):
        used = 0
    try:
        window = int(window_size)
    except (TypeError, ValueError):
        window = DEFAULT_WINDOW_SIZE
    if window <= 0:
        window = DEFAULT_WINDOW_SIZE
    return ContextReading(
        used=used,
        window=window,
        pct=compute_pct(used, window),
        ts=time.time() if ts is None else float(ts),
    )
