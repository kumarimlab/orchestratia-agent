#!/usr/bin/env python3
"""Relay reconnection — an editor must survive a relay restart.

Dependency-free — run directly:  python3 tests/test_relay_client.py

The relay client used to give up after one failed connect. That meant every
relay deploy — and every autoheal restart — permanently orphaned every open
editor: the browser got "502 editor is not connected" forever, because nothing
re-established the link until a brand-new code_server_start.

Two properties matter, and they pull in opposite directions:

  * TRANSIENT failures must retry. A restarting relay is a 502 from nginx and a
    perfectly normal thing to ride out.
  * PERMANENT rejections must NOT retry. The relay closes 4401/4403 when the
    session is not ours, revoked, or closed; retrying that forever is a pointless
    login storm against a session that is gone. This is also what lets the loop
    terminate on its own: once the session ends, the relay says 4403 and the
    agent stops.

Backoff is jittered because every agent reconnects at the same instant after a
relay deploy — identical timers would turn that into a synchronised stampede.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import relay_client as rc  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def test_backoff_grows_caps_and_jitters():
    lows = [rc.backoff_for(i) for i in range(0, 8)]
    ok("backoff is positive from the first attempt", all(v > 0 for v in lows), lows[:3])
    ok("backoff grows with consecutive failures", lows[0] < lows[3], f"{lows[0]} -> {lows[3]}")
    ok("backoff is capped (no runaway sleep)",
       all(v <= rc.MAX_BACKOFF_SECONDS for v in lows), max(lows))
    spread = {round(rc.backoff_for(4), 4) for _ in range(12)}
    ok("backoff is jittered — agents must not reconnect in lockstep",
       len(spread) > 1, f"{len(spread)} distinct values")


def test_permanent_rejections_stop_the_loop():
    ok("4403 (not your session / revoked) is permanent", rc.should_retry(4403) is False)
    ok("4401 (bad handshake) is permanent", rc.should_retry(4401) is False)
    ok("an abnormal close is transient", rc.should_retry(1006) is True)
    ok("a clean server close is transient", rc.should_retry(1000) is True)
    ok("no close code at all (connect never completed) is transient",
       rc.should_retry(None) is True)


def test_backoff_resets_after_a_successful_connection():
    """A link that connected and later dropped must retry FAST again.

    Without a reset the attempt counter only ever grows, so an editor that rode
    out a long outage would then sit at the 30s ceiling for every subsequent
    blip — slowest exactly when the system is healthy again.
    """
    st = rc.RetryState()
    for _ in range(6):
        st.failed()
    ok("backoff has climbed after repeated failures", st.next_delay() > rc.BASE_BACKOFF_SECONDS)
    st.connected()
    ok("a successful connection resets the backoff",
       st.next_delay() <= rc.BASE_BACKOFF_SECONDS, st.next_delay())


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            failures.append((fn.__name__, f"{type(e).__name__}: {e}"))
    bad = [r for r in results if not r]
    if failures or bad:
        for name, msg in failures:
            print(f"ERROR {name}: {msg}")
        print(f"\n{len(bad)} assertion(s) failed, {len(failures)} error(s)")
        raise SystemExit(1)
    print(f"ok  {len(results)} assertions passed")


if __name__ == "__main__":
    main()
