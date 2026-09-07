#!/usr/bin/env python3
"""Every hub->daemon message must be classified by privilege.

remote_exec was found by reading code. This test means the next one is found by
CI. Dependency-free — run:  python3 tests/test_privilege_surface.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.privilege_surface import (  # noqa: E402
    PRIVILEGE_CLASSIFICATION, UNCONFINED, message_types_in_hub,
)

HUB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "orchestratia_agent", "hub.py")


def _found():
    with open(HUB) as fh:
        return message_types_in_hub(fh.read())


def test_every_message_type_is_classified():
    missing = sorted(_found() - set(PRIVILEGE_CLASSIFICATION))
    assert not missing, (
        f"unclassified hub message types: {missing}. Add each to "
        f"PRIVILEGE_CLASSIFICATION — a new message must not join the "
        f"unconfined set silently."
    )


def test_no_stale_classifications():
    stale = sorted(set(PRIVILEGE_CLASSIFICATION) - _found())
    assert not stale, f"classified but no longer handled: {stale}"


def test_unconfined_set_is_explicit_and_small():
    """Unconfined entries are a standing liability. Keep the list short enough
    that adding one is a visible decision rather than a rounding error."""
    unconfined = sorted(k for k, v in PRIVILEGE_CLASSIFICATION.items()
                        if v == UNCONFINED)
    assert len(unconfined) <= 12, (
        f"{len(unconfined)} unconfined message types: {unconfined}"
    )


def test_remote_exec_is_tier_bounded():
    """The one that was actually exploitable."""
    assert PRIVILEGE_CLASSIFICATION["remote_exec"] == "tier_bounded"


def test_every_value_is_a_known_bucket():
    bad = {k: v for k, v in PRIVILEGE_CLASSIFICATION.items()
           if v not in ("tier_bounded", "no_execution", "unconfined")}
    assert not bad, bad


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = []
    for fn in CASES:
        try:
            fn()
        except AssertionError as e:
            failures.append((fn.__name__, str(e) or "assertion failed"))
        except Exception as e:  # noqa: BLE001
            failures.append((fn.__name__, f"{type(e).__name__}: {e}"))
    if failures:
        for name, msg in failures:
            print(f"FAIL  {name}: {msg}")
        print(f"\n{len(failures)}/{len(CASES)} failed")
        raise SystemExit(1)
    print(f"ok  {len(CASES)} passed")


if __name__ == "__main__":
    main()
