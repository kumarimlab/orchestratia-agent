#!/usr/bin/env python3
"""Tests for orchestratia_agent/privilege.py — tier resolution and workspace verification.

Dependency-free — run directly:  python3 tests/test_privilege.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import privilege as p  # noqa: E402


def cfg(**kw):
    base = {"privilege": {"restricted_user": "orc-agent",
                          "workspaces": ["/srv/acme", "/home/ubuntu/repo"],
                          "tmux_path": "/usr/bin/tmux"}}
    base["privilege"].update(kw)
    return base


def test_unprovisioned_box_offers_only_standard():
    tc = p.load_tier_config({})
    assert tc.restricted_user is None
    assert p.available_tiers(tc) == [p.TIER_STANDARD]


def test_provisioned_box_offers_both():
    tc = p.load_tier_config(cfg())
    assert p.available_tiers(tc) == [p.TIER_STANDARD, p.TIER_RESTRICTED]


def test_standard_resolves_to_daemon_user():
    assert p.resolve_user(p.TIER_STANDARD, p.load_tier_config(cfg())) is None


def test_restricted_resolves_to_configured_user():
    assert p.resolve_user(p.TIER_RESTRICTED, p.load_tier_config(cfg())) == "orc-agent"


def test_restricted_on_unprovisioned_box_is_refused():
    try:
        p.resolve_user(p.TIER_RESTRICTED, p.load_tier_config({}))
    except p.PrivilegeError:
        return
    raise AssertionError("must refuse restricted when no user is provisioned")


def test_unknown_tier_is_refused():
    try:
        p.resolve_user("break_glass", p.load_tier_config(cfg()))
    except p.PrivilegeError:
        return
    raise AssertionError("unknown tier must be refused, not silently downgraded")


def test_workspace_inside_grant_is_accepted():
    tc = p.load_tier_config(cfg())
    assert p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme/sub/dir", tc) == "/srv/acme/sub/dir"


def test_workspace_outside_grant_is_refused():
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/etc", tc)
    except p.PrivilegeError:
        return
    raise AssertionError("ungranted directory must be refused")


def test_traversal_escape_is_refused():
    """/srv/acme/../../etc must not pass just because it starts with /srv/acme."""
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme/../../etc", tc)
    except p.PrivilegeError:
        return
    raise AssertionError("path traversal out of a workspace must be refused")


def test_sibling_prefix_is_not_a_match():
    """/srv/acme-other must NOT match the /srv/acme grant (string-prefix bug)."""
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme-other", tc)
    except p.PrivilegeError:
        return
    raise AssertionError("sibling directory sharing a prefix must not be treated as granted")


def test_missing_working_dir_is_refused_for_restricted():
    """No $HOME fallback: a fallback would make a privilege decision silently."""
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, None, tc)
    except p.PrivilegeError:
        return
    raise AssertionError("restricted tier must refuse an unspecified working_dir")


def test_standard_tier_allows_any_dir():
    tc = p.load_tier_config(cfg())
    assert p.verify_workspace(p.TIER_STANDARD, "/anywhere", tc) == "/anywhere"


def test_sudo_prefix_for_standard_is_empty():
    assert p.sudo_prefix(None, p.load_tier_config(cfg())) == []


def test_sudo_prefix_uses_H_not_i():
    """-H sets HOME without a login shell. -i re-parses args through a shell,
    which breaks any workspace path containing a space."""
    pre = p.sudo_prefix("orc-agent", p.load_tier_config(cfg()))
    assert pre == ["sudo", "-n", "-u", "orc-agent", "-H"], pre
    assert "-i" not in pre


def test_capability_payload_shape():
    payload = p.capability_payload(p.load_tier_config(cfg()))
    assert payload == {"tiers": ["standard", "restricted"],
                       "restricted_workspaces": ["/srv/acme", "/home/ubuntu/repo"]}


def test_capability_payload_unprovisioned():
    payload = p.capability_payload(p.load_tier_config({}))
    assert payload == {"tiers": ["standard"], "restricted_workspaces": []}


def test_capability_merges_into_existing_capabilities():
    """Advertising privilege must not clobber tags/tools/languages used by
    the hub's task-matching service."""
    tc = p.load_tier_config(cfg())
    existing = {"tags": ["gpu"], "tools": ["claude"]}
    merged = p.merge_capabilities(existing, tc)
    assert merged["tags"] == ["gpu"]
    assert merged["tools"] == ["claude"]
    assert merged["privilege"]["tiers"] == ["standard", "restricted"]


def test_capability_merge_tolerates_none():
    tc = p.load_tier_config({})
    merged = p.merge_capabilities(None, tc)
    assert merged["privilege"]["tiers"] == ["standard"]


def test_capability_merge_does_not_mutate_input():
    """The caller's config dict must not be edited underneath it."""
    tc = p.load_tier_config(cfg())
    existing = {"tags": ["gpu"]}
    p.merge_capabilities(existing, tc)
    assert "privilege" not in existing


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
