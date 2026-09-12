#!/usr/bin/env python3
"""Tests for orchestratia_agent/privilege.py — per-project tier resolution.

Dependency-free — run directly:  python3 tests/test_privilege.py

Restricted sessions run as a per-PROJECT OS user (orcp-<project>). The user of a
session is resolved from its project_id; a session whose project is not
provisioned is refused, never run under another project's user.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import privilege as p  # noqa: E402

PID_A = "a1b2c3d4-5e6f-7890-abcd-ef0123456789"
PID_B = "99887766-5544-3322-1100-ffeeddccbbaa"


def cfg(**kw):
    """A box provisioned for one project (PID_A) with two workspaces."""
    base = {"privilege": {
        "tmux_path": "/usr/bin/tmux",
        "git_path": "/usr/bin/git",
        "projects": {
            PID_A: {"user": "orcp-a1b2c3d45e6f",
                    "workspaces": ["/srv/acme", "/home/ubuntu/repo"]},
        },
    }}
    base["privilege"].update(kw)
    return base


# ── deterministic username (T1) ──────────────────────────────────────────────

def test_project_username_is_deterministic_and_compliant():
    u = p.project_username(PID_A)
    assert u == "orcp-a1b2c3d45e6f", u
    assert len(u) <= 32
    assert re.match(r"^[a-z_][a-z0-9_-]{0,31}$", u)
    assert p.project_username(PID_A) == u


def test_project_username_rejects_non_hex():
    for bad in ("not-a-uuid-zzzz", "", "short"):
        try:
            p.project_username(bad)
        except p.PrivilegeError:
            continue
        raise AssertionError(f"{bad!r} should have been refused")


def test_project_username_is_case_insensitive_on_input():
    assert p.project_username(PID_A.upper()) == p.project_username(PID_A)


# ── config load + legacy normalization (T1) ──────────────────────────────────

def test_load_tier_config_reads_projects_map():
    tc = p.load_tier_config(cfg())
    assert tc.git_path == "/usr/bin/git"
    assert tc.projects[PID_A].user == "orcp-a1b2c3d45e6f"
    assert tc.projects[PID_A].workspaces == ("/srv/acme", "/home/ubuntu/repo")


def test_load_tier_config_normalizes_legacy_flat_config():
    tc = p.load_tier_config({"privilege": {
        "restricted_user": "orc-agent", "workspaces": ["/srv/legacy"]}})
    assert p.LEGACY_KEY in tc.projects
    assert tc.projects[p.LEGACY_KEY].user == "orc-agent"
    # a legacy config exposes NO real project
    assert [k for k in tc.projects if k != p.LEGACY_KEY] == []


def test_unprovisioned_box_has_no_projects():
    tc = p.load_tier_config({})
    assert tc.projects == {}


# ── available tiers (T2) ──────────────────────────────────────────────────────

def test_unprovisioned_box_offers_only_standard():
    assert p.available_tiers(p.load_tier_config({})) == [p.TIER_STANDARD]


def test_legacy_only_box_offers_only_standard():
    """A legacy host must re-provision; LEGACY_KEY does not count as a real project."""
    tc = p.load_tier_config({"privilege": {
        "restricted_user": "orc-agent", "workspaces": ["/srv/legacy"]}})
    assert p.available_tiers(tc) == [p.TIER_STANDARD]


def test_provisioned_box_offers_both():
    assert p.available_tiers(p.load_tier_config(cfg())) == \
        [p.TIER_STANDARD, p.TIER_RESTRICTED]


# ── resolve_user (T2) ─────────────────────────────────────────────────────────

def test_standard_resolves_to_daemon_user():
    assert p.resolve_user(p.TIER_STANDARD, PID_A, p.load_tier_config(cfg())) is None
    # standard does not even need a project
    assert p.resolve_user(p.TIER_STANDARD, None, p.load_tier_config(cfg())) is None


def test_restricted_resolves_to_the_projects_user():
    assert p.resolve_user(p.TIER_RESTRICTED, PID_A, p.load_tier_config(cfg())) == \
        "orcp-a1b2c3d45e6f"


def test_restricted_refuses_unprovisioned_project():
    tc = p.load_tier_config(cfg())
    for pid in (PID_B, None, p.LEGACY_KEY):
        try:
            p.resolve_user(p.TIER_RESTRICTED, pid, tc)
        except p.PrivilegeError:
            continue
        raise AssertionError(f"must refuse restricted for unprovisioned project {pid!r}")


def test_restricted_on_unprovisioned_box_is_refused():
    try:
        p.resolve_user(p.TIER_RESTRICTED, PID_A, p.load_tier_config({}))
    except p.PrivilegeError:
        return
    raise AssertionError("must refuse restricted when nothing is provisioned")


def test_unknown_tier_is_refused():
    try:
        p.resolve_user("break_glass", PID_A, p.load_tier_config(cfg()))
    except p.PrivilegeError:
        return
    raise AssertionError("unknown tier must be refused, not silently downgraded")


# ── verify_workspace (T2) — security regressions carried over, per-project ────

def test_workspace_inside_grant_is_accepted():
    tc = p.load_tier_config(cfg())
    assert p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme/sub/dir", PID_A, tc) == \
        "/srv/acme/sub/dir"


def test_workspace_of_another_project_is_refused():
    """The cross-tenant case: a path granted to project B must not be usable by a
    session for project A, even on a box that provisions both."""
    both = cfg()
    both["privilege"]["projects"][PID_B] = {"user": "orcp-998877665544",
                                            "workspaces": ["/srv/beta"]}
    tc = p.load_tier_config(both)
    assert p.verify_workspace(p.TIER_RESTRICTED, "/srv/beta", PID_B, tc) == "/srv/beta"
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/srv/beta", PID_A, tc)  # B's path, A's project
    except p.PrivilegeError:
        return
    raise AssertionError("a path granted to another project must be refused")


def test_workspace_outside_grant_is_refused():
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/etc", PID_A, tc)
    except p.PrivilegeError:
        return
    raise AssertionError("ungranted directory must be refused")


def test_traversal_escape_is_refused():
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme/../../etc", PID_A, tc)
    except p.PrivilegeError:
        return
    raise AssertionError("path traversal out of a workspace must be refused")


def test_sibling_prefix_is_not_a_match():
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, "/srv/acme-other", PID_A, tc)
    except p.PrivilegeError:
        return
    raise AssertionError("sibling sharing a prefix must not be treated as granted")


def test_missing_working_dir_is_refused_for_restricted():
    tc = p.load_tier_config(cfg())
    try:
        p.verify_workspace(p.TIER_RESTRICTED, None, PID_A, tc)
    except p.PrivilegeError:
        return
    raise AssertionError("restricted tier must refuse an unspecified working_dir")


def test_standard_tier_allows_any_dir():
    tc = p.load_tier_config(cfg())
    assert p.verify_workspace(p.TIER_STANDARD, "/anywhere", None, tc) == "/anywhere"


def test_verify_workspace_returns_the_resolved_path():
    """SECURITY: returning the caller's raw string let a symlink flipped between
    the check and the chdir escape the grant."""
    with tempfile.TemporaryDirectory() as td:
        real = os.path.join(td, "real"); os.makedirs(os.path.join(real, "inner"))
        link = os.path.join(real, "wd"); os.symlink(os.path.join(real, "inner"), link)
        tc = p.load_tier_config({"privilege": {"projects": {
            PID_A: {"user": "orcp-a1b2c3d45e6f", "workspaces": [real]}}}})
        got = p.verify_workspace(p.TIER_RESTRICTED, link, PID_A, tc)
        assert got == os.path.realpath(link), got
        assert got != link, "must not return the unresolved symlink path"


# ── sudo prefix / exec argv (unchanged behaviour) ─────────────────────────────

def test_sudo_prefix_for_standard_is_empty():
    assert p.sudo_prefix(None, p.load_tier_config(cfg())) == []


def test_sudo_prefix_uses_H_not_i():
    pre = p.sudo_prefix("orcp-a1b2c3d45e6f", p.load_tier_config(cfg()))
    assert pre == ["sudo", "-n", "-u", "orcp-a1b2c3d45e6f", "-H"], pre
    assert "-i" not in pre


def test_standard_tier_execs_via_PATH():
    argv = p.tmux_exec_argv(None, ["ls"], p.load_tier_config(cfg()))
    assert argv[0] == "tmux", argv


def test_restricted_tier_execs_absolute_under_sudo():
    argv = p.tmux_exec_argv("orcp-a1b2c3d45e6f", ["ls"], p.load_tier_config(cfg()))
    assert argv[:5] == ["sudo", "-n", "-u", "orcp-a1b2c3d45e6f", "-H"], argv
    assert argv[5].startswith("/"), "sudo needs an absolute path to match sudoers"


def test_default_tmux_path_is_resolved_not_hardcoded():
    import shutil
    expected = shutil.which("tmux") or "/usr/bin/tmux"
    assert p.DEFAULT_TMUX_PATH == expected, p.DEFAULT_TMUX_PATH


# ── capability advertisement (T2) — now per-project ───────────────────────────

def test_capability_payload_is_per_project():
    payload = p.capability_payload(p.load_tier_config(cfg()))
    assert payload["tiers"] == ["standard", "restricted"]
    assert payload["projects"] == {
        PID_A: {"workspaces": ["/srv/acme", "/home/ubuntu/repo"]}}


def test_capability_payload_unprovisioned():
    payload = p.capability_payload(p.load_tier_config({}))
    assert payload == {"tiers": ["standard"], "projects": {}}


def test_capability_payload_omits_legacy_project():
    tc = p.load_tier_config({"privilege": {
        "restricted_user": "orc-agent", "workspaces": ["/srv/legacy"]}})
    payload = p.capability_payload(tc)
    assert payload["tiers"] == ["standard"]
    assert payload["projects"] == {}


def test_capability_merges_into_existing_capabilities():
    tc = p.load_tier_config(cfg())
    merged = p.merge_capabilities({"tags": ["gpu"], "tools": ["claude"]}, tc)
    assert merged["tags"] == ["gpu"]
    assert merged["tools"] == ["claude"]
    assert merged["privilege"]["tiers"] == ["standard", "restricted"]


def test_capability_merge_tolerates_none():
    merged = p.merge_capabilities(None, p.load_tier_config({}))
    assert merged["privilege"]["tiers"] == ["standard"]


def test_capability_merge_does_not_mutate_input():
    existing = {"tags": ["gpu"]}
    p.merge_capabilities(existing, p.load_tier_config(cfg()))
    assert "privilege" not in existing


# ── hub wiring seam (T6) ──────────────────────────────────────────────────────

def test_hub_priv_user_for_passes_project_id():
    from orchestratia_agent import hub

    class FakeState:
        config = cfg()

    st = FakeState()
    assert hub._priv_user_for(st, p.TIER_RESTRICTED, PID_A) == "orcp-a1b2c3d45e6f"
    # unprovisioned project -> None (never raises into the spawn path), which the
    # spawn path treats as "no restricted user" and refuses downstream.
    assert hub._priv_user_for(st, p.TIER_RESTRICTED, PID_B) is None
    assert hub._priv_user_for(st, p.TIER_STANDARD, PID_A) is None


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
