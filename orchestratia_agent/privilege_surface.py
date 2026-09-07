"""Which hub->daemon messages can execute at what privilege.

Every message type must appear here. The accompanying test fails the build if
one does not, so a new message cannot silently join the unconfined set.

`remote_exec` was found by reading code during design; five more handlers in the
same shape were found the same way. This file exists so the next one is found by
CI instead of by an adversarial reviewer, or by a customer.

  tier_bounded   — runs at the tier of the session it names
  no_execution   — moves data or state; executes nothing on the host
  unconfined     — runs as the daemon user by design; MUST be unreachable from
                   a session-scoped credential
"""

TIER_BOUNDED = "tier_bounded"
NO_EXECUTION = "no_execution"
UNCONFINED = "unconfined"

PRIVILEGE_CLASSIFICATION = {
    # Session lifecycle — the tier is chosen by the hub and enforced at spawn.
    "session_start": TIER_BOUNDED,
    "session_input": TIER_BOUNDED,
    "session_resize": TIER_BOUNDED,
    "session_close": TIER_BOUNDED,
    "session_kill": TIER_BOUNDED,
    "session_recovered_ack": NO_EXECUTION,
    "session_exit_copy_mode": TIER_BOUNDED,
    "capture_scrollback": TIER_BOUNDED,

    # Execution.
    "remote_exec": TIER_BOUNDED,

    # Filesystem side-panel — scoped to the session's working_dir.
    # NOTE: these still run IN THE DAEMON PROCESS as the daemon user. They are
    # path-scoped, not privilege-scoped. Tracked as a known gap; see the
    # feature spec's "known limits".
    "fs_list_dir": TIER_BOUNDED,
    "fs_read_file": TIER_BOUNDED,
    "fs_write_file": TIER_BOUNDED,
    "fs_stat": TIER_BOUNDED,

    # Task/plan/note plumbing — writes into a session or the daemon's state.
    "task_assigned": NO_EXECUTION,
    "task_approved": NO_EXECUTION,
    "task_rejected": NO_EXECUTION,
    "task_note": NO_EXECUTION,
    "task_updated": NO_EXECUTION,
    "task_status_update": NO_EXECUTION,
    "note_for_session": NO_EXECUTION,
    "intervention_response": NO_EXECUTION,
    "intervention_for_session": NO_EXECUTION,
    "plan_approved": NO_EXECUTION,
    "plan_revision": NO_EXECUTION,
    "code_review_fix_request": NO_EXECUTION,
    "approval_rules_updated": NO_EXECUTION,

    # File transfer — writes files as the daemon user.
    "file_offer": NO_EXECUTION,
    "file_send_start": UNCONFINED,
    "file_accepted": NO_EXECUTION,
    "file_rejected": NO_EXECUTION,
    "file_chunk": UNCONFINED,
    "file_complete": UNCONFINED,
    "file_ack": NO_EXECUTION,
    "file_error": NO_EXECUTION,

    # Tunnels and SSH access — daemon-level, admin-initiated.
    "tunnel_open": UNCONFINED,
    "tunnel_data": NO_EXECUTION,
    "tunnel_ready": NO_EXECUTION,
    "tunnel_close": NO_EXECUTION,
    "tunnel_closed": NO_EXECUTION,
    "setup_ssh_access": UNCONFINED,
    "revoke_ssh_access": UNCONFINED,
    "grant_ssh_access": UNCONFINED,
    "revoke_grant_access": UNCONFINED,

    # Scanning.
    "scan_architecture": UNCONFINED,

    # Keepalive.
    "pong": NO_EXECUTION,
}


def message_types_in_hub(hub_source: str) -> set[str]:
    """Extract every `msg_type == "..."` / `msg_type in (...)` literal."""
    import re
    found = set(re.findall(r'msg_type\s*==\s*"([a-z_]+)"', hub_source))
    for group in re.findall(r'msg_type\s+in\s+\(([^)]*)\)', hub_source):
        found.update(re.findall(r'"([a-z_]+)"', group))
    return found
