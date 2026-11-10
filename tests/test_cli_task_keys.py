#!/usr/bin/env python3
"""CLI task keys: keys (ORC-42) resolve through the hub, task get shows the key, epic and
assignee (epic as data), and `task create --epic` sends `parent`.

Dependency-free — run directly:  python3 tests/test_cli_task_keys.py
"""
import contextlib
import io
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import cli  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


UUID = "0b3f1a2e-1111-2222-3333-444455556666"
real_api = cli._api_request

calls = []


def fake_get(method, path, data=None, base="/api/v1/server/tasks"):
    calls.append((method, path))
    return {"id": UUID, "key": "ORC-42"}


cli._api_request = fake_get
ok("key resolves through the hub", cli._resolve_task_id("orc-42") == UUID)
ok("…with one GET of the upper-cased key", calls == [("GET", "/ORC-42")], calls)

calls.clear()
ok("full UUID passes through without a call", cli._resolve_task_id(UUID) == UUID and calls == [], calls)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    cli._print_task({"id": UUID, "key": "ORC-42", "title": "Fix retry", "status": "running", "priority": "high",
                     "type": "bugfix", "assigned_user_name": "Priya", "spec": "s", "target_repo": None,
                     "acceptance_criteria": [], "dependencies": [],
                     "epic": {"key": "ORC-12", "title": "Uploads v2", "description": "goal"}}, verbose=True)
out = buf.getvalue()
ok("task get shows the key", "ORC-42" in out, out[:200])
ok("task get shows the assignee", "Priya" in out)
ok("task get shows the epic as data", "ORC-12" in out and "Uploads v2" in out)

sent = {}


def fake_post(method, path, data=None, base="/api/v1/server/tasks"):
    if method == "POST" and path == "":
        sent.update(data)
        return {"id": UUID, "key": "ORC-43", "title": data["title"], "status": "pending", "priority": "normal"}
    return {}


cli._api_request = fake_post
cli.JSON_MODE = True
args = types.SimpleNamespace(title="t", spec="s", priority="normal", type="feature", repo=None, branch=None,
                             acceptance_criteria=None, depends_on=None, assign=None, require_plan=False,
                             epic="ORC-12")
with contextlib.redirect_stdout(io.StringIO()):
    cli.cmd_create(args)
ok("task create --epic sends parent", sent.get("parent") == "ORC-12", sent)
cli._api_request = real_api

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
