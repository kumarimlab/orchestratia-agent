#!/usr/bin/env python3
"""Orchestratia CLI - Inter-agent task communication tool.

Used by AI agents (Claude Code, etc.) running in PTY sessions to
create, check, and complete tasks. Reads configuration from
environment variables set by the daemon.

Usage:
  orchestratia task create --title "..." --spec "..." [--priority high]
  orchestratia task check
  orchestratia task view <id>
  orchestratia task complete <id> --result "..."
  orchestratia task status <id>
  orchestratia task list [--status pending]
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl

# Read config from environment (set by daemon when spawning PTY)
HUB_URL = os.environ.get("ORCHESTRATIA_HUB_URL", "")
API_KEY = os.environ.get("ORCHESTRATIA_API_KEY", "")
SESSION_ID = os.environ.get("ORCHESTRATIA_SESSION_ID", "")
PROJECT_ID = os.environ.get("ORCHESTRATIA_PROJECT_ID", "")

# Colors for terminal output
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"
BRAND = "\033[38;2;212;114;47m"  # Orchestratia brand color


def _api_request(method: str, path: str, data: dict | None = None) -> dict:
    """Make an authenticated API request to the hub."""
    if not HUB_URL:
        print(f"{RED}Error: ORCHESTRATIA_HUB_URL not set{RESET}", file=sys.stderr)
        sys.exit(1)
    if not API_KEY:
        print(f"{RED}Error: ORCHESTRATIA_API_KEY not set{RESET}", file=sys.stderr)
        sys.exit(1)

    url = f"{HUB_URL}/api/v1/agent/tasks{path}"
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    # Allow self-signed certs in development
    ctx = ssl.create_default_context()
    if HUB_URL.startswith("https://staging.") or HUB_URL.startswith("https://localhost"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, context=ctx)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", body)
        except json.JSONDecodeError:
            detail = body
        print(f"{RED}Error ({e.code}): {detail}{RESET}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"{RED}Connection error: {e.reason}{RESET}", file=sys.stderr)
        sys.exit(1)


def _print_task(task: dict, verbose: bool = False):
    """Pretty-print a task."""
    priority_color = {
        "critical": RED, "high": YELLOW, "normal": "", "low": DIM
    }.get(task["priority"], "")

    status_color = {
        "pending": YELLOW, "assigned": CYAN, "running": CYAN,
        "done": GREEN, "failed": RED, "needs_human": RED,
    }.get(task["status"], "")

    print(f"  {BRAND}#{task['id'][:8]}{RESET} {BOLD}{task['title']}{RESET}")
    print(f"    Status: {status_color}{task['status']}{RESET}  "
          f"Priority: {priority_color}{task['priority']}{RESET}")

    if verbose:
        print(f"    Spec: {task['spec']}")
        if task.get("source_session_name"):
            print(f"    From: {task['source_session_name']}")
        if task.get("target_session_name"):
            print(f"    Assigned to: {task['target_session_name']}")
        if task.get("result"):
            result = task["result"]
            if isinstance(result, dict) and "summary" in result:
                print(f"    Result: {result['summary']}")
            else:
                print(f"    Result: {json.dumps(result)}")


def cmd_create(args):
    """Create a new task."""
    data = {
        "title": args.title,
        "spec": args.spec,
        "priority": args.priority,
    }
    if SESSION_ID:
        data["session_id"] = SESSION_ID
    if PROJECT_ID:
        data["project_id"] = PROJECT_ID

    task = _api_request("POST", "", data)
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task created:")
    _print_task(task)


def cmd_check(args):
    """Check for tasks assigned to this session."""
    params = f"?session_id={SESSION_ID}" if SESSION_ID else ""
    result = _api_request("GET", f"/check{params}")

    count = result["count"]
    if count == 0:
        print(f"{DIM}[ORCHESTRATIA] No new tasks assigned.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {BOLD}{count} task(s) assigned:{RESET}")
    for task in result["tasks"]:
        _print_task(task)
        print()


def cmd_view(args):
    """View task details."""
    task = _api_request("GET", f"/{args.task_id}")
    print(f"{BRAND}[ORCHESTRATIA]{RESET} Task detail:")
    _print_task(task, verbose=True)


def cmd_complete(args):
    """Complete a task with result."""
    task = _api_request("POST", f"/{args.task_id}/complete", {
        "result": args.result,
    })
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task completed:")
    _print_task(task)


def cmd_status(args):
    """Check status of a task."""
    task = _api_request("GET", f"/{args.task_id}")
    print(f"{BRAND}[ORCHESTRATIA]{RESET} Task status:")
    _print_task(task, verbose=True)


def cmd_list(args):
    """List tasks."""
    params = []
    if args.status:
        params.append(f"status={args.status}")
    if PROJECT_ID:
        params.append(f"project_id={PROJECT_ID}")
    query = "?" + "&".join(params) if params else ""

    result = _api_request("GET", f"{query}")
    tasks = result["tasks"]

    if not tasks:
        print(f"{DIM}[ORCHESTRATIA] No tasks found.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {len(tasks)} task(s):")
    for task in tasks:
        _print_task(task)
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="orchestratia",
        description="Orchestratia CLI - Inter-agent task communication",
    )
    subparsers = parser.add_subparsers(dest="command")

    # task subcommand
    task_parser = subparsers.add_parser("task", help="Task operations")
    task_sub = task_parser.add_subparsers(dest="action")

    # task create
    create_p = task_sub.add_parser("create", help="Create a new task")
    create_p.add_argument("--title", required=True, help="Task title")
    create_p.add_argument("--spec", required=True, help="Task specification")
    create_p.add_argument("--priority", default="normal",
                         choices=["low", "normal", "high", "critical"],
                         help="Task priority")

    # task check
    task_sub.add_parser("check", help="Check for assigned tasks")

    # task view
    view_p = task_sub.add_parser("view", help="View task details")
    view_p.add_argument("task_id", help="Task ID")

    # task complete
    complete_p = task_sub.add_parser("complete", help="Complete a task")
    complete_p.add_argument("task_id", help="Task ID")
    complete_p.add_argument("--result", required=True, help="Completion result")

    # task status
    status_p = task_sub.add_parser("status", help="Check task status")
    status_p.add_argument("task_id", help="Task ID")

    # task list
    list_p = task_sub.add_parser("list", help="List tasks")
    list_p.add_argument("--status", help="Filter by status")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "task":
        if not args.action:
            task_parser.print_help()
            sys.exit(1)

        actions = {
            "create": cmd_create,
            "check": cmd_check,
            "view": cmd_view,
            "complete": cmd_complete,
            "status": cmd_status,
            "list": cmd_list,
        }
        actions[args.action](args)


if __name__ == "__main__":
    main()
