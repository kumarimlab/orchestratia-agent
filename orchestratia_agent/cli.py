"""Orchestratia CLI - Inter-agent task communication tool.

Used by AI agents (Claude Code, etc.) running in PTY sessions to
create, check, and complete tasks. Reads configuration from
environment variables set by the daemon.

Usage:
  orchestratia task create --title "..." --spec "..." [--priority high]
  orchestratia task check
  orchestratia task view <id>
  orchestratia task complete <id> --result "..."
  orchestratia task start <id>
  orchestratia task fail <id> --error "..."
  orchestratia task help <id> --question "..."
  orchestratia task assign <id> --agent "name"
  orchestratia task update <id> [--title/--spec/--priority/...]
  orchestratia task cancel <id>
  orchestratia task status <id>
  orchestratia task list [--status pending]
  orchestratia task deps add <id> --depends-on <dep_id> [--type blocks]
  orchestratia task deps remove <id> --depends-on <dep_id>
  orchestratia agent list
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


def _api_request(method: str, path: str, data: dict | None = None, base: str = "/api/v1/agent/tasks") -> dict:
    """Make an authenticated API request to the hub."""
    if not HUB_URL:
        print(f"{RED}Error: ORCHESTRATIA_HUB_URL not set{RESET}", file=sys.stderr)
        sys.exit(1)
    if not API_KEY:
        print(f"{RED}Error: ORCHESTRATIA_API_KEY not set{RESET}", file=sys.stderr)
        sys.exit(1)

    url = f"{HUB_URL}{base}{path}"
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
          f"Priority: {priority_color}{task['priority']}{RESET}", end="")

    if task.get("type"):
        print(f"  Type: {task['type']}", end="")
    print()

    if task.get("assigned_agent_name"):
        print(f"    Agent: {CYAN}{task['assigned_agent_name']}{RESET}")

    if task.get("target_repo"):
        print(f"    Repo: {task['target_repo']}", end="")
        if task.get("target_branch"):
            print(f" ({task['target_branch']})", end="")
        print()

    if verbose:
        print(f"    Spec: {task['spec']}")

        if task.get("acceptance_criteria"):
            print(f"    Acceptance criteria:")
            for i, crit in enumerate(task["acceptance_criteria"], 1):
                print(f"      {i}. {crit}")

        if task.get("structured_spec"):
            reqs = task["structured_spec"].get("requirements", [])
            if reqs:
                print(f"    Requirements:")
                for r in reqs:
                    pri = r.get("priority", "")
                    print(f"      [{pri}] {r.get('description', '')}")

        if task.get("dependencies"):
            print(f"    Dependencies:")
            for dep in task["dependencies"]:
                resolved = f"{GREEN}resolved{RESET}" if dep["resolved"] else f"{YELLOW}pending{RESET}"
                dtype = dep.get("dependency_type", "blocks")
                line = f"      {dtype} #{dep['depends_on_task_id'][:8]} [{resolved}]"
                if dep.get("contract_key"):
                    line += f" key={dep['contract_key']}"
                print(line)

        if task.get("resolved_inputs"):
            print(f"    Resolved inputs:")
            for key, val in task["resolved_inputs"].items():
                print(f"      {key}: {json.dumps(val, indent=2)[:200]}")

        if task.get("source_session_name"):
            print(f"    From: {task['source_session_name']}")
        if task.get("target_session_name"):
            print(f"    Assigned to session: {task['target_session_name']}")
        if task.get("created_by"):
            print(f"    Created by: {task['created_by']}")
        if task.get("started_at"):
            print(f"    Started: {task['started_at']}")
        if task.get("completed_at"):
            print(f"    Completed: {task['completed_at']}")

        if task.get("result"):
            result = task["result"]
            if isinstance(result, dict) and "summary" in result:
                print(f"    Result: {result['summary']}")
            elif isinstance(result, dict) and "error" in result:
                print(f"    Error: {RED}{result['error']}{RESET}")
            else:
                print(f"    Result: {json.dumps(result)}")


# ── Task Commands ────────────────────────────────────────────────────


def cmd_create(args):
    """Create a new task."""
    data = {
        "title": args.title,
        "spec": args.spec,
        "priority": args.priority,
        "type": args.type,
    }
    if SESSION_ID:
        data["session_id"] = SESSION_ID
    if PROJECT_ID:
        data["project_id"] = PROJECT_ID
    if args.repo:
        data["target_repo"] = args.repo
    if args.branch:
        data["target_branch"] = args.branch
    if args.acceptance_criteria:
        data["acceptance_criteria"] = args.acceptance_criteria
    if args.depends_on:
        data["dependency_ids"] = args.depends_on

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


def cmd_start(args):
    """Start a task (transition to running)."""
    task = _api_request("POST", f"/{args.task_id}/start")
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task started:")
    _print_task(task)


def cmd_fail(args):
    """Mark a task as failed."""
    task = _api_request("POST", f"/{args.task_id}/fail", {
        "error": args.error,
    })
    print(f"{RED}[ORCHESTRATIA]{RESET} Task failed:")
    _print_task(task)


def cmd_help(args):
    """Request human intervention for a task."""
    data = {"question": args.question}
    if args.context:
        data["context"] = args.context
    result = _api_request("POST", f"/{args.task_id}/help", data)
    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Help requested:")
    print(f"  Intervention ID: {result['intervention_id']}")
    print(f"  Status: {result['status']}")


def cmd_assign(args):
    """Assign a task to an agent by name."""
    task = _api_request("POST", f"/{args.task_id}/assign", {
        "agent_name": args.agent,
    })
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task assigned:")
    _print_task(task)


def cmd_update(args):
    """Update task fields."""
    data = {}
    if args.title:
        data["title"] = args.title
    if args.spec:
        data["spec"] = args.spec
    if args.priority:
        data["priority"] = args.priority
    if args.type:
        data["type"] = args.type
    if args.repo:
        data["target_repo"] = args.repo
    if args.branch:
        data["target_branch"] = args.branch
    if args.acceptance_criteria:
        data["acceptance_criteria"] = args.acceptance_criteria

    if not data:
        print(f"{YELLOW}[ORCHESTRATIA] No fields to update.{RESET}", file=sys.stderr)
        sys.exit(1)

    task = _api_request("PUT", f"/{args.task_id}", data)
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task updated:")
    _print_task(task, verbose=True)


def cmd_cancel(args):
    """Cancel a task."""
    result = _api_request("DELETE", f"/{args.task_id}")
    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Task cancelled: #{args.task_id[:8]}")


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


# ── Dependency Commands ──────────────────────────────────────────────


def cmd_deps_add(args):
    """Add a dependency to a task."""
    data = {
        "depends_on_task_id": args.depends_on,
        "dependency_type": args.type,
    }
    if args.contract_key:
        data["contract_key"] = args.contract_key

    result = _api_request("POST", f"/{args.task_id}/dependencies", data)
    resolved = f"{GREEN}resolved{RESET}" if result["resolved"] else f"{YELLOW}pending{RESET}"
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Dependency added:")
    print(f"  #{args.task_id[:8]} depends on #{args.depends_on[:8]} ({result['dependency_type']}) [{resolved}]")
    if result.get("contract_key"):
        print(f"  Contract key: {result['contract_key']}")


def cmd_deps_remove(args):
    """Remove a dependency from a task."""
    _api_request("DELETE", f"/{args.task_id}/dependencies/{args.depends_on}")
    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Dependency removed:")
    print(f"  #{args.task_id[:8]} no longer depends on #{args.depends_on[:8]}")


# ── Agent Commands ───────────────────────────────────────────────────


def cmd_agent_list(args):
    """List all agents."""
    result = _api_request("GET", "", base="/api/v1/agent/agents")
    agents = result["agents"]

    if not agents:
        print(f"{DIM}[ORCHESTRATIA] No agents registered.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {len(agents)} agent(s):")
    for a in agents:
        status_color = GREEN if a["status"] == "online" else DIM
        print(f"  {CYAN}{a['name']}{RESET} ({a['hostname']}, {a['os']})")
        print(f"    Status: {status_color}{a['status']}{RESET}", end="")
        if a.get("last_heartbeat"):
            print(f"  Last heartbeat: {a['last_heartbeat']}", end="")
        print()
        if a.get("repos"):
            repos = a["repos"]
            if isinstance(repos, dict):
                print(f"    Repos: {', '.join(repos.keys())}")
            elif isinstance(repos, list):
                print(f"    Repos: {', '.join(str(r) for r in repos)}")
        print()


# ── Main ─────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        prog="orchestratia",
        description="Orchestratia CLI - Inter-agent task communication",
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── task subcommand ──
    task_parser = subparsers.add_parser("task", help="Task operations")
    task_sub = task_parser.add_subparsers(dest="action")

    # task create
    create_p = task_sub.add_parser("create", help="Create a new task")
    create_p.add_argument("--title", required=True, help="Task title")
    create_p.add_argument("--spec", required=True, help="Task specification")
    create_p.add_argument("--priority", default="normal",
                         choices=["low", "normal", "high", "critical"],
                         help="Task priority")
    create_p.add_argument("--type", default="feature",
                         choices=["feature", "bugfix", "refactor", "chore", "docs"],
                         help="Task type")
    create_p.add_argument("--repo", help="Target repository name")
    create_p.add_argument("--branch", help="Target branch name")
    create_p.add_argument("--acceptance-criteria", nargs="+",
                         help="Acceptance criteria (space-separated)")
    create_p.add_argument("--depends-on", nargs="+",
                         help="IDs of tasks this depends on")

    # task check
    task_sub.add_parser("check", help="Check for assigned tasks")

    # task view
    view_p = task_sub.add_parser("view", help="View task details")
    view_p.add_argument("task_id", help="Task ID")

    # task complete
    complete_p = task_sub.add_parser("complete", help="Complete a task")
    complete_p.add_argument("task_id", help="Task ID")
    complete_p.add_argument("--result", required=True, help="Completion result")

    # task start
    start_p = task_sub.add_parser("start", help="Start a task (transition to running)")
    start_p.add_argument("task_id", help="Task ID")

    # task fail
    fail_p = task_sub.add_parser("fail", help="Mark a task as failed")
    fail_p.add_argument("task_id", help="Task ID")
    fail_p.add_argument("--error", required=True, help="Error description")

    # task help
    help_p = task_sub.add_parser("help", help="Request human intervention")
    help_p.add_argument("task_id", help="Task ID")
    help_p.add_argument("--question", required=True, help="Question for human")
    help_p.add_argument("--context", help="Additional context")

    # task assign
    assign_p = task_sub.add_parser("assign", help="Assign task to an agent")
    assign_p.add_argument("task_id", help="Task ID")
    assign_p.add_argument("--agent", required=True, help="Agent name")

    # task update
    update_p = task_sub.add_parser("update", help="Update task fields")
    update_p.add_argument("task_id", help="Task ID")
    update_p.add_argument("--title", help="New title")
    update_p.add_argument("--spec", help="New spec")
    update_p.add_argument("--priority", choices=["low", "normal", "high", "critical"])
    update_p.add_argument("--type", choices=["feature", "bugfix", "refactor", "chore", "docs"])
    update_p.add_argument("--repo", help="Target repository")
    update_p.add_argument("--branch", help="Target branch")
    update_p.add_argument("--acceptance-criteria", nargs="+",
                         help="Acceptance criteria")

    # task cancel
    cancel_p = task_sub.add_parser("cancel", help="Cancel a task")
    cancel_p.add_argument("task_id", help="Task ID")

    # task status
    status_p = task_sub.add_parser("status", help="Check task status")
    status_p.add_argument("task_id", help="Task ID")

    # task list
    list_p = task_sub.add_parser("list", help="List tasks")
    list_p.add_argument("--status", help="Filter by status")

    # task deps
    deps_parser = task_sub.add_parser("deps", help="Manage task dependencies")
    deps_sub = deps_parser.add_subparsers(dest="deps_action")

    # task deps add
    deps_add_p = deps_sub.add_parser("add", help="Add a dependency")
    deps_add_p.add_argument("task_id", help="Task ID")
    deps_add_p.add_argument("--depends-on", required=True, help="ID of upstream task")
    deps_add_p.add_argument("--type", default="blocks",
                           choices=["blocks", "input", "related"],
                           help="Dependency type")
    deps_add_p.add_argument("--contract-key", help="Contract key for input deps")

    # task deps remove
    deps_rm_p = deps_sub.add_parser("remove", help="Remove a dependency")
    deps_rm_p.add_argument("task_id", help="Task ID")
    deps_rm_p.add_argument("--depends-on", required=True, help="ID of upstream task")

    # ── agent subcommand ──
    agent_parser = subparsers.add_parser("agent", help="Agent operations")
    agent_sub = agent_parser.add_subparsers(dest="action")

    # agent list
    agent_sub.add_parser("list", help="List all agents")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "task":
        if not args.action:
            task_parser.print_help()
            sys.exit(1)

        if args.action == "deps":
            if not args.deps_action:
                deps_parser.print_help()
                sys.exit(1)
            deps_actions = {
                "add": cmd_deps_add,
                "remove": cmd_deps_remove,
            }
            deps_actions[args.deps_action](args)
        else:
            actions = {
                "create": cmd_create,
                "check": cmd_check,
                "view": cmd_view,
                "complete": cmd_complete,
                "start": cmd_start,
                "fail": cmd_fail,
                "help": cmd_help,
                "assign": cmd_assign,
                "update": cmd_update,
                "cancel": cmd_cancel,
                "status": cmd_status,
                "list": cmd_list,
            }
            actions[args.action](args)

    elif args.command == "agent":
        if not args.action:
            agent_parser.print_help()
            sys.exit(1)

        agent_actions = {
            "list": cmd_agent_list,
        }
        agent_actions[args.action](args)


if __name__ == "__main__":
    main()
