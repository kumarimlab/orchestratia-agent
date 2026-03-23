"""Orchestratia CLI - Inter-agent task communication tool.

Used by AI agents (Claude Code, etc.) running in PTY sessions to
create, check, and complete tasks. Reads configuration from
environment variables set by the daemon, with fallback to config.yaml.

Usage:
  orchestratia task create --title "..." --spec "..." [--priority high] [--assign session-name]
  orchestratia task check
  orchestratia task view <id>
  orchestratia task complete <id> --result "..."
  orchestratia task start <id>
  orchestratia task fail <id> --error "..."
  orchestratia task help <id> --question "..." [--type help|question]
  orchestratia task plan <id> --plan '{"summary": "...", "impact": "..."}'
  orchestratia task note <id> --content "..." [--urgent]
  orchestratia task notes <id>
  orchestratia task assign <id> --server "name"
  orchestratia task update <id> [--title/--spec/--priority/...]
  orchestratia task cancel <id>
  orchestratia task status <id>
  orchestratia task list [--status pending] [--json]
  orchestratia task deps add <id> --depends-on <dep_id> [--type blocks]
  orchestratia task deps remove <id> --depends-on <dep_id>
  orchestratia intervention list [--task-id X] [--status pending]
  orchestratia intervention respond <id> --response "..."
  orchestratia server list [--json]
  orchestratia session list [--json]
  orchestratia pipeline create --file pipeline.json [--json]
  orchestratia file send <path> --to <session-name> [--timeout 300]
  orchestratia file status <transfer-id>
  orchestratia init [--print]

All commands support --json for machine-readable output.
Task IDs accept short prefixes (minimum 4 chars) that resolve to full UUIDs.
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import ssl

# Read config from environment (set by daemon when spawning PTY)
HUB_URL = os.environ.get("ORCHESTRATIA_HUB_URL", "").rstrip("/")
API_KEY = os.environ.get("ORCHESTRATIA_API_KEY", "")
SESSION_ID = os.environ.get("ORCHESTRATIA_SESSION_ID", "")
PROJECT_ID = os.environ.get("ORCHESTRATIA_PROJECT_ID", "")

# Config file: ALWAYS read for hub_url and api_key.
# The config file is the source of truth — env vars can become stale in
# long-running tmux sessions after daemon reinstall/re-registration
# (registration generates a new key, but existing shells keep the old env).
try:
    from orchestratia_agent.config import default_config_path, load_config
    _cfg_path = default_config_path()
    if os.path.exists(_cfg_path):
        _cfg = load_config(_cfg_path)
        # Config file always wins for hub_url and api_key
        _cfg_hub = _cfg.get("hub_url", "")
        _cfg_key = _cfg.get("api_key", "")
        if _cfg_hub:
            HUB_URL = _cfg_hub.rstrip("/")
        if _cfg_key:
            API_KEY = _cfg_key
except Exception:
    pass

# JSON output mode (set in main() before command dispatch)
JSON_MODE = False

# Colors for terminal output
BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"
BRAND = "\033[38;2;212;114;47m"  # Orchestratia brand color


# ── Helpers ─────────────────────────────────────────────────────────


def _json_output(data):
    """Print data as formatted JSON."""
    print(json.dumps(data, indent=2, default=str))


def _error_exit(msg, code=1):
    """Print error and exit, respecting JSON mode."""
    if JSON_MODE:
        _json_output({"error": msg})
    else:
        print(f"{RED}Error: {msg}{RESET}", file=sys.stderr)
    sys.exit(code)


def _api_request(method: str, path: str, data: dict | None = None, base: str = "/api/v1/server/tasks") -> dict:
    """Make an authenticated API request to the hub."""
    if not HUB_URL:
        _error_exit("ORCHESTRATIA_HUB_URL not set (set env var or configure config.yaml)")
    if not API_KEY:
        _error_exit("ORCHESTRATIA_API_KEY not set (set env var or configure config.yaml)")

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
        _error_exit(f"HTTP {e.code}: {detail}")
    except urllib.error.URLError as e:
        _error_exit(f"Connection error: {e.reason}")


def _resolve_task_id(prefix: str) -> str:
    """Resolve a task ID prefix to a full UUID.

    - Full UUID (36 chars with dashes) -> pass through
    - Short prefix (4+ chars) -> fetch task list, find unique match
    """
    if not prefix:
        _error_exit("Task ID is required")

    # Full UUID: pass through
    if len(prefix) == 36 and prefix.count("-") == 4:
        return prefix

    # Short prefix: search task list
    if len(prefix) < 4:
        _error_exit(f"Task ID prefix too short (minimum 4 characters): {prefix}")

    result = _api_request("GET", "")
    tasks = result.get("tasks", [])

    matches = [t for t in tasks if t["id"].startswith(prefix)]

    if len(matches) == 1:
        return matches[0]["id"]
    elif len(matches) == 0:
        _error_exit(
            f"No task found matching prefix '{prefix}'. "
            "The task may be older than the last 50 — use the full UUID."
        )
    else:
        ids = ", ".join(m["id"][:12] + "..." for m in matches[:5])
        _error_exit(
            f"Ambiguous prefix '{prefix}' matches {len(matches)} tasks: {ids}. "
            "Use a longer prefix or full UUID."
        )


def _task_to_dict(task: dict) -> dict:
    """Convert a task API response to a clean dict for JSON output."""
    return task


def _print_task(task: dict, verbose: bool = False):
    """Pretty-print a task."""
    priority_color = {
        "critical": RED, "high": YELLOW, "normal": "", "low": DIM
    }.get(task["priority"], "")

    status_color = {
        "pending": YELLOW, "assigned": CYAN, "planning": CYAN,
        "plan_review": YELLOW, "running": CYAN,
        "done": GREEN, "failed": RED, "needs_human": RED, "cancelled": DIM,
    }.get(task["status"], "")

    print(f"  {BRAND}#{task['id']}{RESET} {BOLD}{task['title']}{RESET}")
    print(f"    Status: {status_color}{task['status']}{RESET}  "
          f"Priority: {priority_color}{task['priority']}{RESET}", end="")

    if task.get("type"):
        print(f"  Type: {task['type']}", end="")
    print()

    if task.get("assigned_server_name"):
        print(f"    Server: {CYAN}{task['assigned_server_name']}{RESET}")

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
                line = f"      {dtype} #{dep['depends_on_task_id']} [{resolved}]"
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

        if task.get("plan"):
            plan = task["plan"]
            if isinstance(plan, dict) and "summary" in plan:
                print(f"    Plan: {plan['summary']}")
            else:
                print(f"    Plan: {json.dumps(plan)[:200]}")
        if task.get("plan_feedback"):
            print(f"    Plan feedback: {YELLOW}{task['plan_feedback']}{RESET}")

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
        data["dependency_ids"] = [_resolve_task_id(d) for d in args.depends_on]

    task = _api_request("POST", "", data)

    # Auto-assign if requested
    if args.assign:
        assign_data = {"session_name": args.assign}
        if args.require_plan:
            assign_data["require_plan"] = True
        task = _api_request("POST", f"/{task['id']}/assign", assign_data)

    if JSON_MODE:
        _json_output(task)
        return

    action = "Task created and assigned" if args.assign else "Task created"
    print(f"{GREEN}[ORCHESTRATIA]{RESET} {action}:")
    _print_task(task)


def cmd_check(args):
    """Check for tasks assigned to this session."""
    params = f"?session_id={SESSION_ID}" if SESSION_ID else ""
    result = _api_request("GET", f"/check{params}")

    if JSON_MODE:
        _json_output(result)
        return

    count = result["count"]
    if count == 0:
        print(f"{DIM}[ORCHESTRATIA] No new tasks assigned.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {BOLD}{count} task(s) assigned:{RESET}")
    for task in result["tasks"]:
        _print_task(task, verbose=True)
        print()


def cmd_view(args):
    """View task details."""
    args.task_id = _resolve_task_id(args.task_id)
    task = _api_request("GET", f"/{args.task_id}")

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} Task detail:")
    _print_task(task, verbose=True)


def cmd_complete(args):
    """Complete a task with result."""
    args.task_id = _resolve_task_id(args.task_id)

    # Parse result as JSON if possible, so structured results (contracts,
    # changes, tests) are sent as objects rather than opaque strings.
    # This enables the hub to extract contracts for downstream tasks.
    result_value = args.result
    try:
        result_value = json.loads(args.result)
    except (json.JSONDecodeError, TypeError):
        pass  # plain string is fine

    task = _api_request("POST", f"/{args.task_id}/complete", {
        "result": result_value,
    })

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task completed:")
    _print_task(task)


def cmd_start(args):
    """Start a task (transition to running)."""
    args.task_id = _resolve_task_id(args.task_id)
    task = _api_request("POST", f"/{args.task_id}/start")

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task started:")
    _print_task(task)


def cmd_fail(args):
    """Mark a task as failed."""
    args.task_id = _resolve_task_id(args.task_id)
    task = _api_request("POST", f"/{args.task_id}/fail", {
        "error": args.error,
    })

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{RED}[ORCHESTRATIA]{RESET} Task failed:")
    _print_task(task)


def cmd_help(args):
    """Request intervention for a task."""
    args.task_id = _resolve_task_id(args.task_id)
    data = {"question": args.question}
    if args.context:
        data["context"] = args.context
    if hasattr(args, "type") and args.type:
        data["intervention_type"] = args.type
    result = _api_request("POST", f"/{args.task_id}/help", data)

    if JSON_MODE:
        _json_output(result)
        return

    itype = data.get("intervention_type", "help")
    print(f"{YELLOW}[ORCHESTRATIA]{RESET} {'Question' if itype == 'question' else 'Help'} requested:")
    print(f"  Intervention ID: {result['intervention_id']}")
    print(f"  Status: {result['status']}")


def cmd_plan(args):
    """Submit a plan for a task in planning state."""
    args.task_id = _resolve_task_id(args.task_id)

    # Parse plan as JSON if possible, otherwise wrap as {summary: ...}
    plan_value = args.plan
    try:
        plan_value = json.loads(args.plan)
    except (json.JSONDecodeError, TypeError):
        plan_value = {"summary": args.plan}

    result = _api_request("POST", f"/{args.task_id}/plan", {
        "plan": plan_value,
    })

    if JSON_MODE:
        _json_output(result)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Plan submitted for review:")
    _print_task(result)


def cmd_note(args):
    """Add a note to a task."""
    args.task_id = _resolve_task_id(args.task_id)
    data = {
        "content": args.content,
        "urgent": args.urgent,
    }
    result = _api_request("POST", f"/{args.task_id}/notes", data)

    if JSON_MODE:
        _json_output(result)
        return

    urgency = f"{RED}URGENT{RESET} " if args.urgent else ""
    print(f"{GREEN}[ORCHESTRATIA]{RESET} {urgency}Note added to task #{args.task_id[:8]}")


def cmd_notes(args):
    """List notes for a task."""
    args.task_id = _resolve_task_id(args.task_id)
    notes = _api_request("GET", f"/{args.task_id}/notes")

    if JSON_MODE:
        _json_output(notes)
        return

    if not notes:
        print(f"{DIM}[ORCHESTRATIA]{RESET} No notes for task #{args.task_id[:8]}")
        return

    print(f"{BOLD}Notes for task #{args.task_id[:8]}:{RESET}")
    for n in notes:
        urgency = f"{RED}[URGENT]{RESET} " if n.get("urgent") else ""
        ts = n.get("created_at", "")[:19]
        print(f"  {DIM}{ts}{RESET} {urgency}{n.get('author', '?')}: {n.get('content', '')}")


def cmd_intervention_list(args):
    """List interventions."""
    params = []
    if hasattr(args, "task_id") and args.task_id:
        params.append(f"task_id={_resolve_task_id(args.task_id)}")
    if hasattr(args, "status") and args.status:
        params.append(f"status={args.status}")
    qs = "?" + "&".join(params) if params else ""
    result = _api_request("GET", f"{qs}", base="/api/v1/server/interventions")

    if JSON_MODE:
        _json_output(result)
        return

    if not result:
        print(f"{DIM}[ORCHESTRATIA]{RESET} No interventions found")
        return

    print(f"{BOLD}Interventions:{RESET}")
    for i in result:
        status_color = GREEN if i["status"] == "responded" else YELLOW
        itype = i.get("intervention_type", "help")
        print(f"  {i['id'][:8]}  {status_color}{i['status']}{RESET}  [{itype}]  {i.get('question', '')[:60]}")


def cmd_intervention_respond(args):
    """Respond to an intervention programmatically."""
    result = _api_request(
        "POST",
        f"/{args.intervention_id}/respond",
        {"response": args.response},
        base="/api/v1/server/interventions",
    )

    if JSON_MODE:
        _json_output(result)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Intervention responded:")
    print(f"  ID: {result.get('id', args.intervention_id)[:8]}")
    print(f"  Status: {result.get('status')}")


def cmd_assign(args):
    """Assign a task to a session by name."""
    args.task_id = _resolve_task_id(args.task_id)
    data = {"session_name": args.session}
    if args.require_plan:
        data["require_plan"] = True
    task = _api_request("POST", f"/{args.task_id}/assign", data)

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task assigned:")
    _print_task(task)


def cmd_update(args):
    """Update task fields."""
    args.task_id = _resolve_task_id(args.task_id)
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
        _error_exit("No fields to update")

    task = _api_request("PUT", f"/{args.task_id}", data)

    if JSON_MODE:
        _json_output(task)
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Task updated:")
    _print_task(task, verbose=True)


def cmd_cancel(args):
    """Cancel a task."""
    args.task_id = _resolve_task_id(args.task_id)
    result = _api_request("DELETE", f"/{args.task_id}")

    if JSON_MODE:
        _json_output({"cancelled": True, "task_id": args.task_id})
        return

    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Task cancelled: #{args.task_id}")


def cmd_status(args):
    """Check status of a task."""
    args.task_id = _resolve_task_id(args.task_id)
    task = _api_request("GET", f"/{args.task_id}")

    if JSON_MODE:
        _json_output(task)
        return

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

    if JSON_MODE:
        _json_output(result)
        return

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
    args.task_id = _resolve_task_id(args.task_id)
    args.depends_on = _resolve_task_id(args.depends_on)

    data = {
        "depends_on_task_id": args.depends_on,
        "dependency_type": args.type,
    }
    if args.contract_key:
        data["contract_key"] = args.contract_key

    result = _api_request("POST", f"/{args.task_id}/dependencies", data)

    if JSON_MODE:
        _json_output(result)
        return

    resolved = f"{GREEN}resolved{RESET}" if result["resolved"] else f"{YELLOW}pending{RESET}"
    print(f"{GREEN}[ORCHESTRATIA]{RESET} Dependency added:")
    print(f"  #{args.task_id} depends on #{args.depends_on} ({result['dependency_type']}) [{resolved}]")
    if result.get("contract_key"):
        print(f"  Contract key: {result['contract_key']}")


def cmd_deps_remove(args):
    """Remove a dependency from a task."""
    args.task_id = _resolve_task_id(args.task_id)
    args.depends_on = _resolve_task_id(args.depends_on)

    _api_request("DELETE", f"/{args.task_id}/dependencies/{args.depends_on}")

    if JSON_MODE:
        _json_output({"removed": True, "task_id": args.task_id, "depends_on": args.depends_on})
        return

    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Dependency removed:")
    print(f"  #{args.task_id} no longer depends on #{args.depends_on}")


# ── Server Commands ──────────────────────────────────────────────────


def cmd_server_list(args):
    """List all registered servers."""
    result = _api_request("GET", "", base="/api/v1/server/servers")
    servers = result["servers"]

    if JSON_MODE:
        _json_output(result)
        return

    if not servers:
        print(f"{DIM}[ORCHESTRATIA] No servers registered.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {len(servers)} server(s):")
    for s in servers:
        status_color = GREEN if s["status"] == "online" else DIM
        print(f"  {CYAN}{s['name']}{RESET} ({s['hostname']}, {s['os']})")
        print(f"    Status: {status_color}{s['status']}{RESET}", end="")
        if s.get("last_heartbeat"):
            print(f"  Last heartbeat: {s['last_heartbeat']}", end="")
        print()
        if s.get("repos"):
            repos = s["repos"]
            if isinstance(repos, dict):
                print(f"    Repos: {', '.join(repos.keys())}")
            elif isinstance(repos, list):
                print(f"    Repos: {', '.join(str(r) for r in repos)}")
        print()


# ── Session Commands ─────────────────────────────────────────────────


def cmd_session_list(args):
    """List active sessions in the current project."""
    if not PROJECT_ID:
        _error_exit("ORCHESTRATIA_PROJECT_ID not set (set env var or configure config.yaml)")

    result = _api_request("GET", f"?project_id={PROJECT_ID}", base="/api/v1/server/sessions")
    sessions = result["sessions"]

    if JSON_MODE:
        _json_output(result)
        return

    if not sessions:
        print(f"{DIM}[ORCHESTRATIA] No active sessions in this project.{RESET}")
        return

    print(f"{BRAND}[ORCHESTRATIA]{RESET} {len(sessions)} active session(s):")
    for s in sessions:
        print(f"  {CYAN}{s['name'] or 'unnamed'}{RESET} ({s['server_name']})")
        print(f"    ID: {s['id']}  Status: {GREEN}{s['status']}{RESET}", end="")
        if s.get("working_directory"):
            print(f"  Dir: {s['working_directory']}", end="")
        print()


# ── Pipeline Commands ────────────────────────────────────────────────


def cmd_pipeline_create(args):
    """Create a multi-task pipeline from a JSON definition."""
    # Load pipeline definition
    if args.file:
        try:
            with open(args.file) as f:
                pipeline = json.load(f)
        except FileNotFoundError:
            _error_exit(f"File not found: {args.file}")
        except json.JSONDecodeError as e:
            _error_exit(f"Invalid JSON in {args.file}: {e}")
    elif args.inline:
        try:
            pipeline = json.loads(args.inline)
        except json.JSONDecodeError as e:
            _error_exit(f"Invalid inline JSON: {e}")
    else:
        _error_exit("Provide --file or --inline with pipeline JSON")

    if "tasks" not in pipeline or not isinstance(pipeline["tasks"], list):
        _error_exit("Pipeline JSON must have a 'tasks' array")

    if not pipeline["tasks"]:
        _error_exit("Pipeline has no tasks")

    # Map temp IDs → real UUIDs as we create tasks
    id_map = {}  # temp_id -> real UUID
    created_tasks = []

    for i, task_def in enumerate(pipeline["tasks"]):
        temp_id = task_def.get("id", f"task-{i}")

        if not task_def.get("title"):
            _error_exit(f"Task '{temp_id}' is missing required field 'title'")
        if not task_def.get("spec"):
            _error_exit(f"Task '{temp_id}' is missing required field 'spec'")

        # Build creation payload
        data = {
            "title": task_def["title"],
            "spec": task_def["spec"],
            "priority": task_def.get("priority", "normal"),
            "type": task_def.get("type", "feature"),
        }
        if SESSION_ID:
            data["session_id"] = SESSION_ID
        if PROJECT_ID:
            data["project_id"] = PROJECT_ID
        if task_def.get("repo"):
            data["target_repo"] = task_def["repo"]
        if task_def.get("branch"):
            data["target_branch"] = task_def["branch"]
        if task_def.get("acceptance_criteria"):
            data["acceptance_criteria"] = task_def["acceptance_criteria"]

        # Resolve depends_on temp IDs to real UUIDs
        # Supports: string temp IDs ("setup"), numeric indices (0), or real UUIDs
        if task_def.get("depends_on"):
            dep_uuids = []
            for dep_ref in task_def["depends_on"]:
                dep_ref = str(dep_ref)  # normalize numeric indices to strings
                if dep_ref in id_map:
                    dep_uuids.append(id_map[dep_ref])
                elif dep_ref.isdigit():
                    # Numeric index → reference to earlier task by position
                    idx = int(dep_ref)
                    if idx < len(created_tasks):
                        dep_uuids.append(created_tasks[idx]["id"])
                    else:
                        _error_exit(f"Pipeline index {idx} out of range (only {len(created_tasks)} tasks created so far)")
                else:
                    # Try as a real UUID or prefix
                    dep_uuids.append(_resolve_task_id(dep_ref))
            data["dependency_ids"] = dep_uuids

        task = _api_request("POST", "", data)
        id_map[temp_id] = task["id"]

        # Auto-assign if specified
        if task_def.get("assign"):
            task = _api_request("POST", f"/{task['id']}/assign", {
                "session_name": task_def["assign"],
            })

        created_tasks.append(task)

        if not JSON_MODE:
            status = "created + assigned" if task_def.get("assign") else "created"
            print(f"  {GREEN}[{i+1}/{len(pipeline['tasks'])}]{RESET} {status}: "
                  f"{BRAND}#{task['id']}{RESET} {task['title']}")

    if JSON_MODE:
        _json_output({
            "pipeline": True,
            "tasks_created": len(created_tasks),
            "id_map": id_map,
            "tasks": created_tasks,
        })
        return

    print(f"\n{GREEN}[ORCHESTRATIA]{RESET} Pipeline created: {len(created_tasks)} task(s)")


# ── Agent Status Command ─────────────────────────────────────────


def cmd_agent_status(args):
    """Show agent connection status, session info, and assigned tasks."""
    status = {
        "connected": False,
        "server_name": None,
        "server_id": None,
        "session_id": None,
        "session_name": None,
        "project_id": None,
        "project_name": None,
        "role": None,
        "tasks": [],
        "task_summary": {"pending": 0, "running": 0, "total": 0},
    }

    # Check if we're in an Orchestratia session at all
    if not HUB_URL or not API_KEY:
        status["error"] = "Not in an Orchestratia session"
        if JSON_MODE:
            _json_output(status)
        else:
            print(f"{DIM}[ORCHESTRATIA] Not in an Orchestratia session (no env vars){RESET}")
        return

    # Try to get server name from config as fallback
    fallback_name = None
    try:
        from orchestratia_agent.config import default_config_path, load_config
        _cfg_path = default_config_path()
        if os.path.exists(_cfg_path):
            _cfg = load_config(_cfg_path)
            fallback_name = _cfg.get("server_name", _cfg.get("name"))
    except Exception:
        pass

    # Build request URL
    params = f"?session_id={SESSION_ID}" if SESSION_ID else ""
    url = f"{HUB_URL}/api/v1/server/status{params}"
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json",
    }

    ctx = ssl.create_default_context()
    if HUB_URL.startswith("https://staging.") or HUB_URL.startswith("https://localhost"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        resp = urllib.request.urlopen(req, context=ctx, timeout=5)
        data = json.loads(resp.read())
        status.update(data)
    except Exception as e:
        status["error"] = str(e)
        if fallback_name:
            status["server_name"] = fallback_name

    # Derive role from session name heuristic
    sname = status.get("session_name") or ""
    if any(k in sname.lower() for k in ("orchestrat", "platform", "coordinator")):
        status["role"] = "orchestrator"
    elif sname:
        status["role"] = "worker"

    if JSON_MODE:
        _json_output(status)
        return

    # Pretty print
    if not status.get("connected"):
        err = status.get("error", "unknown")
        print(f"{YELLOW}[ORCHESTRATIA]{RESET} Hub unreachable: {err}")
        if status.get("server_name"):
            print(f"  Server: {status['server_name']}")
        return

    role_str = f" ({status['role']})" if status.get("role") else ""
    session_str = status.get("session_name") or "no session"
    print(f"{BRAND}[ORCHESTRATIA]{RESET} {BOLD}{status['server_name']}{RESET} / {CYAN}{session_str}{RESET}{role_str}")

    if status.get("project_name"):
        print(f"  Project: {status['project_name']}")

    summary = status.get("task_summary", {})
    total = summary.get("total", 0)
    if total > 0:
        running = summary.get("running", 0)
        pending = summary.get("pending", 0)
        print(f"  Tasks: {running} running, {pending} pending")
        for t in status.get("tasks", []):
            status_color = {
                "running": CYAN, "pending": YELLOW, "assigned": CYAN,
                "planning": CYAN, "plan_review": YELLOW,
            }.get(t["status"], "")
            print(f"    {BRAND}#{t['id'][:8]}{RESET} {BOLD}{t['title']}{RESET} ({status_color}{t['status']}{RESET})")
    else:
        print(f"  {DIM}No assigned tasks{RESET}")


# ── Update Command ───────────────────────────────────────────────


def cmd_agent_update(args):
    """Update the agent: pull latest code, reinstall package.

    On Linux: git pull + pip reinstall from /opt/orchestratia-agent.
    On macOS: pip install --upgrade (pip-based install, no git repo).
    On Windows (standalone exe): re-runs the PowerShell install script in upgrade mode.
    """
    import subprocess

    if sys.platform == "win32":
        _agent_update_windows()
        return

    # Detect install method: git repo (Linux) or pip-only (macOS)
    install_dir = os.environ.get("ORCHESTRATIA_INSTALL_DIR", "/opt/orchestratia-agent")
    has_git_repo = os.path.isdir(os.path.join(install_dir, ".git"))

    if not has_git_repo:
        # pip-only install (macOS, or Linux without git clone)
        _agent_update_pip()
        return

    if JSON_MODE:
        results = {"install_dir": install_dir, "steps": []}

    # Helper: run a command, use sudo if it fails with permission error
    def _run_git(cmd_args):
        try:
            return subprocess.run(
                cmd_args, cwd=install_dir, check=True,
                capture_output=True, text=True,
            )
        except subprocess.CalledProcessError as e:
            err = (e.stderr or "") + (e.stdout or "")
            if "Permission denied" in err or "unable to create" in err:
                return subprocess.run(
                    ["sudo"] + cmd_args, cwd=install_dir, check=True,
                    capture_output=True, text=True,
                )
            raise

    # Step 1: git fetch + reset
    if not JSON_MODE:
        print(f"{BRAND}[ORCHESTRATIA]{RESET} Updating agent from {install_dir}...")

    try:
        _run_git(["git", "fetch", "origin"])

        # Detect default branch (main or master)
        branch_result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=install_dir, capture_output=True, text=True,
        )
        branch = branch_result.stdout.strip() or "main"

        old_commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=install_dir, capture_output=True, text=True,
        ).stdout.strip()

        _run_git(["git", "reset", "--hard", f"origin/{branch}"])

        new_commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=install_dir, capture_output=True, text=True,
        ).stdout.strip()

        if old_commit == new_commit:
            step_msg = f"Already up to date ({new_commit})"
        else:
            step_msg = f"Updated {old_commit} -> {new_commit}"

        if JSON_MODE:
            results["steps"].append({"git": step_msg, "old": old_commit, "new": new_commit})
        else:
            print(f"  {GREEN}git:{RESET} {step_msg}")

    except subprocess.CalledProcessError as e:
        msg = f"git failed: {e.stderr.strip() if e.stderr else str(e)}"
        if JSON_MODE:
            results["steps"].append({"git": "failed", "error": msg})
        else:
            print(f"  {RED}git:{RESET} {msg}")
        if JSON_MODE:
            _json_output(results)
        return

    # Step 2: reinstall package (no-deps, just update entry points + code)
    # Try plain pip first, then with --break-system-packages (PEP 668 on Ubuntu 24.04+)
    pip_cmd = [sys.executable, "-m", "pip", "install", "--no-deps", "--quiet", install_dir]
    try:
        subprocess.run(pip_cmd, check=True, capture_output=True, text=True)
        if JSON_MODE:
            results["steps"].append({"pip": "ok"})
        else:
            print(f"  {GREEN}pip:{RESET} Package reinstalled")
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else ""
        if "externally-managed-environment" in err:
            # PEP 668: retry with --break-system-packages
            try:
                pip_cmd_bsp = [sys.executable, "-m", "pip", "install", "--no-deps",
                               "--quiet", "--break-system-packages", install_dir]
                subprocess.run(pip_cmd_bsp, check=True, capture_output=True, text=True)
                if JSON_MODE:
                    results["steps"].append({"pip": "ok"})
                else:
                    print(f"  {GREEN}pip:{RESET} Package reinstalled")
            except subprocess.CalledProcessError as e2:
                msg = e2.stderr.strip() if e2.stderr else str(e2)
                if JSON_MODE:
                    results["steps"].append({"pip": "failed", "error": msg})
                else:
                    print(f"  {YELLOW}pip:{RESET} {msg}")
        else:
            if JSON_MODE:
                results["steps"].append({"pip": "failed", "error": err or str(e)})
            else:
                print(f"  {YELLOW}pip:{RESET} {err or str(e)}")

    # Skill file updates automatically via symlink — no action needed

    if JSON_MODE:
        _json_output(results)
    else:
        print(f"\n{GREEN}[ORCHESTRATIA]{RESET} Update complete. Skill file updated via symlink.")
        if sys.platform == "darwin":
            print(f"  {DIM}Restart the daemon to apply: launchctl kickstart -k gui/$(id -u)/com.orchestratia.agent{RESET}")
        else:
            print(f"  {DIM}Restart the daemon to apply: sudo systemctl restart orchestratia-agent{RESET}")


def _agent_update_pip():
    """Update via pip install --upgrade (macOS and pip-only Linux installs)."""
    import subprocess

    if JSON_MODE:
        results = {"platform": sys.platform, "method": "pip", "steps": []}

    if not JSON_MODE:
        print(f"{BRAND}[ORCHESTRATIA]{RESET} Updating agent via pip...")

    try:
        # Get current version
        old_ver = ""
        try:
            out = subprocess.run(
                [sys.executable, "-m", "pip", "show", "orchestratia-agent"],
                capture_output=True, text=True,
            )
            for line in out.stdout.splitlines():
                if line.startswith("Version:"):
                    old_ver = line.split(":", 1)[1].strip()
        except Exception:
            pass

        pip_src = "git+https://github.com/kumarimlab/orchestratia-agent.git"
        pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet", pip_src]
        result = subprocess.run(pip_cmd, capture_output=True, text=True, timeout=120)

        # Retry with --break-system-packages if PEP 668 blocks it
        if result.returncode != 0 and "externally-managed-environment" in (result.stderr or ""):
            pip_cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet",
                       "--break-system-packages", pip_src]
            result = subprocess.run(pip_cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            # Get new version
            new_ver = ""
            try:
                out = subprocess.run(
                    [sys.executable, "-m", "pip", "show", "orchestratia-agent"],
                    capture_output=True, text=True,
                )
                for line in out.stdout.splitlines():
                    if line.startswith("Version:"):
                        new_ver = line.split(":", 1)[1].strip()
            except Exception:
                pass

            if old_ver and new_ver and old_ver == new_ver:
                step_msg = f"Already up to date ({new_ver})"
            elif old_ver and new_ver:
                step_msg = f"Updated {old_ver} -> {new_ver}"
            else:
                step_msg = "Package upgraded"

            if JSON_MODE:
                results["steps"].append({"pip": step_msg, "old": old_ver, "new": new_ver})
            else:
                print(f"  {GREEN}pip:{RESET} {step_msg}")
        else:
            msg = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
            if JSON_MODE:
                results["steps"].append({"pip": "failed", "error": msg})
            else:
                print(f"  {RED}pip:{RESET} {msg}")

    except subprocess.TimeoutExpired:
        msg = "pip install timed out after 120s"
        if JSON_MODE:
            results["steps"].append({"pip": "failed", "error": msg})
        else:
            print(f"  {RED}pip:{RESET} {msg}")

    if JSON_MODE:
        _json_output(results)
    else:
        print(f"\n{GREEN}[ORCHESTRATIA]{RESET} Update complete.")
        if sys.platform == "darwin":
            print(f"  {DIM}Restart the daemon: launchctl unload ~/Library/LaunchAgents/com.orchestratia.agent.plist && launchctl load ~/Library/LaunchAgents/com.orchestratia.agent.plist{RESET}")
        else:
            print(f"  {DIM}Restart the daemon: sudo systemctl restart orchestratia-agent{RESET}")


def _agent_update_windows():
    """Windows update: re-run the PowerShell installer in upgrade mode (no token = upgrade)."""
    import subprocess

    install_url = "https://raw.githubusercontent.com/kumarimlab/orchestratia-agent/main/scripts/install-windows.ps1"

    if JSON_MODE:
        results = {"platform": "windows", "steps": []}

    if not JSON_MODE:
        print(f"{BRAND}[ORCHESTRATIA]{RESET} Updating agent (Windows exe)...")
        print(f"  {DIM}Running install script in upgrade mode...{RESET}")

    try:
        result = subprocess.run(
            [
                "powershell", "-ExecutionPolicy", "Bypass", "-Command",
                f"irm {install_url} | iex",
            ],
            capture_output=True, text=True, timeout=120,
        )

        if result.returncode == 0:
            if JSON_MODE:
                results["steps"].append({"upgrade": "ok", "output": result.stdout[-500:] if result.stdout else ""})
            else:
                # Print the installer output (it has its own formatting)
                if result.stdout:
                    print(result.stdout)
                print(f"{GREEN}[ORCHESTRATIA]{RESET} Update complete.")
        else:
            msg = result.stderr.strip() if result.stderr else f"exit code {result.returncode}"
            if JSON_MODE:
                results["steps"].append({"upgrade": "failed", "error": msg})
            else:
                print(f"  {RED}Upgrade failed:{RESET} {msg}")
                if result.stdout:
                    print(result.stdout[-500:])

    except FileNotFoundError:
        msg = "PowerShell not found. Run manually in PowerShell:"
        if JSON_MODE:
            results["steps"].append({"upgrade": "failed", "error": msg})
        else:
            print(f"  {RED}{msg}{RESET}")
            print(f"  {CYAN}irm {install_url} | iex{RESET}")

    except subprocess.TimeoutExpired:
        msg = "Upgrade timed out after 120s"
        if JSON_MODE:
            results["steps"].append({"upgrade": "failed", "error": msg})
        else:
            print(f"  {RED}{msg}{RESET}")

    if JSON_MODE:
        _json_output(results)


# ── Init Command ─────────────────────────────────────────────────────


_INIT_TEMPLATE = """# Orchestratia Integration

This project is coordinated via [Orchestratia](https://orchestratia.com) — an AI agent orchestration platform.

## CLI Quick Reference

The `orchestratia` CLI is available in your terminal. All commands support `--json` for machine-readable output.

### Check for assigned work
```bash
orchestratia task check
```

### View task details
```bash
orchestratia task view <task-id>      # full UUID or 4+ char prefix
```

### Start working on a task
```bash
orchestratia task start <task-id>
```

### Complete a task
```bash
orchestratia task complete <task-id> --result "Summary of what was done"
```

### Report failure
```bash
orchestratia task fail <task-id> --error "What went wrong"
```

### Request human help
```bash
orchestratia task help <task-id> --question "What should I do about X?"
```

### Create a new task
```bash
orchestratia task create --title "Fix login bug" --spec "The login form crashes when..." --priority high
```

### Create and assign in one command
```bash
orchestratia task create --title "Build API" --spec "..." --assign session-name --json
```

### List tasks
```bash
orchestratia task list --status running --json
```

### List registered servers
```bash
orchestratia server list --json
```

### List active sessions in your project
```bash
orchestratia session list --json
```

### Create a multi-task pipeline
```bash
orchestratia pipeline create --file pipeline.json --json
```

### Remote execution on another session
```bash
orchestratia remote sessions                              # list sessions in project
orchestratia remote exec <session-name> "ls -la"          # run command on remote session
orchestratia remote read <session-name> /path/to/file     # read file from remote session
```

### File transfer between agents
```bash
orchestratia file send ./build.tar.gz --to other-session  # send file to another session
orchestratia file status <transfer-id>                    # check transfer progress
```

Files are transferred through the hub (chunked, SHA-256 verified). Sender and receiver must be in the same project and owned by the same user.

## Workflow for AI Agents

1. **Check** for assigned tasks: `orchestratia task check --json`
2. **Start** the task: `orchestratia task start <id> --json`
3. Do the work
4. **Complete** or **fail**: `orchestratia task complete <id> --result '{"summary": "..."}' --json`

Always use `--json` when parsing output programmatically. Task IDs support prefix matching (minimum 4 characters).
"""


def cmd_init(args):
    """Generate ORCHESTRATIA.md with CLI usage instructions."""
    content = _INIT_TEMPLATE.strip() + "\n"

    if args.print_only:
        print(content)
        return

    out_path = os.path.join(os.getcwd(), "ORCHESTRATIA.md")
    if os.path.exists(out_path) and not args.force:
        _error_exit(f"{out_path} already exists. Use --force to overwrite.")

    with open(out_path, "w") as f:
        f.write(content)

    if JSON_MODE:
        _json_output({"created": out_path})
        return

    print(f"{GREEN}[ORCHESTRATIA]{RESET} Created {out_path}")
    print(f"  Add this file to your repo so AI agents know how to use Orchestratia.")


# ── Main ─────────────────────────────────────────────────────────────


# ── Remote Commands ──────────────────────────────────────────────────


def cmd_remote_sessions(args):
    """List sessions in the current project (alias for session list)."""
    cmd_session_list(args)


def cmd_remote_exec(args):
    """Execute a command on a remote session."""
    if not PROJECT_ID:
        _error_exit("ORCHESTRATIA_PROJECT_ID not set (set env var or configure config.yaml)")

    result = _api_request(
        "POST", "",
        data={
            "session_name": args.session_name,
            "command": args.command,
            "timeout": args.timeout,
        },
        base=f"/api/v1/server/remote/exec?project_id={PROJECT_ID}",
    )

    if JSON_MODE:
        _json_output(result)
        return

    exit_code = result.get("exit_code", -1)
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    if stdout:
        print(stdout, end="")
    if stderr:
        print(f"{RED}{stderr}{RESET}", end="", file=sys.stderr)

    if exit_code != 0:
        print(f"\n{DIM}[exit code: {exit_code}]{RESET}")


def cmd_remote_read(args):
    """Read a file from a remote session (sugar for exec + cat)."""
    # Reuse remote exec with cat
    args.command = f"cat {args.path}"
    if not hasattr(args, "timeout"):
        args.timeout = 30
    cmd_remote_exec(args)


# ── File Transfer Commands ──────────────────────────────────────────


def cmd_file_send(args):
    """Send a file to a target session via hub relay."""
    import hashlib

    if not PROJECT_ID:
        _error_exit("ORCHESTRATIA_PROJECT_ID not set (set env var or configure config.yaml)")

    file_path = os.path.abspath(args.path)
    if not os.path.isfile(file_path):
        _error_exit(f"File not found: {file_path}")

    file_size = os.path.getsize(file_path)
    filename = os.path.basename(file_path)

    # Pre-compute SHA-256
    if not JSON_MODE:
        print(f"{DIM}Computing SHA-256...{RESET}", end="", flush=True)
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    sha256 = hasher.hexdigest()
    if not JSON_MODE:
        print(f"\r{DIM}SHA-256: {sha256[:16]}...{RESET}")

    # Initiate transfer via REST
    result = _api_request(
        "POST", "",
        data={
            "target_session": args.to,
            "project_id": PROJECT_ID,
            "filename": filename,
            "file_path": file_path,
            "file_size": file_size,
            "sha256": sha256,
        },
        base="/api/v1/server/remote/file-transfer",
    )

    transfer_id = result.get("transfer_id", "")
    if not transfer_id:
        _error_exit("Failed to initiate transfer: no transfer_id returned")

    if not JSON_MODE:
        print(f"{GREEN}[ORCHESTRATIA]{RESET} Transfer initiated: {transfer_id[:12]}...")
        print(f"  File: {filename} ({file_size:,} bytes)")
        print(f"  Target: {args.to}")
        print(f"  {DIM}Waiting for receiver to accept...{RESET}")

    # Poll for completion
    timeout = getattr(args, "timeout", 300)
    import time
    start = time.time()
    while time.time() - start < timeout:
        status = _api_request(
            "GET", f"/{transfer_id}",
            base="/api/v1/server/remote/file-transfer",
        )
        st = status.get("status", "")

        if st == "completed":
            if JSON_MODE:
                _json_output(status)
            else:
                print(f"{GREEN}[ORCHESTRATIA]{RESET} Transfer complete! File delivered to '{args.to}'")
            return

        if st in ("failed", "rejected"):
            error = status.get("error", st)
            if JSON_MODE:
                _json_output(status)
            else:
                print(f"{RED}[ORCHESTRATIA]{RESET} Transfer {st}: {error}")
            sys.exit(1)

        if st == "transferring" and not JSON_MODE:
            relayed = status.get("chunks_relayed", 0)
            total = status.get("total_chunks", 0)
            if total:
                pct = int(relayed / total * 100)
                print(f"\r  {DIM}Progress: {relayed}/{total} chunks ({pct}%){RESET}    ", end="", flush=True)

        time.sleep(1)

    if JSON_MODE:
        _json_output({"error": f"Transfer timed out after {timeout}s", "transfer_id": transfer_id})
    else:
        print(f"\n{RED}[ORCHESTRATIA]{RESET} Transfer timed out after {timeout}s")
    sys.exit(1)


def cmd_file_status(args):
    """Check file transfer status."""
    result = _api_request(
        "GET", f"/{args.transfer_id}",
        base="/api/v1/server/remote/file-transfer",
    )

    if JSON_MODE:
        _json_output(result)
        return

    st = result.get("status", "unknown")
    status_color = {
        "pending": YELLOW, "accepted": CYAN, "transferring": CYAN,
        "completed": GREEN, "failed": RED, "rejected": RED,
    }.get(st, "")

    print(f"{BRAND}Transfer {result.get('transfer_id', '')[:12]}...{RESET}")
    print(f"  Status: {status_color}{st}{RESET}")
    print(f"  File: {result.get('filename', '?')} ({result.get('file_size', 0):,} bytes)")
    relayed = result.get("chunks_relayed", 0)
    total = result.get("total_chunks", 0)
    if total:
        print(f"  Progress: {relayed}/{total} chunks ({int(relayed / total * 100)}%)")
    if result.get("error"):
        print(f"  Error: {RED}{result['error']}{RESET}")


def main():
    global JSON_MODE

    # Handle --json at any argv position before argparse processes it.
    # This lets both `orchestratia --json task list` and
    # `orchestratia task list --json` work uniformly.
    if "--json" in sys.argv[1:]:
        JSON_MODE = True
        sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a != "--json"]

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
    create_p.add_argument("--assign", help="Session name to auto-assign after creation")
    create_p.add_argument("--require-plan", action="store_true",
                          help="Require plan approval before execution (used with --assign)")

    # task check
    task_sub.add_parser("check", help="Check for assigned tasks")

    # task view
    view_p = task_sub.add_parser("view", help="View task details")
    view_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")

    # task complete
    complete_p = task_sub.add_parser("complete", help="Complete a task")
    complete_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    complete_p.add_argument("--result", required=True, help="Completion result (string or JSON)")

    # task start
    start_p = task_sub.add_parser("start", help="Start a task (transition to running)")
    start_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")

    # task fail
    fail_p = task_sub.add_parser("fail", help="Mark a task as failed")
    fail_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    fail_p.add_argument("--error", required=True, help="Error description")

    # task help
    help_p = task_sub.add_parser("help", help="Request intervention")
    help_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    help_p.add_argument("--question", required=True, help="Question for human or orchestrator")
    help_p.add_argument("--context", help="Additional context")
    help_p.add_argument("--type", choices=["help", "question", "approval"],
                        default="help", help="Intervention type (help=human, question=agent-answerable)")

    # task plan
    plan_p = task_sub.add_parser("plan", help="Submit a plan for review")
    plan_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    plan_p.add_argument("--plan", required=True, help="Plan content (string or JSON)")

    # task note
    note_p = task_sub.add_parser("note", help="Add a note to a task")
    note_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    note_p.add_argument("--content", required=True, help="Note content")
    note_p.add_argument("--urgent", action="store_true", help="Mark as urgent (interrupts agent)")

    # task notes (list)
    notes_p = task_sub.add_parser("notes", help="List notes for a task")
    notes_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")

    # task assign
    assign_p = task_sub.add_parser("assign", help="Assign task to a session")
    assign_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    assign_p.add_argument("--session", required=True, help="Session name")
    assign_p.add_argument("--require-plan", action="store_true",
                          help="Require plan approval before execution")

    # task update
    update_p = task_sub.add_parser("update", help="Update task fields")
    update_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
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
    cancel_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")

    # task status
    status_p = task_sub.add_parser("status", help="Check task status")
    status_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")

    # task list
    list_p = task_sub.add_parser("list", help="List tasks")
    list_p.add_argument("--status", help="Filter by status")

    # task deps
    deps_parser = task_sub.add_parser("deps", help="Manage task dependencies")
    deps_sub = deps_parser.add_subparsers(dest="deps_action")

    # task deps add
    deps_add_p = deps_sub.add_parser("add", help="Add a dependency")
    deps_add_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    deps_add_p.add_argument("--depends-on", required=True, help="ID of upstream task")
    deps_add_p.add_argument("--type", default="blocks",
                           choices=["blocks", "input", "related"],
                           help="Dependency type")
    deps_add_p.add_argument("--contract-key", help="Contract key for input deps")

    # task deps remove
    deps_rm_p = deps_sub.add_parser("remove", help="Remove a dependency")
    deps_rm_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    deps_rm_p.add_argument("--depends-on", required=True, help="ID of upstream task")

    # ── server subcommand ──
    server_parser = subparsers.add_parser("server", help="Server operations")
    server_sub = server_parser.add_subparsers(dest="action")

    # server list
    server_sub.add_parser("list", help="List all registered servers")

    # ── session subcommand ──
    session_parser = subparsers.add_parser("session", help="Session operations")
    session_sub = session_parser.add_subparsers(dest="action")

    # session list
    session_sub.add_parser("list", help="List active sessions in this project")

    # ── intervention subcommand ──
    intervention_parser = subparsers.add_parser("intervention", help="Intervention operations")
    intervention_sub = intervention_parser.add_subparsers(dest="action")

    # intervention list
    int_list_p = intervention_sub.add_parser("list", help="List interventions")
    int_list_p.add_argument("--task-id", help="Filter by task ID")
    int_list_p.add_argument("--status", help="Filter by status (pending, responded)")

    # intervention respond
    int_respond_p = intervention_sub.add_parser("respond", help="Respond to an intervention")
    int_respond_p.add_argument("intervention_id", help="Intervention ID")
    int_respond_p.add_argument("--response", required=True, help="Response text")

    # ── pipeline subcommand ──
    pipeline_parser = subparsers.add_parser("pipeline", help="Multi-task pipeline operations")
    pipeline_sub = pipeline_parser.add_subparsers(dest="action")

    # pipeline create
    pipe_create_p = pipeline_sub.add_parser("create", help="Create a pipeline from JSON")
    pipe_create_p.add_argument("--file", help="Path to pipeline JSON file")
    pipe_create_p.add_argument("--inline", help="Inline pipeline JSON string")

    # ── remote subcommand ──
    remote_parser = subparsers.add_parser("remote", help="Cross-session remote commands")
    remote_sub = remote_parser.add_subparsers(dest="action")

    # remote sessions
    remote_sub.add_parser("sessions", help="List sessions in this project")

    # remote exec
    remote_exec_p = remote_sub.add_parser("exec", help="Execute command on remote session")
    remote_exec_p.add_argument("session_name", help="Target session name")
    remote_exec_p.add_argument("command", help="Command to execute")
    remote_exec_p.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")

    # remote read
    remote_read_p = remote_sub.add_parser("read", help="Read file from remote session")
    remote_read_p.add_argument("session_name", help="Target session name")
    remote_read_p.add_argument("path", help="File path to read")
    remote_read_p.add_argument("--timeout", type=int, default=30, help="Timeout in seconds")

    # ── file subcommand ──
    file_parser = subparsers.add_parser("file", help="File transfer operations")
    file_sub = file_parser.add_subparsers(dest="action")

    # file send
    file_send_p = file_sub.add_parser("send", help="Send a file to another session")
    file_send_p.add_argument("path", help="Path to the file to send")
    file_send_p.add_argument("--to", required=True, help="Target session name")
    file_send_p.add_argument("--timeout", type=int, default=300,
                             help="Timeout in seconds (default: 300)")

    # file status
    file_status_p = file_sub.add_parser("status", help="Check file transfer status")
    file_status_p.add_argument("transfer_id", help="Transfer ID")

    # ── status subcommand (top-level agent status) ──
    subparsers.add_parser("status", help="Show agent status: connection, session, tasks")

    # ── update subcommand ──
    subparsers.add_parser("update", help="Update agent: pull latest code, reinstall package, refresh skill")

    # ── init subcommand ──
    init_parser = subparsers.add_parser("init", help="Generate ORCHESTRATIA.md for this repo")
    init_parser.add_argument("--print", dest="print_only", action="store_true",
                            help="Print to stdout instead of writing file")
    init_parser.add_argument("--force", action="store_true",
                            help="Overwrite existing ORCHESTRATIA.md")

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
                "plan": cmd_plan,
                "note": cmd_note,
                "notes": cmd_notes,
                "assign": cmd_assign,
                "update": cmd_update,
                "cancel": cmd_cancel,
                "status": cmd_status,
                "list": cmd_list,
            }
            actions[args.action](args)

    elif args.command == "server":
        if not args.action:
            server_parser.print_help()
            sys.exit(1)

        server_actions = {
            "list": cmd_server_list,
        }
        server_actions[args.action](args)

    elif args.command == "session":
        if not args.action:
            session_parser.print_help()
            sys.exit(1)

        session_actions = {
            "list": cmd_session_list,
        }
        session_actions[args.action](args)

    elif args.command == "intervention":
        if not args.action:
            intervention_parser.print_help()
            sys.exit(1)

        intervention_actions = {
            "list": cmd_intervention_list,
            "respond": cmd_intervention_respond,
        }
        intervention_actions[args.action](args)

    elif args.command == "remote":
        if not args.action:
            remote_parser.print_help()
            sys.exit(1)

        remote_actions = {
            "sessions": cmd_remote_sessions,
            "exec": cmd_remote_exec,
            "read": cmd_remote_read,
        }
        remote_actions[args.action](args)

    elif args.command == "pipeline":
        if not args.action:
            pipeline_parser.print_help()
            sys.exit(1)

        pipeline_actions = {
            "create": cmd_pipeline_create,
        }
        pipeline_actions[args.action](args)

    elif args.command == "file":
        if not args.action:
            file_parser.print_help()
            sys.exit(1)

        file_actions = {
            "send": cmd_file_send,
            "status": cmd_file_status,
        }
        file_actions[args.action](args)

    elif args.command == "status":
        cmd_agent_status(args)

    elif args.command == "update":
        cmd_agent_update(args)

    elif args.command == "init":
        cmd_init(args)


if __name__ == "__main__":
    main()
