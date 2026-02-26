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
  orchestratia task help <id> --question "..."
  orchestratia task plan <id> --plan '{"summary": "...", "impact": "..."}'
  orchestratia task note <id> --content "..." [--urgent]
  orchestratia task assign <id> --server "name"
  orchestratia task update <id> [--title/--spec/--priority/...]
  orchestratia task cancel <id>
  orchestratia task status <id>
  orchestratia task list [--status pending] [--json]
  orchestratia task deps add <id> --depends-on <dep_id> [--type blocks]
  orchestratia task deps remove <id> --depends-on <dep_id>
  orchestratia server list [--json]
  orchestratia session list [--json]
  orchestratia pipeline create --file pipeline.json [--json]
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
HUB_URL = os.environ.get("ORCHESTRATIA_HUB_URL", "")
API_KEY = os.environ.get("ORCHESTRATIA_API_KEY", "")
SESSION_ID = os.environ.get("ORCHESTRATIA_SESSION_ID", "")
PROJECT_ID = os.environ.get("ORCHESTRATIA_PROJECT_ID", "")

# Config file fallback: env var > config.yaml
if not HUB_URL or not API_KEY:
    try:
        from orchestratia_agent.config import default_config_path, load_config
        _cfg_path = default_config_path()
        if os.path.exists(_cfg_path):
            _cfg = load_config(_cfg_path)
            if not HUB_URL:
                HUB_URL = _cfg.get("hub_url", "")
            if not API_KEY:
                API_KEY = _cfg.get("api_key", "")
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
    """Request human intervention for a task."""
    args.task_id = _resolve_task_id(args.task_id)
    data = {"question": args.question}
    if args.context:
        data["context"] = args.context
    result = _api_request("POST", f"/{args.task_id}/help", data)

    if JSON_MODE:
        _json_output(result)
        return

    print(f"{YELLOW}[ORCHESTRATIA]{RESET} Help requested:")
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
    help_p = task_sub.add_parser("help", help="Request human intervention")
    help_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    help_p.add_argument("--question", required=True, help="Question for human")
    help_p.add_argument("--context", help="Additional context")

    # task plan
    plan_p = task_sub.add_parser("plan", help="Submit a plan for review")
    plan_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    plan_p.add_argument("--plan", required=True, help="Plan content (string or JSON)")

    # task note
    note_p = task_sub.add_parser("note", help="Add a note to a task")
    note_p.add_argument("task_id", help="Task ID (full UUID or 4+ char prefix)")
    note_p.add_argument("--content", required=True, help="Note content")
    note_p.add_argument("--urgent", action="store_true", help="Mark as urgent (interrupts agent)")

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

    # ── pipeline subcommand ──
    pipeline_parser = subparsers.add_parser("pipeline", help="Multi-task pipeline operations")
    pipeline_sub = pipeline_parser.add_subparsers(dest="action")

    # pipeline create
    pipe_create_p = pipeline_sub.add_parser("create", help="Create a pipeline from JSON")
    pipe_create_p.add_argument("--file", help="Path to pipeline JSON file")
    pipe_create_p.add_argument("--inline", help="Inline pipeline JSON string")

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

    elif args.command == "pipeline":
        if not args.action:
            pipeline_parser.print_help()
            sys.exit(1)

        pipeline_actions = {
            "create": cmd_pipeline_create,
        }
        pipeline_actions[args.action](args)

    elif args.command == "init":
        cmd_init(args)


if __name__ == "__main__":
    main()
