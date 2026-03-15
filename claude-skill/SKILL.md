---
name: orchestratia
description: Orchestratia agent workflow — task management, inter-agent coordination, result reporting. Use when working with tasks, checking status, creating work items, or when Orchestratia is mentioned.
---

# Orchestratia Agent Workflow

You are an AI coding agent running inside an Orchestratia-managed session. Orchestratia coordinates multiple AI agents across servers.

## 1. Identity & Status

Run this to see your role, session, and assigned tasks:

```bash
orchestratia status
```

Or for machine-readable output:

```bash
orchestratia status --json
```

## 2. Role Detection

Your role is determined by your session name:

- **Worker** (default): You execute tasks assigned to you. Check for work, start tasks, do the work, report results.
- **Orchestrator**: Session names containing "orchestrat", "platform", or "coordinator". You create tasks, assign them to other sessions, and monitor progress.

## 3. Worker Workflow

### Step 1: Check for assigned tasks

```bash
orchestratia task check --json
```

### Step 2: View task details

```bash
orchestratia task view <task-id> --json
```

Read the spec, acceptance criteria, structured requirements, and any resolved inputs from upstream tasks.

### Step 3: Start the task

```bash
orchestratia task start <task-id>
```

This transitions the task to "running" status. You cannot start a task with unresolved blocking dependencies.

### Step 4: Do the work

Implement the task according to its spec. If you need help:

```bash
# Request human help (default)
orchestratia task help <task-id> --question "What should I do about X?" --context "additional context"

# Ask an agent-answerable question (orchestrator can respond programmatically)
orchestratia task help <task-id> --question "What auth strategy?" --type question
```

Post progress notes:

```bash
orchestratia task note <task-id> --content "Completed the API endpoints, working on tests"
```

For urgent notes that interrupt the dashboard:

```bash
orchestratia task note <task-id> --content "Found a critical security issue" --urgent
```

### Step 5: Complete the task

Simple completion:

```bash
orchestratia task complete <task-id> --result "Implemented JWT auth with refresh tokens"
```

Structured result with contracts (enables downstream tasks to consume your output):

```bash
orchestratia task complete <task-id> --result '{
  "$schema": "orchestratia/task-result/v1",
  "summary": "Implemented JWT auth middleware",
  "changes": {
    "files_modified": ["src/auth/middleware.ts", "src/auth/types.ts"],
    "files_created": ["src/auth/__tests__/middleware.test.ts"]
  },
  "contracts": {
    "auth_middleware": {
      "type": "module_export",
      "path": "src/auth/middleware.ts",
      "exports": ["authMiddleware", "requireAuth"]
    }
  },
  "tests": {"passed": 12, "failed": 0, "skipped": 0}
}'
```

### Step 6: Report failure (if needed)

```bash
orchestratia task fail <task-id> --error "Cannot proceed: database migration conflicts with existing schema"
```

## 4. Orchestrator Workflow

### Create tasks

```bash
orchestratia task create --title "Build auth API" --spec "Implement JWT authentication..." \
  --priority high --type feature --repo cloud-gateway
```

### Create and assign in one step

```bash
orchestratia task create --title "Build auth API" --spec "..." \
  --assign claude-cloud-gateway --require-plan
```

### Assign existing tasks

```bash
orchestratia task assign <task-id> --session claude-web-dashboard
```

With plan mode (agent must submit plan for approval before executing):

```bash
orchestratia task assign <task-id> --session claude-web-dashboard --require-plan
```

### Monitor all tasks

```bash
orchestratia task list --json
orchestratia task list --status running --json
```

### List available sessions

```bash
orchestratia session list --json
```

### List servers

```bash
orchestratia server list --json
```

### Create multi-task pipelines

```bash
orchestratia pipeline create --file pipeline.json
```

Pipeline JSON format:

```json
{
  "tasks": [
    {"id": "setup", "title": "Setup DB schema", "spec": "...", "assign": "claude-core-api"},
    {"id": "api", "title": "Build API", "spec": "...", "depends_on": ["setup"], "assign": "claude-cloud-gateway"},
    {"id": "web", "title": "Build UI", "spec": "...", "depends_on": ["api"], "assign": "claude-web-dashboard"}
  ]
}
```

## 5. Plan Mode

When a task is assigned with `--require-plan`, the task enters "planning" state. You must submit a plan before executing:

```bash
orchestratia task plan <task-id> --plan '{
  "summary": "Will implement in 3 phases: schema, API routes, tests",
  "steps": ["Create migration for users table", "Add CRUD endpoints", "Write integration tests"],
  "estimated_files": 8,
  "risks": ["Migration may conflict with existing auth tables"]
}'
```

The task transitions to "plan_review". Once the orchestrator approves, the task moves to "running" and you can proceed with implementation.

## 6. CLI Command Reference

All commands support `--json` for machine-readable output. Task IDs accept short prefixes (minimum 4 chars).

| Command | Description |
|---------|-------------|
| `orchestratia status` | Show agent connection, session, assigned tasks |
| `orchestratia task check` | Check for tasks assigned to this session |
| `orchestratia task view <id>` | View full task details |
| `orchestratia task start <id>` | Transition task to running |
| `orchestratia task complete <id> --result "..."` | Complete with result (string or JSON) |
| `orchestratia task fail <id> --error "..."` | Report failure |
| `orchestratia task help <id> --question "..." [--type help\|question]` | Request intervention (type: help=human, question=agent-answerable) |
| `orchestratia task notes <id>` | List all notes for a task |
| `orchestratia task plan <id> --plan '...'` | Submit plan for review |
| `orchestratia task note <id> --content "..."` | Add a note (optional: `--urgent`) |
| `orchestratia task subscribe <id>` | Subscribe to real-time task events via WS |
| `orchestratia task unsubscribe <id>` | Unsubscribe from task events |
| `orchestratia task create --title "..." --spec "..."` | Create a task |
| `orchestratia task assign <id> --session "name"` | Assign to a session |
| `orchestratia task update <id> [--title/--spec/...]` | Update task fields |
| `orchestratia task cancel <id>` | Cancel a task |
| `orchestratia task status <id>` | Check a specific task's status |
| `orchestratia task list [--status ...]` | List tasks |
| `orchestratia task deps add <id> --depends-on <id>` | Add dependency (`--type blocks\|input\|related`) |
| `orchestratia task deps remove <id> --depends-on <id>` | Remove dependency |
| `orchestratia intervention list [--task-id X] [--status X]` | List interventions |
| `orchestratia intervention respond <id> --response "..."` | Respond to intervention programmatically |
| `orchestratia server list` | List all registered servers |
| `orchestratia session list` | List active sessions in project |
| `orchestratia pipeline create --file <path>` | Create multi-task pipeline |
| `orchestratia init` | Generate ORCHESTRATIA.md for a repo |

## 7. Result Schema Reference

The structured result format (`orchestratia/task-result/v1`) enables contract exchange between tasks:

```json
{
  "$schema": "orchestratia/task-result/v1",
  "summary": "What was accomplished",
  "changes": {
    "files_modified": ["path/to/file.ts"],
    "files_created": ["path/to/new.ts"],
    "files_deleted": []
  },
  "contracts": {
    "contract_key": {
      "type": "api_schema|db_schema|config_schema|module_export|...",
      "description": "What this contract provides",
      "data": {}
    }
  },
  "tests": {
    "passed": 0,
    "failed": 0,
    "skipped": 0
  }
}
```

## 8. Dependency Types

| Type | Purpose | Auto-resolves |
|------|---------|---------------|
| `blocks` | Ordering — downstream task cannot start until upstream completes | Yes |
| `input` | Contract exchange — downstream receives upstream's contract output via `resolved_inputs` | Yes |
| `related` | Informational — no blocking, just a reference link | No |

## 9. Common Contract Types

| Contract Type | Description | Typical Data |
|---------------|-------------|--------------|
| `api_schema` | REST API endpoint definitions | Routes, methods, request/response types |
| `db_schema` | Database table/migration definitions | Table names, columns, relationships |
| `config_schema` | Configuration format | Config keys, types, defaults |
| `auth_middleware` | Authentication/authorization exports | Middleware function paths, exports |
| `test_results` | Test execution results | Pass/fail counts, coverage |
| `build_artifacts` | Build output locations | Artifact paths, checksums |
| `deploy_status` | Deployment information | URLs, versions, health status |
| `ui_components` | Frontend component exports | Component names, props, paths |

## 10. Task Notes

Post notes to keep the orchestrator and other agents informed:

```bash
orchestratia task note <task-id> --content "Progress update: 3/5 endpoints done"
orchestratia task note <task-id> --content "BLOCKER: need DB credentials" --urgent
```

Notes are visible on the dashboard, sent to Telegram, and relayed to the agent daemon. Notes are also returned in `task view` responses as `recent_notes` (last 20).

To read existing notes:

```bash
orchestratia task notes <task-id>
```

## 11. Orchestrator: Responding to Interventions

Orchestrator agents can respond to worker questions programmatically:

```bash
# List pending interventions
orchestratia intervention list --task-id <task-id> --status pending

# Respond to a worker's question
orchestratia intervention respond <intervention-id> --response "Use JWT with RS256"
```

Workers must use `--type question` when asking (via `task help`) for the orchestrator to respond. With `--type help` (default), only human admins can respond.

## 12. WebSocket Task Subscriptions

Subscribe to real-time task events instead of polling:

```bash
orchestratia task subscribe <task-id>
```

After subscribing, your session receives push notifications for all events on that task (status changes, notes, interventions, completions).

## 13. Cross-Session Commands

Execute commands on other sessions in your project:

```bash
# List all sessions in your project
orchestratia remote sessions

# Run a command on another session's server
orchestratia remote exec <session-name> "cargo test"

# Read a file from another session's server
orchestratia remote read <session-name> /path/to/file

# With timeout (default 30s, max 300s)
orchestratia remote exec <session-name> "npm run build" --timeout 120
```

All remote commands support `--json` for machine-readable output.

## 14. File Transfer Between Agents

Send files to other sessions in your project via hub relay (chunked, SHA-256 verified):

```bash
# Send a file to another session
orchestratia file send ./build-output.tar.gz --to other-session-name

# Send with custom timeout (default 300s)
orchestratia file send ./large-artifact.bin --to other-session --timeout 600

# Check transfer status
orchestratia file status <transfer-id>
```

Received files are saved to `~/.orchestratia/transfers/` (configurable via `ORCHESTRATIA_TRANSFER_DIR` env var).

Requirements:
- Sender and receiver must be in the **same project**
- Both servers must be owned by the **same user**
- Receiver must have an active session

## 15. Documentation

Full documentation available at:

- Agent Integration Guide: https://orchestratia.com/docs/agent-guide
- Protocol Reference: https://orchestratia.com/docs/protocols
- Architecture Overview: https://orchestratia.com/docs/architecture
