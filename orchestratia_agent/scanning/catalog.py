"""The scan catalog (spec §6). Stdlib only. The hub keeps the POLICY half; this file
says what each scan is and how to run it. Phase 1: code scans only."""
from dataclasses import asdict, dataclass

CATALOG_VERSION = "1"
_IMPACT_WORDS = {"none": "Reads files only. Sends nothing anywhere and changes nothing.",
                 "light": "Sends normal requests to the target. Never sends attack payloads.",
                 "attack": "Sends attack payloads; creates junk data; may crash the app."}


@dataclass(frozen=True)
class ScanSpec:
    id: str
    title: str
    checks: tuple[str, ...]
    impact: str
    target: str
    tool: str
    timeout_s: int
    memory_max: str
    typical: str
    deps_only: bool = False
    needs_git: bool = False


CATALOG = {s.id: s for s in (
    ScanSpec("code.secrets", "Secrets in code and history",
             ("API keys, tokens and passwords in files", "the same in git history"),
             "none", "repo", "gitleaks", 900, "2G", "under 1 min", needs_git=True),
    ScanSpec("code.deps", "Vulnerable dependencies",
             ("known CVEs in packages from manifests and lockfiles (offline database)",),
             "none", "repo", "osv-scanner", 600, "1G", "under 1 min", deps_only=True),
    ScanSpec("code.agent", "AI-agent shortcuts",
             ("suppressions without a reason", "skipped or focused tests", "removed assertions or tests",
              "placeholders left in", "removed CI steps", "edits to agent-steering files", "hidden Unicode"),
             "none", "repo", "orchestratia", 300, "512M", "under 1 min", needs_git=True),
)}


def get(scan_id: str):
    return CATALOG.get(scan_id)


def describe(scan_id: str) -> str:
    s = CATALOG.get(scan_id)
    if s is None:
        return f"Unknown scan: {scan_id}"
    lines = [f"{s.id}   {s.title} ({s.tool})", "  Checks:  " + "; ".join(s.checks),
             f"  Impact:  {_IMPACT_WORDS[s.impact]}", "  Needs:   a session's repository",
             f"  Takes:   {s.typical} (stops after {s.timeout_s // 60} min)"]
    return "\n".join(lines)


def public() -> list:
    return [{k: v for k, v in asdict(s).items() if k not in ("timeout_s", "memory_max")}
            for s in CATALOG.values()]
