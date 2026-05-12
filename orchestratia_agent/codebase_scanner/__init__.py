"""Codebase scanner — zero-dependency architecture analysis.

Scans a repository and produces:
- File tree with per-file metrics (lines, complexity, imports)
- Dependency graph with circular dependency detection
- Git churn analysis (hotspot files)
- Health score (0-100, A-F grade)
- Mermaid architecture diagram

All analysis uses Python stdlib only (ast, re, os, subprocess).
No tree-sitter, no external packages.
"""

import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .python_analyzer import analyze_python_file
from .js_analyzer import analyze_js_file, analyze_go_file, analyze_rust_file
from .git_analyzer import analyze_git_history
from .graph_builder import build_dependency_graph
from .mermaid_generator import generate_module_diagram
from .metrics import calculate_health_score

log = logging.getLogger("orchestratia.scanner")

# File extensions to analyze
_ANALYZERS = {
    ".py": analyze_python_file,
    ".js": analyze_js_file,
    ".jsx": analyze_js_file,
    ".ts": analyze_js_file,
    ".tsx": analyze_js_file,
    ".mjs": analyze_js_file,
    ".go": analyze_go_file,
    ".rs": analyze_rust_file,
}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", ".env",
    "dist", "build", ".next", ".nuxt", "target", ".tox", ".mypy_cache",
    ".pytest_cache", "coverage", ".coverage", "htmlcov", "egg-info",
    ".eggs", ".cache", ".turbo", ".vercel", ".svelte-kit",
}

# Max files to analyze (safety limit)
_MAX_FILES = 2000
_MAX_FILE_SIZE = 500_000  # 500KB per file


class CodebaseScanner:
    """Scan a repository and produce architecture metrics."""

    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)

    def scan(self) -> dict:
        """Run full codebase scan. Returns snapshot dict ready for hub."""
        start = time.monotonic()

        # 1. Walk the file tree
        source_files = self._discover_files()
        log.info(f"Scanner: found {len(source_files)} source files in {self.repo_path}")

        # 2. Analyze each file
        analyzed = []
        language_counts = {}
        total_lines = 0

        for file_path in source_files:
            ext = Path(file_path).suffix.lower()
            analyzer = _ANALYZERS.get(ext)
            if not analyzer:
                continue

            result = analyzer(file_path)
            if result is None:
                continue

            # Store with relative path
            rel_path = os.path.relpath(file_path, self.repo_path)
            result["path"] = rel_path
            analyzed.append(result)

            lang = result.get("language", "unknown")
            language_counts[lang] = language_counts.get(lang, 0) + 1
            total_lines += result.get("lines", 0)

        # 3. Git analysis
        git_data = analyze_git_history(self.repo_path)

        # Merge churn into file data
        for f in analyzed:
            f["churn"] = git_data.get("file_churn", {}).get(f["path"], 0)

        # 4. Build dependency graph
        graph = build_dependency_graph(analyzed, self.repo_path)

        # 5. Calculate health score
        health = calculate_health_score(analyzed, graph, git_data)

        # 6. Generate Mermaid diagram
        mermaid = generate_module_diagram(graph["modules"], graph["edges"])

        duration_ms = int((time.monotonic() - start) * 1000)

        # Count all files (including non-analyzed ones like YAML, MD, etc.)
        all_files = self._count_all_files()

        # Build tech debt lookup for per-file data
        debt_lookup = {}
        tech_debt = health.get("tech_debt", {})
        for fd in tech_debt.get("files", []):
            debt_lookup[fd["path"]] = fd["hours"]

        snapshot = {
            "repo_path": self.repo_path,
            "git_commit": git_data.get("current_commit"),
            "git_branch": git_data.get("branch"),
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_ms": duration_ms,
            "stats": {
                "total_files": all_files,
                "analyzed_files": len(analyzed),
                "total_lines": total_lines,
                "languages": language_counts,
            },
            "modules": graph["modules"],
            "files": [
                {
                    "path": f["path"],
                    "language": f.get("language", "unknown"),
                    "lines": f.get("lines", 0),
                    "imports": f.get("imports", []),
                    "function_count": f.get("function_count", 0),
                    "class_count": f.get("class_count", 0),
                    "complexity": f.get("complexity", 0),
                    "churn": f.get("churn", 0),
                    "tech_debt_hours": debt_lookup.get(f["path"], 0),
                }
                for f in analyzed
            ],
            "dependencies": graph["edges"],
            "circular_deps": graph["circular_deps"],
            "orphan_files": graph["orphans"],
            "health": health,
            "mermaid_graph": mermaid,
            "git": {
                "is_git_repo": git_data["is_git_repo"],
                "current_commit": git_data.get("current_commit"),
                "branch": git_data.get("branch"),
                "commits_last_30d": git_data.get("total_commits_in_period", 0),
                "hotspots": git_data.get("hotspots", []),
                "authors": git_data.get("recent_authors", []),
            },
        }

        log.info(
            f"Scanner: completed in {duration_ms}ms — "
            f"{len(analyzed)} files, score={health['score']} ({health['grade']})"
        )

        return snapshot

    def _discover_files(self) -> list[str]:
        """Walk directory tree and collect analyzable source files."""
        files = []
        count = 0

        for root, dirs, filenames in os.walk(self.repo_path):
            # Skip ignored directories (modify in-place to prevent descent)
            dirs[:] = [
                d for d in dirs
                if d not in _SKIP_DIRS and not d.startswith(".")
            ]

            for filename in filenames:
                ext = Path(filename).suffix.lower()
                if ext not in _ANALYZERS:
                    continue

                filepath = os.path.join(root, filename)

                # Skip oversized files
                try:
                    if os.path.getsize(filepath) > _MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue

                files.append(filepath)
                count += 1
                if count >= _MAX_FILES:
                    log.warning(f"Scanner: hit {_MAX_FILES} file limit, stopping discovery")
                    return files

        return files

    def _count_all_files(self) -> int:
        """Count all non-hidden files in repo (quick, no analysis)."""
        count = 0
        for root, dirs, filenames in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            count += len(filenames)
            if count > 10000:
                return count  # safety limit
        return count
