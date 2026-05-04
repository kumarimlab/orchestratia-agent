"""Build dependency graphs from import data. Detect circular dependencies."""

from collections import defaultdict


def build_dependency_graph(files: list[dict], repo_path: str) -> dict:
    """Build a module dependency graph from file analysis results.

    Args:
        files: list of file analysis dicts (must have 'path' and 'imports')
        repo_path: root path of the repo (for resolving relative imports)

    Returns:
        Dict with 'edges', 'modules', 'circular_deps', 'max_depth', 'orphans'
    """
    # Map file paths to their module info
    path_set = {f["path"] for f in files}

    # Build adjacency list
    edges = []
    adj = defaultdict(set)

    for f in files:
        src = f["path"]
        for imp in f.get("imports", []):
            # Try to resolve import to a known file
            target = _resolve_import(imp, src, path_set, repo_path)
            if target and target != src:
                edges.append({"from": src, "to": target, "type": "import"})
                adj[src].add(target)

    # Detect circular dependencies
    circular = _find_cycles(adj)

    # Find orphan files (no imports and not imported by anyone)
    imported_by_someone = set()
    for targets in adj.values():
        imported_by_someone.update(targets)
    imports_something = set(adj.keys())

    orphans = [
        f["path"] for f in files
        if f["path"] not in imported_by_someone and f["path"] not in imports_something
        and not f["path"].endswith("__init__.py")
        and not f["path"].endswith("conftest.py")
    ]

    # Compute max depth (longest dependency chain)
    max_depth = _compute_max_depth(adj)

    # Group files into modules (directories)
    modules = _group_into_modules(files)

    return {
        "edges": edges,
        "modules": modules,
        "circular_deps": circular,
        "max_depth": max_depth,
        "orphans": orphans[:20],  # limit to 20
        "total_edges": len(edges),
    }


def _resolve_import(imp: str, source_path: str, known_paths: set, repo_path: str) -> str | None:
    """Try to resolve an import string to a known file path."""
    # Convert dotted import to path fragments
    # e.g., "app.services.task_service" -> "app/services/task_service"
    parts = imp.replace(".", "/")

    # Try common patterns
    candidates = [
        f"{parts}.py",
        f"{parts}/index.ts",
        f"{parts}/index.tsx",
        f"{parts}/index.js",
        f"{parts}/__init__.py",
        f"{parts}.ts",
        f"{parts}.tsx",
        f"{parts}.js",
    ]

    for candidate in candidates:
        if candidate in known_paths:
            return candidate

    # For relative JS/TS imports (starting with ./ or ../)
    if imp.startswith("./") or imp.startswith("../"):
        import os
        source_dir = os.path.dirname(source_path)
        resolved = os.path.normpath(os.path.join(source_dir, imp))
        for ext in [".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.tsx", "/index.js"]:
            candidate = resolved + ext
            if candidate in known_paths:
                return candidate

    return None


def _find_cycles(adj: dict[str, set]) -> list[list[str]]:
    """Find circular dependencies using DFS."""
    cycles = []
    visited = set()
    path = []
    path_set = set()

    def dfs(node):
        if node in path_set:
            # Found a cycle
            cycle_start = path.index(node)
            cycle = path[cycle_start:] + [node]
            # Only keep short cycles (direct or near-direct)
            if len(cycle) <= 5:
                cycles.append(cycle)
            return
        if node in visited:
            return

        visited.add(node)
        path.append(node)
        path_set.add(node)

        for neighbor in adj.get(node, []):
            dfs(neighbor)

        path.pop()
        path_set.discard(node)

    for node in adj:
        dfs(node)

    # Deduplicate cycles (same cycle can be found from different starting nodes)
    seen = set()
    unique = []
    for cycle in cycles:
        key = tuple(sorted(cycle[:-1]))
        if key not in seen:
            seen.add(key)
            unique.append(cycle)

    return unique[:10]  # limit to 10


def _compute_max_depth(adj: dict[str, set]) -> int:
    """Find the longest dependency chain using DFS with memoization."""
    memo = {}

    def depth(node, visited=None):
        if visited is None:
            visited = set()
        if node in memo:
            return memo[node]
        if node in visited:
            return 0  # cycle, don't recurse
        visited.add(node)
        max_d = 0
        for neighbor in adj.get(node, []):
            max_d = max(max_d, 1 + depth(neighbor, visited))
        visited.discard(node)
        memo[node] = max_d
        return max_d

    return max(depth(n) for n in adj) if adj else 0


def _group_into_modules(files: list[dict]) -> list[dict]:
    """Group files into directory-based modules."""
    modules = defaultdict(lambda: {"files": 0, "lines": 0, "complexity": 0, "functions": 0})

    for f in files:
        import os
        module_path = os.path.dirname(f["path"]) or "."
        m = modules[module_path]
        m["files"] += 1
        m["lines"] += f.get("lines", 0)
        m["complexity"] += f.get("complexity", 0)
        m["functions"] += f.get("function_count", 0)

    return [
        {
            "path": path,
            "files": data["files"],
            "lines": data["lines"],
            "complexity_avg": round(data["complexity"] / max(data["files"], 1), 1),
            "functions": data["functions"],
        }
        for path, data in sorted(modules.items())
    ]
