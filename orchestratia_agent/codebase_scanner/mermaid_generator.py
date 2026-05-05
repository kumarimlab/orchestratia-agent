"""Generate Mermaid diagrams from dependency graphs and module data."""

import os


def generate_module_diagram(modules: list[dict], edges: list[dict], max_nodes: int = 20) -> str:
    """Generate a Mermaid flowchart showing module-level dependencies.

    Groups files into high-level modules (max 2 directory levels deep) and
    shows dependency arrows between them. Limited to max_nodes to keep
    the diagram readable.
    """
    if not modules:
        return "graph TD\n  empty[No modules detected]"

    # Aggregate modules to max 2 levels deep
    aggregated = {}
    for m in modules:
        key = _collapse_path(m["path"], max_depth=2)
        if key not in aggregated:
            aggregated[key] = {"path": key, "files": 0, "lines": 0, "complexity": 0, "functions": 0, "count": 0}
        agg = aggregated[key]
        agg["files"] += m["files"]
        agg["lines"] += m["lines"]
        agg["complexity"] += m.get("complexity_avg", 0) * m["files"]
        agg["functions"] += m.get("functions", 0)
        agg["count"] += 1

    # Compute average complexity
    for agg in aggregated.values():
        agg["complexity_avg"] = round(agg["complexity"] / max(agg["files"], 1), 1)

    # Aggregate edges at the same level
    module_edges = set()
    for edge in edges:
        src_mod = _collapse_path(os.path.dirname(edge["from"]) or ".", max_depth=2)
        tgt_mod = _collapse_path(os.path.dirname(edge["to"]) or ".", max_depth=2)
        if src_mod != tgt_mod and src_mod in aggregated and tgt_mod in aggregated:
            module_edges.add((src_mod, tgt_mod))

    # Sort by file count descending and take top N
    sorted_modules = sorted(aggregated.values(), key=lambda m: m["files"], reverse=True)[:max_nodes]
    show_set = {m["path"] for m in sorted_modules}

    # Filter edges to only shown modules
    shown_edges = [(s, t) for s, t in module_edges if s in show_set and t in show_set]

    lines = ["graph TD"]

    # Add nodes
    for m in sorted_modules:
        safe = _safe_id(m["path"])
        label = m["path"]
        files = m["files"]
        lines.append(f'  {safe}["{label}<br/>{files} files"]')

    # Add edges
    for src, tgt in sorted(shown_edges):
        lines.append(f"  {_safe_id(src)} --> {_safe_id(tgt)}")

    # Style nodes by complexity
    for m in sorted_modules:
        safe = _safe_id(m["path"])
        avg = m.get("complexity_avg", 0)
        if avg > 15:
            lines.append(f"  style {safe} fill:#FEF2F2,stroke:#EF4444")
        elif avg > 8:
            lines.append(f"  style {safe} fill:#FFF7ED,stroke:#F97316")
        else:
            lines.append(f"  style {safe} fill:#F0F9F7,stroke:#2A9D88")

    return "\n".join(lines)


def _collapse_path(path: str, max_depth: int = 2) -> str:
    """Collapse a path to max N directory levels.

    e.g., 'backend/app/api/v1' with max_depth=2 → 'backend/app'
    e.g., 'frontend/src/components/terminal' with max_depth=2 → 'frontend/src'
    """
    parts = path.replace("\\", "/").split("/")
    return "/".join(parts[:max_depth]) if len(parts) > max_depth else path


def _safe_id(path: str) -> str:
    """Convert a file path to a safe Mermaid node ID."""
    return path.replace("/", "_").replace("\\", "_").replace(".", "_").replace("-", "_").replace(" ", "_").replace("(", "").replace(")", "")
