"""Generate Mermaid diagrams from dependency graphs and module data."""


def generate_module_diagram(modules: list[dict], edges: list[dict]) -> str:
    """Generate a Mermaid flowchart showing module-level dependencies.

    Groups files into their parent directories and shows dependency arrows
    between modules (directories), not individual files.
    """
    if not modules:
        return "graph TD\n  empty[No modules detected]"

    # Aggregate edges at module level
    module_edges = set()
    for edge in edges:
        import os
        src_mod = os.path.dirname(edge["from"]) or "."
        tgt_mod = os.path.dirname(edge["to"]) or "."
        if src_mod != tgt_mod:
            module_edges.add((src_mod, tgt_mod))

    # Filter to modules that have connections (avoid cluttering isolated modules)
    connected_modules = set()
    for src, tgt in module_edges:
        connected_modules.add(src)
        connected_modules.add(tgt)

    # Also include top-level modules even if not connected
    top_modules = {m["path"] for m in modules if m["path"].count("/") <= 1 or m["path"].count("\\") <= 1}
    show_modules = connected_modules | top_modules

    if not show_modules:
        show_modules = {m["path"] for m in modules[:15]}

    # Build node map
    node_map = {}
    for m in modules:
        if m["path"] in show_modules:
            safe_id = _safe_id(m["path"])
            label = m["path"].replace("/", "/")
            node_map[m["path"]] = safe_id
            # Could add metrics to label: f"{label}\\n{m['files']} files"

    lines = ["graph TD"]

    # Add nodes with labels
    for m in modules:
        if m["path"] in node_map:
            safe = node_map[m["path"]]
            label = m["path"]
            files = m["files"]
            lines.append(f'  {safe}["{label}<br/>{files} files"]')

    # Add edges
    for src, tgt in sorted(module_edges):
        if src in node_map and tgt in node_map:
            lines.append(f"  {node_map[src]} --> {node_map[tgt]}")

    # Style with Orchestratia palette
    for m in modules:
        if m["path"] in node_map:
            safe = node_map[m["path"]]
            # Color based on complexity
            if m.get("complexity_avg", 0) > 15:
                lines.append(f"  style {safe} fill:#FEF2F2,stroke:#EF4444")  # red - hot
            elif m.get("complexity_avg", 0) > 8:
                lines.append(f"  style {safe} fill:#FFF7ED,stroke:#F97316")  # amber - warm
            else:
                lines.append(f"  style {safe} fill:#F0F9F7,stroke:#2A9D88")  # teal - healthy

    return "\n".join(lines)


def generate_file_diagram(files: list[dict], edges: list[dict], max_files: int = 30) -> str:
    """Generate a Mermaid flowchart showing file-level dependencies.

    Limited to the most connected/important files to avoid noise.
    """
    if not files:
        return "graph TD\n  empty[No files detected]"

    # Rank files by connectivity (imports + imported-by)
    connectivity = {}
    for f in files:
        connectivity[f["path"]] = len(f.get("imports", []))
    for edge in edges:
        connectivity[edge["to"]] = connectivity.get(edge["to"], 0) + 1

    # Take top N files
    top_files = sorted(connectivity, key=connectivity.get, reverse=True)[:max_files]
    top_set = set(top_files)

    lines = ["graph LR"]

    # Nodes
    for f in files:
        if f["path"] in top_set:
            safe = _safe_id(f["path"])
            import os
            name = os.path.basename(f["path"])
            lines.append(f'  {safe}["{name}"]')

    # Edges (only between top files)
    for edge in edges:
        if edge["from"] in top_set and edge["to"] in top_set:
            lines.append(f"  {_safe_id(edge['from'])} --> {_safe_id(edge['to'])}")

    return "\n".join(lines)


def _safe_id(path: str) -> str:
    """Convert a file path to a safe Mermaid node ID."""
    return path.replace("/", "_").replace("\\", "_").replace(".", "_").replace("-", "_").replace(" ", "_")
