"""Health score calculation from scan data. No external dependencies."""


def calculate_health_score(
    files: list[dict],
    graph: dict,
    git_data: dict,
) -> dict:
    """Calculate a health score (0-100) with grade and factor breakdown.

    Four factors, each 0-100, weighted equally:
    - Complexity: file size and function counts
    - Dependencies: circular deps, depth, orphans
    - Churn: change frequency hotspots
    - Structure: module consistency
    """
    complexity_score = _score_complexity(files)
    dependency_score = _score_dependencies(graph)
    churn_score = _score_churn(files, git_data)
    structure_score = _score_structure(files, graph.get("modules", []))

    overall = round(
        complexity_score["score"] * 0.25
        + dependency_score["score"] * 0.25
        + churn_score["score"] * 0.25
        + structure_score["score"] * 0.25
    )

    # Identify hotspots (files with worst combined score)
    hotspot_scores = {}
    for f in files:
        path = f["path"]
        score = 0
        if f.get("complexity", 0) > 15:
            score += 3
        if f.get("lines", 0) > 500:
            score += 2
        if f.get("function_count", 0) > 15:
            score += 2
        churn = git_data.get("file_churn", {}).get(path, 0)
        if churn > 10:
            score += 3
        if churn > 20:
            score += 2
        if score > 0:
            hotspot_scores[path] = score

    hotspots = sorted(hotspot_scores, key=hotspot_scores.get, reverse=True)[:10]

    # Tech debt estimation
    tech_debt = _estimate_tech_debt(files, graph, git_data)

    return {
        "score": max(0, min(100, overall)),
        "grade": _score_to_grade(overall),
        "factors": {
            "complexity": complexity_score,
            "dependencies": dependency_score,
            "churn": churn_score,
            "structure": structure_score,
        },
        "hotspots": hotspots,
        "tech_debt": tech_debt,
    }


def _score_complexity(files: list[dict]) -> dict:
    """Score based on file sizes and function counts."""
    if not files:
        return {"score": 100, "details": "No files to analyze"}

    penalties = 0
    large_files = 0
    complex_files = 0

    for f in files:
        lines = f.get("lines", 0)
        funcs = f.get("function_count", 0)
        complexity = f.get("complexity", 0)

        if lines > 800:
            penalties += 5
            large_files += 1
        elif lines > 500:
            penalties += 2
            large_files += 1

        if funcs > 20:
            penalties += 5
            complex_files += 1
        elif funcs > 15:
            penalties += 2
            complex_files += 1

        if complexity > 30:
            penalties += 3

    score = max(0, 100 - penalties)
    details = []
    if large_files:
        details.append(f"{large_files} large files (>500 lines)")
    if complex_files:
        details.append(f"{complex_files} complex files (>15 functions)")
    if not details:
        details.append("All files within healthy thresholds")

    return {"score": score, "details": "; ".join(details)}


def _score_dependencies(graph: dict) -> dict:
    """Score based on dependency health."""
    score = 100
    details = []

    circular = graph.get("circular_deps", [])
    if circular:
        score -= 20 * len(circular)
        details.append(f"{len(circular)} circular dependency(ies)")

    max_depth = graph.get("max_depth", 0)
    if max_depth > 8:
        score -= 15
        details.append(f"Deep dependency chain ({max_depth} levels)")
    elif max_depth > 5:
        score -= 5
        details.append(f"Moderate dependency depth ({max_depth} levels)")

    orphans = graph.get("orphans", [])
    if len(orphans) > 10:
        score -= 10
        details.append(f"{len(orphans)} orphan files (unused)")
    elif len(orphans) > 5:
        score -= 5
        details.append(f"{len(orphans)} orphan files")

    if not details:
        details.append(f"Healthy (max depth {max_depth}, no circular deps)")

    return {"score": max(0, score), "details": "; ".join(details)}


def _score_churn(files: list[dict], git_data: dict) -> dict:
    """Score based on file change frequency."""
    if not git_data.get("is_git_repo"):
        return {"score": 80, "details": "Not a git repo — no churn data"}

    churn = git_data.get("file_churn", {})
    if not churn:
        return {"score": 100, "details": "No recent changes"}

    score = 100
    hot_files = 0
    details = []

    for path, changes in churn.items():
        if changes > 20:
            score -= 5
            hot_files += 1
        elif changes > 10:
            score -= 2
            hot_files += 1

    if hot_files:
        details.append(f"{hot_files} high-churn files")
    else:
        details.append("No high-churn hotspots")

    return {"score": max(0, score), "details": "; ".join(details)}


def _score_structure(files: list[dict], modules: list[dict]) -> dict:
    """Score based on structural consistency."""
    if not modules:
        return {"score": 80, "details": "No module structure detected"}

    score = 100
    details = []

    # Check if modules have consistent sizes
    file_counts = [m["files"] for m in modules if m["files"] > 0]
    if file_counts:
        avg_files = sum(file_counts) / len(file_counts)
        oversized = sum(1 for c in file_counts if c > avg_files * 3)
        if oversized:
            score -= 5 * oversized
            details.append(f"{oversized} oversized modules")

    # Check for too many top-level files (no module structure)
    root_files = sum(1 for f in files if "/" not in f["path"] and "\\" not in f["path"])
    if root_files > 10:
        score -= 10
        details.append(f"{root_files} files in root (consider organizing into modules)")

    if not details:
        details.append("Consistent module structure")

    return {"score": max(0, score), "details": "; ".join(details)}


def _estimate_tech_debt(files: list[dict], graph: dict, git_data: dict) -> dict:
    """Estimate technical debt in hours per file and total.

    Rule-based estimation:
    - Function complexity > 20: ~2h to decompose
    - File > 500 lines: ~1h to split
    - High churn + high complexity: ~4h to stabilize
    - Circular dependency: ~3h to resolve per cycle
    - Deep nesting (>20 functions): ~1.5h to flatten
    """
    churn = git_data.get("file_churn", {})
    file_debts: list[dict] = []
    total_hours = 0.0

    for f in files:
        path = f["path"]
        lines = f.get("lines", 0)
        complexity = f.get("complexity", 0)
        func_count = f.get("function_count", 0)
        file_churn = churn.get(path, 0)
        hours = 0.0
        reasons = []

        # Large file
        if lines > 800:
            hours += 2.0
            reasons.append("split large file (2h)")
        elif lines > 500:
            hours += 1.0
            reasons.append("split oversized file (1h)")

        # High complexity
        if complexity > 30:
            hours += 3.0
            reasons.append("reduce high complexity (3h)")
        elif complexity > 20:
            hours += 2.0
            reasons.append("decompose complex functions (2h)")

        # Many functions (deep file)
        if func_count > 25:
            hours += 1.5
            reasons.append("extract functions to modules (1.5h)")
        elif func_count > 20:
            hours += 1.0
            reasons.append("organize functions (1h)")

        # High churn + complexity = hotspot debt
        if file_churn > 10 and complexity > 15:
            hours += 4.0
            reasons.append("stabilize high-churn hotspot (4h)")
        elif file_churn > 10:
            hours += 1.0
            reasons.append("reduce churn (1h)")

        if hours > 0:
            file_debts.append({
                "path": path,
                "hours": round(hours, 1),
                "reasons": reasons,
            })
            total_hours += hours

    # Circular dependencies
    circular = graph.get("circular_deps", [])
    circular_hours = len(circular) * 3.0
    total_hours += circular_hours

    # Sort by debt descending
    file_debts.sort(key=lambda x: x["hours"], reverse=True)

    return {
        "total_hours": round(total_hours, 1),
        "file_count": len(file_debts),
        "circular_dep_hours": round(circular_hours, 1),
        "files": file_debts[:30],  # Top 30 debtors
    }


def _score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 85:
        return "A-"
    elif score >= 80:
        return "B+"
    elif score >= 75:
        return "B"
    elif score >= 70:
        return "B-"
    elif score >= 65:
        return "C+"
    elif score >= 60:
        return "C"
    elif score >= 55:
        return "C-"
    elif score >= 45:
        return "D"
    else:
        return "F"
