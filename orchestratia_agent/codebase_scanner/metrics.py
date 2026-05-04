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
