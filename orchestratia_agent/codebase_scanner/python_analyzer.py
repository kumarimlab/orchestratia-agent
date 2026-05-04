"""Python file analyzer using the stdlib ast module. Zero external dependencies."""

import ast
import os
from pathlib import Path


def analyze_python_file(file_path: str) -> dict | None:
    """Parse a Python file and extract structural information.

    Returns None if the file can't be parsed.
    """
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return None

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return None

    imports = []
    classes = []
    functions = []
    line_count = source.count("\n") + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)
        elif isinstance(node, ast.ClassDef):
            methods = [
                n.name for n in node.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            classes.append({
                "name": node.name,
                "methods": methods,
                "method_count": len(methods),
                "line": node.lineno,
            })
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Only top-level functions (not methods inside classes)
            if not any(
                isinstance(parent, ast.ClassDef)
                for parent in _iter_parents(tree, node)
            ):
                functions.append({
                    "name": node.name,
                    "line": node.lineno,
                    "is_async": isinstance(node, ast.AsyncFunctionDef),
                })

    # Complexity: rough estimate based on structural elements
    complexity = (
        len(functions)
        + sum(c["method_count"] for c in classes)
        + _count_branches(tree)
    )

    return {
        "language": "python",
        "lines": line_count,
        "imports": sorted(set(imports)),
        "classes": classes,
        "functions": functions,
        "class_count": len(classes),
        "function_count": len(functions) + sum(c["method_count"] for c in classes),
        "complexity": complexity,
    }


def _count_branches(tree: ast.AST) -> int:
    """Count branching statements as a rough complexity metric."""
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                             ast.With, ast.Assert, ast.Try)):
            count += 1
    return count


def _iter_parents(tree: ast.AST, target: ast.AST):
    """Yield parent nodes of the target node."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            if child is target:
                yield node
