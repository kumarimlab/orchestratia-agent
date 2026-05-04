"""JavaScript/TypeScript file analyzer using regex. Zero external dependencies."""

import re
from pathlib import Path

# Import patterns
_ES6_IMPORT = re.compile(
    r"""import\s+(?:"""
    r"""(?:(?P<default>\w+)\s*,?\s*)?"""  # default import
    r"""(?:\{[^}]*\}\s*,?\s*)?"""         # named imports
    r"""(?:\*\s+as\s+\w+\s*)?"""          # namespace import
    r""")?\s*from\s+['"](?P<module>[^'"]+)['"]""",
    re.MULTILINE,
)
_REQUIRE = re.compile(r"""require\s*\(\s*['"](?P<module>[^'"]+)['"]\s*\)""")
_DYNAMIC_IMPORT = re.compile(r"""import\s*\(\s*['"](?P<module>[^'"]+)['"]\s*\)""")

# Export patterns
_EXPORT_DEFAULT = re.compile(r"""export\s+default\s+(?:function|class|const|let|var)?\s*(\w+)?""")
_EXPORT_NAMED = re.compile(r"""export\s+(?:const|let|var|function|class|async\s+function|interface|type|enum)\s+(\w+)""")

# Component detection (React)
_REACT_COMPONENT = re.compile(r"""(?:export\s+)?(?:default\s+)?function\s+([A-Z]\w+)\s*\(""")
_ARROW_COMPONENT = re.compile(r"""(?:export\s+)?(?:const|let)\s+([A-Z]\w+)\s*[=:]\s*(?:\([^)]*\)|[^=])\s*=>""")

# Go imports
_GO_IMPORT_SINGLE = re.compile(r"""import\s+"(?P<module>[^"]+)"\s*$""", re.MULTILINE)
_GO_IMPORT_BLOCK = re.compile(r"""import\s*\((.*?)\)""", re.DOTALL)
_GO_IMPORT_LINE = re.compile(r"""\s*(?:\w+\s+)?"(?P<module>[^"]+)"\s*""")

# Rust use
_RUST_USE = re.compile(r"""use\s+(?P<module>[\w:]+)""")


def analyze_js_file(file_path: str) -> dict | None:
    """Parse a JS/TS/TSX file and extract structural information."""
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return None

    ext = Path(file_path).suffix.lower()
    line_count = source.count("\n") + 1

    # Extract imports
    imports = []
    for m in _ES6_IMPORT.finditer(source):
        imports.append(m.group("module"))
    for m in _REQUIRE.finditer(source):
        imports.append(m.group("module"))
    for m in _DYNAMIC_IMPORT.finditer(source):
        imports.append(m.group("module"))

    # Extract exports
    exports = []
    for m in _EXPORT_DEFAULT.finditer(source):
        name = m.group(1)
        if name:
            exports.append(name)
    for m in _EXPORT_NAMED.finditer(source):
        exports.append(m.group(1))

    # Detect React components
    components = []
    for m in _REACT_COMPONENT.finditer(source):
        components.append(m.group(1))
    for m in _ARROW_COMPONENT.finditer(source):
        components.append(m.group(1))

    # Count functions (rough)
    func_count = len(re.findall(r"""(?:function\s+\w+|(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?\([^)]*\)\s*=>)""", source))

    # Complexity: imports + exports + branches
    branches = len(re.findall(r"""\b(?:if|else if|for|while|switch|catch|case)\b""", source))
    complexity = func_count + branches

    language = {
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".mjs": "javascript",
        ".cjs": "javascript",
    }.get(ext, "javascript")

    return {
        "language": language,
        "lines": line_count,
        "imports": sorted(set(imports)),
        "exports": exports,
        "components": components,
        "function_count": func_count,
        "complexity": complexity,
    }


def analyze_go_file(file_path: str) -> dict | None:
    """Parse a Go file for imports."""
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return None

    imports = []
    # Single imports
    for m in _GO_IMPORT_SINGLE.finditer(source):
        imports.append(m.group("module"))
    # Block imports
    for block in _GO_IMPORT_BLOCK.finditer(source):
        for line_match in _GO_IMPORT_LINE.finditer(block.group(1)):
            imports.append(line_match.group("module"))

    func_count = len(re.findall(r"""func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(""", source))
    struct_count = len(re.findall(r"""type\s+\w+\s+struct\b""", source))
    line_count = source.count("\n") + 1

    return {
        "language": "go",
        "lines": line_count,
        "imports": sorted(set(imports)),
        "function_count": func_count,
        "struct_count": struct_count,
        "complexity": func_count + struct_count,
    }


def analyze_rust_file(file_path: str) -> dict | None:
    """Parse a Rust file for use statements."""
    try:
        source = Path(file_path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, IOError):
        return None

    imports = []
    for m in _RUST_USE.finditer(source):
        imports.append(m.group("module"))

    func_count = len(re.findall(r"""(?:pub\s+)?(?:async\s+)?fn\s+(\w+)""", source))
    struct_count = len(re.findall(r"""(?:pub\s+)?struct\s+(\w+)""", source))
    line_count = source.count("\n") + 1

    return {
        "language": "rust",
        "lines": line_count,
        "imports": sorted(set(imports)),
        "function_count": func_count,
        "struct_count": struct_count,
        "complexity": func_count + struct_count,
    }
