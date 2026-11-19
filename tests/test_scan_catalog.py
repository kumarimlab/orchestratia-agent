#!/usr/bin/env python3
"""Scan catalog (spec §6): Phase 1 code scans, honest descriptions, nothing else.

Run:  python3 tests/test_scan_catalog.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning import catalog  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


ok("phase 1 has exactly the three code scans", set(catalog.CATALOG) == {"code.secrets", "code.deps", "code.agent"},
   sorted(catalog.CATALOG))
ok("all are impact none and target repo",
   all(s.impact == "none" and s.target == "repo" for s in catalog.CATALOG.values()))
ok("code.deps streams manifests only", catalog.get("code.deps").deps_only is True)
ok("code.secrets and code.agent need git history",
   catalog.get("code.secrets").needs_git and catalog.get("code.agent").needs_git)
ok("unknown id → None", catalog.get("web.active") is None)
d = catalog.describe("code.secrets")
ok("describe states impact plainly and the tool", "reads files only" in d.lower() and "gitleaks" in d, d)
ok("describe of an unknown scan says so", "unknown scan" in catalog.describe("nope").lower())
pub = catalog.public()
ok("public form omits limits", all("timeout_s" not in p and "memory_max" not in p for p in pub) and len(pub) == 3)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
