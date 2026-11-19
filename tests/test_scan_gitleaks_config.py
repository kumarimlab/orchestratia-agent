#!/usr/bin/env python3
"""The pinned gitleaks config (adversarial review M5): the upstream rules, without any path allowlist.

`[extend] useDefault = true` inherited gitleaks' default GLOBAL allowlist, which skips files by name
(settings.svg / settings.pdf / vendor/... / node_modules/... / lockfiles): a planted secret there was
never reported. The vendored file is the pinned binary's own default config with every path
allowlist removed (scripts/gen-gitleaks-config.py); this test re-generates it from the pinned binary
when available and checks the result byte for byte, and checks the structure always.

Run:  python3 tests/test_scan_gitleaks_config.py
"""
import hashlib
import importlib.util
import os
import sys
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(ROOT, "orchestratia_agent", "scanning", "gitleaks.toml")
GITLEAKS = "/tmp/orc-pin/gitleaks"
# sha256 of the vendored file. Changing it means regenerating from a newly pinned binary.
PINNED = "ac2c156086883946fd99c78bc7d64d3fdf9f8e1c4383d9cf4c40d122e74ce13f"
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


raw = open(CFG, "rb").read()
cfg = tomllib.loads(raw.decode())
ok("the config does not extend the upstream default (which brings the global path allowlist)", "extend" not in cfg)
ok("the global allowlist skips only .git", cfg.get("allowlist", {}).get("paths") == [r"(?:^|/)\.git$"],
   cfg.get("allowlist", {}).get("paths"))
ok("no rule has a path allowlist", not [r["id"] for r in cfg["rules"] for a in r.get("allowlists", []) if a.get("paths")])
ok("the upstream rules are all there (gitleaks 8.30.1: 222)", len(cfg["rules"]) == 222, len(cfg["rules"]))
ok("the true/false/null value allowlist is anchored as a whole",
   r"(?i)^(?:true|false|null)$" in cfg["allowlist"]["regexes"]
   and r"(?i)^true|false|null$" not in cfg["allowlist"]["regexes"])
ok("the vendored file is pinned by hash", hashlib.sha256(raw).hexdigest() == PINNED, hashlib.sha256(raw).hexdigest())
if os.path.exists(GITLEAKS):
    spec = importlib.util.spec_from_file_location("gen", os.path.join(ROOT, "scripts", "gen-gitleaks-config.py"))
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    ok("re-generated from the pinned binary, byte for byte", gen.transform(gen.upstream_from_binary(GITLEAKS)) == raw.decode())
else:
    print("[SKIP] re-generation check: /tmp/orc-pin/gitleaks missing")

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
