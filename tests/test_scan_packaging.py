#!/usr/bin/env python3
"""The built wheel carries the scanner data files the runner reads at run time.

gitleaks.toml (the pinned rules passed via --config) and manifest.json (pinned tool versions and
digests) are not Python modules, so setuptools leaves them out unless they are declared; a pip
install from git would then fail `scanners install` and every secrets scan.

Run:  python3 tests/test_scan_packaging.py
"""
import os
import subprocess
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


with tempfile.TemporaryDirectory() as out, tempfile.TemporaryDirectory() as work:
    # Build from a copy so the build's own egg-info/build dirs never land in the checkout, and with
    # build isolation, as `pip install git+…` and `orchestratia update` do.
    src = os.path.join(work, "src")
    files = subprocess.run(["git", "-C", ROOT, "ls-files", "-co", "--exclude-standard"],
                           capture_output=True, text=True, check=True).stdout.split("\n")
    for rel in filter(None, files):
        if not os.path.isfile(os.path.join(ROOT, rel)):
            continue
        os.makedirs(os.path.dirname(os.path.join(src, rel)), exist_ok=True)
        with open(os.path.join(ROOT, rel), "rb") as a, open(os.path.join(src, rel), "wb") as b:
            b.write(a.read())
    r = subprocess.run([sys.executable, "-m", "pip", "wheel", src, "--no-deps",
                        "--quiet", "-w", out], capture_output=True, text=True)
    ok("the wheel builds", r.returncode == 0, r.stderr[-500:])
    wheels = [f for f in os.listdir(out) if f.endswith(".whl")]
    names = set(zipfile.ZipFile(os.path.join(out, wheels[0])).namelist()) if wheels else set()
    for rel in ("orchestratia_agent/scanning/gitleaks.toml", "orchestratia_agent/scanning/manifest.json"):
        ok(f"the wheel contains {rel}", rel in names)
    if wheels:
        z = zipfile.ZipFile(os.path.join(out, wheels[0]))
        for rel in ("gitleaks.toml", "manifest.json"):
            path = f"orchestratia_agent/scanning/{rel}"
            with open(os.path.join(ROOT, path), "rb") as f:
                ok(f"the packaged {rel} matches the source", path in names and z.read(path) == f.read())

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
