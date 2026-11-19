#!/usr/bin/env python3
"""code.deps snapshot (adversarial review M2): a deps-only snapshot must carry every manifest osv-scanner
would read — not only an exact-name allowlist — and what an included requirements file pulls in.
The end-to-end part runs the pinned osv-scanner 2.7.0 offline on the PyPI DB (/tmp/orc-pin; skipped
when missing).

Run:  python3 tests/test_scan_deps_snapshot.py
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import pack  # noqa: E402

HELPER = os.path.join(HERE, "orchestratia_agent", "dl_helper.py")
OSV = "/tmp/orc-pin/osv-scanner_linux_amd64"
DB = "/tmp/orc-pin/db"
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def write(repo, rel, data):
    os.makedirs(os.path.dirname(os.path.join(repo, rel)) or repo, exist_ok=True)
    with open(os.path.join(repo, rel), "w") as f:
        f.write(data)


def snap(repo):
    p = subprocess.run([sys.executable, "-I", HELPER, "snap", "--deps-only", "--", repo], capture_output=True, timeout=60)
    head, _, body = p.stdout.partition(b"\n")
    assert p.returncode == 0 and json.loads(head)["ok"], (p.returncode, head)
    return body


def names(body):
    with tarfile.open(fileobj=io.BytesIO(body), mode="r|") as tf:
        return sorted(m.name for m in tf)


VULN = "django==3.2.0\n"
with tempfile.TemporaryDirectory() as td:
    repo = os.path.join(td, "repo")
    files = {"requirements-prod.txt": VULN, "requirements.txt": "-r requirements/base.txt\n-c constraints/pins.txt\n",
             "requirements/base.txt": "--requirement=../extra/more.txt\n" + VULN, "extra/more.txt": "flask==0.12\n",
             "constraints/pins.txt": "requests==2.0.0\n", "build/requirements.txt": VULN, "dist/Pipfile.lock": "{}",
             "target/Cargo.lock": "", "app/Pipfile": "[packages]\n", "svc/svc.csproj": "<Project/>",
             "svc/packages.config": "<packages/>", "android/build.gradle": "", "mob/pubspec.lock": "", "web/bun.lock": "",
             "x/pdm.lock": "", "x/gems.locked": "", "x/mix.lock": "", "src/main.py": "print(1)\n",
             "README.md": "-r not-a-requirements-file\n", "requirements/escape.txt": "-r ../../../../etc/passwd\n",
             "node_modules/p/package.json": "{}"}
    for rel, data in files.items():
        write(repo, rel, data)
    got = names(snap(repo))
    want = sorted(set(files) - {"src/main.py", "README.md", "node_modules/p/package.json"})
    ok("deps-only carries every manifest-like file, any name or directory (build/dist/target too)",
       set(want) <= set(got), sorted(set(want) - set(got)))
    ok("deps-only leaves out source, docs and node_modules", not {"src/main.py", "README.md",
                                                                  "node_modules/p/package.json"} & set(got), got)
    ok("an include outside the repository is never followed", not [g for g in got if "passwd" in g or g.startswith("..")], got)

    if os.path.exists(OSV) and os.path.isdir(DB):
        flat = tempfile.mkdtemp(prefix="orc-flat-")
        for name in pack.RUNNER_FILES:
            shutil.copy(os.path.join(HERE, "orchestratia_agent", "scanning", name), flat)
        for case, layout in (("requirements-prod.txt", {"requirements-prod.txt": VULN}),
                             ("-r include", {"requirements.txt": "-r requirements/base.txt\n", "requirements/base.txt": VULN}),
                             ("build/requirements.txt", {"build/requirements.txt": VULN})):
            r = os.path.join(td, "e2e-" + str(abs(hash(case))))
            for rel, data in layout.items():
                write(r, rel, data)
            hdr = {"scan_id": "code.deps", "since": None, "tools": {"osv-scanner": OSV}, "osv_db": DB,
                   "data_as_of": "2026-11-16", "known": []}
            home = tempfile.mkdtemp()
            p = subprocess.run([sys.executable, "-I", os.path.join(flat, "shim.py")],
                               input=json.dumps(hdr).encode() + b"\n" + snap(r), capture_output=True, timeout=600,
                               env={"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": home}, cwd="/")
            lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
            fs = [x for x in lines if x.get("type") == "finding"]
            meta = next((x for x in lines if x.get("type") == "meta"), {})
            ok(f"M2 e2e {case}: django 3.2.0 advisories are reported", len(fs) > 10 and lines[-1].get("status") == "done",
               (len(fs), meta.get("manifests_scanned"), lines[-1:]))
        # manifests_scanned must list every manifest osv read, not only those with a vulnerable package:
        # the hub auto-fixes a code.deps issue only when its manifest is in the list (Ruling A4).
        r = os.path.join(td, "e2e-listed")
        write(r, "vuln/requirements.txt", VULN)
        write(r, "clean/requirements.txt", "orc-no-such-package-xyz==1.0.0\n")   # no advisories at all
        write(r, "emptied/requirements.txt", "# every dependency removed\n")
        hdr = {"scan_id": "code.deps", "since": None, "tools": {"osv-scanner": OSV}, "osv_db": DB,
               "data_as_of": "2026-11-16", "known": []}
        home = tempfile.mkdtemp()
        p = subprocess.run([sys.executable, "-I", os.path.join(flat, "shim.py")],
                           input=json.dumps(hdr).encode() + b"\n" + snap(r), capture_output=True, timeout=600,
                           env={"PATH": "/usr/bin:/bin", "HOME": home, "TMPDIR": home}, cwd="/")
        lines = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
        meta = next((x for x in lines if x.get("type") == "meta"), {})
        fs = [x["finding"] for x in lines if x.get("type") == "finding"]
        ok("A4 manifests_scanned lists the vulnerable, the clean and the emptied manifest",
           sorted(meta.get("manifests_scanned") or []) == ["clean/requirements.txt", "emptied/requirements.txt",
                                                           "vuln/requirements.txt"]
           and fs and all(f["location"]["path"] == "vuln/requirements.txt" for f in fs), meta.get("manifests_scanned"))
    else:
        print("[SKIP] M2 end-to-end: pinned osv-scanner or DB missing")

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
