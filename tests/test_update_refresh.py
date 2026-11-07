#!/usr/bin/env python3
"""`orchestratia update` keeps the restricted helper / sudoers / upload folders in step.

Before 0.33.0 it only printed a hint, so a restricted host kept its protocol-1 helper
and every restricted upload failed helper_outdated. As root it now runs the refresh
itself — through the NEWLY installed entry point, never the old in-memory modules.

Dependency-free — run directly:  python3 tests/test_update_refresh.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import cli  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


BIN = "/opt/orchestratia-venv/bin/orchestratia-agent"
CFG = "/etc/orchestratia/config.yaml"

kind, argv = cli.tier_refresh_plan(0, CFG, "ubuntu", BIN, True)
ok("root + restricted -> runs --refresh-existing with the unit's user", kind == "run" and argv == [
    BIN, "provision-tier", "--refresh-existing", "--config", CFG, "--daemon-user", "ubuntu"], argv)
kind, argv = cli.tier_refresh_plan(1000, CFG, "ubuntu", BIN, True)
ok("not root + restricted -> prints the exact sudo command", kind == "hint" and argv[0] == "sudo"
   and argv[1:] == [BIN, "provision-tier", "--refresh-existing", "--config", CFG, "--daemon-user", "ubuntu"], argv)
kind, argv = cli.tier_refresh_plan(0, CFG, None, BIN, True)
ok("root but daemon user unknown -> hint, never a guess", kind == "hint" and argv[-1] == "<daemon-user>", argv)
kind, argv = cli.tier_refresh_plan(0, None, "ubuntu", BIN, False)
ok("root, no restricted, no tmpfiles reservation -> --upload-dirs", kind == "run"
   and "--upload-dirs" in argv and "--refresh-existing" not in argv, argv)
ok("no restricted, reservation present -> nothing to do", cli.tier_refresh_plan(0, None, "ubuntu", BIN, True)
   == ("skip", []))

with tempfile.TemporaryDirectory() as d:
    unit = os.path.join(d, "orchestratia-agent.service")
    open(unit, "w").write("[Service]\nType=simple\nUser=svc-user\nGroup=svc-user\n")
    ok("daemon user read from the unit's User=", cli._service_user(unit) == "svc-user")
    old = os.environ.pop("SUDO_USER", None)
    os.environ["SUDO_USER"] = "from-sudo"
    try:
        ok("no unit -> $SUDO_USER", cli._service_user(os.path.join(d, "missing")) == "from-sudo")
    finally:
        os.environ.pop("SUDO_USER", None)
        if old is not None:
            os.environ["SUDO_USER"] = old
    plain = os.path.join(d, "plain.yaml")
    tiered = os.path.join(d, "tiered.yaml")
    open(plain, "w").write("hub_url: x\n")
    open(tiered, "w").write("privilege:\n  projects:\n    p:\n      user: orcp-0123456789ab\n")
    ok("restricted config found", cli._restricted_config((plain, tiered)) == tiered)
    ok("no restricted config", cli._restricted_config((plain,)) is None)

    calls = []
    saved = subprocess.run

    def fake_run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "refreshed", "")
    subprocess.run = fake_run
    try:
        if sys.platform.startswith("linux"):
            steps = {"steps": []}
            kind = cli._after_update_refresh(steps, euid=0, config_paths=(tiered,), unit_path=unit,
                                             tmpfiles_path=os.path.join(d, "none.conf"))
            ok("as root it runs the refresh itself", kind == "run" and len(calls) == 1
               and calls[0][1:3] == ["provision-tier", "--refresh-existing"]
               and calls[0][-2:] == ["--daemon-user", "svc-user"], calls)
            ok("…through the installed entry point, not this process", calls[0][0].endswith("orchestratia-agent"),
               calls[0][0])
            ok("…and reports it in --json mode", steps["steps"][-1]["restricted_tier"] == "refreshed", steps)
            calls.clear()
            kind = cli._after_update_refresh(steps, euid=1000, config_paths=(tiered,), unit_path=unit,
                                             tmpfiles_path=os.path.join(d, "none.conf"))
            ok("not root: prints, runs nothing", kind == "hint" and calls == []
               and steps["steps"][-1]["command"].startswith("sudo "), steps["steps"][-1])
        else:
            print("[SKIP] refresh execution (Linux only)")
    finally:
        subprocess.run = saved

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
