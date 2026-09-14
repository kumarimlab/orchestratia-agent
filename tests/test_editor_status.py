#!/usr/bin/env python3
"""code_server_start always answers the hub; tiers route correctly; capability advertised.
Dependency-free — run directly:  python3 tests/test_editor_status.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import hub, code_server, code_server_install, relay_client, privilege, tls, git_changes  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class St:
    config = {}
    api_key = "orc_test"
    hub_url = "https://hub.example"


class _Harness:
    """Stub the side effects of the handler; capture what it sends to the hub."""

    def __init__(self, *, installed=True, start_result=41000, ensure_error=None):
        self.sent, self.started, self.connected, self.ensured = [], [], [], []
        self.saved = (hub.ws_send, code_server.start, relay_client.connect, tls.build_ssl_context,
                      hub._tier_config, code_server_install.installed, code_server_install.ensure,
                      git_changes.baseline)

        async def ws_send(state, msg):
            self.sent.append(msg)
            return True

        def start(sid, pid, wd, tier, tc, *, hub_url=""):
            self.started.append((sid, pid, wd, tier, hub_url))
            if isinstance(start_result, Exception):
                raise start_result
            return start_result

        def ensure():
            self.ensured.append(1)
            if ensure_error:
                raise ensure_error
            return "/x/bin/code-server"

        hub.ws_send = ws_send
        code_server.start = start
        relay_client.connect = lambda sid, url, key, port, on_activity, ssl_ctx: self.connected.append((sid, port))
        tls.build_ssl_context = lambda state=None: None
        hub._tier_config = lambda state: privilege.load_tier_config({})
        code_server_install.installed = lambda version=None: installed
        code_server_install.ensure = ensure
        git_changes.baseline = lambda path, run_as=None: {"is_repo": False}

    def run(self, tier, wd="/srv/a"):
        asyncio.get_event_loop().run_until_complete(
            hub._handle_code_server_start(St(), "sess-1", "pid-A", wd, "wss://relay.example", tier))

    def states(self):
        return [m.get("state") for m in self.sent if m.get("type") == "editor_status"]

    def close(self):
        (hub.ws_send, code_server.start, relay_client.connect, tls.build_ssl_context, hub._tier_config,
         code_server_install.installed, code_server_install.ensure, git_changes.baseline) = self.saved


def test_standard_already_installed_reports_ready_and_bridges():
    h = _Harness(installed=True)
    try:
        h.run("standard")
        ok("started as standard with hub url",
           h.started == [("sess-1", "pid-A", "/srv/a", "standard", "https://hub.example")], h.started)
        ok("no download when installed", h.ensured == [])
        ok("reports ready (and not preparing)", h.states() == ["ready"], h.states())
        ok("relay bridged with the pinned port", h.connected == [("sess-1", 41000)])
    finally:
        h.close()


def test_standard_first_time_reports_preparing_then_ready():
    h = _Harness(installed=False)
    try:
        h.run("standard")
        ok("downloads once", h.ensured == [1])
        ok("preparing then ready", h.states() == ["preparing", "ready"], h.states())
        prep = [m for m in h.sent if m.get("state") == "preparing"]
        ok("preparing has a readable reason", prep and "first time" in prep[0].get("reason", ""), prep)
    finally:
        h.close()


def test_download_failure_is_reported_not_logged_only():
    h = _Harness(installed=False,
                 ensure_error=code_server_install.InstallError("could not download the editor: timeout"))
    try:
        h.run("standard")
        err = [m for m in h.sent if m.get("state") == "error"]
        ok("reports error", h.states() == ["preparing", "error"], h.states())
        ok("reason is the installer's", err and "could not download" in err[0]["reason"], err)
        ok("nothing started or bridged", h.started == [] and h.connected == [])
    finally:
        h.close()


def test_start_errors_are_reported():
    for exc, label, tier in ((code_server.EditorStartError("folder /nope does not exist on this server"), "missing folder", "standard"),
                             (privilege.PrivilegeError("project not provisioned"), "privilege refusal", "restricted"),
                             (FileNotFoundError("code-server"), "unexpected exception", "standard")):
        h = _Harness(installed=True, start_result=exc)
        try:
            h.run(tier)
            err = [m for m in h.sent if m.get("state") == "error"]
            ok(f"{label}: reported as error", len(err) == 1 and bool(err[0]["reason"]), h.sent)
            ok(f"{label}: nothing bridged", h.connected == [])
        finally:
            h.close()


def test_missing_tier_means_restricted_for_old_hubs():
    msg = {"type": "code_server_start", "session_id": "sess-1", "project_id": "pid-A",
           "working_directory": "/srv/a", "relay_url": "wss://relay.example"}
    ok("tier defaults to restricted", hub._editor_tier_from(msg) == "restricted")
    ok("explicit standard honoured", hub._editor_tier_from({**msg, "privilege_tier": "standard"}) == "standard")
    ok("unknown tier refused to restricted", hub._editor_tier_from({**msg, "privilege_tier": "root"}) == "restricted")


def test_capability_advertised_on_linux_only():
    saved = (hub.platform.system, code_server_install.arch, code_server_install.installed)
    try:
        hub.platform.system = lambda: "Linux"
        code_server_install.arch = lambda: "amd64"
        code_server_install.installed = lambda version=None: False
        cap = hub._editor_capability()
        ok("linux amd64 supported",
           cap == {"supported": True, "installed": False, "version": code_server_install.VERSION}, cap)
        merged = privilege.merge_capabilities({"tags": ["x"]}, privilege.load_tier_config({}), cap)
        ok("merged under code_server.standard", merged.get("code_server", {}).get("standard") == cap, merged)
        ok("existing capabilities kept", merged.get("tags") == ["x"])
        ok("no restricted projects key without provisioning", "projects" not in merged["code_server"])
        hub.platform.system = lambda: "Darwin"
        ok("macOS not advertised", hub._editor_capability() is None)
        hub.platform.system = lambda: "Linux"

        def bad_arch():
            raise code_server_install.InstallError("riscv64")
        code_server_install.arch = bad_arch
        ok("unsupported arch not advertised", hub._editor_capability() is None)
        ok("no code_server key when nothing to advertise",
           "code_server" not in privilege.merge_capabilities({}, privilege.load_tier_config({}), None))
        ok("a stale code_server key from config is not kept when nothing to advertise",
           "code_server" not in privilege.merge_capabilities({"code_server": {"old": 1}}, privilege.load_tier_config({}), None))
    finally:
        hub.platform.system, code_server_install.arch, code_server_install.installed = saved


CASES = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failed = []
    for case in CASES:
        try:
            case()
        except Exception as e:  # noqa: BLE001
            failed.append(f"{case.__name__}: {e!r}")
            results.append(False)
    for f in failed:
        print("ERROR", f)
    if not all(results):
        print(f"FAIL  {results.count(False)} of {len(results)} failed")
        sys.exit(1)
    print(f"ok  {len(results)} assertions passed")


if __name__ == "__main__":
    main()
