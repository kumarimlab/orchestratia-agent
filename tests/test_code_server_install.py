#!/usr/bin/env python3
"""code-server installer — pinned version, verified before extraction, atomic, no root.
Dependency-free — run directly:  python3 tests/test_code_server_install.py
"""
import hashlib
import http.server
import io
import os
import shutil
import sys
import tarfile
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import code_server_install as ci  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def _tarball(version, arch, evil=False):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        top = f"code-server-{version}-linux-{arch}"
        body = b"#!/bin/sh\necho fake-code-server\n"
        info = tarfile.TarInfo(f"{top}/bin/code-server")
        info.size = len(body)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(body))
        if evil:
            e = tarfile.TarInfo("../escaped.txt")
            e.size = 3
            tf.addfile(e, io.BytesIO(b"bad"))
    return buf.getvalue()


class _Server:
    """Serves one payload; counts requests."""

    def __init__(self, payload):
        self.payload, self.hits = payload, 0
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.hits += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(outer.payload)))
                self.end_headers()
                self.wfile.write(outer.payload)

            def log_message(self, *a):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()


class _Env:
    """Point the module at a temp root + local server; restore afterwards."""

    def __init__(self, payload, sha=None, version="9.9.9"):
        self.saved = (ci.VERSION, dict(ci.SHA256), ci.URL_TEMPLATE, ci._ROOT_OVERRIDE, ci.arch, ci.MIN_FREE_BYTES)
        self.root = tempfile.mkdtemp()
        self.srv = _Server(payload)
        ci.VERSION = version
        ci.SHA256 = {"amd64": sha or hashlib.sha256(payload).hexdigest()}
        ci.URL_TEMPLATE = self.srv.url + "/code-server-{v}-linux-{arch}.tar.gz"
        ci._ROOT_OVERRIDE = self.root
        ci.arch = lambda: "amd64"
        ci.MIN_FREE_BYTES = 1

    def close(self):
        (ci.VERSION, ci.SHA256, ci.URL_TEMPLATE, ci._ROOT_OVERRIDE, ci.arch, ci.MIN_FREE_BYTES) = self.saved
        self.srv.close()
        shutil.rmtree(self.root, ignore_errors=True)


def test_installs_and_returns_an_executable():
    env = _Env(_tarball("9.9.9", "amd64"))
    try:
        path = ci.ensure()
        ok("returns the pinned version's binary", path == os.path.join(env.root, "9.9.9", "bin", "code-server"), path)
        ok("binary is executable", os.access(path, os.X_OK))
        ok("installed() is true afterwards", ci.installed())
        ok("no temp or partial files left behind",
           sorted(os.listdir(env.root)) in (["9.9.9"], [".lock", "9.9.9"]), sorted(os.listdir(env.root)))
    finally:
        env.close()


def test_second_call_does_not_download_again():
    env = _Env(_tarball("9.9.9", "amd64"))
    try:
        ci.ensure()
        ci.ensure()
        ok("downloaded exactly once", env.srv.hits == 1, f"hits={env.srv.hits}")
    finally:
        env.close()


def test_checksum_mismatch_is_refused_and_nothing_is_installed():
    env = _Env(_tarball("9.9.9", "amd64"), sha="0" * 64)
    try:
        err = None
        try:
            ci.ensure()
        except ci.InstallError as e:
            err = e
        ok("mismatch raises InstallError", err is not None)
        ok("reason mentions verification", err is not None and "verif" in err.reason.lower(), getattr(err, "reason", ""))
        ok("no version directory created", not os.path.exists(os.path.join(env.root, "9.9.9")))
        ok("partial download removed", not any(n.endswith(".part") for n in os.listdir(env.root)), os.listdir(env.root))
    finally:
        env.close()


def test_archive_escaping_its_directory_is_refused():
    payload = _tarball("9.9.9", "amd64", evil=True)
    env = _Env(payload)
    try:
        err = None
        try:
            ci.ensure()
        except ci.InstallError as e:
            err = e
        ok("unsafe member raises InstallError", err is not None)
        ok("nothing written outside the root", not os.path.exists(os.path.join(os.path.dirname(env.root), "escaped.txt")))
        ok("not installed", not ci.installed())
    finally:
        env.close()


def test_low_disk_refuses_before_downloading():
    env = _Env(_tarball("9.9.9", "amd64"))
    saved = ci.shutil.disk_usage
    try:
        ci.MIN_FREE_BYTES = 10 ** 15
        err = None
        try:
            ci.ensure()
        except ci.InstallError as e:
            err = e
        ok("low disk raises InstallError", err is not None)
        ok("reason mentions disk space", err is not None and "space" in err.reason.lower(), getattr(err, "reason", ""))
        ok("no request was made", env.srv.hits == 0, f"hits={env.srv.hits}")
    finally:
        ci.shutil.disk_usage = saved
        env.close()


def test_concurrent_calls_download_once():
    env = _Env(_tarball("9.9.9", "amd64"))
    try:
        errs = []

        def run():
            try:
                ci.ensure()
            except Exception as e:  # noqa: BLE001
                errs.append(e)
        ts = [threading.Thread(target=run) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        ok("no errors", not errs, repr(errs))
        ok("single download", env.srv.hits == 1, f"hits={env.srv.hits}")
    finally:
        env.close()


def test_older_versions_removed_after_install():
    env = _Env(_tarball("9.9.9", "amd64"))
    try:
        os.makedirs(os.path.join(env.root, "1.0.0", "bin"))
        ci.ensure()
        ok("old version directory removed", not os.path.exists(os.path.join(env.root, "1.0.0")))
    finally:
        env.close()


def test_arch_mapping():
    saved = ci.platform.machine
    try:
        for machine, want in (("x86_64", "amd64"), ("aarch64", "arm64"), ("arm64", "arm64")):
            ci.platform.machine = lambda m=machine: m
            ok(f"{machine} -> {want}", ci.arch() == want)
        ci.platform.machine = lambda: "riscv64"
        try:
            ci.arch()
            ok("unsupported arch refused", False)
        except ci.InstallError:
            ok("unsupported arch refused", True)
    finally:
        ci.platform.machine = saved


def test_unwritable_root_is_a_readable_error():
    env = _Env(_tarball("9.9.9", "amd64"))
    locked = os.path.join(env.root, "locked")
    os.makedirs(locked)
    os.chmod(locked, 0o500)
    saved = ci._ROOT_OVERRIDE
    try:
        ci._ROOT_OVERRIDE = os.path.join(locked, "code-server")
        err = None
        try:
            ci.ensure()
        except ci.InstallError as e:
            err = e
        except Exception as e:  # noqa: BLE001
            err = e
        ok("unwritable root raises InstallError (not a raw OSError)",
           isinstance(err, ci.InstallError) or os.geteuid() == 0, repr(err))
        ok("reason names the folder", os.geteuid() == 0 or (isinstance(err, ci.InstallError) and locked in err.reason),
           getattr(err, "reason", repr(err)))
    finally:
        ci._ROOT_OVERRIDE = saved
        os.chmod(locked, 0o700)
        env.close()


def test_pinned_checksums_are_real():
    ok("amd64 pin is a sha256", len(ci.SHA256.get("amd64", "")) == 64 and set(ci.SHA256["amd64"]) <= set("0123456789abcdef"))
    ok("arm64 pin is a sha256", len(ci.SHA256.get("arm64", "")) == 64 and set(ci.SHA256["arm64"]) <= set("0123456789abcdef"))


def _fake_install_tree():
    """A minimal extracted code-server tree with the bundled copilot chat + product.json."""
    import json
    root = tempfile.mkdtemp()
    vscode = os.path.join(root, "lib", "vscode")
    os.makedirs(os.path.join(vscode, "extensions", "copilot"))
    open(os.path.join(vscode, "extensions", "copilot", "package.json"), "w").write('{"name":"copilot-chat"}')
    os.makedirs(os.path.join(vscode, "extensions", "json-language-features"))   # a keeper
    with open(os.path.join(vscode, "product.json"), "w") as f:
        json.dump({"nameShort": "code-server", "defaultChatAgent": {"chatExtensionId": "GitHub.copilot-chat"}}, f)
    return root


def test_neutralize_removes_the_copilot_chat_panel():
    import json
    root = _fake_install_tree()
    try:
        ci._neutralize_bundled_chat(root)
        ext = os.path.join(root, "lib", "vscode", "extensions")
        ok("the Copilot chat extension is removed", not os.path.exists(os.path.join(ext, "copilot")))
        ok("other built-in extensions are kept", os.path.exists(os.path.join(ext, "json-language-features")))
        prod = json.load(open(os.path.join(root, "lib", "vscode", "product.json")))
        ok("the default chat agent is cleared", "defaultChatAgent" not in prod)
        ok("the rest of product.json is intact", prod.get("nameShort") == "code-server")
        ok("a marker is written", os.path.exists(os.path.join(root, ci._CHAT_MARKER)))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_neutralize_is_idempotent_and_a_noop_when_already_clean():
    root = _fake_install_tree()
    try:
        ci._neutralize_bundled_chat(root)
        # a re-run must not error and must not touch anything (marker short-circuits)
        marker = os.path.join(root, ci._CHAT_MARKER)
        before = os.path.getmtime(marker)
        ci._neutralize_bundled_chat(root)
        ok("second run is a no-op (marker unchanged)", os.path.getmtime(marker) == before)
        # a tree with no copilot ext / no chat agent is handled cleanly
        clean = tempfile.mkdtemp()
        os.makedirs(os.path.join(clean, "lib", "vscode", "extensions"))
        open(os.path.join(clean, "lib", "vscode", "product.json"), "w").write('{"nameShort":"x"}')
        ci._neutralize_bundled_chat(clean)
        ok("no-copilot tree still gets a marker", os.path.exists(os.path.join(clean, ci._CHAT_MARKER)))
        shutil.rmtree(clean, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


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
