#!/usr/bin/env python3
"""Which credential the CLI sends (plan 1C Task 2). A standard session prefers its own token, falls back to
the server key from config.yaml on a dead token for ordinary commands (never on security routes), and a
restricted session never falls back. `orchestratia status`, `grants` and orc_attach keep the server key.

Dependency-free — run:  python3 tests/test_cli_session_token.py
"""
import contextlib
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import cli  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def secret_file(value):
    fd, path = tempfile.mkstemp()
    os.write(fd, value.encode())
    os.close(fd)
    return path


cfg = {"hub_url": "https://hub/", "api_key": "orc_serverkey"}
std, res = secret_file("orcs_std"), secret_file("orcs_res")

hub, key, tok, fb = cli._credentials({}, cfg)
ok("no session file: the server key, no token, no fallback", (hub, key, tok, fb) == ("https://hub", "orc_serverkey", "", ""))
hub, key, tok, fb = cli._credentials({"ORCHESTRATIA_SESSION_TOKEN_FILE": std}, cfg)
ok("standard: token preferred, server key kept as API_KEY and as the fallback",
   (key, tok, fb) == ("orc_serverkey", "orcs_std", "orc_serverkey"), (key, tok, fb))
hub, key, tok, fb = cli._credentials({"ORCHESTRATIA_KEY_FILE": res, "ORCHESTRATIA_SESSION_TOKEN_FILE": std}, cfg)
ok("restricted wins over standard and never falls back", (key, tok, fb) == ("orcs_res", "orcs_res", ""), (key, tok, fb))
hub, key, tok, fb = cli._credentials({"ORCHESTRATIA_SESSION_TOKEN_FILE": "/nonexistent/x"}, cfg)
ok("an unreadable token file is remembered as LOST (not as no token)", (key, tok, fb) == ("orc_serverkey", cli.TOKEN_LOST, "orc_serverkey"), (key, tok, fb))

sent = []


def fake_send(responses):
    it = iter(responses)

    def _send(method, url, data, key):
        sent.append((url, key))
        return next(it)
    return _send


def call(base, responses, token="orcs_std", fallback="orc_serverkey", api_key="orc_serverkey"):
    sent.clear()
    cli.HUB_URL, cli.API_KEY, cli.SESSION_TOKEN, cli._FALLBACK_KEY = "https://hub", api_key, token, fallback
    cli._send = fake_send(responses)
    err = io.StringIO()
    code = None
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        try:
            out = cli._api_request("GET", "/x", base=base)
        except SystemExit as e:
            out, code = None, e.code
    return out, code, err.getvalue()


DEAD = (401, {"detail": "Invalid session token"})
out, code, err = call("/api/v1/server/tasks", [(200, {"ok": 1})])
ok("standard: an ordinary command sends the token", out == {"ok": 1} and sent == [("https://hub/api/v1/server/tasks/x", "orcs_std")], sent)
out, code, err = call("/api/v1/server/tasks", [DEAD, (200, {"ok": 2})])
ok("standard: a dead token falls back to the server key once", out == {"ok": 2} and [k for _, k in sent] == ["orcs_std", "orc_serverkey"], sent)
out, code, err = call("/api/v1/server/tasks", [(401, {"detail": "Invalid API key"})])
ok("any other 401 does not fall back", code == 1 and len(sent) == 1, (code, sent))
out, code, err = call(cli.SECURITY_BASE, [DEAD])
ok("security routes never fall back; the message says to start a new session",
   code == 1 and len(sent) == 1 and "Start a new session" in err, (code, sent, err))
out, code, err = call("/api/v1/server/tasks", [DEAD], token="orcs_res", fallback="", api_key="orcs_res")
ok("restricted: a dead token never falls back", code == 1 and len(sent) == 1, (code, sent))
out, code, err = call("/api/v1/server/tasks", [(200, {"ok": 5})], token=cli.TOKEN_LOST)
ok("lost token file: ordinary commands use the server key, never the sentinel",
   out == {"ok": 5} and sent == [("https://hub/api/v1/server/tasks/x", "orc_serverkey")], sent)
out, code, err = call(cli.SECURITY_BASE, [(200, {})], token=cli.TOKEN_LOST)
ok("lost token file: security routes send nothing and say to start a new session",
   code == 1 and sent == [] and "Start a new session" in err, (code, sent, err))
out, code, err = call("/api/v1/server/tasks", [(200, {"ok": 3})], token="", fallback="")
ok("no token (pre-0.35 session): the server key as before", out == {"ok": 3} and sent[0][1] == "orc_serverkey", sent)

# orc_attach keeps the config key whatever the session environment says (the hub refuses tokens there).
from orchestratia_agent import config as _config, orc_attach  # noqa: E402
os.environ["ORCHESTRATIA_SESSION_TOKEN_FILE"], os.environ["ORCHESTRATIA_KEY_FILE"] = std, res
_real = (_config.load_config, _config.default_config_path)
_config.load_config, _config.default_config_path = (lambda p: dict(cfg)), (lambda: "/etc/orchestratia/config.yaml")
try:
    ok("orc_attach uses the server key from config.yaml", orc_attach._hub_credentials() == ("https://hub", "orc_serverkey"),
       orc_attach._hub_credentials())
finally:
    _config.load_config, _config.default_config_path = _real
    del os.environ["ORCHESTRATIA_SESSION_TOKEN_FILE"], os.environ["ORCHESTRATIA_KEY_FILE"]
for p in (std, res):
    os.unlink(p)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
