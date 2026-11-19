#!/usr/bin/env python3
"""Grant targets converge through the helper only for what changed (hardening plan Task 4): no sudo when nothing did,
elevated follows the hub's list, a refused policy isn't retried every minute; the reconcile hands the hub's target
grants to converge_target.

Dependency-free — run:  python3 tests/test_grant_reconcile.py
"""
import asyncio
import base64
import json
import os
import subprocess
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import hub, s2s_tunnel, ssh_setup, tls  # noqa: E402

results = []
G1 = "11111111-2222-3333-4444-555555555555"
G2 = "11111111-2222-3333-4444-666666666666"


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def key(b=1):
    blob = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + bytes([b]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


class Helper:
    def __init__(self, keys=None, elevated=False, allowed=True, fail=()):
        self.calls, self.keys, self.elevated, self.allowed, self.fail = [], dict(keys or {}), elevated, allowed, fail

    def __call__(self, args, input_data=None):
        self.calls.append(list(args))
        if args[0] in self.fail:
            return subprocess.CompletedProcess(args, 1, "", "broke")
        if args[0] == "status":
            return subprocess.CompletedProcess(args, 0, json.dumps({"user": True, "keys": self.keys,
                                               "elevated": self.elevated, "elevated_allowed": self.allowed}), "")
        if args[0] == "add-key":
            self.keys[args[1]] = input_data.strip()
        if args[0] == "set-elevated":
            if not self.allowed:
                return subprocess.CompletedProcess(args, 3, "", "elevated grants are off")
            self.elevated = True
        if args[0] == "clear-elevated":
            self.elevated = False
        if args[0] == "remove-key":
            self.keys.pop(args[1], None)
        return subprocess.CompletedProcess(args, 0, "ok", "")


ssh_setup.HELPER_PLATFORM = True
ssh_setup._target.reset()
h = Helper(keys={G1: key(1)})
n = ssh_setup.converge_target({G1: (key(1) + " hub@comment", "standard"), G2: (key(2), "standard")}, helper=h)
ok("first run: one status, one add-key for the missing grant", h.calls == [["status"], ["add-key", G2]] and n == 2, h.calls)
h.calls.clear()
ok("nothing changed -> no helper call at all",
   ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "standard")}, helper=h) == 0 and h.calls == [])
ok("an elevated grant appears -> one set-elevated",
   ssh_setup.converge_target({G1: (key(1), "elevated"), G2: (key(2), "standard")}, helper=h) == 1
   and h.calls == [["set-elevated"]], h.calls)
h.calls.clear()
ok("…then nothing", ssh_setup.converge_target({G1: (key(1), "elevated"), G2: (key(2), "standard")}, helper=h) == 0)
# fix round 1: the hub stopped listing G1 (a lost revoke) -> its key goes; no elevated grant left -> clear + deny
ok("G1 no longer listed, no elevated grant left -> remove-key G1, then clear-elevated",
   ssh_setup.converge_target({G2: (key(2), "standard")}, helper=h) == 2
   and h.calls == [["remove-key", G1], ["clear-elevated"]], h.calls)
h.calls.clear()
ok("an invalid key costs no helper call", ssh_setup.converge_target(
    {G2: (key(2), "standard"), G1: ('command="sh" ' + key(1), "standard")}, helper=h) == 0 and h.calls == [], h.calls)

ssh_setup._target.reset()
h = Helper(allowed=False)
ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
h.calls.clear()
ok("policy denies elevated -> not retried every minute",
   ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h) == 0 and h.calls == [], h.calls)

ssh_setup._target.reset()
h = Helper(fail=("add-key",))
ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
h.fail, h.calls = (), []
ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
ok("a failed call -> the next run re-reads status first", h.calls[:1] == [["status"]], h.calls)

# ── the reconcile hands the hub's TARGET grants to converge_target ──
GRANTS = [{"grant_id": G1, "role": "target", "ssh_public_key": key(1), "privilege_level": "standard"},
          {"grant_id": G2, "role": "target", "ssh_public_key": key(2), "privilege_level": "elevated"},
          {"grant_id": "x", "role": "target", "ssh_public_key": "", "privilege_level": "standard"}]


class Resp:
    status_code = 200

    def json(self):
        return GRANTS


class Client:
    def __init__(self, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url, **kw):
        return Resp()


import httpx  # noqa: E402

seen = []


async def _flush():
    return None
saved = (httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids,
         ssh_setup.converge_target)
httpx.AsyncClient, tls.httpx_verify = Client, (lambda **k: True)
s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids = _flush, (lambda: set())
ssh_setup.converge_target = lambda desired, helper=None: seen.append(desired) or 0
try:
    asyncio.run(hub._reconcile_grants(SimpleNamespace(hub_url="https://hub", api_key="k"), None))
finally:
    (httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids,
     ssh_setup.converge_target) = saved
ok("reconcile: one converge_target call with the target grants that carry a key",
   seen == [{G1: (key(1), "standard"), G2: (key(2), "elevated")}], seen)


# ══ beyond the brief ══
import tempfile  # noqa: E402

ssh_setup.HELPER_PLATFORM = True
saved_helper = ssh_setup._helper

# ── revoke: the key goes at once; elevated stays while another live grant is elevated (planner finding) ──
ssh_setup._target.reset()
h = Helper(keys={G1: key(1), G2: key(2)}, elevated=True)
ssh_setup._helper = h
try:
    ssh_setup.converge_target({G1: (key(1), "elevated"), G2: (key(2), "elevated")}, helper=h)
    ok("seeded: one status, nothing else", h.calls == [["status"]], h.calls)
    h.calls.clear()
    ok("revoke (Linux) -> one remove-key through the helper", ssh_setup.remove_authorized_key(G1) is True
       and h.calls == [["remove-key", G1]], h.calls)
    h.calls.clear()
    ok("a reconcile that fetched before the revoke never puts the revoked key back",
       ssh_setup.converge_target({G1: (key(1), "elevated"), G2: (key(2), "elevated")}, helper=h) == 0
       and h.calls == [], h.calls)
    ok("another elevated grant is still live -> elevated stays",
       ssh_setup.converge_target({G2: (key(2), "elevated")}, helper=h) == 0 and h.calls == [], h.calls)
    h.calls.clear()
    ok("…and goes with the last one (its key too: the hub lists nothing)", ssh_setup.converge_target({}, helper=h) == 2
       and h.calls == [["remove-key", G2], ["clear-elevated"]], h.calls)

    # a revoke whose remove-key failed is retried by the next reconcile (after re-reading status)
    ssh_setup._target.reset()
    h = Helper(keys={G1: key(1), G2: key(2)}, fail=("remove-key",))
    ssh_setup._helper = h
    ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "standard")}, helper=h)
    ok("a failed remove-key reports failure", ssh_setup.remove_authorized_key(G1) is False)
    h.fail, h.calls = (), []
    ssh_setup.converge_target({G2: (key(2), "standard")}, helper=h)
    ok("…and the next reconcile re-reads status and removes it", h.calls == [["status"], ["remove-key", G1]], h.calls)

    # the Linux push path goes through the helper with the normalised key; a bad key costs no call
    ssh_setup._target.reset()
    h = Helper()
    ssh_setup._helper = h
    ok("setup_authorized_key (Linux) -> add-key with the normalised key",
       ssh_setup.setup_authorized_key(key(3) + " hub@x", G2, "standard") is True
       and h.calls == [["add-key", G2]] and h.keys[G2] == key(3), h.calls)
    h.calls.clear()
    ok("…a key with options -> refused, no helper call",
       ssh_setup.setup_authorized_key('command="sh" ' + key(3), G2, "standard") is False and h.calls == [])
    ok("setup_sudoers('elevated') (Linux) -> set-elevated", ssh_setup.setup_sudoers("elevated") is True
       and h.calls == [["set-elevated"]], h.calls)
finally:
    ssh_setup._helper = saved_helper

# ── the owner turning elevated grants on is noticed without sudo (the policy file is world-readable) ──
pol = os.path.join(tempfile.mkdtemp(), "orchestratia-grants.conf")
saved_pol = ssh_setup.POLICY_PATH
ssh_setup.POLICY_PATH = pol
try:
    ssh_setup._target.reset()
    h = Helper(allowed=False)
    ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
    h.calls.clear()
    ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
    ok("denied: no retry", h.calls == [], h.calls)
    with open(pol, "w") as fh:
        fh.write("elevated=allow\n")
    h.allowed = True
    ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
    ok("the policy file changed -> status re-read, then set-elevated", h.calls == [["status"], ["set-elevated"]], h.calls)
finally:
    ssh_setup.POLICY_PATH = saved_pol

# ── an hourly status re-read keeps the cache honest, only where there is something to verify ──
now = [1000.0]
saved_clock = ssh_setup._clock
ssh_setup._clock = lambda: now[0]
try:
    ssh_setup._target.reset()
    h = Helper(keys={G1: key(1)})
    ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
    h.calls.clear()
    now[0] += ssh_setup.STATUS_TTL - 1
    ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
    ok("within the hour: no call", h.calls == [], h.calls)
    now[0] += 2
    ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
    ok("after an hour: one status, nothing else", h.calls == [["status"]], h.calls)
    ssh_setup._target.reset()
    h = Helper()
    ssh_setup.converge_target({}, helper=h)
    h.calls.clear()
    now[0] += 10 * ssh_setup.STATUS_TTL
    ssh_setup.converge_target({}, helper=h)
    ok("no grants, no keys, not elevated: never re-read", h.calls == [], h.calls)
finally:
    ssh_setup._clock = saved_clock

# ── _helper: a missing helper costs no sudo; a sudo that hangs is a failed call, not an exception ──
saved = (ssh_setup.GRANT_HELPER, ssh_setup._sudo_run)
sudo_calls = []
try:
    ssh_setup.GRANT_HELPER = "/nonexistent/grant-helper"
    ssh_setup._legacy_reset()
    # final review I1: one `sudo -l` probe for the old rules (none here), then no grant sudo call at all
    ssh_setup._sudo_run = lambda *a, **k: sudo_calls.append(a) or subprocess.CompletedProcess(a, 1, "", "")
    res = ssh_setup._helper(["status"])
    ok("helper not installed, no old rules -> 127, only the rules probe", res.returncode == 127
       and [c[0][0] for c in sudo_calls] == ["-l"], (res, sudo_calls))
    sudo_calls.clear()
    res = ssh_setup._helper(["status"])
    ok("…and within the hour no sudo at all", res.returncode == 127 and sudo_calls == [], (res, sudo_calls))
    ssh_setup._legacy_reset()
    ssh_setup.GRANT_HELPER = sys.executable

    def hang(*a, **k):
        raise subprocess.TimeoutExpired(a, 10)
    ssh_setup._sudo_run = hang
    res = ssh_setup._helper(["status"])
    ok("sudo times out -> a failed call", res.returncode != 0 and "timed out" in (res.stderr or ""), res)
finally:
    ssh_setup.GRANT_HELPER, ssh_setup._sudo_run = saved

# ── the hub's revoke push (Linux): the key now, elevated by the hub's list; elsewhere unchanged ──
rec = []
saved = (ssh_setup.remove_authorized_key, ssh_setup.remove_sudoers, hub._reconcile_grants)
ssh_setup.remove_authorized_key = lambda gid: rec.append(("remove-key", gid)) or True
ssh_setup.remove_sudoers = lambda: rec.append("remove-sudoers") or True


async def fake_reconcile(state, sender):
    rec.append("reconcile")


hub._reconcile_grants = fake_reconcile


async def drive():
    await hub._revoke_target_grant(None, None, G1)
    for _ in range(3):
        await asyncio.sleep(0)


try:
    ssh_setup.HELPER_PLATFORM = True
    asyncio.run(drive())
    ok("revoke push (Linux): remove-key, then a reconcile; never an unconditional clear",
       rec == [("remove-key", G1), "reconcile"], rec)
    rec.clear()
    ssh_setup.HELPER_PLATFORM = False
    asyncio.run(drive())
    ok("revoke push (macOS/Windows): unchanged, key then the elevated rule", rec == [("remove-key", G1), "remove-sudoers"], rec)
finally:
    ssh_setup.remove_authorized_key, ssh_setup.remove_sudoers, hub._reconcile_grants = saved
    ssh_setup.HELPER_PLATFORM = True

# ── macOS / Windows: converge_target keeps the old per-grant calls ──
legacy = []
saved = (ssh_setup.setup_authorized_key, ssh_setup.setup_sudoers)
ssh_setup.setup_authorized_key = lambda k, g, lvl="standard": legacy.append(("key", g, lvl)) or True
ssh_setup.setup_sudoers = lambda lvl: legacy.append(("sudoers", lvl)) or True
try:
    ssh_setup.HELPER_PLATFORM = False
    n = ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "elevated")})
finally:
    ssh_setup.setup_authorized_key, ssh_setup.setup_sudoers = saved
    ssh_setup.HELPER_PLATFORM = True
ok("off Linux: the same per-grant calls as before", n == 2 and ("key", G1, "standard") in legacy
   and ("key", G2, "elevated") in legacy and ("sudoers", "elevated") in legacy and len(legacy) == 3, legacy)

# ══ fix round 1 ══
# a lost revoke: the next reconcile with a 200 list removes the key of the grant the hub no longer lists (tagged only:
# the helper's status lists only orchestratia-grant-tagged keys, so a manually added key is never touched)
ssh_setup._target.reset()
h = Helper(keys={G1: key(1), G2: key(2)})
ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "standard")}, helper=h)
h.calls.clear()
ok("lost revoke of G1 -> the next reconcile removes its key, and only it",
   ssh_setup.converge_target({G2: (key(2), "standard")}, helper=h) == 1 and h.calls == [["remove-key", G1]], h.calls)
h.calls.clear()
ok("…then nothing", ssh_setup.converge_target({G2: (key(2), "standard")}, helper=h) == 0 and h.calls == [])

# fix round 2: the policy never changes automatically: after the last elevated grant goes, a new one is set again
ssh_setup._target.reset()
h = Helper(keys={G1: key(1)}, elevated=True)
ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
ssh_setup.converge_target({G1: (key(1), "standard")}, helper=h)
h.calls.clear()
ssh_setup.converge_target({G1: (key(1), "elevated")}, helper=h)
ok("after clear-elevated (policy still allow): a new elevated grant -> set-elevated", h.calls == [["set-elevated"]],
   h.calls)

# the reconcile only converges after a 200 list: a failed fetch removes nothing


class BadResp:
    status_code = 500

    def json(self):
        return []


class BadClient(Client):
    async def get(self, url, **kw):
        return BadResp()


class BrokenClient(Client):
    async def get(self, url, **kw):
        raise httpx.ConnectError("down")


for name, cls in (("HTTP 500", BadClient), ("a connection error", BrokenClient)):
    seen.clear()
    saved = (httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids,
             ssh_setup.converge_target)
    httpx.AsyncClient, tls.httpx_verify = cls, (lambda **k: True)
    s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids = _flush, (lambda: set())
    ssh_setup.converge_target = lambda desired, helper=None: seen.append(desired) or 0
    try:
        asyncio.run(hub._reconcile_grants(SimpleNamespace(hub_url="https://hub", api_key="k"), None))
    finally:
        (httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids,
         ssh_setup.converge_target) = saved
    ok(f"reconcile after {name}: converge_target never runs, so no key is removed", seen == [], seen)
ok("the reconcile docstring no longer claims a missed revoke is safe once the source drops its key",
   "not a security regression" not in (hub._reconcile_grants.__doc__ or ""))

# ══ fix round 2: a grant push that lands while a reconcile awaits its list is never undone by that stale list ══
G3 = "11111111-2222-3333-4444-777777777777"
PUSH = {"type": "setup_ssh_access", "grant_id": G3, "ssh_public_key": key(3), "privilege_level": "standard"}
STATE = SimpleNamespace(hub_url="https://hub", api_key="k")


def patched(client_cls):
    saved = (httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids)
    httpx.AsyncClient, tls.httpx_verify = client_cls, (lambda **k: True)
    s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids = _flush, (lambda: set())
    return saved


def restore(saved):
    httpx.AsyncClient, tls.httpx_verify, s2s_tunnel.flush_unsent_closes, s2s_tunnel.active_grant_ids = saved


gate = {}


class GateClient(Client):
    async def get(self, url, **kw):
        gate["fetched"].set()
        await gate["go"].wait()
        return Resp()                     # GRANTS: G1 standard, G2 elevated — no G3: fetched before G3's push


async def race():
    gate["fetched"], gate["go"] = asyncio.Event(), asyncio.Event()
    t = asyncio.create_task(hub._reconcile_grants(STATE, None))
    await gate["fetched"].wait()          # the reconcile holds its (soon stale) list ...
    await hub._target_grant_push(PUSH)    # ... a push adds G3 ...
    gate["go"].set()                      # ... then the reconcile goes on
    await t


ssh_setup._target.reset()
h = Helper(keys={G1: key(1), G2: key(2)}, elevated=True)
saved_helper, ssh_setup._helper = ssh_setup._helper, h
saved = patched(GateClient)
try:
    ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "elevated")})   # seeded, in step
    h.calls.clear()
    asyncio.run(race())
finally:
    restore(saved)
    ssh_setup._helper = saved_helper
ok("push during a reconcile's fetch: G3's key is added and the stale list never removes it",
   h.calls == [["add-key", G3]] and G3 in h.keys, h.calls)

# control: with no push in between, the same list is applied (G3 isn't listed, so its key goes)
ssh_setup._target.reset()
h = Helper(keys={G1: key(1), G2: key(2), G3: key(3)}, elevated=True)
saved_helper, ssh_setup._helper = ssh_setup._helper, h
saved = patched(Client)
try:
    ssh_setup.converge_target({G1: (key(1), "standard"), G2: (key(2), "elevated"), G3: (key(3), "standard")})
    h.calls.clear()
    asyncio.run(hub._reconcile_grants(STATE, None))
finally:
    restore(saved)
    ssh_setup._helper = saved_helper
ok("control: no push in between -> the list is applied", h.calls == [["remove-key", G3]], h.calls)

# the push and the reconcile's apply are serialised by one lock
applied = []
saved_fns = (ssh_setup.setup_authorized_key, ssh_setup.setup_sudoers, ssh_setup.converge_target)
ssh_setup.setup_authorized_key = lambda k, g, lvl="standard": applied.append(("push", g)) or True
ssh_setup.setup_sudoers = lambda lvl: applied.append(("sudoers", lvl)) or True
ssh_setup.converge_target = lambda desired, helper=None: applied.append(("converge", sorted(desired))) or 0
saved = patched(Client)


async def serialised():
    lock = hub._grant_lock()
    await lock.acquire()
    p = asyncio.create_task(hub._target_grant_push(PUSH))
    r = asyncio.create_task(hub._reconcile_grants(STATE, None))
    for _ in range(20):
        await asyncio.sleep(0)
    held = list(applied)
    lock.release()
    await p
    await r
    return held


try:
    held = asyncio.run(serialised())
finally:
    restore(saved)
    ssh_setup.setup_authorized_key, ssh_setup.setup_sudoers, ssh_setup.converge_target = saved_fns
ok("while the grant lock is held neither a push nor a reconcile applies anything", held == [], held)
ok("…released: the push applies; the reconcile that fetched before it is discarded",
   applied == [("push", G3)], applied)

# every grant push bumps the generation (target and source, setup and revoke)
gens = []
saved_fns = (ssh_setup.setup_authorized_key, ssh_setup.remove_authorized_key, ssh_setup.store_private_key,
             ssh_setup.clean_known_hosts, ssh_setup.remove_private_key, s2s_tunnel.setup_grant, s2s_tunnel.teardown_grant)
ssh_setup.setup_authorized_key = lambda *a, **k: True
ssh_setup.remove_authorized_key = lambda *a, **k: True
ssh_setup.store_private_key = lambda *a, **k: None
ssh_setup.clean_known_hosts = lambda *a, **k: None
ssh_setup.remove_private_key = lambda *a, **k: True


async def _noop(*a, **k):
    return None
s2s_tunnel.setup_grant = s2s_tunnel.teardown_grant = _noop
saved_rec, hub._reconcile_grants = hub._reconcile_grants, _noop


async def pushes():
    gens.append(hub._grant_generation())
    await hub._target_grant_push(PUSH)
    gens.append(hub._grant_generation())
    await hub._revoke_target_grant(None, None, G3)
    gens.append(hub._grant_generation())
    await hub._source_grant_push({"grant_id": G3, "ssh_private_key": "k", "local_bind_port": 2222}, None)
    gens.append(hub._grant_generation())
    await hub._source_grant_revoke({"grant_id": G3})
    gens.append(hub._grant_generation())
    for _ in range(3):
        await asyncio.sleep(0)


try:
    asyncio.run(pushes())
finally:
    (ssh_setup.setup_authorized_key, ssh_setup.remove_authorized_key, ssh_setup.store_private_key,
     ssh_setup.clean_known_hosts, ssh_setup.remove_private_key, s2s_tunnel.setup_grant,
     s2s_tunnel.teardown_grant) = saved_fns
    hub._reconcile_grants = saved_rec
ok("each grant push (target/source, setup/revoke) bumps the generation", gens == sorted(set(gens)) and len(gens) == 5,
   gens)

# ══ final review I1: a half-upgraded server (0.35 code running, no helper yet, the 0.34 broad rules still there) ══
# A 0.34 host that ran the update once (or without sudo) and restarted. Revokes must still remove the key, through the
# old rules; nothing is ever added or elevated that way. With the helper installed the old path is never used.
import logging  # noqa: E402

AUTH = "/home/orchestratia/.ssh/authorized_keys"
ELEV = "/etc/sudoers.d/orchestratia"
G3 = "11111111-2222-3333-4444-777777777777"
HAND = key(9) + " admin@laptop"


class LegacySudo:
    """`sudo -n …` as a 0.34 host's /etc/sudoers.d/orchestratia-agent allows it (or, rules=False, after they're gone)."""

    def __init__(self, keys_text="", rules=True, elevated=True):
        self.rules, self.calls = rules, []
        self.files = {AUTH: keys_text}
        if elevated:
            self.files[ELEV] = "orchestratia ALL=(ALL) NOPASSWD: ALL\n"

    def __call__(self, cmd, **kw):
        self.calls.append(list(cmd))
        cp = subprocess.CompletedProcess
        legacy = [["-l", "tee", AUTH], ["cat", AUTH], ["tee", AUTH], ["tee", ELEV], ["rm", "-f", ELEV]]
        if not self.rules or list(cmd) not in legacy and cmd[0] not in ("mkdir", "chmod", "chown"):
            return cp(cmd, 1, "", "sudo: a password is required\n")
        if cmd[0] == "-l":
            return cp(cmd, 0, "/usr/bin/tee " + AUTH + "\n", "")
        if cmd[0] == "cat":
            if AUTH not in self.files:
                return cp(cmd, 1, "", f"cat: {AUTH}: No such file or directory\n")
            return cp(cmd, 0, self.files[AUTH], "")
        if cmd[0] == "tee":
            self.files[cmd[1]] = kw.get("input") or ""
            return cp(cmd, 0, kw.get("input") or "", "")
        if cmd[0] == "rm":
            self.files.pop(cmd[2], None)
        return cp(cmd, 0, "", "")


def writes(s):
    return [c for c in s.calls if c[0] in ("tee", "mkdir", "chmod", "chown", "useradd")]


class Logs(logging.Handler):
    def __init__(self):
        super().__init__()
        self.msgs = []

    def emit(self, record):
        self.msgs.append(record.getMessage())


def legacy_reset():
    getattr(ssh_setup, "_legacy_reset", lambda: None)()
    ssh_setup._target.reset()


saved = (ssh_setup.GRANT_HELPER, ssh_setup._sudo_run, ssh_setup._helper)
ssh_setup._helper = saved_helper
logs = Logs()
ssh_setup.log.addHandler(logs)
try:
    ssh_setup.GRANT_HELPER = "/nonexistent/grant-helper"
    two = f"{key(1)} orchestratia-grant:{G1}\n{HAND}\n{key(2)} orchestratia-grant:{G2}\n"

    legacy_reset()
    s = LegacySudo(two)
    ssh_setup._sudo_run = s
    ok("I1: half-upgraded, revoke push -> the key is removed through the old rules",
       ssh_setup.remove_authorized_key(G1) is True and f"grant:{G1}" not in s.files[AUTH]
       and f"grant:{G2}" in s.files[AUTH] and HAND in s.files[AUTH], (s.calls, s.files.get(AUTH)))
    ok("I1: …it says how to finish the upgrade",
       any("finish the upgrade" in m.lower() and "sudo orchestratia update" in m for m in logs.msgs), logs.msgs)

    legacy_reset()
    s = LegacySudo(two)
    ssh_setup._sudo_run = s
    ok("I1: a lost revoke (the hub lists nothing) -> the reconcile removes the unlisted keys and the elevated rule",
       ssh_setup.converge_target({}) >= 1 and "orchestratia-grant:" not in s.files[AUTH] and HAND in s.files[AUTH]
       and ELEV not in s.files, (s.calls, s.files))
    s.calls.clear()
    ok("I1: …then nothing (no sudo) within the hour", ssh_setup.converge_target({}) == 0 and s.calls == [], s.calls)

    legacy_reset()
    s = LegacySudo(f"{key(1)} orchestratia-grant:{G1}\n", elevated=False)
    ssh_setup._sudo_run = s
    ssh_setup.converge_target({G1: (key(1), "standard"), G3: (key(3), "elevated")})
    ok("I1: never adds or elevates through the old rules (reconcile)",
       writes(s) == [] and f"grant:{G3}" not in s.files[AUTH] and ELEV not in s.files, s.calls)
    s.calls.clear()
    ok("I1: …a missing key isn't retried with a sudo call every minute",
       ssh_setup.converge_target({G1: (key(1), "standard"), G3: (key(3), "elevated")}) <= 1 and s.calls == [],
       s.calls)
    ok("I1: never adds or elevates through the old rules (push)",
       ssh_setup.setup_authorized_key(key(3), G3, "elevated") is False and ssh_setup.setup_sudoers("elevated") is False
       and writes(s) == [] and ELEV not in s.files, s.calls)

    legacy_reset()
    s = LegacySudo(two)
    ssh_setup._sudo_run = s
    ssh_setup.remove_authorized_key(G1)
    s.rules = False                                    # the second update removed the old rules (helper still missing)
    ok("I1: old rules gone -> a revoke reports failure (a refused cat is never 'nothing to remove')",
       ssh_setup.remove_authorized_key(G2) is False and f"grant:{G2}" in s.files[AUTH], s.calls)

    legacy_reset()
    s = LegacySudo(two, rules=False)
    ssh_setup._sudo_run = s
    ok("I1: helper missing, no old rules -> the revoke fails; only the rules probe ran, nothing else",
       ssh_setup.remove_authorized_key(G1) is False and all(c[0] == "-l" for c in s.calls) and len(s.calls) <= 1,
       s.calls)

    legacy_reset()
    s = LegacySudo(two)
    ssh_setup._sudo_run = s
    ssh_setup.GRANT_HELPER = sys.executable           # the helper is installed
    ssh_setup.remove_authorized_key(G1)
    ok("I1: helper installed -> the old path is never used (no rules probe, no cat/tee/rm)",
       s.calls == [[sys.executable, "remove-key", G1]], s.calls)
finally:
    ssh_setup.GRANT_HELPER, ssh_setup._sudo_run, ssh_setup._helper = saved
    ssh_setup.log.removeHandler(logs)
    legacy_reset()

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
