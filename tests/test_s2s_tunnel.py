#!/usr/bin/env python3
"""S2S tunnels: a reconcile never takes the listener down; every way a tunnel dies
tells the hub; orphans are closed instead of logged forever; known_hosts cleanup
works on hashed entries.

Run:  python3 tests/test_s2s_tunnel.py
"""
import asyncio
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import s2s_tunnel, tunnel  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


sent: list[dict] = []


async def hub(msg):
    sent.append(msg)
    return True


def free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def wait_for_msg(pred, timeout=2.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for m in sent:
            if pred(m):
                return m
        await asyncio.sleep(0.02)
    return None


async def open_tunnel_through(port, ready=True):
    """Connect a client to the listener; play the hub+target and confirm it."""
    before = len(sent)
    r, w = await asyncio.open_connection("127.0.0.1", port)
    m = await wait_for_msg(lambda m: m["type"] == "s2s_tunnel_open" and sent.index(m) >= before)
    tid = m["tunnel_id"] if m else None
    if tid and ready:
        s2s_tunnel.mark_ready(tid)
        await asyncio.sleep(0.05)
    return r, w, tid


async def eof_within(reader, seconds):
    try:
        return await asyncio.wait_for(reader.read(1), seconds) == b""
    except asyncio.TimeoutError:
        return False


def closed_sent(tid):
    return [m for m in sent if m["type"] == "tunnel_closed" and m["tunnel_id"] == tid]


async def main():
    g, port = "grant-aaaa-1", free_port()
    await s2s_tunnel.setup_grant(g, port, 22, hub)

    # ── A. an unchanged re-broadcast (the 60s reconcile) keeps listener + tunnels ──
    r1, w1, t1 = await open_tunnel_through(port)
    ok("tunnel opens", t1 is not None)
    t0 = time.monotonic()
    await asyncio.wait_for(s2s_tunnel.setup_grant(g, port, 22, hub), 3)
    ok("re-broadcast returns at once with a tunnel open", time.monotonic() - t0 < 0.5)
    r2, w2, t2 = await open_tunnel_through(port)
    ok("listener still accepts new connections after a re-broadcast", t2 is not None)
    await s2s_tunnel.write_data(t1, "aGk=")  # "hi"
    got = await asyncio.wait_for(r1.read(2), 1)
    ok("the open tunnel survives the re-broadcast", got == b"hi", got)

    # ── B. teardown with live tunnels finishes promptly and tells the hub ──
    t0 = time.monotonic()
    await asyncio.wait_for(s2s_tunnel.teardown_grant(g), 3)
    ok("teardown does not hang on live tunnels", time.monotonic() - t0 < 1.0)
    ok("teardown closes the client sockets", await eof_within(r1, 1) and await eof_within(r2, 1))
    ok("teardown sends tunnel_closed for each tunnel", closed_sent(t1) and closed_sent(t2))
    try:
        await asyncio.open_connection("127.0.0.1", port)
        refused = False
    except OSError:
        refused = True
    ok("listener is gone after teardown", refused)

    # ── C. data for a tunnel we don't have → close it, don't just log ──
    # (hub.py routes an id s2s doesn't own to tunnel.write_tunnel_data with the WS sender)
    sent.clear()
    ok("an orphan id is not owned by s2s", not s2s_tunnel.owns("orphan-1234"))
    await tunnel.write_tunnel_data("orphan-1234", "aGk=", hub)
    ok("unknown tunnel data is answered with tunnel_closed", closed_sent("orphan-1234"))

    # ── D. target never answers → the hub is told, so a late target is torn down ──
    s2s_tunnel.READY_TIMEOUT = 0.3
    await s2s_tunnel.setup_grant(g, port, 22, hub)
    r, w, t = await open_tunnel_through(port, ready=False)
    ok("timed-out tunnel closes the client", await eof_within(r, 2))
    ok("timed-out tunnel sends tunnel_closed", closed_sent(t))
    s2s_tunnel.READY_TIMEOUT = 10.0

    # ── E. hub/target refuses before ready → fail now with the reason, not after 10s ──
    sent.clear()
    r, w, t = await open_tunnel_through(port, ready=False)
    t0 = time.monotonic()
    s2s_tunnel.handle_remote_close(t, "Grant not active or not found")
    ok("remote refusal closes the client immediately", await eof_within(r, 1) and time.monotonic() - t0 < 1)
    await asyncio.sleep(0.1)
    ok("a remote close is not echoed back to the hub", not closed_sent(t))

    # Remote close of an established tunnel: closes it, no echo.
    sent.clear()
    r, w, t = await open_tunnel_through(port)
    s2s_tunnel.handle_remote_close(t, "remote closed")
    ok("remote close of a live tunnel closes the client", await eof_within(r, 1))
    await asyncio.sleep(0.1)
    ok("...without echoing tunnel_closed", not closed_sent(t))
    ok("owns() forgets closed tunnels", not s2s_tunnel.owns(t))

    # ── F. a real change (new port) still moves the listener ──
    new_port = free_port()
    await s2s_tunnel.setup_grant(g, new_port, 22, hub)
    try:
        await asyncio.open_connection("127.0.0.1", port)
        old_refused = False
    except OSError:
        old_refused = True
    r, w, t = await open_tunnel_through(new_port)
    ok("port change moves the listener", old_refused and t is not None)
    await s2s_tunnel.close_all()

    # ── G. target side: unknown tunnel data → tunnel_closed (only when given a sender) ──
    sent.clear()
    await tunnel.write_tunnel_data("tgt-orphan", "aGk=", hub)
    ok("target answers unknown tunnel data with tunnel_closed", closed_sent("tgt-orphan"))
    sent.clear()
    await tunnel.write_tunnel_data("tgt-orphan2", "aGk=")
    ok("target without a sender keeps the old behaviour (relay path)", not sent)

    # ── H. known_hosts cleanup must handle HASHED entries (Ubuntu default) ──
    from orchestratia_agent import ssh_setup
    with tempfile.TemporaryDirectory() as home:
        os.makedirs(f"{home}/.ssh")
        kh = f"{home}/.ssh/known_hosts"
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICKUM92XXLLfD37fXNb9eCkwjxQ0N+NGkol5z/PBb9hc"
        with open(kh, "w") as f:
            f.write(f"[localhost]:30001 {key}\n[localhost]:30002 {key}\nexample.com {key}\n")
        subprocess.run(["ssh-keygen", "-H", "-f", kh], capture_output=True, check=True)
        old_home = os.environ["HOME"]
        os.environ["HOME"] = home
        try:
            ssh_setup.clean_known_hosts(30001)
        finally:
            os.environ["HOME"] = old_home

        def has(h):
            return subprocess.run(["ssh-keygen", "-F", h, "-f", kh], capture_output=True).returncode == 0
        ok("hashed entry for the grant port is removed", not has("[localhost]:30001"))
        ok("other entries are kept", has("[localhost]:30002") and has("example.com"))

        # A user's own known_hosts.old survives; ssh-keygen's fresh one doesn't linger.
        with open(f"{kh}.old", "w") as f:
            f.write("mine\n")
        os.environ["HOME"] = home
        try:
            ssh_setup.clean_known_hosts(30002)
        finally:
            os.environ["HOME"] = old_home
        ok("a pre-existing known_hosts.old is left alone", open(f"{kh}.old").read() == "mine\n")

        # No ssh-keygen (optional on Windows): fall back to the plain-text match.
        with open(kh, "w") as f:
            f.write(f"[localhost]:30005 {key}\nexample.com {key}\n")
        real_run = subprocess.run

        def no_keygen(*a, **k):
            raise FileNotFoundError("ssh-keygen")
        ssh_setup.subprocess.run = no_keygen
        os.environ["HOME"] = home
        try:
            ssh_setup.clean_known_hosts(30005)
        finally:
            os.environ["HOME"] = old_home
            ssh_setup.subprocess.run = real_run
        txt = open(kh).read()
        ok("without ssh-keygen, unhashed entries are still cleaned",
           "[localhost]:30005" not in txt and "example.com" in txt)

    # ── review fixes ──
    s2s_tunnel._shutting_down = False
    g2, p2 = "grant-bbbb-2", free_port()
    await s2s_tunnel.setup_grant(g2, p2, 22, hub)

    # Ready timeouts must not leak per-tunnel state (an autossh loop would).
    s2s_tunnel.READY_TIMEOUT = 0.2
    for _ in range(3):
        r, w, t = await open_tunnel_through(p2, ready=False)
        await eof_within(r, 1)
    s2s_tunnel.READY_TIMEOUT = 10.0
    ok("timed-out tunnels leave no _refused/_ready/_writers entries",
       not s2s_tunnel._refused and not s2s_tunnel._ready_events and not s2s_tunnel._writers,
       (len(s2s_tunnel._refused), len(s2s_tunnel._ready_events), len(s2s_tunnel._writers)))

    # Closes that fail while the WS is down are resent on the next reconcile.
    r, w, t = await open_tunnel_through(p2)
    up = {"v": False}

    async def flaky(msg):
        if not up["v"]:
            return False
        sent.append(msg)
        return True
    s2s_tunnel._ws_send = flaky
    sent.clear()
    w.close()  # user's ssh exits while the hub link is down
    await asyncio.sleep(0.2)
    ok("a close that couldn't be sent is kept", t in s2s_tunnel._unsent_closes)
    up["v"] = True
    await s2s_tunnel.flush_unsent_closes()
    ok("...and flushed once the WS is back", closed_sent(t) and not s2s_tunnel._unsent_closes)
    s2s_tunnel._ws_send = hub

    # After shutdown begins nothing may restart a listener (reconcile/push race).
    await s2s_tunnel.close_all()
    started = await s2s_tunnel.setup_grant(g2, p2, 22, hub)
    try:
        await asyncio.open_connection("127.0.0.1", p2)
        listening = True
    except OSError:
        listening = False
    ok("setup_grant is refused once shutdown has begun", started is False and not listening)
    s2s_tunnel._shutting_down = False

    # Target: far end closes while our connect is still in flight → no ready, socket closed.
    accepted = []

    async def sshd(reader, writer):
        accepted.append(reader)
    srv = await asyncio.start_server(sshd, "127.0.0.1", 0)
    sport = srv.sockets[0].getsockname()[1]
    sent.clear()
    task = asyncio.create_task(tunnel.open_tunnel("late-1", "127.0.0.1", sport, hub))
    await asyncio.sleep(0)  # open_tunnel is now awaiting the connect
    tunnel.close_tunnel("late-1")
    await task
    await asyncio.sleep(0.1)
    ok("a tunnel closed mid-connect never reports ready",
       not [m for m in sent if m["type"] == "tunnel_ready"] and "late-1" not in tunnel.active_tunnels)
    ok("...and its socket is closed",
       bool(accepted) and await asyncio.wait_for(accepted[0].read(1), 1) == b"")
    srv.close()

    # A burst of orphan data costs one tunnel_closed, not one per chunk.
    sent.clear()
    for _ in range(20):
        await tunnel.write_tunnel_data("burst-1", "aGk=", hub)
    ok("orphan data burst → a single tunnel_closed", len(closed_sent("burst-1")) == 1, len(closed_sent("burst-1")))

    print(f"\n{sum(results)}/{len(results)} passed")
    return all(results)


if __name__ == "__main__":
    sys.exit(0 if asyncio.run(main()) else 1)
