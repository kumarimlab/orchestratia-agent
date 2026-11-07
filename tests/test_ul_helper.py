#!/usr/bin/env python3
"""dl_helper upload ops, driven exactly as the agent drives them: a subprocess
`[python, -I, dl_helper.py, ul-*, --base FOLDER]` with the request on stdin.

Every crash point a subprocess can reach is simulated (kill -9 mid-chunk, a part
ahead of its journal, a part shorter than its journal, a done record before and
after the link). A disk filling up mid-upload is NOT simulated here — the helper
carries no test hooks — and is covered by the loop-mounted filesystem in the real
E2E (Task 21); the free-space refusal itself is tested through ul-prepare.

Dependency-free — run directly:  python3 tests/test_ul_helper.py
"""
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from orchestratia_agent import dl_helper as h  # noqa: E402

HELPER = os.path.join(ROOT, "orchestratia_agent", "dl_helper.py")
CS = 64 * 1024                    # small chunks keep most tests fast
results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


def argv(op, base):
    return [sys.executable, "-I", HELPER, op, "--base", base]


def req(uid, name="data.bin", size=0, chunk_size=CS, reservation=0):
    return {"upload_id": uid, "name": name, "size": size, "chunk_size": chunk_size,
            "reservation": reservation}


def once(op, base, request):
    p = subprocess.run(argv(op, base), input=json.dumps(request).encode() + b"\n",
                       capture_output=True, timeout=30, cwd="/")
    return p.returncode, json.loads(p.stdout.split(b"\n", 1)[0] or b"{}")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def seeded(n, seed):
    """Non-repeating bytes, so an offset bug can't hide behind identical chunks."""
    return random.Random(seed).randbytes(n)


class Writer:
    """One ul-write helper, spoken to over its pipes like uploads.py does."""

    def __init__(self, base, request):
        self.p = subprocess.Popen(argv("ul-write", base), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, cwd="/")
        self.p.stdin.write(json.dumps(request).encode() + b"\n")
        self.p.stdin.flush()
        self.first = self.line()

    def line(self):
        raw = self.p.stdout.readline()
        return json.loads(raw) if raw else None

    def chunk(self, offset, data, index, final, digest=None, send=None):
        frame = {"offset": offset, "length": len(data), "index": index,
                 "sha256": digest or sha(data), "final": final}
        self.p.stdin.write(json.dumps(frame).encode() + b"\n")
        self.p.stdin.write(data if send is None else data[:send])
        self.p.stdin.flush()

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        self.p.wait(timeout=30)

    def kill(self):
        self.p.kill()
        self.p.wait(timeout=30)


def upload(base, uid, name, data, cs=CS):
    """A whole upload over one link; returns the final line (done or error)."""
    w = Writer(base, req(uid, name, len(data), cs))
    assert w.first["type"] == "ready", w.first
    off, i, last = w.first["offset"], w.first["offset"] // cs, None
    while True:
        piece = data[off:off + cs]
        final = off + len(piece) == len(data)
        w.chunk(off, piece, i, final)
        ack = w.line()
        assert ack and ack["type"] == "ack", ack
        off, i = ack["offset"], i + 1
        if final:
            last = w.line()
            break
    w.close()
    return last


def files(base):
    return sorted(os.listdir(base))


def published(base):
    return sorted(n for n in os.listdir(base) if not n.startswith(".orchestratia-"))


def new_base():
    return tempfile.mkdtemp(prefix="ul-test-")          # 0700, owned by us


# ── pure helpers ─────────────────────────────────────────────────────────────
ok("protocol 2 with every op listed", h.PROTOCOL == 2 and set(h.OPS) >= {
    "stat", "read", "zip", "ul-prepare", "ul-write", "ul-cancel", "ul-sweep"})
names = list(h.candidate_names("a.tar.gz", 2))
ok("compound extension kept: a (1).tar.gz", names == ["a.tar.gz", "a (1).tar.gz", "a (2).tar.gz"], names)
ok("plain extension", list(h.candidate_names("report.pdf", 1)) == ["report.pdf", "report (1).pdf"])
ok("dotfile has no extension", list(h.candidate_names(".bashrc", 1)) == [".bashrc", ".bashrc (1)"])
ok("no extension", list(h.candidate_names("Makefile", 1)) == ["Makefile", "Makefile (1)"])
ok("inner dots stay in the stem", list(h.candidate_names("v1.2.zip", 1))[1] == "v1.2 (1).zip")
for bad in ("", ".", "..", "a/b", "a\x00b", ".orchestratia-x", "a‮b.txt", "a​b", "x" * 201,
            "é" * 101, "\ud800", " lead.txt", "trail.txt ", "tab\t"):
    ok(f"name refused: {bad[:12]!r}", not h.valid_name(bad))
for good in ("-rf.txt", "résumé 日本.pdf", "x" * 200, "with space.txt", ".env"):
    ok(f"name accepted: {good[:12]!r}", h.valid_name(good))


# ── ul-prepare ───────────────────────────────────────────────────────────────
base = new_base()
U = str(uuid.uuid4())
rc, head = once("ul-prepare", base, req(U, size=1000))
ok("prepare: header carries protocol and ops", head.get("protocol") == 2 and "ul-write" in head.get("ops", []), head)
ok("prepare: ok, dir, free space, offset 0", rc == 0 and head["ok"] and head["dir"] == base
   and head["free_bytes"] > 0 and head["offset"] == 0 and head["done"] is None, head)
rc, head = once("ul-prepare", base, req(U, size=2 ** 62))
ok("prepare: larger than free space -> no_space", rc == 2 and head["error"] == "no_space", head)
rc, head = once("ul-prepare", base, req(U, size=10, reservation=2 ** 62))
ok("prepare: other uploads' reservation counts -> no_space", rc == 2 and head["error"] == "no_space", head)
rc, head = once("ul-prepare", base, req("../../etc", size=10))
ok("prepare: upload id must be a UUID", rc == 2 and head["error"] == "invalid", head)
rc, head = once("ul-prepare", base, req(U.upper(), size=10))
ok("prepare: upper-case id refused (exact form only)", head.get("error") == "invalid", head)
for bad in ("a‮b.txt", "x" * 250, "../x", ".orchestratia-1.part", ".."):
    rc, head = once("ul-prepare", base, req(U, name=bad, size=1))
    ok(f"prepare: invalid_name for {bad[:14]!r}", rc == 2 and head["error"] == "invalid_name", head)
rc, head = once("ul-prepare", base, dict(req(U, size=1), size=True))
ok("prepare: a boolean is not a size", head.get("error") == "invalid", head)
p = subprocess.run(argv("ul-prepare", base), input=b"not json\n", capture_output=True, timeout=30, cwd="/")
ok("prepare: garbage stdin -> invalid", json.loads(p.stdout.split(b"\n")[0])["error"] == "invalid")
p = subprocess.run([sys.executable, "-I", HELPER, "ul-prepare", "--base", base, "extra"],
                   input=b"{}\n", capture_output=True, timeout=30, cwd="/")
ok("prepare: no positional path accepted", p.returncode == 2 and not p.stdout)

# folder safety
link = base + "-link"
os.symlink(base, link)
rc, head = once("ul-prepare", link, req(U, size=1))
ok("symlinked folder -> unsafe_destination", head.get("error") == "unsafe_destination", head)
gw = new_base()
os.chmod(gw, 0o770)
rc, head = once("ul-prepare", gw, req(U, size=1))
ok("group-writable folder -> unsafe_destination", head.get("error") == "unsafe_destination", head)
ow = new_base()
os.chmod(ow, 0o703)
rc, head = once("ul-prepare", ow, req(U, size=1))
ok("other-writable folder -> unsafe_destination", head.get("error") == "unsafe_destination", head)
rc, head = once("ul-prepare", "relative/dir", req(U, size=1))
ok("relative folder -> invalid", head.get("error") == "invalid", head)
rc, head = once("ul-prepare", os.path.join(base, "missing"), req(U, size=1))
ok("missing folder -> unsafe_destination", head.get("error") == "unsafe_destination", head)
if os.geteuid() == 0:
    theirs = new_base()
    os.chown(theirs, 65534, 65534)
    rc, head = once("ul-prepare", theirs, req(U, size=1))
    ok("folder owned by someone else -> unsafe_destination", head.get("error") == "unsafe_destination", head)
else:
    print("[SKIP] folder owned by someone else (needs root to chown)")


# ── happy path, naming, repeats, empty ───────────────────────────────────────
base = new_base()
data = seeded(3 * CS + 1234, 1)
last = upload(base, str(uuid.uuid4()), "data.bin", data)
ok("3+ chunk upload -> done with the whole-file sha256", last["type"] == "done"
   and last["sha256"] == sha(data) and last["path"] == os.path.join(base, "data.bin"), last)
ok("published bytes are exact", open(os.path.join(base, "data.bin"), "rb").read() == data)
ok("published file is 0600", os.stat(os.path.join(base, "data.bin")).st_mode & 0o777 == 0o600)
ok("no part/journal left; done record kept for idempotent replies",
   [n for n in files(base) if n.startswith(".orchestratia-")] and
   all(n.endswith(".done") for n in files(base) if n.startswith(".orchestratia-")), files(base))
ok("chunks_digest = sha256 over the ordered chunk digests",
   last["chunks_digest"] == h.chunks_digest([sha(data[i:i + CS]) for i in range(0, len(data), CS)]))

last = upload(base, str(uuid.uuid4()), "data.bin", data)
ok("same file twice -> second is 'data (1).bin', first untouched",
   last["path"].endswith("/data (1).bin") and open(os.path.join(base, "data.bin"), "rb").read() == data, last)
open(os.path.join(base, "a.tar.gz"), "wb").write(b"existing")
last = upload(base, str(uuid.uuid4()), "a.tar.gz", b"new archive")
ok("existing a.tar.gz -> a (1).tar.gz, original kept", last["path"].endswith("/a (1).tar.gz")
   and open(os.path.join(base, "a.tar.gz"), "rb").read() == b"existing", last)
victim = os.path.join(new_base(), "victim")
open(victim, "wb").write(b"do not touch")
os.symlink(victim, os.path.join(base, "evil.txt"))
last = upload(base, str(uuid.uuid4()), "evil.txt", b"payload")
ok("a symlink at the name is never followed", last["path"].endswith("/evil (1).txt")
   and open(victim, "rb").read() == b"do not touch", last)
last = upload(base, str(uuid.uuid4()), "-rf.txt", b"dash")
ok("leading dash saved as-is", last["path"].endswith("/-rf.txt"), last)
uni = "résumé 日本 " + "x" * 150 + ".pdf"
last = upload(base, str(uuid.uuid4()), uni, b"unicode")
ok("unicode name, ~170 bytes, saved exactly", os.path.basename(last["path"]) == uni, last)
last = upload(base, str(uuid.uuid4()), "empty.txt", b"")
ok("zero-byte file -> one empty final chunk -> done", last["type"] == "done" and last["sha256"] == sha(b"")
   and os.path.getsize(os.path.join(base, "empty.txt")) == 0, last)

# Review Focus 1 (helper half): two identical 16 MiB chunks, then a different one.
big = 16 * 1024 * 1024
block = seeded(big, 7)
rep = block + block + seeded(big // 2, 8)
last = upload(base, str(uuid.uuid4()), "repeat.img", rep, cs=big)
ok("repeating 16 MiB chunks -> exact sha256", last.get("sha256") == sha(rep)
   and open(os.path.join(base, "repeat.img"), "rb").read() == rep, last.get("sha256"))


# ── per-chunk refusals ───────────────────────────────────────────────────────
base = new_base()
U = str(uuid.uuid4())
data = seeded(2 * CS + 10, 2)
w = Writer(base, req(U, "c.bin", len(data)))
w.chunk(0, data[:CS], 0, False, digest=sha(b"something else"))
e = w.line()
ok("checksum mismatch -> error, offset unchanged", e == {"type": "error", "code": "checksum_mismatch", "offset": 0}, e)
ok("checksum mismatch -> part rolled back to 0", os.path.getsize(os.path.join(base, f".orchestratia-{U}.part")) == 0)
w.chunk(0, data[:CS], 0, False)
a = w.line()
ok("helper keeps serving after a mismatch", a["type"] == "ack" and a["offset"] == CS, a)
w.chunk(0, data[:CS], 0, False)
e = w.line()
ok("stale offset -> offset_mismatch with the real offset", e["code"] == "offset_mismatch" and e["offset"] == CS, e)
w.chunk(CS, data[CS:CS + 100], 1, False)
e = w.line()
ok("short non-final chunk -> offset_mismatch", e["code"] == "offset_mismatch", e)
w.chunk(CS, data[CS:2 * CS], 1, True)
e = w.line()
ok("'final' before the end -> offset_mismatch", e["code"] == "offset_mismatch", e)
w.chunk(CS, data[CS:2 * CS], 1, False)
ok("framing survives refusals", w.line()["offset"] == 2 * CS)
w.close()

# two helpers on one part
w1 = Writer(base, req(U, "c.bin", len(data)))
w2 = Writer(base, req(U, "c.bin", len(data)))
ok("first ul-write gets ready", w1.first["type"] == "ready" and w1.first["offset"] == 2 * CS, w1.first)
ok("second concurrent ul-write -> busy", w2.first.get("code") == "busy" and w2.p.wait(timeout=10) == 2, w2.first)
rc, head = once("ul-cancel", base, {"upload_id": U})
ok("cancel while a helper holds the lock -> busy, nothing removed",
   head == {"ok": False, "error": "busy", "protocol": 2, "ops": h.OPS} and
   os.path.exists(os.path.join(base, f".orchestratia-{U}.part")), head)
w1.close()


# ── crash points ─────────────────────────────────────────────────────────────
def part_of(base, uid):
    return os.path.join(base, f".orchestratia-{uid}.part")


def journal_of(base, uid):
    return json.load(open(os.path.join(base, f".orchestratia-{uid}.journal")))


base = new_base()
U = str(uuid.uuid4())
data = seeded(3 * CS, 3)
w = Writer(base, req(U, "k.bin", len(data)))
w.chunk(0, data[:CS], 0, False)
w.line()
w.chunk(CS, data[CS:2 * CS], 1, False, send=CS // 2)    # half a chunk, then the link dies
time.sleep(0.3)
w.kill()
ok("kill -9 mid-chunk: journal still says one chunk", journal_of(base, U)["offset"] == CS)
w = Writer(base, req(U, "k.bin", len(data)))
ok("restart after kill: ready at the journal offset", w.first["offset"] == CS and not w.first["reset"], w.first)
ok("restart after kill: part truncated to the journal", os.path.getsize(part_of(base, U)) == CS)
w.close()

with open(part_of(base, U), "ab") as f:                  # crash between fsync and journal rename
    f.write(data[CS:2 * CS])
w = Writer(base, req(U, "k.bin", len(data)))
ok("journal behind part: ready at the journal offset", w.first["offset"] == CS, w.first)
ok("journal behind part: extra bytes dropped", os.path.getsize(part_of(base, U)) == CS)
w.chunk(CS, data[CS:2 * CS], 1, False)
w.line()
w.close()

sizes = (os.path.getsize(part_of(base, U)), journal_of(base, U))
rc, head = once("ul-prepare", base, req(U, "k.bin", len(data), reservation=2 ** 62))
ok("a refused prepare at offset 2 chunks (no_space) leaves part and journal untouched for a resume",
   head.get("error") == "no_space" and (os.path.getsize(part_of(base, U)), journal_of(base, U)) == sizes, head)
ok("…which really had bytes committed", sizes[0] == 2 * CS and sizes[1]["offset"] == 2 * CS, sizes[1])
os.truncate(part_of(base, U), CS)                        # part shorter than the journal (2 chunks)
w = Writer(base, req(U, "k.bin", len(data)))
ok("part shorter than journal: reset to 0 and reported", w.first["offset"] == 0 and w.first["reset"], w.first)
ok("part shorter than journal: journal reset too", journal_of(base, U)["offset"] == 0)
w.close()
os.unlink(part_of(base, U))                              # part lost entirely
w = Writer(base, req(U, "k.bin", len(data)))
ok("part missing: starts again from 0", w.first["offset"] == 0, w.first)
w.close()
last = upload(base, U, "k.bin", data)
ok("…and the upload still completes exactly", last["sha256"] == sha(data), last)

# tamper between chunks: bytes altered after their ack -> finalize refuses
base = new_base()
U = str(uuid.uuid4())
data = seeded(2 * CS, 4)
w = Writer(base, req(U, "t.bin", len(data)))
w.chunk(0, data[:CS], 0, False)
w.line()
with open(part_of(base, U), "r+b") as f:
    f.seek(10)
    f.write(b"X")
w.chunk(CS, data[CS:], 1, True)
a, e = w.line(), w.line()
w.close()
ok("tampered part: last chunk acked, then finalize -> tampered", a["type"] == "ack"
   and e == {"type": "error", "code": "tampered", "offset": 2 * CS}, e)
ok("tampered part: nothing published, no done record", published(base) == []
   and not os.path.exists(os.path.join(base, f".orchestratia-{U}.done")), files(base))

# crash during finalize: journal final, no done record
base = new_base()
U = str(uuid.uuid4())
data = seeded(2 * CS + 5, 5)
part, jrnl, done = (os.path.join(base, f".orchestratia-{U}.{x}") for x in ("part", "journal", "done"))
open(part, "wb").write(data)
digests = [sha(data[i:i + CS]) for i in range(0, len(data), CS)]
json.dump({"upload_id": U, "size": len(data), "chunk_size": CS, "offset": len(data),
           "digests": digests, "final": True}, open(jrnl, "w"))
w = Writer(base, req(U, "f.bin", len(data)))
d = w.line()
w.close()
ok("final journal, no done record: ready says finalizing", w.first["finalizing"] is True, w.first)
ok("…then it finalizes and publishes", d["type"] == "done" and d["sha256"] == sha(data)
   and published(base) == ["f.bin"], d)

# .done present, link not made yet
base = new_base()
part, jrnl, done = (os.path.join(base, f".orchestratia-{U}.{x}") for x in ("part", "journal", "done"))
open(part, "wb").write(data)
json.dump({"upload_id": U, "size": len(data), "chunk_size": CS, "offset": len(data),
           "digests": digests, "final": True}, open(jrnl, "w"))
json.dump({"upload_id": U, "path": os.path.join(base, "f.bin"), "sha256": sha(data)}, open(done, "w"))
w = Writer(base, req(U, "f.bin", len(data)))
d = w.line()
w.close()
ok(".done before link: publishes once", d["type"] == "done" and published(base) == ["f.bin"]
   and not os.path.exists(part) and not os.path.exists(jrnl), (d, files(base)))

# .done present AND the link happened (crash between link and unlink)
base = new_base()
part, jrnl, done = (os.path.join(base, f".orchestratia-{U}.{x}") for x in ("part", "journal", "done"))
open(part, "wb").write(data)
os.link(part, os.path.join(base, "f.bin"))
json.dump({"upload_id": U, "size": len(data), "chunk_size": CS, "offset": len(data),
           "digests": digests, "final": True}, open(jrnl, "w"))
json.dump({"upload_id": U, "path": os.path.join(base, "f.bin"), "sha256": sha(data)}, open(done, "w"))
w = Writer(base, req(U, "f.bin", len(data)))
d = w.line()
w.close()
ok(".done after link: ready carries done", w.first["done"] and w.first["done"]["path"].endswith("/f.bin"), w.first)
ok(".done after link: reports done, never a second copy", d["type"] == "done" and published(base) == ["f.bin"]
   and not os.path.exists(part) and not os.path.exists(jrnl), (d, files(base)))
w = Writer(base, req(U, "f.bin", len(data)))
d = w.line()
w.close()
ok("a later ul-write (lost response) is idempotent", w.first["done"] and d["type"] == "done"
   and published(base) == ["f.bin"], files(base))
rc, head = once("ul-prepare", base, req(U, "f.bin", len(data)))
ok("ul-prepare reports the finished upload", head["ok"] and head["done"]["path"].endswith("/f.bin")
   and head["offset"] == len(data), head)

# .done names a path someone else took meanwhile (not our inode) -> next free name
base = new_base()
part, jrnl, done = (os.path.join(base, f".orchestratia-{U}.{x}") for x in ("part", "journal", "done"))
open(part, "wb").write(data)
json.dump({"upload_id": U, "size": len(data), "chunk_size": CS, "offset": len(data),
           "digests": digests, "final": True}, open(jrnl, "w"))
json.dump({"upload_id": U, "path": os.path.join(base, "f.bin"), "sha256": sha(data)}, open(done, "w"))
open(os.path.join(base, "f.bin"), "wb").write(b"someone else's file")
w = Writer(base, req(U, "f.bin", len(data)))
d = w.line()
w.close()
ok(".done names a taken path: published as 'f (1).bin', other file kept", d["path"].endswith("/f (1).bin")
   and open(os.path.join(base, "f.bin"), "rb").read() == b"someone else's file", d)


# ── cancel and sweep ─────────────────────────────────────────────────────────
base = new_base()
U = str(uuid.uuid4())
w = Writer(base, req(U, "x.bin", 2 * CS))
w.chunk(0, seeded(CS, 6), 0, False)
w.line()
w.close()
rc, head = once("ul-cancel", base, {"upload_id": U})
ok("cancel removes part and journal", head["ok"] and head["removed"] == 2 and files(base) == [], (head, files(base)))
rc, head = once("ul-cancel", base, {"upload_id": U})
ok("cancel is idempotent", head["ok"] and head["removed"] == 0, head)

base = new_base()
old_id, live_id, fresh_id = (str(uuid.uuid4()) for _ in range(3))
for uid in (old_id, live_id, fresh_id):
    for x in ("part", "journal"):
        open(os.path.join(base, f".orchestratia-{uid}.{x}"), "wb").write(b"x")
open(os.path.join(base, ".orchestratia-stray"), "wb").write(b"x")
open(os.path.join(base, "keep-me.txt"), "wb").write(b"user file")
past = time.time() - 25 * 3600
for n in os.listdir(base):
    if not n.startswith(f".orchestratia-{fresh_id}"):
        os.utime(os.path.join(base, n), (past, past))
holder = subprocess.Popen([sys.executable, "-c", (
    "import fcntl,os,sys,time\n"
    "fd=os.open(sys.argv[1],os.O_RDWR)\n"
    "fcntl.flock(fd,fcntl.LOCK_EX)\n"
    "print('locked',flush=True)\n"
    "time.sleep(30)\n"), os.path.join(base, f".orchestratia-{live_id}.part")], stdout=subprocess.PIPE)
holder.stdout.readline()
rc, head = once("ul-sweep", base, {})
holder.kill()
holder.wait()
left = files(base)
ok("sweep removes day-old upload files", f".orchestratia-{old_id}.part" not in left
   and ".orchestratia-stray" not in left, left)
ok("sweep skips a locked (live) part", f".orchestratia-{live_id}.part" in left, left)
ok("sweep keeps recent uploads and user files", f".orchestratia-{fresh_id}.part" in left
   and "keep-me.txt" in left, left)
ok("sweep reports what it removed", head["ok"] and head["removed"] == 3, head)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
