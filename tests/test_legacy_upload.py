#!/usr/bin/env python3
"""Legacy (<= 10 MB, store-and-forward) upload writer: hub.py _process_pending_upload.

The shipped writer followed a planted `<name>.part` symlink and wrote into a /tmp folder
any local user could pre-create. These pin the 0.33.0 hardening: private folder checked
on its fd, O_EXCL|O_NOFOLLOW part, no-clobber link() publish.

Run:  python3 tests/test_legacy_upload.py   (needs httpx, an agent dependency)
"""
import asyncio
import hashlib
import os
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent import hub, upload_dirs  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


class _Resp:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    async def aiter_bytes(self, n):
        for i in range(0, len(self.data), n):
            yield self.data[i:i + n]


class _Stream:
    def __init__(self, data):
        self.resp = _Resp(data)

    async def __aenter__(self):
        return self.resp

    async def __aexit__(self, *exc):
        return False


class FakeClient:
    """Serves one file for GET and records every ack the writer posts."""

    def __init__(self, data):
        self.data, self.acks, self.urls = data, [], []

    def stream(self, method, url, headers=None):
        self.urls.append(url)
        return _Stream(self.data)

    async def post(self, url, json=None, headers=None):
        self.acks.append(json)
        return SimpleNamespace(raise_for_status=lambda: None)


STATE = SimpleNamespace(hub_url="https://hub.example", api_key="orc_k")


def deliver(folder, name, data, sha=None, upload_id="tok_abc-123"):
    upload_dirs.folder_for = lambda run_as: folder
    client = FakeClient(data)
    item = {"upload_id": upload_id, "filename": name, "download_url": f"/api/v1/files/temp/{upload_id}",
            "sha256": sha if sha is not None else hashlib.sha256(data).hexdigest()}
    asyncio.run(hub._process_pending_upload(client, STATE, item))
    return client


def new_folder():
    return tempfile.mkdtemp(prefix="legacy-")            # 0700, ours


def leftovers(folder):
    return [n for n in os.listdir(folder) if n.startswith(".orchestratia-")]


d = new_folder()
c = deliver(d, "report.pdf", b"one")
ok("delivered into the private folder", c.acks == [{"success": True, "path": os.path.join(d, "report.pdf")}], c.acks)
ok("relative download URL is joined to the hub", c.urls == ["https://hub.example/api/v1/files/temp/tok_abc-123"])
ok("file is 0600 and exact", os.stat(os.path.join(d, "report.pdf")).st_mode & 0o777 == 0o600
   and open(os.path.join(d, "report.pdf"), "rb").read() == b"one")
ok("no part left behind", leftovers(d) == [], leftovers(d))

c = deliver(d, "report.pdf", b"two")
ok("existing name -> 'report (1).pdf', original kept", c.acks[0]["path"] == os.path.join(d, "report (1).pdf")
   and open(os.path.join(d, "report.pdf"), "rb").read() == b"one", c.acks)

victim_dir = new_folder()
victim = os.path.join(victim_dir, "victim")
open(victim, "wb").write(b"precious")
os.symlink(victim, os.path.join(d, "notes.txt"))
c = deliver(d, "notes.txt", b"payload")
ok("a symlink at the final name is never followed", c.acks[0]["path"] == os.path.join(d, "notes (1).txt")
   and open(victim, "rb").read() == b"precious", c.acks)

os.symlink(victim, os.path.join(d, hub._legacy_part_name("tok_planted")))
c = deliver(d, "planted.txt", b"payload", upload_id="tok_planted")
ok("a pre-created symlink at the .part name is not followed", c.acks[0]["success"]
   and open(victim, "rb").read() == b"precious" and open(os.path.join(d, "planted.txt"), "rb").read() == b"payload",
   c.acks)
ok("…and the planted name is gone", leftovers(d) == [], leftovers(d))

c = deliver(d, "bad.bin", b"data", sha="0" * 64)
ok("sha256 mismatch -> failure ack, nothing published, no part", c.acks == [{"success": False,
   "error": "sha256 mismatch"}] and not os.path.exists(os.path.join(d, "bad.bin")) and leftovers(d) == [], c.acks)

c = deliver(d, "../../etc/escape.txt", b"x")
ok("a path in the name is reduced to its base name, inside the folder",
   c.acks[0]["path"] == os.path.join(d, "escape.txt"), c.acks)
c = deliver(d, ".orchestratia-x.part", b"x")
ok("the reserved prefix is refused", c.acks == [{"success": False, "error": "invalid file name"}], c.acks)

gw = new_folder()
os.chmod(gw, 0o770)
c = deliver(gw, "a.txt", b"x")
ok("group-writable folder refused", not c.acks[0]["success"] and "not safe" in c.acks[0]["error"]
   and os.listdir(gw) == [], c.acks)

real = new_folder()
link = real + "-link"
os.symlink(real, link)
c = deliver(link, "a.txt", b"x")
ok("symlinked folder refused", not c.acks[0]["success"] and os.listdir(real) == [], c.acks)


def _unavailable(run_as):
    raise upload_dirs.UploadDirError("unsafe_destination", "squatted")


upload_dirs.folder_for = _unavailable
c = FakeClient(b"x")
asyncio.run(hub._process_pending_upload(c, STATE, {"upload_id": "t", "filename": "a", "download_url": "/x"}))
ok("no usable folder -> clear failure ack", c.acks == [{"success": False,
                                                        "error": "upload folder unavailable: squatted"}], c.acks)

if os.geteuid() == 0:
    theirs = new_folder()
    os.chown(theirs, 65534, 65534)
    c = deliver(theirs, "a.txt", b"x")
    ok("folder owned by another user refused", not c.acks[0]["success"] and "not safe" in c.acks[0]["error"]
       and os.listdir(theirs) == [], c.acks)
else:
    print("[SKIP] folder owned by another user (needs root to chown)")

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
