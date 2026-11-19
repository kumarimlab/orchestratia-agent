#!/usr/bin/env python3
"""Masking (spec §10.2): headers, tokens, JWTs, path tokens, known values in many encodings.

Run:  python3 tests/test_scan_masking.py
"""
import base64
import html
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from orchestratia_agent.scanning.masking import MASK, mask_finding, mask_text  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
PW = "Sup3r-Secret!pw"
cases = {
    "Cookie header": ("GET / HTTP/1.1\nCookie: clm_session=abc123def\n", "abc123def"),
    "Set-Cookie header": ("Set-Cookie: sid=zzz999; Path=/", "zzz999"),
    "Authorization header": ("Authorization: Bearer tok_live_42", "tok_live_42"),
    "JWT anywhere": (f"see {JWT} here", JWT),
    "token query param": ("/cb?state=1&access_token=ya29.xyz&x=2", "ya29.xyz"),
    "jsessionid path param": ("/app;jsessionid=ABCDEF0123?x=1", "ABCDEF0123"),
    "presigned S3": ("/b/o?X-Amz-Credential=AKIA%2Fx&X-Amz-Signature=deadbeef99", "deadbeef99"),
    "JSON token field": ('{"refresh_token": "rt-777", "ok": true}', "rt-777"),
    "reset path token": ("/reset/9f8e7d6c5b4a", "9f8e7d6c5b4a"),
}
for name, (text, secret) in cases.items():
    out, n = mask_text(text)
    ok(f"masks {name}", secret not in out and MASK in out and n >= 1, out)

forms = {
    "raw": PW,
    "url-encoded": urllib.parse.quote(PW, safe=""),
    "double url-encoded": urllib.parse.quote(urllib.parse.quote(PW, safe=""), safe=""),
    "html entities": html.escape(PW).replace("!", "&#33;"),
    "json \\u escaped": json.dumps(PW + "é")[1:-1],
    "base64(user:pass)": base64.b64encode(f"qa-user:{PW}".encode()).decode(),
    "base64url": base64.urlsafe_b64encode(f"x{PW}yy".encode()).decode().rstrip("="),
}
for name, text in forms.items():
    out, _ = mask_text(f"body={text}&z=1", known=[PW])
    leaked = PW in out or urllib.parse.quote(PW, safe="") in out or text in out
    ok(f"masks a known credential, {name}", not leaked, out)

out, _ = mask_text("username=admin&role=admin", known=["admin"])
ok("a short known value is masked but the text survives", "admin" not in out and "username=" in out, out)
out, n = mask_text("nothing to see here, version 1.2.3")
ok("plain text is untouched", out == "nothing to see here, version 1.2.3" and n == 0)

f = {"title": f"Token {JWT}", "description": "", "evidence": f"Cookie: a=b\npw={PW}",
     "location": {"kind": "url", "url": f"/x?token={PW}", "param": "token"},
     "references": {"urls": [f"https://h/?api_key={PW}"], "cwe": [], "cve": []}}
n = mask_finding(f, known=[PW])
blob = json.dumps(f)
ok("mask_finding covers title, evidence, location and reference urls",
   JWT not in blob and PW not in blob and n >= 4, blob)
ok("mask_finding masks title", JWT not in f["title"] and MASK in f["title"])
ok("mask_finding masks evidence", PW not in f["evidence"] and "a=b" not in f["evidence"])
ok("mask_finding masks location.url", PW not in f["location"]["url"] and MASK in f["location"]["url"])
ok("mask_finding masks references.urls", PW not in f["references"]["urls"][0] and MASK in f["references"]["urls"][0])

import time
t0 = time.time()
mask_text("\n" * 50000 + "Cookie: x")
mixed = ("GET /a?b=1 HTTP/1.1\n   \t\nHost: h\n" + "x" * 50 + " ") * 3000
mask_text(mixed[:200000], known=[PW, "ab"])
mask_text(" \t" * 50000 + "Cookie")
el = time.time() - t0
ok("no quadratic blowup on newline/whitespace floods and 200 KB mixed text", el < 1.0, f"{el:.2f}s")

out, n = mask_text("pw=abc&x=1", ["abc"])
ok("1-3 char known value masked when bounded", "abc" not in out and n >= 1, out)
out, _ = mask_text("abcdef", ["abc"])
ok("short known value left alone inside a longer word", out == "abcdef", out)
out, _ = mask_text('{"Authorization": "Bearer xyz123", "a": 1}')
ok("masks JSON-form secret header", "xyz123" not in out and '"a": 1' in out, out)
out, _ = mask_text("req Cookie: a=bcd\nnext line")
ok("masks mid-line header to end of line only", "bcd" not in out and "next line" in out, out)
g = {"title": "", "location": {"a": {"u": "?token=zzz"}, "b": ["?token=yyy"]}}
mask_finding(g)
ok("mask_finding masks nested location strings", "zzz" not in json.dumps(g) and "yyy" not in json.dumps(g), json.dumps(g))
NONE_JWT = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0In0."
out, _ = mask_text(f"t={NONE_JWT} end")
ok("masks alg=none JWT with empty signature", "eyJzdWIi" not in out, out)
lower = urllib.parse.quote("a/b é!", safe="").lower()
out, _ = mask_text(f"x={lower}&y=1", known=["a/b é!"])
ok("lowercase percent-encoding of a known value is masked", lower not in out and MASK in out, out)


# ---------------------------------------------------------------- final fix wave: pattern pass (C1b, M2)
# Fake secrets are assembled at runtime so the public repo never holds a scanner-shaped literal.
AKIA = "AKIA" + "Z3MSJV4WZXQ7RT2P"
GHP = "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GHPAT = "github" + "_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuv"
SKLIVE = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
SKTEST = "sk" + "_test_" + "51H8xYzABCdefGHIjkl"
RKLIVE = "rk" + "_live_" + "51H8xYzABCdefGHIjkl"
XOXB = "xox" + "b-" + "123456789012-123456789012-AbCdEfGhIjKlMnOpQrStUvWx"
SKPROJ = "sk" + "-proj-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
SKANT = "sk" + "-ant-" + "api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
SKOLD = "sk" + "-" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd"
AIZA = "AI" + "za" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
GLPAT = "glpat" + "-" + "aBcDeFgHiJkLmNoPqRsT"
NPM = "npm" + "_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789a"
PEM = ("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6\n"
       "q2bx3yZ\n-----END " + "RSA PRIVATE KEY-----")
for name, text, secret in (
        ("AWS access key id", f"aws = {AKIA}", AKIA), ("ASIA key id", "k ASIA" + "Z3MSJV4WZXQ7RT2P end", "Z3MSJV4WZXQ7RT2P"),
        ("ghp_ token", f"t {GHP}", GHP), ("github_pat_", f"x={GHPAT}", GHPAT),
        ("sk_live_", f"stripe {SKLIVE}", SKLIVE), ("sk_test_", f"{SKTEST}", SKTEST), ("rk_live_", RKLIVE, RKLIVE),
        ("slack xoxb-", f"slack {XOXB}", XOXB), ("sk-proj-", SKPROJ, SKPROJ), ("sk-ant-", SKANT, SKANT),
        ("sk- long", f"openai {SKOLD}", SKOLD), ("AIza", AIZA, AIZA), ("glpat-", GLPAT, GLPAT), ("npm_", NPM, NPM),
        ("PEM private key block", f"key:\n{PEM}\nafter", "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6"),
        ("URL userinfo", "DB = postgres://app:Sup3rS3cret!@db.internal:5432/x", "Sup3rS3cret!"),
        ("generic password assignment", 'password = "hunter2-is-long"', "hunter2-is-long"),
        ("generic SECRET_KEY assignment", 'SECRET_KEY = "django-insecure-abc$%^def"', "django-insecure-abc$%^def"),
        ("generic AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
         "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("generic json api_key", '{"api_key": "abc-def-ghi"}', "abc-def-ghi"),
        ("generic client_secret yaml", "client_secret: 'cs-value-1'", "cs-value-1"),
        ("generic DB_PWD", 'DB_PWD="p4ss"', "p4ss")):
    out, n = mask_text(text)
    ok(f"pattern pass masks {name}", secret not in out and MASK in out and n >= 1, out)
out, _ = mask_text("PEM tail " + PEM)
ok("PEM block: neither the base64 body nor its last line survive", "q2bx3yZ" not in out and "MIIE" not in out, out)
out, _ = mask_text('see https://user:pw@host/a and password_hint = "x"')
ok("userinfo masked, host and path kept", "user:pw" not in out and "host/a" in out, out)
for keep in ("version 1.2.3", "https://github.com/advisories/GHSA-xxxx", "AKIA too short", "skip = 'x'",
             "pkg django==2.2.0", "def get_token(self):", "tokenizer = load()"):
    ok(f"pattern pass leaves plain text alone: {keep!r}", mask_text(keep)[0] == keep, mask_text(keep)[0])

t0 = time.time()
for hostile in ("tokentoken" * 100000, "sk-" * 300000, "password=\"" * 100000, "://a" * 200000,
                "-----BEGIN PRIVATE KEY-----" * 30000, "ghp_" * 200000, "a" * 1000000,
                "secret" + " " * 500000 + "=", "x://" + "u" * 500000, "AKIA" * 200000):
    mask_text(hostile)
el = time.time() - t0
ok("pattern pass is linear on hostile 1 MB inputs", el < 5.0, f"{el:.2f}s")   # 10 inputs, ~10 MB in all

# M2: mask THEN cut — a JWT straddling the cap must not leave header+payload behind.
from orchestratia_agent.scanning import parsers  # noqa: E402
body = "x" * 500 + JWT
cut = parsers._s(body, 512)
ok("parsers._s masks before cutting (JWT at the boundary)", "eyJhbGciOiJIUzI1NiJ9" not in cut and "eyJ" not in cut, cut[-40:])


# ---------------------------------------------------------------- adversarial-review round (hub H1, agent M4)
# H1: every pattern must stay linear on long adversarial inputs (re holds the GIL: a quadratic pattern freezes
# the daemon's event loop / the hub's realtime tier). Each pattern alone, then mask_text as a whole.
from orchestratia_agent.scanning import masking as _m  # noqa: E402
PATTERNS = {k: v for k, v in vars(_m).items() if k.endswith("_RE") and hasattr(v, "subn")}
K = 40000
HOSTILE = {
    "eyJ run": "eyJ" * K, "eyJ dotted": "eyJaaaa." * K, "dash eyJ": "-eyJaaaa" * K, "dot eyJ": ".eyJ" * K,
    "long token run": "A" * (3 * K), "ghp_ run": "ghp_" * K, "sk- run": "sk-" * K, "xoxb run": "xoxb-" * K,
    "key=value chain": "password=x;" * K, "key: chain": "token: " * K, "unquoted kv no eol": "password=" + "x" * (3 * K),
    "kv long spaces": "password: a" + " " * (3 * K), "kv spaces then #": ("password: a" + " " * 30) * 4000,
    "kv per line": "password = a\n" * K, "json token open": '"token": "' * K, "json hdr backslash": '"cookie": "\\' * K,
    "json open to end": '"token": "' + "a" * (3 * K) + "\\", "header spaces": "cookie" + " " * (3 * K),
    "secret word run": "secret" * K, "alternating quotes": "pwd:'pwd:\"" * K, "userinfo": "://a" * K,
    "at signs": "a@" * K, "PEM begins": "-----BEGIN PRIVATE KEY-----" * 4000, "BEGIN run": "-----BEGIN " * K,
    "entity run": "&#0" * K, "reset paths": "/reset/" * K, "jsessionid": ";jsessionid=" * K, "_key= run": "_key=" * K,
    "AKIA run": "AKIA" * K, "== run": "token==" * K, "tabs": "token\t" * K,
}
slow = []
for pn, rx in sorted(PATTERNS.items()):
    for hn, text in HOSTILE.items():
        t0 = time.perf_counter()
        rx.subn("X", text)
        el = time.perf_counter() - t0
        if el > 0.25:
            slow.append(f"{pn} on {hn}: {el:.2f}s")
ok("every masking pattern is linear on adversarial inputs (each < 0.25 s on ~120 KB)", not slow, "; ".join(slow))
t0 = time.perf_counter()
mask_text("eyJ" * 40000)
el = time.perf_counter() - t0
ok("mask_text on 'eyJ'*40000 is fast (hub H1 ReDoS)", el < 0.5, f"{el:.2f}s")
t0 = time.perf_counter()
for text in HOSTILE.values():
    mask_text(text, known=[PW, "abc"])
el = time.perf_counter() - t0
ok("mask_text over every hostile input stays bounded", el < 5.0, f"{el:.2f}s")

# mask_cut / mask_tail bound the masking work by the cut, not by the input
from orchestratia_agent.scanning.masking import mask_cut  # noqa: E402
big = "eyJ" * 3_000_000          # 9 MB; quadratic would never finish, linear-on-all would still be slow-ish
t0 = time.perf_counter()
out = mask_cut(big, 200)
el = time.perf_counter() - t0
ok("mask_cut masks only a window around the cut (9 MB input, bounded work)", el < 0.2 and len(out) <= 200, f"{el:.3f}s")
mask_tail = getattr(_m, "mask_tail", None)
if mask_tail is None:
    ok("mask_tail exists (mask-then-keep-the-end, bounded)", False)
else:
    t0 = time.perf_counter()
    out = mask_tail("x" * 9_000_000 + " Authorization: Bearer abc123def", 300)
    el = time.perf_counter() - t0
    ok("mask_tail masks the tail window and keeps the end", el < 0.2 and "abc123def" not in out and out.endswith(MASK), f"{el:.3f}s {out[-60:]}")
# a JWT that straddles the masking window is still masked (truncated JWT at the end of the window)
longjwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJ" + "A" * 9000 + ".sig"   # payload longer than WINDOW
out = mask_cut("x" * 100 + longjwt, 300)
ok("a JWT longer than the window is masked, not cut open", "eyJhbGciOiJIUzI1NiJ9" not in out, out[:160])
out = mask_cut('{"token": "' + "s" * 9000 + '"}', 100)
ok("an unterminated (cut) JSON secret field is masked", "sss" not in out, out)
ok("JWT still masked after a separator", MASK in mask_text(f"Bearer:{JWT}")[0] and JWT not in mask_text(f"Bearer:{JWT}")[0])

# M4: unquoted secret-named values (YAML/env/ini forms), the whole value, comment markers kept
for text, secret, keep in (
        ("POSTGRES_PASSWORD: Pr0d-Db!pass#2026  # TODO rotate", "Pr0d-Db!pass#2026", "# TODO rotate"),
        ("signing_key = s3cr3t.v4lue.k3y.abcdefghij  ; FIXME", "s3cr3t", "; FIXME"),
        ("DB_PASSWORD=hunter2", "hunter2", "DB_PASSWORD="),
        ("api_key: abc def ghi", "def", "api_key:"),
        ("auth_token = 9f8e7d", "9f8e7d", "auth_token"),
        ("secret: p", "p\n", "secret:"),
        ("client_secret=xyz // TODO", "xyz", "// TODO"),
        ("password : spaced-out-value", "spaced-out-value", "password"),
        ("x-api-key=abc.def", "abc.def", "x-api-key")):
    out, n = mask_text(text + "\nnext line")
    ok(f"unquoted secret value masked: {text!r}", secret not in out and keep in out and n >= 1 and "next line" in out, out)
for keep in ("if password == other:", "tokenizer = load()", "max_tokens: 100", "secrets:\n  - a", "monkey: banana",
             "token => 'x'", "def get_token(self):"):
    out = mask_text(keep)[0]
    ok(f"no unquoted-value masking on {keep!r}", MASK not in out or keep.startswith("token =>"), out)
out, n = mask_text("password=abc&x=1")
ok("a param masked once is not re-masked", out.count(MASK) == 1, out)


# ---------------------------------------------------------------- round 2 (re-review N3): 24 unquoted/odd forms
FORMS = [("DB_PASS: Vx01secret", "Vx01secret"), ("SMTP_PASS=Vx02secret", "Vx02secret"),
         ("DB_PASSWORD_PROD: Vx03secret", "Vx03secret"), ("SECRET_KEY_BASE: Vx04secret", "Vx04secret"),
         ("password1: Vx05secret", "Vx05secret"), ("password := Vx06secret", "Vx06secret"),
         ('password := "Vx07secret"', "Vx07secret"), ("password => Vx08secret", "Vx08secret"),
         ("'password' => 'Vx09secret',", "Vx09secret"), ("run --password Vx10secret --verbose", "Vx10secret"),
         ("run --password=Vx11secret", "Vx11secret"), ("tool --db-password Vx12secret", "Vx12secret"),
         ("mysql -uroot -pVx13secret appdb", "Vx13secret"), ("export PGPASSWORD=Vx14secret", "Vx14secret"),
         ("MYSQL_PWD=Vx15secret", "Vx15secret"), ("dbPassword: Vx16secret", "Vx16secret"),
         ("authToken = Vx17secret", "Vx17secret"), ("apiKey: Vx18secret", "Vx18secret"),
         ('DB_PASS: "Vx19secret"', "Vx19secret"), ("SMTP_PASS = 'Vx20secret'", "Vx20secret"),
         ("secret_token=Vx21secret", "Vx21secret"), ("REDIS_AUTH_KEY: Vx22secret", "Vx22secret"),
         ("aws_secret_access_key = Vx23secret", "Vx23secret"), ("cli --api-key=Vx24secret", "Vx24secret")]
for text, secret in FORMS:
    out, n = mask_text(text + "\nnext")
    ok(f"N3 masks {text!r}", secret not in out and "next" in out and n >= 1, out)
for keep in ("passenger: 3", "bypass: true", "compass = north", "max_tokens: 100", "tokenizer = load()",
             "if password == other:", "docker run -p 8080:80 img", "psql -p 5432 -h db", "passes: 4",
             "monkey: banana", "def get_token(self):", "keyboard: us", "--no-password --verbose"):
    out = mask_text(keep)[0]
    ok(f"N3 leaves alone {keep!r}", MASK not in out, out)
# linearity as a property: doubling the input at most ~doubles the time (quadratic would quadruple)
bad = []
for unit in ("://a", "secret ", 'password="', "a_b-c.", "DB_PASS: x\n", "--password ", "mysql -p", "eyJ", "pass_" * 3):
    ts = []
    for k in (40000, 80000):
        t0 = time.perf_counter()
        mask_text(unit * k)
        ts.append(time.perf_counter() - t0)
    if ts[1] > 3.0 * ts[0] + 0.02:
        bad.append((unit, [round(x, 3) for x in ts]))
ok("N3 every pattern scales linearly (2x input -> <= 3x time)", not bad, bad)
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
