#!/usr/bin/env python3
"""Parsers for the pinned tools' JSON (spec §10.1). Fixtures are real outputs;
tests/fixtures/scan/osv.json is a real EXCERPT (4 of 74 vulnerabilities, details/affected dropped).

Run:  python3 tests/test_scan_parsers.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from orchestratia_agent.scanning import parsers  # noqa: E402

results = []


def ok(n, c, d=""):
    results.append(bool(c))
    print(f"[{'PASS' if c else 'FAIL'}] {n}" + (f" — {d}" if d else ""))


KEYS = {"scan_id", "rule_id", "severity", "title", "description", "location", "evidence", "references",
        "tool", "tool_version"}
with open(os.path.join(HERE, "tests/fixtures/scan/gitleaks.json")) as f:
    gl = parsers.gitleaks(json.load(f), "8.x")
ok("gitleaks: one finding with the protocol shape", len(gl) == 1 and set(gl[0]) == KEYS, gl)
ok("gitleaks: rule id, file and line", gl[0]["rule_id"].startswith("gitleaks:")
   and os.path.basename(gl[0]["location"]["path"]) == "k.py"
   and gl[0]["location"]["line"] == 1, gl[0]["location"])
ok("gitleaks: the secret value never appears", "AKIAZ3MSJV4WZXQ7RT2P" not in json.dumps(gl), json.dumps(gl))
ok("gitleaks: severity high", gl[0]["severity"] == "high")
ok("gitleaks: empty/None report → []", parsers.gitleaks(None, "8.x") == [] and parsers.gitleaks([], "8.x") == [])

with open(os.path.join(HERE, "tests/fixtures/scan/osv.json")) as f:
    osv, manifests = parsers.osv(json.load(f), "2.x")
ok("osv: django findings with the protocol shape", osv and all(set(x) == KEYS for x in osv)
   and all("django" in x["title"].lower() for x in osv), [x["title"] for x in osv][:3])
ok("osv: rule ids are osv:<id>", all(x["rule_id"].startswith("osv:") for x in osv))
ok("osv: severities are from the allowed set",
   all(x["severity"] in {"critical", "high", "medium", "low", "info"} for x in osv))
ok("osv: CVE aliases land in references", any(x["references"]["cve"] for x in osv))
ok("osv: manifests scanned are listed", [os.path.basename(m) for m in manifests] == ["requirements.txt"], manifests)
ok("osv: empty report → no findings", parsers.osv({"results": []}, "2.x") == ([], []))

# --- malformed, attacker-influenced input: never raise, stay protocol-shaped, stay capped ---
def shaped(fs):
    return all(set(x) == KEYS and isinstance(x["location"]["line"], (int, type(None)))
               and len(x["rule_id"]) <= 600 and len(x["title"]) <= 512 and len(x["location"]["path"]) <= 512
               and len(x["evidence"]) <= 2048
               and all(len(u) <= 512 for k in ("cwe", "cve", "urls") for u in x["references"][k])
               and all(len(x["references"][k]) <= 20 for k in ("cwe", "cve", "urls")) for x in fs)


def safe(n, fn):
    try:
        r = fn()
    except Exception as e:  # noqa: BLE001
        ok(n, False, repr(e))
        return None
    return r


r = safe("gitleaks non-dict items", lambda: parsers.gitleaks([1, "x", None, [2]], "v"))
ok("gitleaks: non-dict items skipped", r == [])
r = safe("gitleaks dict report", lambda: parsers.gitleaks({"a": 1}, "v"))
ok("gitleaks: dict instead of list -> []", r == [])
r = safe("gitleaks non-str values", lambda: parsers.gitleaks(
    [{"Description": 5, "RuleID": 7, "File": ["x"], "StartLine": "3", "Commit": 12345678901234567}, {}], "v"))
ok("gitleaks: non-str values and missing fields", r is not None and len(r) == 2 and shaped(r)
   and r[0]["location"]["line"] is None, r)
r = safe("gitleaks huge", lambda: parsers.gitleaks([{"RuleID": "r" * 10000, "Description": "d" * 10000,
                                                      "File": "f" * 10000}], "v"))
ok("gitleaks: huge fields capped", r is not None and shaped(r) and len(r[0]["title"]) == 512, "")

for name, rep in [("list", []), ("list-nonempty", [1]), ("str", "x"), ("none", None),
                  ("results dict", {"results": {"a": 1}}), ("results junk", {"results": [1, None, "x"]}),
                  ("packages junk", {"results": [{"packages": [1, None, {"package": 5}]}]}),
                  ("vulns junk", {"results": [{"source": 5, "packages": [{"vulnerabilities": [1, {}]}]}]})]:
    r = safe("osv " + name, lambda: parsers.osv(rep, "v"))
    ok(f"osv: {name} input does not raise", r is not None and isinstance(r[0], list) and shaped(r[0]), r)
ok("osv: non-dict report -> ([], [])", parsers.osv([1], "v") == ([], []) and parsers.osv("x", "v") == ([], []))
bad = {"results": [{"source": {"path": 5}, "packages": [{
    "package": {"name": "n" * 10000, "version": 5, "ecosystem": ["x"]},
    "groups": [{"ids": [[1], {"a": 1}, "A"], "max_severity": "x"}, 7],
    "vulnerabilities": [{"id": "A", "summary": 9, "aliases": [1, ["x"], "CVE-1"] + ["CVE-%d" % i for i in range(100)],
                         "references": [{"url": 5}, 3, {"url": "u" * 10000}] + [{"url": "http://x/%d" % i} for i in range(100)],
                         "database_specific": {"severity": 5}},
                        {"id": ["x"], "references": "nope", "aliases": "nope"}]}]}]}
r = safe("osv bad", lambda: parsers.osv(bad, "v"))
ok("osv: reproduced crashes + non-str everywhere", r is not None and len(r[0]) == 2 and shaped(r[0]), "")
ok("osv: 10,000-char package name capped", r is not None and len(r[0][0]["title"]) <= 512
   and len(r[0][0]["evidence"]) <= 2048)
ok("osv: list lengths capped", r is not None and len(r[0][0]["references"]["urls"]) <= 20
   and len(r[0][0]["references"]["cve"]) <= 20)

r = safe("osv overflow", lambda: parsers.osv({"results": [{"packages": [{"groups": [
    {"ids": ["A"], "max_severity": 10**400}], "vulnerabilities": [{"id": "A"}]}]}]}, "v"))
ok("osv: max_severity 10**400 does not raise", r is not None and len(r[0]) == 1 and shaped(r[0]), r)
r = safe("gitleaks lines", lambda: parsers.gitleaks(
    [{"StartLine": v} for v in (10**30, -1, True, 0, 2**31, 5)], "v"))
ok("gitleaks: line must be 0 < int < 2**31 (bool/huge/negative -> None)",
   r is not None and [x["location"]["line"] for x in r] == [None, None, None, None, None, 5], r)

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if results and all(results) else 1)
