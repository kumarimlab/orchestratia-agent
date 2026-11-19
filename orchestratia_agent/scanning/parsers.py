"""Tool JSON → protocol findings (spec §10.1). Stdlib only; runs inside the sandbox.
Paths are made relative to the snapshot root by the caller passing `root`.
Tool output is attacker-influenced: parsers never raise, skip malformed entries and cap every field.
Every field is masked BEFORE it is cut (a cut can split a secret so no pattern recognises it)."""
import os

try:
    from . import masking
except ImportError:          # installed layout: /opt/orchestratia/scanners/runner/*.py, no package
    import masking

_EVIDENCE_MAX, _TEXT_MAX, _LIST_MAX, _IDS_MAX = 2048, 512, 20, 200


def _str(x):
    if x is None:
        return ""
    try:
        return x if isinstance(x, str) else str(x)
    except Exception:
        return ""


def _s(x, n=_TEXT_MAX, known=()):
    """Masked, then cut to n."""
    try:
        return masking.mask_cut(_str(x), n, known)
    except Exception:
        return ""


def _d(x):
    return x if isinstance(x, dict) else {}


def _l(x):
    return x if isinstance(x, list) else []


def _line(x):
    return x if isinstance(x, int) and not isinstance(x, bool) and 0 < x < 2**31 else None


def _f(scan_id, rule, sev, title, path, line, evidence, tool, ver, cve=(), cwe=(), urls=(), known=()):
    def lst(v):
        return [t for t in (_s(i, known=known) for i in list(v)[:_LIST_MAX]) if t]
    rule = _s(rule, known=known) or "unknown"
    return {"scan_id": scan_id, "rule_id": rule, "severity": sev, "title": _s(title, known=known) or rule,
            "description": "", "location": {"kind": "file", "path": _s(path, known=known), "line": _line(line)},
            "evidence": _s(evidence, _EVIDENCE_MAX, known),
            "references": {"cwe": lst(cwe), "cve": lst(cve), "urls": lst(urls)},
            "tool": tool, "tool_version": _s(ver, known=known)}


def _shift(line, offset):
    v = _line(line)
    return None if v is None else _line(v + offset)


def _rel(path, root):
    if root and path and os.path.isabs(path):
        try:
            return os.path.relpath(path, root)
        except ValueError:
            return path
    return path


def gitleaks(report, tool_version, root="", known=(), line_offset=0):
    """argv: gitleaks {dir|git} --no-banner --redact --report-format json --report-path <out> <src>
    Exit 1 = leaks found (not an error). Secret/Match are dropped regardless of --redact.
    line_offset is added to StartLine (the shim's files pass reads every file one line down)."""
    out = []
    for r in _l(report):
        if not isinstance(r, dict):
            continue
        rule = _s(r.get("RuleID"), known=known) or "unknown"
        commit = _s(r.get("Commit"), 12, known)
        out.append(_f("code.secrets", f"gitleaks:{rule}", "high", r.get("Description") or rule,
                      _rel(_str(r.get("File")), root), _shift(r.get("StartLine"), line_offset),
                      f"{rule} (value masked)" + (f" in commit {commit}" if commit else ""),
                      "gitleaks", tool_version, known=known))
    return out


def _severity(vuln, group_max):
    try:
        score = float(group_max)
    except (TypeError, ValueError, OverflowError):
        score = None
    if score is not None and score == score:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    label = _s(_d(vuln.get("database_specific")).get("severity")).upper()
    return {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium",
            "LOW": "low"}.get(label, "medium")


def osv(report, tool_version, root="", known=()):
    """argv (v2.7.0, verified fully offline): osv-scanner scan source --offline --offline-vulnerabilities
    --format json -r <src>, env OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=<dir> holding
    <dir>/osv-scalibr/<Ecosystem>/all.zip (e.g. PyPI/all.zip). Exit 1 = vulnerabilities."""
    findings, manifests = [], []
    for res in _l(_d(report).get("results")):
        res = _d(res)
        path = _s(_rel(_str(_d(res.get("source")).get("path")), root), known=known)
        if path and path not in manifests:
            manifests.append(path)
        for pkg in _l(res.get("packages")):
            pkg = _d(pkg)
            p = _d(pkg.get("package"))
            groups = {}
            for g in _l(pkg.get("groups")):
                g = _d(g)
                for i in _l(g.get("ids"))[:_IDS_MAX]:
                    groups[_s(i)] = g.get("max_severity")
            for v in _l(pkg.get("vulnerabilities")):
                v = _d(v)
                vid = _s(v.get("id")) or "unknown"
                aliases = [_s(a) for a in _l(v.get("aliases"))]
                refs = [_d(r).get("url") for r in _l(v.get("references"))]
                findings.append(_f("code.deps", f"osv:{vid}", _severity(v, groups.get(vid)),
                                   f"{_s(p.get('name'), 200)} {_s(p.get('version'), 100)}: "
                                   f"{_s(v.get('summary')) or vid}", path, None,
                                   f"{_s(p.get('ecosystem'), 100)} {_s(p.get('name'), 200)}=="
                                   f"{_s(p.get('version'), 100)}", "osv-scanner", tool_version,
                                   cve=[a for a in aliases if a.startswith("CVE-")],
                                   urls=[u for u in refs if isinstance(u, str) and u], known=known))
    return findings, manifests
