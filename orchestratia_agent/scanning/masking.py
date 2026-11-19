"""Masking for scan findings (spec §10.2). Stdlib only: also runs inside the sandbox.

Applied to EVERY free-text field. Order: known values first (in every encoding we can
cheaply produce), then structural patterns (headers, params, JWTs, path tokens), then
secret patterns (well-known token prefixes, PEM private keys, URL userinfo, secret-named
assignments, quoted or not). Input is attacker-controlled: every pattern is linear-time — no
unbounded run is followed by anything that can fail after it, every prefix before one is bounded,
and a pattern that starts with a token run only starts where that run starts (a lookbehind), so a
long run is scanned from O(1) starts, not from each of its characters. mask_cut/mask_tail mask a
window around the cut (WINDOW chars past it), never the whole input: the work is bounded by the
cut, and anything open at the window edge (JWT, JSON string) is masked to the edge."""
import base64
import html
import json
import re
import urllib.parse
from typing import Sequence

MASK = "[masked]"
MIN_KNOWN = 4                      # shorter values would mask half of every page
WINDOW = 4096                      # mask_cut/mask_tail mask this much text beyond the cut

_HEADERS = ("cookie", "set-cookie", "authorization", "proxy-authorization", "x-api-key", "x-auth-token")
_PARAMS = ("token", "access_token", "refresh_token", "id_token", "client_secret", "api_key", "apikey",
           "key", "secret", "password", "session", "sid", "code", "x-amz-signature", "x-amz-credential",
           "x-amz-security-token", "signature", "sig")
_alt = lambda xs: "|".join(re.escape(x) for x in xs)
# Whitespace around a header colon is [ \t] only: \s would span newlines and go O(n^2).
_HEADER_RE = re.compile(r"(?i)(\b(?:%s)[ \t]*:[ \t]*)([^\r\n]+)" % _alt(_HEADERS))
_JSON_HEADER_RE = re.compile(r'(?i)("(?:%s)"[ \t]*:[ \t]*")((?:[^"\\]|\\.)*)("|\Z)' % _alt(_HEADERS))
_PARAM_RE = re.compile(r"(?i)((?:^|[?&;\s])(?:%s)=)([^&#\s\"'<>]+)" % _alt(_PARAMS))
_JSESSION_RE = re.compile(r"(?i)(;jsessionid=)([^?#&\s/]+)")
_JSON_RE = re.compile(r'(?i)("(?:%s)"\s*:\s*")((?:[^"\\]|\\.)*)("|\Z)' % _alt(_PARAMS))
_PATH_RE = re.compile(r"(?i)(/(?:reset|verify|invite|magic)/)([^/?#\s\"'<>]+)")
# JWT: a token run holding "eyJ" plus up to two ".segment"s; _jwt_repl decides (eyJ + 4 chars, then
# .4+ chars.any — or cut open by the end of the text, e.g. a mask_cut window) and masks from the eyJ on.
# Matching only from where a token run STARTS keeps it linear: `eyJ[..]{4,}\.` tried at every "eyJ"
# is O(N^2) on "eyJ"*N (each start scans to the end of the run and fails).
_JWT_RE = re.compile(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*?eyJ)([A-Za-z0-9_-]+)((?:\.[A-Za-z0-9_-]*){0,2})")
# High-confidence token prefixes (spec §10.2 item 6).
_TOKEN_RE = re.compile(
    r"\b(?:A(?:KIA|SIA)[A-Z0-9]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|[sr]k_(?:live|test)_[A-Za-z0-9]{10,}"
    r"|xox[abpr]-[A-Za-z0-9-]{10,}"
    r"|sk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"
    r"|AIza[0-9A-Za-z_-]{30,}|glpat-[0-9A-Za-z_-]{20,}|npm_[A-Za-z0-9]{30,})")
# A PEM private key, to its END line or (cut/unterminated) to the end of the text.
_PEM_RE = re.compile(r"-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY-----.*?(?:-----END[A-Z0-9 ]{0,40}PRIVATE KEY-----|\Z)", re.S)
# scheme://userinfo@ — userinfo can't contain "/", so each scan stops at the next "://".
_USERINFO_RE = re.compile(r"(?<=://)[^/\s@]{1,2048}(?=@)")
# Assignment operators: `:`, `=`, Go `:=`, Ruby/PHP/Perl `=>` (`==` is a comparison: never matched).
_OP = r"(?::=|=>|[:=])"
# secret-named assignment with a quoted value: SECRET_KEY = "...", "api_key": '...', password: "..."
_ASSIGN_RE = re.compile(
    r"(?i)((?:secret|passw(?:or)?d|pwd|token|api_?key|access_?key|private_?key|client_?secret)\w{0,40}[\"']?"
    r"[ \t]{0,20}" + _OP + r"[ \t]{0,20}([\"']))((?:(?!\2)[^\r\n]){1,512})(\2)")
# A secret-named KEY, as a whole identifier (it starts where the identifier starts: a lookbehind, so a
# long run is tried from one place). A secret word as a segment — at the start or after `_ . -`, with
# segment or digit suffixes: DB_PASS, SMTP_PASS, DB_PASSWORD_PROD, SECRET_KEY_BASE, password1,
# aws_secret_access_key, x-api-key, --db-password — or camelCase (dbPassword, authToken, apiKey).
# "passenger", "bypass", "max_tokens", "tokenizer", "keyboard" are not keys: a word must end its segment.
_SECRET_WORD = (r"(?:pass(?:word|wd|phrase)?|pwd|pgpassword|secret|token|credentials?|key[_.-]?base"
                r"|api[_.-]?key|apikey|private[_.-]?key|access[_.-]?key|signing[_.-]?key|secret[_.-]?key"
                r"|client[_.-]?secret|auth[_.-]?key|encryption[_.-]?key|master[_.-]?key)")
_KEY = (r"(?<![\w.-])(?:(?:[\w.-]{0,64}?[_.-])?" + _SECRET_WORD + r"(?:[_.-][A-Za-z0-9]{1,20}|\d{1,6}){0,3}"
        r"|(?-i:(?:[a-z][a-z0-9]{0,40}?(?:Password|Passwd|Passphrase|Pass|Pwd|Secret|Token|Credentials?|ApiKey"
        r"|PrivateKey|AccessKey|SecretKey|SigningKey)|(?:api|secret|private|access|signing)Key)"
        r"(?:[A-Z][a-z0-9]{1,20}|\d{1,6}){0,3}))")
# The value after such a key: quoted (masked inside the quotes), or unquoted to the end of the line,
# keeping a trailing comment (` # TODO`, ` // x`, ` ; FIXME`). Already-masked values are skipped.
# Linear: the key is bounded, the quoted value is bounded, and the unquoted loop always succeeds at the
# line end with a bounded lookahead.
_ASSIGN_BARE_RE = re.compile(
    r"(?i)(" + _KEY + r"[\"']?[ \t]{0,20}" + _OP + r"[ \t]{0,20})(?!\[masked\]|[\"']\[masked\])"
    r"(?:([\"'])((?:(?!\2)[^\r\n]){1,512})\2|([^\s\"'`=>](?:[^\r\n]*?)"
    r"(?=[ \t]{1,20}(?:#|//|;|--|/\*)|[ \t]{0,20}(?:[\r\n]|\Z))))")
# Command-line secrets: `--password v`, `--db-password "v"`, `--api-key=v` (a flag whose last word is a
# secret word; never a value that starts with `-`), and mysql's attached `-p<password>`.
_CLI_RE = re.compile(
    r"(?i)((?<![\w-])--?(?:[a-z0-9]{1,20}-){0,3}(?:password|passwd|pass|pwd|secret|token|api-?key|access-key"
    r"|secret-key|private-key|client-secret|credentials?)(?:[ \t]{1,20}|[ \t]{0,20}=[ \t]{0,20}))"
    r"(?!\[masked\]|-)(\"[^\"\r\n]{0,512}\"|'[^'\r\n]{0,512}'|[^\s\"']+)")
_MYSQL_P_RE = re.compile(r"(?i)(\b(?:mysql|mysqldump|mysqladmin|mariadb|mariadb-dump)\b[^\r\n]{0,200}?[ \t]-p)([^\s-]\S*)")


def _assign_repl(m):
    if m.group(2):                        # quoted: keep the quotes
        return m.group(1) + m.group(2) + MASK + m.group(2)
    return m.group(1) + MASK


def _jwt_repl(m):
    head, parts = m.group(1), m.group(2).split(".")[1:]
    i = head.find("eyJ")                  # the earliest eyJ has the most chars after it
    if len(head) - i - 3 < 4:
        return m.group(0)
    if not ((len(parts) == 2 and len(parts[0]) >= 4) or m.end() == len(m.string)):
        return m.group(0)
    return head[:i] + MASK


def _b64_cores(value: bytes) -> set[str]:
    """Base64 substrings that appear whenever `value` sits at ANY byte alignment inside a
    larger encoded buffer: encode with 0/1/2 filler bytes in front, drop the 4-char groups
    that mix in filler or the unknown following bytes."""
    cores = set()
    for k in range(3):
        enc = base64.b64encode(b"\x00" * k + value).decode()
        start = 4 if k else 0
        end = len(enc) if (k + len(value)) % 3 == 0 else len(enc) - 4
        core = enc[start:end]
        if len(core) >= 8:
            cores.add(core)
            cores.add(core.replace("+", "-").replace("/", "_"))
    return cores


def _variants(v: str) -> set[str]:
    once = urllib.parse.quote(v, safe="")
    out = {v, once, urllib.parse.quote_plus(v), urllib.parse.quote(once, safe=""), html.escape(v),
           json.dumps(v)[1:-1], json.dumps(v, ensure_ascii=False)[1:-1],
           "".join(f"&#{ord(c)};" if not c.isalnum() else c for c in v)}
    out |= _b64_cores(v.encode())
    # percent-encodings must match whatever hex case the producer used
    out |= {re.sub(r"%[0-9A-Fa-f]{2}", lambda m: m.group(0).lower(), x) for x in list(out) if "%" in x}
    return {x for x in out if len(x) >= MIN_KNOWN}


def _entity_re(v: str):
    """Regex matching `v` with any non-alphanumeric char written literally, as an HTML named
    escape, or as a decimal/hex numeric entity, independently per character (html.escape plus
    partial numeric encoding produce mixtures no single fixed variant covers)."""
    parts = []
    for c in v:
        if c.isalnum():
            parts.append(re.escape(c))
        else:
            alts = [re.escape(c), re.escape(html.escape(c)), "&#0*%d;" % ord(c), "&#[xX]0*%x;" % ord(c)]
            parts.append("(?:%s)" % "|".join(dict.fromkeys(alts)))
    return re.compile("".join(parts), re.I)


def mask_text(text: str, known: Sequence[str] = ()) -> tuple[str, int]:
    if not text:
        return text, 0
    n = 0
    for v in sorted({k for k in known if k and len(k) < MIN_KNOWN}, key=len, reverse=True):
        # 1-3 chars: raw form only, and only as a whole token (never inside a longer word)
        text, c = re.subn(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(v), MASK, text)
        n += c
    for v in sorted({k for k in known if k and len(k) >= MIN_KNOWN}, key=len, reverse=True):
        for form in sorted(_variants(v), key=len, reverse=True):
            if form in text:
                n += text.count(form)
                text = text.replace(form, MASK)
        if "&" in text:
            text, c = _entity_re(v).subn(MASK, text)
            n += c
    for rx, repl in ((_JSON_HEADER_RE, r"\1" + MASK + r"\3"), (_HEADER_RE, r"\1" + MASK), (_PARAM_RE, r"\1" + MASK), (_JSESSION_RE, r"\1" + MASK),
                     (_JSON_RE, r"\1" + MASK + r"\3"), (_PATH_RE, r"\1" + MASK), (_JWT_RE, _jwt_repl),
                     (_PEM_RE, MASK), (_TOKEN_RE, MASK), (_USERINFO_RE, MASK), (_ASSIGN_RE, r"\1" + MASK + r"\4"),
                     (_ASSIGN_BARE_RE, _assign_repl), (_CLI_RE, r"\1" + MASK), (_MYSQL_P_RE, r"\1" + MASK)):
        if callable(repl):                # counts only the matches it actually changed
            if rx is _JWT_RE and "eyJ" not in text:
                continue
            parts, last, c = [], 0, 0
            for m in rx.finditer(text):
                r = repl(m)
                if r != m.group(0):
                    parts += [text[last:m.start()], r]
                    last, c = m.end(), c + 1
            text = "".join(parts) + text[last:] if c else text
        else:
            text, c = rx.subn(repl, text)
        n += c
    return text, n


def mask_cut(text, n, known: Sequence[str] = ()) -> str:
    """Mask, THEN cut to n chars: cutting first can split a secret so no pattern sees it. Only the
    first n + WINDOW chars are masked, so the work is bounded by n, not by the input."""
    return mask_text(text[:n + WINDOW], known)[0][:n] if text else text


def mask_tail(text, n, known: Sequence[str] = ()) -> str:
    """mask_cut keeping the LAST n chars (tool stderr): masks only the last n + WINDOW chars."""
    if not text or n <= 0:
        return "" if text else text
    return mask_text(text[-(n + WINDOW):], known)[0][-n:]


def _mask_nested(node, known: Sequence[str]) -> int:
    """Mask every string at any depth inside dicts/lists, in place."""
    n = 0
    if isinstance(node, dict):
        items = list(node.items())
    elif isinstance(node, list):
        items = list(enumerate(node))
    else:
        return 0
    for k, v in items:
        if isinstance(v, str):
            node[k], c = mask_text(v, known)
            n += c
        else:
            n += _mask_nested(v, known)
    return n


def mask_finding(f: dict, known: Sequence[str] = ()) -> int:
    n = 0
    for k in ("title", "description", "evidence"):
        if isinstance(f.get(k), str):
            f[k], c = mask_text(f[k], known)
            n += c
    n += _mask_nested(f.get("location"), known)
    refs = f.get("references") or {}
    urls = refs.get("urls") or []
    for i, u in enumerate(urls):
        if isinstance(u, str):
            urls[i], c = mask_text(u, known)
            n += c
    return n
