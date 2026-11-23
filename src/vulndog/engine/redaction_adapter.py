"""F4 -- redaction adapter: the SINGLE enforcement point (design section 6).

Law (C2/C6): the upstream redaction module is USED AS-IS via
a read-only import -- never bypassed, never reimplemented, and NEVER
modified. On top of the pattern pass the adapter applies the stdlib
Shannon-entropy scrubber for opaque non-pattern tokens (Security
C-1/SEC-01): random reset tokens, opaque query values, key classes that
pass every denylist pattern.

P1 formalization (brief MaxQwenAgent-002 item 3) adds, on top of the P0
benchmark adapter (API-compatible):
- ``mask_url`` / ``redact_url``: query VALUES -> length-only mask
  (``sid=<len-24>``, design 5.0), param NAMES survive; opaque path
  segments -> length-only mask; URL userinfo credentials masked;
  fragment dropped; host+port preserved (SEC-08: host stays event
  metadata; it is excluded from the EMBED TEXT by the matcher, not here);
- the header law (C-1/SEC-12): ``find_forbidden_fields`` flags any
  header-value-carrying key; ``redact_event`` DROPS such events
  fail-closed, and also drops events carrying non-scalar values
  (dict/list/bytes smuggling guard) -- no header values beyond
  ``content_type`` can ever enter a persisted event;
- ``redact_body``: SEC-06 pre-truncate (8 KB, owner-approved default ON)
  -> upstream ``sanitize_snapshot`` (storage-line drop + pattern redact)
  -> upstream ``scrub`` (partial-JWT kill, persist channel) -> entropy
  scrub -> 4,000-char persist cap.

Ordering law: pre-truncate -> upstream passes -> entropy scrub -> cap.
Fail-closed: ANY redaction exception DROPS the event (counted by the
caller), it is NEVER passed through raw.

P2 hardening (security-code-review 2026-10-15, COND-1..3; SCC-01..04):
- COND-1(a): path segments mixing letters AND digits at
  ``SEGMENT_OPACITY_FLOOR`` (8) chars or more are length-masked
  REGARDLESS of entropy; exact vuln-id pins (CVE/CWE/edb/owasp) are
  exempt (calibrated against the must-survive control set: v2/sha256/
  mp4, ordinary words, short pct-encodings, numeric ids);
- COND-1(b): flag-position query params (no '=') and param NAMES mixing
  letters+digits at the same floor are length-masked (alpha-only names
  like ``debug`` and short mixed names like ``utf8`` survive);
- COND-1(c): hex-alphabet rule -- runs consisting solely of
  ``[0-9a-fA-F]`` at len >= 16 are opaque REGARDLESS of Shannon entropy
  (the 16-symbol alphabet's measured entropy ~3.6-3.7 sits just under
  the 3.7 threshold: md5/sha1/sha256-shaped tokens used to slip);
- COND-1(d): the entropy test is separator-tolerant -- candidate spans
  may carry internal ``-``/``/``/``.``; the length+entropy+hex test runs
  on the CONCATENATED (separator-stripped) form and replaces the WHOLE
  original span (CVE-2024-50001 concatenated = 12 chars, under the 16
  floor -> survives; UUID/hyphen-split/base64-slash tokens die);
- COND-2: the structural ``url``/``body_redacted`` branches of
  ``redact_event`` match keys case-insensitively (parity with the
  case-insensitive forbidden-key law);
- COND-3: EVERY string field is length-capped (per-field caps mirrored
  from ``event_schema.FIELD_CAPS``; generous pre-slice bounds redaction
  CPU -- the SEC-06 window -- then a hard post-redaction cap).
"""
from __future__ import annotations

import math
import re
from urllib.parse import urlsplit

# Vendored copy of the upstream redaction module (C2: used as-is; ADR-1d).
# Upstream: the upstream runtime redaction module, copied byte-for-byte
# into _redaction_core.py so the engine imports with no upstream package.
from ._redaction_core import sanitize_snapshot as _upstream_sanitize
from ._redaction_core import scrub as _upstream_scrub

# COND-3: single source of truth for per-field caps (schema side mirrors).
from .event_schema import DEFAULT_FIELD_CAP, FIELD_CAPS

# COND-3: pre-slice multiplier -- redaction runs on at most cap*4 chars
# (bounds the regex/entropy CPU in the flusher thread: the SEC-06 window),
# then the redacted output is hard-sliced to the cap.
_PRE_SLICE_FACTOR = 4

PRE_TRUNCATE_BYTES = 8192       # SEC-06 pre-truncate default (owner 2026-10-15: ON)
PERSIST_CAP_CHARS = 4000        # event persistence cap, post-redaction (design 6)

ENTROPY_THRESHOLD = 3.7         # bits/char
ENTROPY_MIN_LEN = 16            # run length floor (3-class runs)
ENTROPY_MIN_LEN_TWO_CLASS = 24  # lower+digit / upper+digit runs need more length

# COND-1(a)/(b): calibrated opacity floor for URL path segments and query
# param names/flags. 8 keeps every must-survive control intact (v2, sha256,
# mp4, utf8, debug, page2, a%20b, numeric ids, dates) while closing the
# probe-01 leak set (11-15 char reset tokens, UUID segments, pct-smuggling).
SEGMENT_OPACITY_FLOOR = 8

# COND-1(a) exemption: exact vuln-id pins must survive (charset goal;
# design 5.3.5 exact-id pin signal). Matched against the WHOLE segment.
_VULN_PIN_RE = re.compile(
    r"(?:CVE-\d{4}-\d{4,}|CWE-\d+|EDB-\d+|OWASP-[A-Za-z0-9.]+-[A-Za-z0-9._-]+)\Z",
    re.IGNORECASE)

# COND-1(d) pin law: a concatenated span that CONTAINS an exact vuln-id pin
# never gets the wholesale replacement -- it falls back to per-run scrubbing
# (pins survive, opaque runs inside the same span still die). Without this,
# URL-shaped body text ("https://t.local/advisory/CVE-2024-50001") would
# concatenate across '/'+'-' into one 3-class span and eat the pin.
_VULN_PIN_ANY_RE = re.compile(r"CVE-\d{4}-\d{4,}|CWE-\d+|EDB-\d+",
                              re.IGNORECASE)

# COND-1(c): hex-alphabet rule (md5/sha1/sha256/git-sha shaped tokens).
_HEX_ONLY_RE = re.compile(r"[0-9a-fA-F]{%d,}\Z" % ENTROPY_MIN_LEN)

# base62/base64url-ish runs WITHOUT '-' and '/': excluding them keeps
# hyphenated vuln ids (CVE-2024-50001, CWE-79) and path words intact while
# still catching every opaque-token vector class.
_RUN_RE = re.compile(r"[A-Za-z0-9+=_]{%d,}" % ENTROPY_MIN_LEN)

_HAS_LOWER = re.compile(r"[a-z]")
_HAS_UPPER = re.compile(r"[A-Z]")
_HAS_DIGIT = re.compile(r"[0-9]")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# COND-1(d): separator-tolerant candidate spans. Manual single-pass scanner
# (NOT a regex): a span is a maximal run of charset chars that may carry
# INTERNAL '-'/''/'.' separators and always starts/ends on a charset char.
# Linear by construction -- no catastrophic backtracking on hostile bodies
# (the redaction pass runs in the flusher thread, GIL-shared: SEC-06).
_RUN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+=_")
_SEP_CHARS = frozenset("./-")
_STRIP_SEPS_RE = re.compile(r"[-/.]")

# Header law (C-1/SEC-12): presence booleans only -- these event keys would
# carry header/credential VALUES, so an event containing any of them (or any
# key containing "header") is DROPPED fail-closed. Schema fields
# (ua_present/cookie_present/content_type/...) are NOT in this set.
FORBIDDEN_EVENT_KEYS = frozenset({
    "header", "headers", "request_headers", "response_headers",
    "req_headers", "resp_headers",
    "cookie", "cookies", "set_cookie", "set-cookie",
    "authorization", "auth", "www_authenticate", "www-authenticate",
    "proxy_authorization", "proxy-authorization",
    "x_api_key", "x-api-key", "api_key", "apikey", "api-key",
    "user_agent", "user-agent", "ua", "ua_value",
    "referer", "referrer", "origin",
    "x_forwarded_for", "x-forwarded-for",
    "csrf_token", "xsrf_token", "x_csrf_token",
    "session_id", "sessionid", "phpsessid", "jsessionid", "sid",
    "password", "pass", "pwd", "secret", "client_secret",
    "token", "access_token", "refresh_token", "id_token",
    "key", "private_key",
})

# Fail-closed smuggling guard: an F3 event is flat scalars only (F3 schema);
# a container value could hide header values or secrets from the string pass.
_NON_SCALAR = (dict, list, tuple, set, frozenset, bytes, bytearray)


def shannon_entropy(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_opaque(run: str) -> bool:
    # COND-1(c): pure-hex runs >= 16 are opaque REGARDLESS of entropy --
    # the 16-symbol alphabet's measured Shannon entropy (~3.66 at 32 chars,
    # Miller-Madow corrected) sits systematically under the 3.7 threshold,
    # so md5/sha1-shaped hashes used to slip (SCC-04 quantification).
    if _HEX_ONLY_RE.match(run):
        return True
    if not _HAS_DIGIT.search(run) or not _HAS_LETTER.search(run):
        return False  # need digits AND letters (words survive)
    three_class = bool(_HAS_LOWER.search(run) and _HAS_UPPER.search(run))
    if three_class:
        return len(run) >= ENTROPY_MIN_LEN and shannon_entropy(run) >= ENTROPY_THRESHOLD
    return (len(run) >= ENTROPY_MIN_LEN_TWO_CLASS
            and shannon_entropy(run) >= ENTROPY_THRESHOLD)


def _iter_spans(text: str, seps: frozenset):
    """Yield (start, end) of maximal separator-tolerant candidate spans
    (COND-1(d)). Linear single pass; spans start/end on charset chars and
    may carry internal separators from ``seps``."""
    n = len(text)
    i = 0
    while i < n:
        if text[i] not in _RUN_CHARS:
            i += 1
            continue
        j = i + 1
        last = j                      # exclusive end at the last charset char
        while j < n:
            c = text[j]
            if c in _RUN_CHARS:
                j += 1
                last = j
            elif c in seps and j + 1 < n and (
                    text[j + 1] in _RUN_CHARS or text[j + 1] in seps):
                j += 1                # internal separator: keep scanning
            else:
                break                 # trailing separator or foreign char
        yield i, last
        i = max(last, j)


def _scrub_run(m):
    run = m.group(0)
    return "<redacted>" if _is_opaque(run) else run


def _scrub_spans(text: str, seps: frozenset) -> str:
    """COND-1(d) core: the opacity test runs on the concatenated
    (separator-stripped) form of each span; an opaque span is replaced
    WHOLE -- unless it contains an exact vuln-id pin (pin law: per-run
    fallback keeps CVE/CWE/edb ids and still scrubs token runs)."""
    if not text:
        return text
    out = []
    pos = 0
    for start, end in _iter_spans(text, seps):
        span = text[start:end]
        core = (_STRIP_SEPS_RE.sub("", span)
                if any(c in seps for c in span) else span)
        if len(core) < ENTROPY_MIN_LEN or not _is_opaque(core):
            continue
        if _VULN_PIN_ANY_RE.search(span):
            replacement = _RUN_RE.sub(_scrub_run, span)
            if replacement == span:
                continue
        else:
            replacement = "<redacted>"
        out.append(text[pos:start])
        out.append(replacement)
        pos = end
    if not out:
        return text
    out.append(text[pos:])
    return "".join(out)


# Body/string channel: full COND-1(d) merging ('-' '/' '.').
_BODY_SEPS = frozenset("-/.")
# URL channel: '/' is STRUCTURAL in URLs (host/path boundaries) -- never
# merged, so host+path structure and pins survive; '-'/'.' merging still
# kills hyphen/dot-split tokens (hostnames, surviving segments).
_URL_SEPS = frozenset("-.")


def entropy_scrub(text: str) -> str:
    """Replace high-entropy opaque runs with <redacted> (pure stdlib).

    COND-1(d): separator-tolerant -- candidate spans may carry internal
    ``-``/``/``/``.``; the length+entropy+hex test runs on the
    CONCATENATED form and replaces the whole span. Vuln-id pins survive
    by calibration (CVE-2024-50001 concatenated = 12 chars, under the 16
    floor) and by the pin-law fallback for pin-bearing spans.
    """
    return _scrub_spans(text, _BODY_SEPS)


def url_entropy_scrub(text: str) -> str:
    """Entropy pass for the URL channel (after mask_url): same span rules
    WITHOUT '/' merging -- URL path structure and embedded pins survive;
    split tokens in hostnames/segments still die."""
    return _scrub_spans(text, _URL_SEPS)


def redact_text(text: str) -> str:
    """Full adapter pass for plain strings: upstream scrub (patterns +
    partial-JWT kill) -> entropy scrub."""
    return entropy_scrub(_upstream_scrub(text))


# --------------------------------------------------------------------- URLs

def _segment_is_short_opaque(seg: str) -> bool:
    """COND-1(a): a segment mixing letters AND digits at the opacity floor
    or above is treated as an opaque token REGARDLESS of entropy (short
    reset tokens, UUIDs, pct-smuggling hybrids). Exempt: exact vuln-id
    pins (CVE/CWE/edb/owasp) and pure-word or pure-number segments --
    the calibrated must-survive control set."""
    if len(seg) < SEGMENT_OPACITY_FLOOR:
        return False
    if _VULN_PIN_RE.match(seg):
        return False                    # exact-id pin signal survives
    if not _HAS_DIGIT.search(seg):
        return False                    # ordinary words survive
    if not _HAS_LETTER.search(seg):
        return False                    # numeric ids/dates: hex rule decides
    return True


def _mask_path(path: str) -> str:
    if not path:
        return path
    masked = []
    for seg in path.split("/"):
        if not seg:
            masked.append(seg)
            continue
        # percent-encoded payloads defeat the entropy run-charset: a long
        # %XX-bearing segment is treated as opaque wholesale (fail-closed).
        if len(seg) >= ENTROPY_MIN_LEN and _PCT_RE.search(seg):
            masked.append(f"<len-{len(seg)}>")
        elif _segment_is_short_opaque(seg):
            masked.append(f"<len-{len(seg)}>")      # COND-1(a)
        elif _is_opaque(seg):
            masked.append(f"<len-{len(seg)}>")
        else:
            masked.append(entropy_scrub(seg))
    return "/".join(masked)


def _mask_param_name(name: str) -> str:
    """COND-1(b): a param NAME (or flag-position token) mixing letters and
    digits at the opacity floor or above may BE the secret (reset links of
    the ``?<token>`` / ``?<token>=1`` shape) -- length-mask it. Alpha-only
    names (``debug``, ``sid``) and short mixed names (``utf8``, ``page2``)
    survive: they are the matching signal."""
    if _segment_is_short_opaque(name):
        return f"<len-{len(name)}>"
    return name


def _mask_query(query: str) -> str:
    if not query:
        return query
    out = []
    # manual split (not parse_qsl): preserves order, duplicates, raw names,
    # and distinguishes "flag" (no '=') from "empty=" (blank value).
    for part in query.split("&"):
        if not part:
            continue
        name, sep, value = part.partition("=")
        masked_name = _mask_param_name(name)          # COND-1(b)
        if sep:
            out.append(f"{masked_name}=<len-{len(value)}>")  # length-only mask
        else:
            out.append(masked_name)                   # flag param
    return "&".join(out)


def mask_url(url: str) -> str:
    """Structural URL mask (design 5.0 `url` rule / Security C-1).

    - query VALUES -> ``<len-N>`` (param NAMES survive -- they are the
      matching signal);
    - opaque path segments -> ``<len-N>``; embedded opaque runs ->
      entropy ``<redacted>``; ordinary words and vuln-id pins survive;
    - userinfo credentials in the authority -> ``<redacted>@host``;
    - fragment dropped entirely (never sent to the server, may carry
      tokens);
    - scheme/host/port preserved (SEC-08: host is event METADATA; the
      matcher excludes it from the embed text, not this layer).
    """
    parts = urlsplit(url)
    netloc = parts.netloc
    if "@" in netloc:
        netloc = "<redacted>@" + netloc.rsplit("@", 1)[1]
    out = ""
    if parts.scheme:
        out += parts.scheme + "://"
    elif netloc:
        out += "//"
    out += netloc + _mask_path(parts.path)
    masked_query = _mask_query(parts.query)
    if masked_query:
        out += "?" + masked_query
    # parts.fragment is intentionally dropped
    return out


def _redact_masked_url(masked: str) -> str:
    """String pass for an already-masked URL: upstream patterns + the
    URL-channel entropy scrub (no '/' merging -- structure/pins survive)."""
    return url_entropy_scrub(_upstream_scrub(masked))


def redact_url(url: str) -> str:
    """URL pass: structural mask first, then the string pass (layered:
    patterns + entropy catch anything the mask left, e.g. in the host)."""
    return _redact_masked_url(mask_url(url))


# ------------------------------------------------------------------- events

def find_forbidden_fields(event: dict) -> list:
    """Header-law predicate: keys that would carry header/credential
    values (exact denylist, case-insensitive, plus any key containing
    ``header``). Presence booleans (ua_present/cookie_present) and
    content_type are NOT forbidden -- they are the schema's only
    header-derived fields (SEC-12 parity)."""
    found = []
    for key in event:
        k = str(key).lower()
        if k in FORBIDDEN_EVENT_KEYS or "header" in k:
            found.append(key)
    return found


def redact_body(text: str, pre_truncate_bytes: int = PRE_TRUNCATE_BYTES,
                persist_cap: int = PERSIST_CAP_CHARS) -> str:
    """Body law (design 6): SEC-06 pre-truncate -> upstream
    sanitize_snapshot (storage-line drop + pattern redact + size cap) ->
    upstream scrub (partial-JWT kill) -> entropy scrub -> persist cap."""
    body = text[:pre_truncate_bytes]
    body = _upstream_sanitize(body)
    body = _upstream_scrub(body)
    return entropy_scrub(body)[:persist_cap]


def redact_event(event: dict, redactor=None,
                 pre_truncate_bytes: int = PRE_TRUNCATE_BYTES,
                 persist_cap: int = PERSIST_CAP_CHARS):
    """Redact EVERY text field of an F3 event (single enforcement point).

    Returns (redacted_event, False) or (None, True) -- fail-closed DROP --
    when: the event is not a dict, it carries a forbidden header-value
    key, it carries a non-scalar value (smuggling guard), or ANY
    redaction step raises. The caller must DROP and count; the event is
    NEVER passed through raw.

    ``redactor`` (test/bench injection) replaces the string pass; the URL
    structural mask and the caps always apply.

    COND-2: the ``url``/``body_redacted`` structural branches match keys
    case-insensitively (parity with the forbidden-key law); the original
    key spelling is preserved in the output. COND-3: EVERY string field is
    capped (``event_schema.FIELD_CAPS``; generous pre-slice bounds the
    redaction CPU -- SEC-06 flusher window -- then a hard post-redaction
    cap). body_redacted keeps the SEC-06 pre-truncate -> persist-cap flow.
    """
    try:
        if not isinstance(event, dict):
            return None, True
        if find_forbidden_fields(event):
            return None, True                      # header law: fail-closed
        out = {}
        for key, value in event.items():
            if isinstance(value, _NON_SCALAR):
                return None, True                  # smuggling guard
            if not isinstance(value, str):
                out[key] = value
                continue
            # COND-2: case-insensitive structural-key handling.
            k = key.lower() if isinstance(key, str) else key
            if k == "url":
                cap = FIELD_CAPS.get("url", DEFAULT_FIELD_CAP)
                masked = mask_url(value[:cap * _PRE_SLICE_FACTOR])
                redacted = (redactor(masked) if redactor
                            else _redact_masked_url(masked))
                out[key] = redacted[:cap]
            elif k == "body_redacted":
                if redactor is not None:
                    out[key] = redactor(value[:pre_truncate_bytes])[:persist_cap]
                else:
                    out[key] = redact_body(value, pre_truncate_bytes,
                                           persist_cap)
            else:
                cap = (FIELD_CAPS.get(k, DEFAULT_FIELD_CAP)
                       if isinstance(k, str) else DEFAULT_FIELD_CAP)
                sliced = value[:cap * _PRE_SLICE_FACTOR]   # COND-3 CPU bound
                redacted = redactor(sliced) if redactor else redact_text(sliced)
                out[key] = redacted[:cap]
        return out, False
    except Exception:
        return None, True
