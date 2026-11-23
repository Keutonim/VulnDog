"""VulnDog observing forward proxy — Mode A (docs/CONFIGURATION.md, ADR-2/3).

A stdlib-only local forward proxy that OBSERVES traffic and never modifies
it: absolute-form plain HTTP is forwarded verbatim (hop-by-hop headers
aside), CONNECT tunnels are relayed as opaque bytes (no TLS termination,
no decryption, no path/body visibility — host:port metadata only).

Every forwarded or scope/connection-denied request produces one redacted
event in the run's events.jsonl. Client-side protocol rejections
(malformed request line -> 400, header overflow -> 431, chunked body ->
501, oversized body -> 413) are answered before any target request is
made and emit no event (documented residual, gates-phase2.md):
- tap_class ``tool_http``, provenance ``vulndog.proxy``;
- ONE redaction door (fix-round-1 B1): every event passes the vendored
  F4 adapter (``engine.redaction_adapter.redact_event``) BEFORE it is
  persisted — the same enforcement point the engine's own tap uses
  (``engine/tap_sim.py`` Flusher). Query VALUES masked as ``<len-N>``
  (names kept), opaque path segments masked, URL fragment dropped,
  bodies pattern+entropy scrubbed; fail-closed: a redaction drop is
  counted (``redaction_dropped``), never written raw;
- URL userinfo stripped before the door (credentials never reach disk);
- ua_present / cookie_present are PRESENCE BOOLEANS only — no header value
  is ever persisted;
- body_redacted: text content types only, capture cap 200 000 chars,
  F4 persist cap 4 000 chars (post-redaction);
- ``corpus_version`` is matcher-owned and cannot be written here (no such
  parameter exists).

Scope enforcement (ADR-8): out-of-scope hosts get HTTP 403 at the proxy and
a ``denied`` event with ``denial_reason: proxy_oos``; no upstream socket is
opened. Out wins over in; an empty in-list allows all PUBLIC hosts.

SSRF rail (M1, fix-round-1; R2-A/B/C, fix-round-2): a safety floor UNDER
the scope decision — loopback, RFC1918, link-local (incl.
169.254.169.254 cloud metadata), CGNAT 100.64.0.0/10, IPv6 ULA/link-local
and internal names (localhost, *.internal) are default-DENIED with
``denial_reason: proxy_private`` (403, no upstream socket, both legs)
unless the explicit ``allow_private`` flag (--allow-private) is passed.
The scope check runs first (proxy_oos vocabulary preserved for
out-of-scope hosts). Numeric IP spellings (decimal/hex/octal inet_aton
forms) are normalized before classification, and NAMES are classified
at connect time against their RESOLVED address — the connection uses
the classified address (one resolution per request; the rebinding
TOCTOU on re-resolution is a recorded residual, not a closed hole).

The event tap is a pure observer: emission failures are reported to stderr
and never raise into the connection handler.

Resource bounds (M4, fix-round-1): a bounded drop-oldest queue (capacity
1000 — docs/RUNS-AND-LOGS.md) fronts the spool; overflow drops the OLDEST
unflushed events and reports the delta as a ``drop_counter`` meta line.
A connection cap (default 64) refuses excess connections with 503 before
any handler thread spawns; a per-run spool budget (default 100 000 lines)
freezes events.jsonl with a visible ``spool_cap`` marker. Every drop /
refusal class is counted and surfaced in watchdog-run.json counters.
"""
from __future__ import annotations

import hmac
import ipaddress
import select
import socket
import socketserver
import sys
import threading
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from vulndog.engine import redaction_adapter as _ra
from vulndog.runs import EventWriter
from vulndog.scope import compile_scope, host_matches, in_scope

PROVENANCE = "vulndog.proxy"
TAP_CLASS = "tool_http"

BODY_CAPTURE_CAP = 200_000   # chars read for capture
BODY_PERSIST_CAP = 4_000     # chars written to the spool
URL_CAP = 4096
CONTENT_TYPE_CAP = 2000

_HEADER_BYTES_CAP = 64 * 1024
_HEADER_COUNT_CAP = 100
_LINE_CAP = 8192
_BODY_FORWARD_CAP = 10 * 1024 * 1024
_CONNECT_TIMEOUT = 10.0
_IO_TIMEOUT = 60.0
_RELAY_CHUNK = 65536
_STOP_POLL_S = 0.25

#: M4 resource caps. QUEUE_CAP is the DOCUMENTED bounded-queue capacity
#: (docs/RUNS-AND-LOGS.md: "capacity 1000, drop-oldest"); the connection
#: cap and the spool event budget are new safety floors (reported as a
#: doc addition, not yet in the approved docs).
QUEUE_CAP = 1000
MAX_CONNECTIONS = 64
SPOOL_EVENT_CAP = 100_000
_FLUSH_WAIT_S = 5.0

# hop-by-hop / proxy-specific headers never forwarded to the origin
_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-connection", "proxy-authorization",
    "transfer-encoding", "te", "trailer", "upgrade",
})
#: client-header names stripped from the forwarded request (hop-by-hop
#: plus the rewritten Host and the inbound Content-Length — F-3: the
#: proxy emits exactly ONE outbound CL computed from the body it read;
#: forwarding the client's CL too produced duplicate framing (CL.CL))
_STRIP_HEADERS = _HOP_HEADERS | {"host", "content-length"}

#: client-side body rejections: status -> HTTP reason phrase
_BODY_ERROR_REASONS = {400: "Bad Request", 413: "Content Too Large",
                       501: "Not Implemented"}
#: denial answers the proxy itself sends
_DENY_REASONS = {403: "Forbidden", 407: "Proxy Authentication Required",
                 502: "Bad Gateway"}


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def strip_userinfo(url: str) -> str:
    """Drop user:pass@ from the netloc so credentials never reach disk.

    Handles scheme-less authorities too (CONNECT targets): urlsplit
    would misread 'user:pass@host:443' as scheme 'user' + path and
    leave the credentials untouched (H2/F9).
    """
    authority_only = "://" not in url and not url.startswith("//")
    parts = urlsplit("//" + url if authority_only else url)
    if "@" not in parts.netloc:
        return url
    hostpart = parts.netloc.rsplit("@", 1)[1]
    if authority_only:
        return hostpart
    return urlunsplit((parts.scheme, hostpart, parts.path, parts.query,
                       parts.fragment))


# M2.2: the scope match law (exact / *.suffix, out wins, empty in-list
# allows all) lives in vulndog.scope — ONE decision in one place. The
# pure functions host_matches / in_scope are re-exported above for the
# shipped surface; ProxyServer compiles once at construction and the
# handler matches via Scope.allows (no per-request recompile).


def _is_loopback(host: str) -> bool:
    h = host.lower()
    return h == "localhost" or h == "::1" or h.startswith("127.")


def _parse_ip_part(part: str) -> int | None:
    """One inet_aton-style numeric part: decimal, 0x-hex, or leading-0
    octal (R2-C). None for anything non-numeric."""
    if not part or not part.isascii():
        return None
    try:
        if part.lower().startswith("0x"):
            return int(part, 16)
        if part.startswith("0") and len(part) > 1:
            return int(part, 8)
        return int(part, 10)
    except ValueError:
        return None


def _parse_inet_aton(host: str) -> ipaddress.IPv4Address | None:
    """Normalize inet_aton numeric IPv4 spellings (R2-C): a single
    32-bit integer or 1-4 parts (decimal/hex/octal), the last part
    taking the remaining bits. glibc resolves these; the Windows
    resolver and ipaddress.ip_address do not — the rail must not
    depend on the host resolver to save it. None for non-literals."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        value = _parse_ip_part(part)
        if value is None:
            return None
        values.append(value)
    widths = [8] * (len(values) - 1) + [32 - 8 * (len(values) - 1)]
    addr = 0
    for value, width in zip(values, widths):
        if not 0 <= value < (1 << width):
            return None
        addr = (addr << width) | value
    return ipaddress.IPv4Address(addr)


def _is_private_address(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """The non-global floor over a PARSED address (R2-B): loopback,
    RFC1918, link-local (incl. cloud metadata), CGNAT 100.64.0.0/10
    (RFC 6598 — NOT is_private on Python 3.14, hence is_global), IPv6
    ULA/link-local, reserved and documentation space. IPv4-mapped IPv6
    (::ffff:a.b.c.d) delegates to the mapped IPv4 address."""
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    return not addr.is_global


def _is_private_target(host: str) -> bool:
    """M1 SSRF rail classifier — the literal/name FAST PATH: loopback,
    RFC1918, link-local (incl. the cloud-metadata address
    169.254.169.254), CGNAT 100.64.0.0/10, IPv6 ULA/link-local,
    reserved ranges, and the known internal NAMES (localhost,
    *.internal — covers metadata.google.internal). Numeric IPv4
    spellings (decimal/hex/octal inet_aton forms) are normalized before
    classification (R2-C) — a stricter default-deny is the safe
    direction.

    Other NAMES are classified at CONNECT time against their RESOLVED
    address (ProxyServer._guarded_connect, R2-A): a public name that
    resolves to a private address is denied there, and the connection
    uses the classified address. Residual (recorded, honest): a DNS
    record flipping BETWEEN resolutions (rebinding TOCTOU) is a known
    narrow race — one resolution per request, no re-resolution at
    connect, but stdlib offers no resolver-level pinning.
    """
    h = host.lower().rstrip(".")
    if h == "localhost" or h.endswith(".internal"):
        return True
    try:
        addr = ipaddress.ip_address(h)
    except ValueError:
        addr = _parse_inet_aton(h)
        if addr is None:
            return False
    return _is_private_address(addr)


def _resolved_addrs_private(infos: list) -> bool:
    """Default-deny over a getaddrinfo answer set (R2-A): ANY non-global
    resolved address denies the whole name — a public decoy record must
    not smuggle a private one through. An unclassifiable address is
    denied too (fail-closed)."""
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            return True
        if _is_private_address(addr):
            return True
    return False


def _connect_resolved(infos: list, timeout: float) -> socket.socket | None:
    """Connect to an address from the CLASSIFIED set (R2-A) — the
    checked address IS the connected address; the name is never
    resolved a second time. First reachable answer wins."""
    for family, socktype, proto, _canon, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            return sock
        except OSError:
            sock.close()
    return None


def _is_text_content(content_type: str | None) -> bool:
    if not content_type:
        return False
    mime = content_type.split(";", 1)[0].strip().lower()
    return mime.startswith("text/") or any(
        token in mime for token in ("json", "xml", "javascript", "html")
    )


def _capture_body(content_type: str | None, resp_body: bytes) -> str | None:
    """Text-like bodies only: capture cap -> decode. The F4 door applies
    the redaction + the 4 000-char PERSIST cap post-redaction (design 6
    ordering law); the capture side must not pre-truncate the secret
    material the door has to see. Binary/empty bodies -> None."""
    if not (_is_text_content(content_type) and resp_body):
        return None
    return resp_body[:BODY_CAPTURE_CAP].decode("utf-8", errors="replace")


def _redact_capture_event(event: dict) -> tuple[dict | None, bool]:
    """THE capture door (B1): the vendored F4 adapter, fail-closed.

    Precedent: engine/tap_sim.py Flusher.flush -> redact_event -> spool.
    CONNECT authorities are scheme-less; urlsplit would misread a
    hostname authority as scheme+path (the H2/F9 class), so they ride
    through the door in the ``//authority`` form and the transport
    prefix is removed afterwards — the redaction itself is untouched.
    Returns (redacted_event, False) or (None, True) — the caller DROPS
    and counts; the event is NEVER persisted raw.
    """
    url = event.get("url") if isinstance(event, dict) else None
    authority_only = (isinstance(url, str) and "://" not in url
                      and not url.startswith("//"))
    if authority_only:
        event = dict(event, url="//" + url)
    redacted, dropped = _ra.redact_event(event)
    if dropped or not isinstance(redacted, dict):
        return None, True
    if authority_only:
        redacted["url"] = redacted["url"].removeprefix("//")
    return redacted, False


def _parse_status_code(status_line: bytes) -> int:
    """The origin's status is EXTERNAL input: non-digit or out-of-range
    (F3 accepts 100..599) falls back to 502 — the same rule for both
    malformed classes (H2/F4). The raw response is forwarded verbatim."""
    pieces = status_line.decode("latin-1").split()
    status = int(pieces[1]) if len(pieces) >= 2 and pieces[1].isdigit() else 502
    if not (100 <= status <= 599):
        return 502
    return status


def _validate_cl_framing(raw_headers: list[tuple[str, str]]) -> tuple[int | None, int | None]:
    """F-3 framing validator (RFC 9112 6.3): EVERY Content-Length field
    value (duplicate headers and comma lists alike) must parse to the
    SAME non-negative integer. Returns (length, None) — length None
    when no CL is present — or (None, error_status): conflicting or
    malformed values are an unrecoverable framing error (400)."""
    pieces = [p.strip() for n, v in raw_headers
              if n.lower() == "content-length" for p in v.split(",")]
    if not pieces:
        return None, None
    lengths = []
    for piece in pieces:
        if not (piece.isascii() and piece.isdigit()):
            return None, 400
        lengths.append(int(piece))
    if len(set(lengths)) > 1:
        return None, 400               # CL.CL ambiguity: unrecoverable
    return lengths[0], None


def _rewrite_header_fields(head: bytes, drop: frozenset[bytes],
                           add: bytes) -> bytes:
    """ONE response header-block rewriter (m2/R2-F dryer): drop every
    named field, append ONE replacement field. Preserves the line-ending
    style and the status line; the blank-line terminator and anything
    after it ride through untouched."""
    sep = b"\r\n\r\n" if b"\r\n\r\n" in head else b"\n\n"
    nl = sep[:2]
    header_block, _, rest = head.partition(sep)
    kept = [line for line in header_block.split(nl)
            if line.split(b":", 1)[0].strip().lower() not in drop]
    kept.append(add)
    return nl.join(kept) + sep + rest


def _rewrite_header_cl(head: bytes, length: int) -> bytes:
    """Replace every Content-Length field in a response header block
    with ONE truthful field (m2)."""
    return _rewrite_header_fields(head, frozenset({b"content-length"}),
                                  f"Content-Length: {length}".encode("latin-1"))


def _sync_response_cl(head: bytes, resp_headers: dict[str, str],
                      body: bytes) -> bytes:
    """m2: the emitted Content-Length must match the emitted body.

    The forward cap can truncate the body and an origin can close early
    (or lie about its length); forwarding the origin's original CL
    verbatim desyncs the client (it waits for bytes that never come).
    When the declared length differs from the body actually read, the
    header block is rewritten with ONE truthful CL. No declared CL ->
    close-delimited, untouched."""
    declared = resp_headers.get("content-length")
    if declared is None:
        return head
    try:
        n = int(declared)
    except ValueError:
        n = -1
    if n == len(body):
        return head
    return _rewrite_header_cl(head, len(body))


def _is_chunked(resp_headers: dict[str, str]) -> bool:
    return "chunked" in resp_headers.get("transfer-encoding", "").lower()


def _consume_trailers(rfile) -> None:
    """After the terminating 0-chunk: optional trailer fields, then the
    final blank line (RFC 9112 7.1.2). Best-effort — EOF ends it."""
    while True:
        line = rfile.readline(_LINE_CAP)
        if not line or line in (b"\r\n", b"\n"):
            return


def _parse_chunk_size(line: bytes) -> int | None:
    """One chunk-size line: hex, optional chunk extensions. None for a
    malformed OR NEGATIVE size — a negative size reaching
    rfile.read(min(size, room)) would be read-all on 3.11 (cap bypass,
    memory exhaustion) or a handler crash on 3.14 (preflight catch)."""
    try:
        size = int(line.split(b";", 1)[0].strip(), 16)
    except ValueError:
        return None
    return size if size >= 0 else None


def _read_chunked_body(rfile, cap: int) -> bytes:
    """Decode a chunked response body frame-by-frame up to the forward
    cap (R2-F). Stops at the terminating 0-chunk — a keep-alive chunked
    origin must not hang the reader (read-to-close would). A malformed
    frame or early close ends the decode best-effort: the caller always
    re-frames the decoded bytes with ONE truthful Content-Length, so
    the persisted body and the emitted framing always agree."""
    out = bytearray()
    while True:
        line = rfile.readline(_LINE_CAP)
        if not line:
            break
        size = _parse_chunk_size(line)
        if size is None:
            break
        if size == 0:
            _consume_trailers(rfile)
            break
        room = cap - len(out)
        if room <= 0:
            break
        out.extend(rfile.read(min(size, room)))
        rfile.readline(_LINE_CAP)  # CRLF terminating the chunk data
    return bytes(out)


def _read_body(rfile, resp_headers: dict[str, str]) -> bytes:
    """Response body per Content-Length (capped); read-to-close when the
    origin sends no length; chunked bodies are DECODED (R2-F) — the
    decoded bytes are what gets persisted AND emitted."""
    if _is_chunked(resp_headers):
        return _read_chunked_body(rfile, _BODY_FORWARD_CAP)
    length = resp_headers.get("content-length")
    if length is None:
        return rfile.read(_BODY_FORWARD_CAP)
    try:
        n = int(length)
    except ValueError:
        n = 0
    return rfile.read(min(n, _BODY_FORWARD_CAP)) if n > 0 else b""


def _sync_response_framing(head: bytes, resp_headers: dict[str, str],
                           body: bytes) -> bytes:
    """m2 + R2-F: the emitted framing must match the emitted body.
    A chunked body arrives DECODED — drop Transfer-Encoding (and any
    stray CL) and emit ONE truthful CL; a CL body keeps the m2 sync law
    (rewrite when the declared length differs from the body read)."""
    if _is_chunked(resp_headers):
        return _rewrite_header_fields(
            head, frozenset({b"transfer-encoding", b"content-length"}),
            f"Content-Length: {len(body)}".encode("latin-1"))
    return _sync_response_cl(head, resp_headers, body)


def build_event(*, hunt_id: str, url: str, decision: str,
                method: str | None = None, status: int | None = None,
                denial_reason: str | None = None,
                ua_present: bool | None = None,
                cookie_present: bool | None = None,
                content_type: str | None = None,
                body_redacted: str | None = None,
                ts: str | None = None) -> dict:
    """Shape one pinned-contract tool_http event.

    There is deliberately NO corpus_version parameter (matcher-owned) and
    NO header-value parameter (presence booleans only) — illegal states
    cannot be written. Caps are enforced here as the capture boundary.
    """
    event: dict = {
        "ts": ts or utc_now_iso(),
        "hunt_id": hunt_id,
        "tap_class": TAP_CLASS,
        "url": url[:URL_CAP],
        "decision": decision,
        "provenance": PROVENANCE,
    }
    if method is not None:
        event["method"] = method.upper()[:16]
    if status is not None:
        event["status"] = status
    if denial_reason is not None:
        event["denial_reason"] = denial_reason
    if ua_present is not None:
        event["ua_present"] = bool(ua_present)
    if cookie_present is not None:
        event["cookie_present"] = bool(cookie_present)
    if content_type is not None:
        event["content_type"] = content_type[:CONTENT_TYPE_CAP]
    if body_redacted is not None:
        # CAPTURE-side cap only (event_schema FIELD_CAPS law): the F4
        # door applies the 4 000-char PERSIST cap POST-redaction. A
        # pre-redaction persist slice could cut a token mid-span and
        # persist the unredacted remainder (design 6 ordering law).
        event["body_redacted"] = body_redacted[:BODY_CAPTURE_CAP]
    return event


class _BoundedDropQueue:
    """Bounded drop-oldest event queue — the documented tap mechanics
    (RUNS-AND-LOGS.md: capacity 1000, drop-oldest, VISIBLE drop counter).

    Shape precedent: the vendored ``engine/tap_sim.py`` BoundedDropQueue
    (the upstream producer mechanics the VulnDog tap replaces, ADR-3).
    Product-owned copy: the tap must not depend on a benchmark module.
    publish never blocks and never raises; overflow drops the OLDEST
    event and increments drop_count (the flusher surfaces the delta as
    a drop_counter spool meta line — visible, never silent)."""

    def __init__(self, cap: int = QUEUE_CAP):
        self.cap = cap
        self._dq: deque = deque()
        self._lock = threading.Lock()
        self.published_count = 0
        self.drop_count = 0
        self.error_count = 0

    def publish(self, event) -> bool:
        try:
            with self._lock:
                if len(self._dq) >= self.cap:
                    self._dq.popleft()
                    self.drop_count += 1
                self._dq.append(event)
            self.published_count += 1
            return True
        except Exception:  # noqa: BLE001 — exception-safe by contract
            self.error_count += 1
            return False

    def drain(self) -> list:
        with self._lock:
            out = list(self._dq)
            self._dq.clear()
        return out


class ProxyServer:
    """Threaded observing forward proxy with a clean stop path.

    Bind happens in __init__ (the actual address is known immediately,
    including an ephemeral port for port=0). Non-loopback binds require
    allow_remote_bind=True — never by accident — AND a client credential
    (client_token / client_allow, M2): without one the server REFUSES TO
    START rather than becoming an unauthenticated LAN-wide open relay.
    """

    def __init__(self, host: str, port: int, *, writer: EventWriter,
                 hunt_id: str, scope: dict | None = None,
                 allow_remote_bind: bool = False,
                 allow_private: bool = False,
                 client_token: str | None = None,
                 client_allow: str | None = None,
                 queue_cap: int = QUEUE_CAP,
                 max_connections: int = MAX_CONNECTIONS,
                 spool_cap: int = SPOOL_EVENT_CAP,
                 stop_event: threading.Event | None = None,
                 stop_file: Path | None = None) -> None:
        if not _is_loopback(host):
            if not allow_remote_bind:
                raise ValueError(
                    f"non-loopback bind {host!r} requires the explicit "
                    "allow_remote_bind flag (--allow-remote-bind)"
                )
            if not client_token and not client_allow:
                # M2: never a silent LAN-wide unauthenticated open relay.
                raise ValueError(
                    "--allow-remote-bind requires a client credential: "
                    "pass --client-token <secret> (checked per request) "
                    "or --client-allow <cidr> — refusing to start an "
                    "unauthenticated network-wide relay"
                )
        self._client_token = client_token or None
        self._client_network = None
        if client_allow:
            # strict=False: host bits set is a user convenience, not an
            # error; a malformed CIDR is a usage error (ValueError).
            self._client_network = ipaddress.ip_network(client_allow,
                                                        strict=False)
        self.host = host
        self.hunt_id = hunt_id
        # M2.2: compile the owner scope ONCE at startup (pattern validation
        # fails fast here — ScopeError is a ValueError, the CLI usage-error
        # path). The compiled Scope is the pure match surface; the SSRF
        # rail below stays the safety floor under it.
        self.scope = compile_scope(scope)
        self.allow_private = allow_private
        self.writer = writer
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.stop_file = Path(stop_file) if stop_file is not None else None
        self.events_emitted = 0
        self.redaction_dropped = 0
        self.flush_dropped = 0
        self._emit_lock = threading.Lock()

        # M4: bounded queue + bounded spool + connection cap, all counted
        self.queue = _BoundedDropQueue(queue_cap)
        self.spool_cap = spool_cap
        self.spool_dropped = 0
        self._drops_reported = 0
        self._spool_frozen = False
        self._flush_cond = threading.Condition()
        self._flushing = False
        self.max_connections = max_connections
        self.connections_active = 0
        self.connections_refused = 0
        self._conn_lock = threading.Lock()

        outer = self

        class _Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = False  # a port conflict must fail loudly

            def handle_error(self, request, client_address):
                exc = sys.exc_info()[1]
                print(f"vulndog.proxy: handler error: {exc}", file=sys.stderr)

            def process_request(self, request, client_address):
                # M4 connection cap: refuse BEFORE spawning a handler
                # thread — a visible brake (503 + counter), never an
                # unbounded thread fan-out, never a crash.
                if not outer._acquire_connection():
                    with outer._emit_lock:
                        outer.connections_refused += 1
                    try:
                        request.sendall(
                            b"HTTP/1.1 503 Service Unavailable\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                    except OSError:
                        pass
                    self.shutdown_request(request)
                    return
                t = threading.Thread(target=self._proxy_request_thread,
                                     args=(request, client_address),
                                     daemon=True)
                t.start()

            def _proxy_request_thread(self, request, client_address):
                try:
                    self.finish_request(request, client_address)
                except Exception:
                    self.handle_error(request, client_address)
                finally:
                    self.shutdown_request(request)
                    outer._release_connection()

        self._server = _Server((host, port), _ProxyHandler)
        self._server.proxy = outer  # handler -> owning ProxyServer
        self._serve_thread: threading.Thread | None = None
        self._watch_thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self._server.server_address[:2]

    def _acquire_connection(self) -> bool:
        with self._conn_lock:
            if self.connections_active >= self.max_connections:
                return False
            self.connections_active += 1
            return True

    def _release_connection(self) -> None:
        with self._conn_lock:
            self.connections_active -= 1

    def _guarded_connect(self, host: str, port: int
                         ) -> tuple[socket.socket | None, str | None]:
        """R2-A: resolve ONCE, classify the RESOLVED addresses, connect
        to an address from that classified set — the checked address IS
        the connected address (no second resolution between check and
        connect). Returns (sock, None) on success; (None, "private")
        when the rail denies any resolved address; (None, "connect")
        on a resolution/connect failure. allow_private skips the rail
        but keeps the single-resolution pinning.

        Residual (honest, recorded): a DNS record flipping BETWEEN
        resolutions (rebinding TOCTOU) is a known narrow race — stdlib
        has no resolver-level pinning; the window is one resolution per
        request and the socket never re-resolves the name.
        """
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            return None, "connect"
        if not self.allow_private and _resolved_addrs_private(infos):
            return None, "private"
        sock = _connect_resolved(infos, _CONNECT_TIMEOUT)
        if sock is None:
            return None, "connect"
        return sock, None

    def emit(self, event: dict) -> None:
        """Pure-observer emission (M4): publish into the bounded queue
        (never blocks, never raises; overflow drops the OLDEST and is
        counted), then flush through the ONE redaction door (B1).

        One flusher at a time: the emitting thread that wins the flush
        role drains the queue synchronously — the event is on disk
        before the client sees the response (deterministic for
        consumers/tests). Threads that find a flush in progress wait
        their turn up to _FLUSH_WAIT_S and then proceed (the observer
        never blocks a handler forever; a dropped event's waiter is
        released when the queue drains)."""
        self.queue.publish(event)
        self._flush_pending(_FLUSH_WAIT_S)

    def _flush_pending(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while True:
            with self._flush_cond:
                if not self._flushing:
                    self._flushing = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return
                self._flush_cond.wait(remaining)
        try:
            self._flush_once()
        except Exception as exc:  # noqa: BLE001 — observer never raises
            print(f"vulndog.proxy: flush failed: {exc}", file=sys.stderr)
        finally:
            with self._flush_cond:
                self._flushing = False
                self._flush_cond.notify_all()

    def _flush_once(self) -> None:
        """The flusher (shape precedent: engine/tap_sim.py Flusher.flush):
        drop_counter meta line first, then drain -> F4 door -> spool.
        Fail-closed redaction drops and spool-cap drops are counted;
        the spool freezes at its budget (a visible spool_cap marker is
        the last line written). R2-E: an event lost to ANY write failure
        is counted (flush_dropped) and the flush CONTINUES — a hostile
        writer exception never abandons the rest of the drained batch."""
        q = self.queue
        if q.drop_count > self._drops_reported and not self._spool_frozen:
            delta = q.drop_count - self._drops_reported
            self._drops_reported = q.drop_count
            self._write_meta_line({"type": "drop_counter", "dropped": delta,
                                   "ts": utc_now_iso()})
        for event in q.drain():
            try:
                self._write_event(event)
            except Exception as exc:  # noqa: BLE001 — observer never raises
                with self._emit_lock:
                    self.flush_dropped += 1
                print(f"vulndog.proxy: event emission failed: {exc}",
                      file=sys.stderr)

    def _write_event(self, event: dict) -> None:
        """One event: F4 door -> spool budget -> writer. Redaction and
        spool-cap drops are counted in their own counters; a write
        failure propagates to the flusher's per-event catch (R2-E:
        counted as flush_dropped, never silent)."""
        redacted, dropped = _redact_capture_event(event)
        if dropped:
            with self._emit_lock:
                self.redaction_dropped += 1
            print("vulndog.proxy: event dropped fail-closed by redaction",
                  file=sys.stderr)
            return
        if self.writer.count >= self.spool_cap:
            with self._emit_lock:
                self.spool_dropped += 1
            if not self._spool_frozen:
                self._spool_frozen = True
                self._write_meta_line({"type": "spool_cap",
                                       "cap": self.spool_cap,
                                       "ts": utc_now_iso()})
            return
        self.writer.write(redacted)
        with self._emit_lock:
            self.events_emitted += 1

    def _write_meta_line(self, meta: dict) -> None:
        try:
            self.writer.write(meta)
        except (OSError, ValueError) as exc:
            print(f"vulndog.proxy: meta line write failed: {exc}",
                  file=sys.stderr)

    def client_auth_error(self, client_ip: str,
                          headers: dict[str, str]) -> tuple[int, str] | None:
        """M2 per-request client gate for non-loopback binds.

        None = allowed. A configured CIDR admits matching client IPs;
        a configured token admits ``Proxy-Authorization: Bearer <token>``
        (scheme case-insensitive, credential compared in constant time;
        the header is hop-by-hop and is NEVER forwarded to the origin).
        Either credential passing suffices.
        Failure: 407 proxy_auth when a token is configured (the
        actionable challenge), else 403 proxy_client_denied. Loopback
        binds require no credential (local single-user default)."""
        if self._client_network is None and self._client_token is None:
            return None
        if self._cidr_admits(client_ip) or self._token_admits(headers):
            return None
        if self._client_token is not None:
            return 407, "proxy_auth"
        return 403, "proxy_client_denied"

    def _cidr_admits(self, client_ip: str) -> bool:
        if self._client_network is None:
            return False
        try:
            return ipaddress.ip_address(client_ip) in self._client_network
        except ValueError:
            return False

    def _token_admits(self, headers: dict[str, str]) -> bool:
        """R2-D: the bearer case is handled EXACTLY ONCE — the scheme is
        split off and matched case-insensitively (RFC 7235 2.1), then
        the presented credential alone is compared to the configured
        token in constant time (hmac.compare_digest)."""
        if self._client_token is None:
            return False
        supplied = headers.get("proxy-authorization", "")
        scheme, _, credential = supplied.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(credential.strip().encode("utf-8"),
                                   self._client_token.encode("utf-8"))

    def start(self) -> None:
        if self._serve_thread is not None:
            return
        self._serve_thread = threading.Thread(
            target=self._server.serve_forever,
            kwargs={"poll_interval": _STOP_POLL_S},
            name="vulndog-proxy-serve", daemon=True)
        self._watch_thread = threading.Thread(
            target=self._watch_stop, name="vulndog-proxy-stop", daemon=True)
        self._serve_thread.start()
        self._watch_thread.start()

    def _watch_stop(self) -> None:
        while not self.stop_event.is_set():
            if self.stop_file is not None and self.stop_file.exists():
                self.stop_event.set()
                break
            time.sleep(_STOP_POLL_S)
        if self._serve_thread is not None and self._serve_thread.is_alive():
            self._server.shutdown()

    def wait(self, timeout: float | None = None) -> bool:
        """Block until the serve loop exits. True if it stopped."""
        if self._serve_thread is None:
            return True
        self._serve_thread.join(timeout)
        return not self._serve_thread.is_alive()

    def stop(self) -> None:
        self.stop_event.set()
        if self._serve_thread is not None and self._serve_thread.is_alive():
            self._server.shutdown()
        self._server.server_close()
        if self._serve_thread is not None:
            self._serve_thread.join(timeout=5)
        if self._watch_thread is not None:
            self._watch_thread.join(timeout=2)
        # final drain: events published just before stop still reach the
        # spool (and the last drop_counter delta is reported)
        self._flush_pending(_FLUSH_WAIT_S)


class _ProxyHandler(socketserver.BaseRequestHandler):
    """One client connection: one request (Connection: close semantics)."""

    def setup(self) -> None:
        self.request.settimeout(_IO_TIMEOUT)
        # UNBUFFERED: a buffered reader could read ahead into tunnel bytes
        self._rfile = self.request.makefile("rb", buffering=0)
        self.proxy: ProxyServer = self.server.proxy  # type: ignore[attr-defined]

    def finish(self) -> None:
        try:
            self._rfile.close()
        except OSError:
            pass

    # ------------------------------------------------------------- utils

    def _send_status(self, code: int, reason: str) -> None:
        try:
            self.request.sendall(
                f"HTTP/1.1 {code} {reason}\r\n"
                f"Content-Length: 0\r\nConnection: close\r\n\r\n".encode("latin-1")
            )
        except OSError:
            pass

    def _read_headers(self) -> tuple[dict[str, str], list[tuple[str, str]]] | None:
        """Return (lowercased dict, raw ordered list) or None on limit breach."""
        headers: dict[str, str] = {}
        raw: list[tuple[str, str]] = []
        total = 0
        while True:
            line = self._rfile.readline(_LINE_CAP)
            if not line or line in (b"\r\n", b"\n"):
                break
            total += len(line)
            if total > _HEADER_BYTES_CAP or len(raw) >= _HEADER_COUNT_CAP:
                return None
            text = line.decode("latin-1").rstrip("\r\n")
            name, sep, value = text.partition(":")
            if not sep:
                continue
            name = name.strip()
            value = value.strip()
            headers[name.lower()] = value
            raw.append((name, value))
        return headers, raw

    def _presence(self, headers: dict[str, str]) -> dict[str, bool]:
        return {"ua_present": "user-agent" in headers,
                "cookie_present": "cookie" in headers}

    def _deny(self, capture_url: str, method: str, status: int,
              reason: str, presence: dict[str, bool]) -> None:
        """One denied request: answer the client AND persist the denial
        event (single shape for every denial path — H3 dryer)."""
        self._send_status(status, _DENY_REASONS.get(status, "Error"))
        self.proxy.emit(build_event(
            hunt_id=self.proxy.hunt_id, url=capture_url, method=method,
            decision="denied", status=status, denial_reason=reason,
            **presence))

    def _read_request_body(self, headers: dict[str, str],
                           raw_headers: list[tuple[str, str]]):
        """(body, None) on success; (b"", error_status) on a client-side
        body rejection (chunked unsupported, bad length, over cap).

        F-3 framing law (RFC 9112 6.3): EVERY Content-Length field value
        (duplicate headers and comma lists alike) must parse to the SAME
        non-negative integer — conflicting values are an unrecoverable
        framing error -> 400 BEFORE any upstream socket. Identical
        duplicates collapse to one; the outbound request carries exactly
        ONE CL (the inbound fields are in _STRIP_HEADERS)."""
        if "transfer-encoding" in headers:
            return b"", 501
        length, framing_error = _validate_cl_framing(raw_headers)
        if framing_error is not None:
            return b"", framing_error
        if length is None:
            return b"", None
        if length > _BODY_FORWARD_CAP:
            return b"", 413
        return (self._rfile.read(length) if length else b""), None

    # ------------------------------------------------------------ handle

    def handle(self) -> None:
        line = self._rfile.readline(_LINE_CAP)
        if not line:
            return
        request_line = line.decode("latin-1").rstrip("\r\n")
        parts = request_line.split()
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            self._send_status(400, "Bad Request")
            return
        method, target, _version = parts
        parsed = self._read_headers()
        if parsed is None:
            self._send_status(431, "Request Header Fields Too Large")
            return
        headers, raw_headers = parsed

        # M2 client gate (non-loopback binds): checked per request on
        # BOTH legs before any dispatch; a denial emits the standard
        # denied event through the same F4 door.
        auth_error = self.proxy.client_auth_error(self.client_address[0],
                                                  headers)
        if auth_error is not None:
            auth_status, auth_reason = auth_error
            self._deny(strip_userinfo(target), method, auth_status,
                       auth_reason, self._presence(headers))
            return

        if method.upper() == "CONNECT":
            self._handle_connect(target, headers)
        elif target.lower().startswith("http://"):
            self._handle_http(method, target, headers, raw_headers)
        else:
            # forward proxy requires absolute-form; https must use CONNECT
            self._send_status(400, "Bad Request")

    # ----------------------------------------------------------- CONNECT

    def _handle_connect(self, authority: str, headers: dict[str, str]) -> None:
        try:
            parts = urlsplit("//" + authority)
            host = parts.hostname or ""
            port = parts.port or 443
        except ValueError:
            # F-13: hostile port / invalid IPv6 literal — a client-side
            # protocol rejection (400), never a dead handler / zero bytes.
            self._send_status(400, "Bad Request")
            return
        presence = self._presence(headers)
        # H2/F9: same capture law as the plain-HTTP leg — a hostile
        # client can put userinfo (or query junk) in the CONNECT
        # authority; credentials must never reach disk on ANY leg.
        # Query/path masking + fragment drop belong to the F4 door
        # (emit); the authority rides through it scheme-normalized.
        capture_url = strip_userinfo(authority)

        if not host or not self.proxy.scope.allows(host):
            self._deny(capture_url, "CONNECT", 403, "proxy_oos", presence)
            return
        if not self.proxy.allow_private and _is_private_target(host):
            # M1 SSRF rail: a safety floor UNDER the scope decision —
            # no upstream socket (and no tunnel) into private ranges.
            self._deny(capture_url, "CONNECT", 403, "proxy_private", presence)
            return

        # R2-A: the rail re-checks the RESOLVED address here (a public
        # name can resolve to a private IP — DNS rebinding) and the
        # tunnel connects to the classified address, never a re-resolve.
        upstream, conn_error = self.proxy._guarded_connect(host, port)
        if conn_error == "private":
            self._deny(capture_url, "CONNECT", 403, "proxy_private", presence)
            return
        if upstream is None:
            self._deny(capture_url, "CONNECT", 502, "connect_refused", presence)
            return

        upstream.settimeout(_IO_TIMEOUT)
        try:
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        except OSError:
            upstream.close()
            return

        # tunnel-level metadata only: authority, no path, no body, no status
        self.proxy.emit(build_event(
            hunt_id=self.proxy.hunt_id, url=capture_url, method="CONNECT",
            decision="allowed", **presence))

        self._relay_tunnel(upstream)

    def _relay_tunnel(self, upstream: socket.socket) -> None:
        """Opaque bidirectional byte pump; no inspection, no decryption."""
        stop = self.proxy.stop_event
        client = self.request

        def pump(src: socket.socket, dst: socket.socket) -> None:
            try:
                while not stop.is_set():
                    readable, _, _ = select.select([src], [], [], _STOP_POLL_S)
                    if not readable:
                        continue
                    data = src.recv(_RELAY_CHUNK)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass

        threads = [
            threading.Thread(target=pump, args=(client, upstream), daemon=True),
            threading.Thread(target=pump, args=(upstream, client), daemon=True),
        ]
        for t in threads:
            t.start()
        try:
            while any(t.is_alive() for t in threads) and not stop.is_set():
                for t in threads:
                    t.join(timeout=_STOP_POLL_S)
        finally:
            for sock in (client, upstream):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            upstream.close()
            for t in threads:
                t.join(timeout=2)

    # --------------------------------------------------------- plain HTTP

    def _handle_http(self, method: str, target: str, headers: dict[str, str],
                     raw_headers: list[tuple[str, str]]) -> None:
        try:
            parts = urlsplit(target)
            host = parts.hostname or ""
            port = parts.port or 80
        except ValueError:
            # F-13: hostile port / invalid IPv6 literal — answer 400
            # BEFORE any upstream socket; no event (client-side class).
            self._send_status(400, "Bad Request")
            return
        presence = self._presence(headers)
        # userinfo stripped here (pinned full-removal form); query
        # values, opaque path segments and the fragment are masked by
        # the F4 door at emit — ONE redaction door for the whole tap.
        capture_url = strip_userinfo(target)

        if not host or not self.proxy.scope.allows(host):
            self._deny(capture_url, method, 403, "proxy_oos", presence)
            return
        if not self.proxy.allow_private and _is_private_target(host):
            # M1 SSRF rail (see _handle_connect): denied BEFORE any
            # upstream socket; --allow-private is the explicit opt-in.
            self._deny(capture_url, method, 403, "proxy_private", presence)
            return

        # request body (fully read before forwarding; chunked not supported)
        body, body_error = self._read_request_body(headers, raw_headers)
        if body_error is not None:
            self._send_status(body_error, _BODY_ERROR_REASONS[body_error])
            return

        # R2-A: resolve-and-classify at connect time (see _handle_connect);
        # the upstream socket uses the classified address only.
        upstream, conn_error = self.proxy._guarded_connect(host, port)
        if conn_error == "private":
            self._deny(capture_url, method, 403, "proxy_private", presence)
            return
        if upstream is None:
            self._deny(capture_url, method, 502, "connect_refused", presence)
            return

        try:
            upstream.settimeout(_IO_TIMEOUT)
            self._forward_http(upstream, method, parts, host, port,
                               raw_headers, body)
            status, resp_headers, resp_body = self._read_response(upstream)
        except OSError:
            # H2/F7: the connection SUCCEEDED; the failure is upstream
            # I/O (forward/response). "connect_refused" here was a false
            # failure class in the persisted record.
            self._deny(capture_url, method, 502, "upstream_io", presence)
            return
        finally:
            upstream.close()

        content_type = resp_headers.get("content-type")
        body_redacted = _capture_body(content_type, resp_body)

        # emit BEFORE answering the client: the event is on disk once the
        # client sees the response (deterministic for consumers/tests)
        self.proxy.emit(build_event(
            hunt_id=self.proxy.hunt_id, url=capture_url, method=method,
            decision="allowed", status=status, content_type=content_type,
            body_redacted=body_redacted, **presence))

        try:
            self.request.sendall(self._raw_response)
        except OSError:
            pass

    def _forward_http(self, upstream: socket.socket, method: str, parts,
                      host: str, port: int,
                      raw_headers: list[tuple[str, str]], body: bytes) -> None:
        origin_form = parts.path or "/"
        if parts.query:
            origin_form += "?" + parts.query
        lines = [f"{method.upper()} {origin_form} HTTP/1.1"]
        host_value = host if port == 80 else f"{host}:{port}"
        lines.append(f"Host: {host_value}")
        for name, value in raw_headers:
            if name.lower() in _STRIP_HEADERS:
                continue
            lines.append(f"{name}: {value}")
        lines.append("Connection: close")
        if body or "content-length" in {n.lower() for n, _ in raw_headers}:
            lines.append(f"Content-Length: {len(body)}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        upstream.sendall(head + body)

    def _read_response(self, upstream: socket.socket) -> tuple[int, dict[str, str], bytes]:
        rfile = upstream.makefile("rb")
        status_line = rfile.readline(_LINE_CAP)
        if not status_line:
            raise OSError("empty upstream response")
        raw = [status_line]
        resp_headers: dict[str, str] = {}
        total = 0
        while True:
            line = rfile.readline(_LINE_CAP)
            if not line:
                break
            raw.append(line)
            if line in (b"\r\n", b"\n"):
                break
            total += len(line)
            if total > _HEADER_BYTES_CAP:
                raise OSError("upstream headers too large")
            name, sep, value = line.decode("latin-1").rstrip("\r\n").partition(":")
            if sep:
                resp_headers[name.strip().lower()] = value.strip()
        head = b"".join(raw)
        body = _read_body(rfile, resp_headers)
        head = _sync_response_framing(head, resp_headers, body)
        self._raw_response = head + body
        return _parse_status_code(status_line), resp_headers, body