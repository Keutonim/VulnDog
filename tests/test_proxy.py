"""Proxy behaviour: plain HTTP forward, CONNECT tunnel, scope denials,
redaction contract, graceful shutdown — all against local stdlib servers.

CONNECT/TLS note: the tunnel test uses a plain-TCP echo server, not a real
TLS handshake. Reason (recorded per brief): the proxy is Mode A — it relays
tunnel bytes OPAQUELY and never decrypts, so a byte-echo proves exactly the
guarantee under test (relay + metadata-only event, no path/body capture).
A real TLS handshake would add certificate machinery without exercising any
additional proxy code path.
"""
from __future__ import annotations

import http.client
import json
import socket
import socketserver
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vulndog import proxy, runs
from vulndog.engine import event_schema as es
from event_contract import assert_pinned_event


# ---------------------------------------------------------------- helpers


class _OriginHandler(BaseHTTPRequestHandler):
    """Local plain-HTTP origin; records every request it actually receives."""

    def _respond(self):
        body = b""
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            body = self.rfile.read(length)
        self.server.hits.append(
            {"method": self.command, "path": self.path,
             "headers": dict(self.headers), "body": body,
             # dict(self.headers) COLLAPSES duplicates — keep the raw
             # list so framing tests can count Content-Length fields
             "cl_values": self.headers.get_all("Content-Length") or []}
        )
        payload = self.server.payload
        self.send_response(self.server.status_code)
        self.send_header("Content-Type", self.server.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = _respond
    do_POST = _respond

    def log_message(self, *args):
        pass


@contextmanager
def origin_up(payload: bytes = b"hello", content_type: str = "text/plain",
              status_code: int = 200):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _OriginHandler)
    srv.hits = []
    srv.payload = payload
    srv.content_type = content_type
    srv.status_code = status_code
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.connections.append(self.client_address)
        self.request.settimeout(10)
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    break
                self.request.sendall(data)
        except OSError:
            pass


@contextmanager
def echo_up():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _EchoHandler)
    srv.daemon_threads = True
    srv.connections = []
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


@contextmanager
def proxy_up(tmp_path: Path, *, scope=None, host="127.0.0.1",
             allow_remote_bind=False, stop_file=None, allow_private=True,
             client_token=None, client_allow=None,
             max_connections=None, spool_cap=None, queue_cap=None):
    # allow_private defaults TRUE in the helper: the forwarding tests
    # legitimately target loopback origins and opt in explicitly (the
    # M1 rail's default-deny is proven by the dedicated rail tests,
    # which pass allow_private=False or construct ProxyServer directly).
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    extra = {}
    if max_connections is not None:
        extra["max_connections"] = max_connections
    if spool_cap is not None:
        extra["spool_cap"] = spool_cap
    if queue_cap is not None:
        extra["queue_cap"] = queue_cap
    server = proxy.ProxyServer(
        host, 0, writer=writer, hunt_id=run.hunt_id, scope=scope,
        allow_remote_bind=allow_remote_bind, stop_file=stop_file,
        allow_private=allow_private,
        client_token=client_token, client_allow=client_allow, **extra,
    )
    server.start()
    try:
        yield run, server
    finally:
        server.stop()
        writer.close()


def http_via_proxy(proxy_port: int, url: str, *, headers=None, method="GET",
                   body=None):
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=15)
    try:
        conn.request(method, url, body=body, headers=headers or {})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def read_events(run) -> list[dict]:
    if not run.events_path.exists():
        return []
    return [json.loads(l) for l in
            run.events_path.read_text(encoding="utf-8").splitlines()]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ------------------------------------------------- pure redaction / scope


# Query-value masking moved to the ONE redaction door (fix-round-1 B1):
# the vendored F4 adapter (redaction_adapter.mask_url/_mask_query) owns
# it now — covered by engine/tests/test_redaction_adapter_f4.py and the
# end-to-end door tests (tests/test_redaction_door.py). The local
# mask_query_values helper was removed: two query-masking doors were
# exactly the premise class this round removes.


def test_strip_userinfo_removes_credentials():
    assert proxy.strip_userinfo("http://user:pass@h:8080/p") == "http://h:8080/p"
    assert proxy.strip_userinfo("http://h/p") == "http://h/p"


def test_strip_userinfo_schemeless_authority():
    # H2/F9 root cause: urlsplit reads 'user:pass@h:443' as scheme+path
    assert proxy.strip_userinfo("user:pass@h:443") == "h:443"
    assert proxy.strip_userinfo("h:443") == "h:443"




@pytest.mark.parametrize("host,patterns,expected", [
    ("example.com", ["example.com"], True),
    ("EXAMPLE.COM", ["example.com"], True),
    ("sub.example.com", ["*.example.com"], True),
    ("example.com", ["*.example.com"], True),
    ("evil-example.com", ["*.example.com"], False),
    ("example.com", ["other.com"], False),
    ("example.com", [], False),
])
def test_host_matches(host, patterns, expected):
    assert proxy.host_matches(host, patterns) is expected


def test_in_scope_out_wins_over_in():
    scope = {"in": ["example.com"], "out": ["example.com"]}
    assert proxy.in_scope("example.com", scope) is False


def test_in_scope_empty_in_allows_all():
    assert proxy.in_scope("anything.tld", {"in": [], "out": []}) is True
    assert proxy.in_scope("anything.tld", None) is True


def test_in_scope_in_list_restricts():
    scope = {"in": ["*.example.com"], "out": []}
    assert proxy.in_scope("a.example.com", scope) is True
    assert proxy.in_scope("other.tld", scope) is False


def test_proxy_scope_surface_delegates_to_scope_module():
    # M2.2: one decision in one place — the match law lives in
    # vulndog.scope; the proxy re-exports the same functions.
    from vulndog import scope as scope_mod
    assert proxy.in_scope is scope_mod.in_scope
    assert proxy.host_matches is scope_mod.host_matches


def test_proxy_server_rejects_invalid_scope_at_construction(tmp_path):
    # M2.2: patterns compile at startup — a non-literal pattern fails
    # fast (ValueError -> CLI exit 2) BEFORE the listener binds.
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    try:
        with pytest.raises(ValueError):
            proxy.ProxyServer("127.0.0.1", 0, writer=writer,
                              hunt_id=run.hunt_id,
                              scope={"in": ["http://example.com"], "out": []})
    finally:
        writer.close()


def test_build_event_contract_and_url_cap():
    event = proxy.build_event(hunt_id="20261023-085501", url="http://h/" + "a" * 5000,
                              decision="allowed", method="get")
    assert_pinned_event(event)
    assert len(event["url"]) == 4096
    assert event["method"] == "GET"
    assert event["provenance"] == "vulndog.proxy"
    assert event["tap_class"] == "tool_http"


def test_build_event_body_capture_cap():
    # design 6 ordering law (fix-round-1 B1): build_event shapes the
    # PRE-redaction event — the CAPTURE cap applies here; the 4 000-char
    # PERSIST cap is applied by the F4 door POST-redaction (proven
    # end-to-end by test_body_capture_capped_at_persist_limit).
    event = proxy.build_event(hunt_id="h", url="http://h/", decision="allowed",
                              body_redacted="x" * 250_000)
    assert len(event["body_redacted"]) == 200_000


# ------------------------------------------------------- plain HTTP leg


def test_plain_http_forwarded_and_event_written(tmp_path):
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        oport = origin.server_address[1]
        pport = server.address[1]
        url = f"http://127.0.0.1:{oport}/path?token=secret123&empty=&flag"
        status, body = http_via_proxy(
            pport, url, headers={"User-Agent": "rig/1.0", "Cookie": "sid=abc"})
        assert status == 200
        assert body == b"hello"
        assert len(origin.hits) == 1
        assert origin.hits[0]["path"] == "/path?token=secret123&empty=&flag"

        events = read_events(run)
        assert len(events) == 1
        ev = events[0]
        assert_pinned_event(ev, persisted=True)
        # F4 canonical form: secret-named params -> <redacted> (pattern
        # pass); flag params (no '=') ride as bare names
        assert ev["url"] == f"http://127.0.0.1:{oport}/path?token=<redacted>&empty=<len-0>&flag"
        assert ev["method"] == "GET"
        assert ev["status"] == 200
        assert ev["decision"] == "allowed"
        assert ev["hunt_id"] == run.hunt_id
        assert ev["ua_present"] is True
        assert ev["cookie_present"] is True
        assert ev["content_type"] == "text/plain"
        assert ev["body_redacted"] == "hello"


def test_presence_booleans_false_when_headers_absent(tmp_path):
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        # strip the default headers http.client adds
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1], timeout=15)
        conn.putrequest("GET", url, skip_host=True, skip_accept_encoding=True)
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        conn.close()
        ev = read_events(run)[0]
        assert ev["ua_present"] is False
        assert ev["cookie_present"] is False


def test_no_header_values_ever_persisted(tmp_path):
    secrets = ["Bearer SUPERSECRET-TOKEN", "session=SECRET-COOKIE-VALUE",
               "custom-secret-value"]
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/login"
        http_via_proxy(server.address[1], url, headers={
            "Authorization": secrets[0], "Cookie": secrets[1],
            "X-Custom": secrets[2], "User-Agent": "rig/1.0",
        })
        raw = run.events_path.read_text(encoding="utf-8")
        for secret in secrets:
            assert secret not in raw, "header value leaked into events.jsonl"
        ev = json.loads(raw.splitlines()[0])
        assert_pinned_event(ev, persisted=True)
        assert ev["ua_present"] is True and ev["cookie_present"] is True
        # origin still received the real headers (forwarding is unmodified)
        assert origin.hits[0]["headers"].get("Authorization") == secrets[0]


def test_url_userinfo_not_persisted(tmp_path):
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        oport = origin.server_address[1]
        url = f"http://user:sup3rpass@127.0.0.1:{oport}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200
        raw = run.events_path.read_text(encoding="utf-8")
        assert "sup3rpass" not in raw
        assert "user:" not in raw
        assert read_events(run)[0]["url"] == f"http://127.0.0.1:{oport}/"


@pytest.mark.parametrize("extra_headers,expected", [
    (b"Transfer-Encoding: chunked\r\n", 501),
    (b"Content-Length: abc\r\n", 400),
    (b"Content-Length: 20000000\r\n", 413),
])
def test_client_body_rejections_answered_no_event(tmp_path, extra_headers,
                                                 expected):
    # H3 mutator coverage: the _read_request_body rejection branches had
    # no dedicated tests. Client-side protocol rejections are answered
    # before any target request; no event is emitted (documented law).
    with proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(b"POST http://127.0.0.1:9/x HTTP/1.1\r\nHost: 127.0.0.1:9\r\n"
                  + extra_headers + b"\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(f"HTTP/1.1 {expected}".encode())
        assert read_events(run) == []


def test_hop_headers_stripped_host_rewritten(tmp_path):
    # _forward_http branch coverage (H3): hop-by-hop/proxy headers never
    # reach the origin; Host is rewritten to the origin authority;
    # end-to-end client headers pass through unmodified.
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        oport = origin.server_address[1]
        http_via_proxy(server.address[1], f"http://127.0.0.1:{oport}/x",
                       headers={"Connection": "keep-alive",
                                "Proxy-Authorization": "Basic cHJveHk=",
                                "X-Custom": "keep-me"})
        got = {k.lower(): v for k, v in origin.hits[0]["headers"].items()}
        assert "proxy-authorization" not in got
        assert got.get("connection") == "close"
        assert got["x-custom"] == "keep-me"
        assert got["host"] == f"127.0.0.1:{oport}"


def test_post_body_forwarded(tmp_path):
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/submit"
        status, _ = http_via_proxy(server.address[1], url, method="POST",
                                   body=b"payload-123",
                                   headers={"Content-Type": "application/x-www-form-urlencoded"})
        assert status == 200
        assert origin.hits[0]["body"] == b"payload-123"
        assert read_events(run)[0]["method"] == "POST"


def test_forwarded_request_carries_exactly_one_content_length(tmp_path):
    # F-3: the proxy used to forward the client's CL AND append its own
    # -> every body request reached the origin with TWO CL headers
    # (RFC 9112 unrecoverable error / CL.CL smuggling primitive).
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/submit"
        status, _ = http_via_proxy(server.address[1], url, method="POST",
                                   body=b"payload-123")
        assert status == 200
        hit = origin.hits[0]
        assert hit["cl_values"] == ["11"], \
            f"expected exactly ONE outbound CL, got {hit['cl_values']}"
        assert hit["body"] == b"payload-123"


def test_conflicting_content_lengths_400_no_upstream(tmp_path):
    # F-3: ambiguous framing (two different CL values) is an
    # unrecoverable error — answer 400 BEFORE any upstream socket.
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"POST {url} HTTP/1.1\r\nHost: h\r\n"
                  "Content-Length: 5\r\nContent-Length: 6\r\n\r\nabcde"
                  .encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 400"), resp[:60]
        assert origin.hits == [], "ambiguous framing reached the origin"
        assert read_events(run) == []   # client-side rejection: no event


def test_duplicate_identical_content_lengths_collapsed(tmp_path):
    # RFC 9112 6.3: identical duplicates MAY be replaced with a single
    # valid field — the proxy collapses them (never forwards two).
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"POST {url} HTTP/1.1\r\nHost: h\r\n"
                  "Content-Length: 5\r\nContent-Length: 5\r\n\r\nabcde"
                  .encode())
        resp = s.recv(4096)
        s.close()
        assert resp.split(b"\r\n", 1)[0].split()[1] == b"200"
        assert origin.hits[0]["cl_values"] == ["5"]
        assert origin.hits[0]["body"] == b"abcde"


def test_body_capture_capped_at_persist_limit(tmp_path):
    # Filler that SURVIVES F4 (ordinary words): a pure 'A'*6000 run is
    # hex-alphabet opaque under COND-1(c) and redacts to <redacted> —
    # correct door behaviour, but it cannot prove the persist cap.
    payload = b"hello world " * 500   # 6000 bytes
    with origin_up(payload=payload) as origin, proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, body = http_via_proxy(server.address[1], url)
        assert status == 200
        assert len(body) == 6000  # forwarding is NOT truncated
        ev = read_events(run)[0]
        assert ev["body_redacted"] == payload.decode()[:4000]


def test_truncated_response_cl_matches_emitted_body(tmp_path, monkeypatch):
    # m2: the forward cap truncates the body, but the origin's original
    # Content-Length was forwarded verbatim -> the client waited for
    # bytes that never came (IncompleteRead). The emitted CL must match
    # the emitted body; the persisted snippet reflects the same body.
    monkeypatch.setattr(proxy, "_BODY_FORWARD_CAP", 1000)
    payload = b"hello world " * 125   # 1500 bytes > cap 1000
    with origin_up(payload=payload) as origin, proxy_up(tmp_path) as (run, server):
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                          timeout=15)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert resp.getheader("Content-Length") == "1000"
        assert len(body) == 1000
        assert body == payload[:1000]
        conn.close()
        ev = read_events(run)[0]
        assert ev["body_redacted"] == payload[:1000].decode()


def test_early_closed_response_cl_matches_emitted_body(tmp_path):
    # m2 sibling: the origin LIES about its length (CL 5000, sends 1000,
    # closes). The proxy must emit the truthful length, not the lie.
    class _LyingOrigin(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(10)
            try:
                while b"\r\n\r\n" not in self.request.recv(4096):
                    pass
            except OSError:
                return
            body = b"x" * 1000
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: 5000\r\n\r\n" + body)
            self.request.close()

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _LyingOrigin)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with proxy_up(tmp_path) as (run, server):
            conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                              timeout=15)
            conn.request("GET", f"http://127.0.0.1:{srv.server_address[1]}/")
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 200
            assert resp.getheader("Content-Length") == "1000"
            assert len(body) == 1000
            conn.close()
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


# ------------------------------------- R2-F chunked-response framing


class _ChunkedOrigin(socketserver.BaseRequestHandler):
    """Sends a canned chunked response, then HOLDS the connection open
    (keep-alive): a read-to-close proxy would hang here — the chunked
    reader must stop at the terminating 0-chunk."""

    def handle(self):
        self.request.settimeout(10)
        try:
            while b"\r\n\r\n" not in self.request.recv(4096):
                pass
        except OSError:
            return
        self.request.sendall(self.server.response_bytes)
        time.sleep(2)  # keep-alive hold; daemon thread, never blocks the test


@contextmanager
def chunked_origin_up(response_bytes: bytes):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ChunkedOrigin)
    srv.daemon_threads = True
    srv.response_bytes = response_bytes
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)


def test_chunked_response_decoded_with_truthful_framing(tmp_path):
    # R2-F: a chunked body must be DECODED and re-framed with one
    # truthful Content-Length — the persisted body and the emitted
    # framing always agree. The origin keeps the connection alive, so
    # this also proves the reader stops at the 0-chunk (no hang).
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
    with chunked_origin_up(wire) as origin, \
            proxy_up(tmp_path) as (run, server):
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                          timeout=15)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert body == b"hello world"
        assert resp.getheader("Content-Length") == "11"
        assert resp.getheader("Transfer-Encoding") is None
        conn.close()
        ev = read_events(run)[0]
        assert ev["body_redacted"] == "hello world"


def test_chunked_truncation_framing_matches_persisted_body(tmp_path,
                                                          monkeypatch):
    # R2-F done-criterion: at the forward cap the chunked body is cut —
    # the emitted framing (ONE truthful CL, no chunked TE) must equal
    # the persisted body length. The old code forwarded a half chunk
    # frame -> client IncompleteRead (QA1 4.1).
    monkeypatch.setattr(proxy, "_BODY_FORWARD_CAP", 10)
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"8\r\nabcdefgh\r\n8\r\nijklmnop\r\n8\r\nqrstuvwx\r\n0\r\n\r\n")
    with chunked_origin_up(wire) as origin, \
            proxy_up(tmp_path) as (run, server):
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                          timeout=15)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert body == b"abcdefghij"          # exactly the cap, no desync
        assert resp.getheader("Content-Length") == "10"
        assert resp.getheader("Transfer-Encoding") is None
        conn.close()
        ev = read_events(run)[0]
        assert ev["body_redacted"] == "abcdefghij"


def test_chunked_trailers_and_extensions_handled(tmp_path):
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5;ext=v\r\nhello\r\n0\r\nX-Trailer: junk\r\n\r\n")
    with chunked_origin_up(wire) as origin, \
            proxy_up(tmp_path) as (run, server):
        status, body = http_via_proxy(
            server.address[1],
            f"http://127.0.0.1:{origin.server_address[1]}/")
        assert status == 200
        assert body == b"hello"
        assert read_events(run)[0]["body_redacted"] == "hello"


def test_chunked_malformed_frame_best_effort_truthful(tmp_path):
    # a hostile origin's broken frame must not desync the client: the
    # decodable prefix is emitted with a truthful CL, never raw frames.
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\nZZZ\r\nnot-a-size\r\n")
    with chunked_origin_up(wire) as origin, \
            proxy_up(tmp_path) as (run, server):
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                          timeout=15)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert body == b"hello"
        assert resp.getheader("Content-Length") == "5"
        conn.close()


def test_chunked_negative_size_cannot_unbound_the_read(tmp_path,
                                                       monkeypatch):
    # preflight catch (fix-round-2): a hostile negative chunk size must
    # not reach rfile.read(min(size, room)) — read(-n) is READ-ALL and
    # would bypass the forward cap (memory exhaustion). A malformed
    # frame ends the decode best-effort: empty body, truthful CL, fast.
    monkeypatch.setattr(proxy, "_BODY_FORWARD_CAP", 10)
    monkeypatch.setattr(proxy, "_IO_TIMEOUT", 2.0)
    wire = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"-5\r\n" + b"x" * 100_000)
    with chunked_origin_up(wire) as origin, \
            proxy_up(tmp_path) as (run, server):
        conn = http.client.HTTPConnection("127.0.0.1", server.address[1],
                                          timeout=15)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/")
        resp = conn.getresponse()
        body = resp.read()
        assert resp.status == 200
        assert body == b"", "negative chunk size bypassed the cap"
        assert resp.getheader("Content-Length") == "0"
        conn.close()


def test_binary_body_not_captured(tmp_path):
    with origin_up(payload=b"\x00\x01\x02", content_type="application/octet-stream") as origin, \
            proxy_up(tmp_path) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/bin"
        http_via_proxy(server.address[1], url)
        ev = read_events(run)[0]
        assert "body_redacted" not in ev


def test_upstream_refused_returns_502_and_denied_event(tmp_path):
    dead_port = free_port()
    with proxy_up(tmp_path) as (run, server):
        status, _ = http_via_proxy(server.address[1], f"http://127.0.0.1:{dead_port}/")
        assert status == 502
        ev = read_events(run)[0]
        assert_pinned_event(ev, persisted=True)
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "connect_refused"


def test_origin_form_request_rejected_400(tmp_path):
    with proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(b"GET /path HTTP/1.1\r\nHost: x\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 400")


@pytest.mark.parametrize("target", [
    "http://127.0.0.1:99999/",   # port out of range -> .port ValueError
    "http://127.0.0.1:-1/",      # negative port
    "http://[::1/",              # invalid IPv6 literal -> urlsplit raises
])
def test_hostile_url_port_or_ipv6_answers_400_not_zero_bytes(tmp_path, target):
    # F-13/M5: urlsplit().port / IPv6 parsing raised ValueError uncaught
    # — the handler died and the client received ZERO bytes. A malformed
    # target is a client-side protocol rejection: 400, no upstream
    # socket, no event, and the server keeps serving.
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"GET {target} HTTP/1.1\r\nHost: h\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 400"), \
            f"client got {resp[:40]!r} instead of a 400 answer"
        assert origin.hits == []
        assert read_events(run) == []
        # the server survived the hostile target
        status, _ = http_via_proxy(
            server.address[1], f"http://127.0.0.1:{origin.server_address[1]}/")
        assert status == 200


def test_connect_hostile_port_answers_400(tmp_path):
    with proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(b"CONNECT 127.0.0.1:99999 HTTP/1.1\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 400"), resp[:40]
        assert read_events(run) == []


def test_malformed_request_line_400_then_server_still_serves(tmp_path):
    with origin_up() as origin, proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(b"GARBAGE\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 400")
        # server survived
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200


# ----------------------------------------------------------- CONNECT leg


def test_connect_tunnel_relays_bytes_metadata_only_event(tmp_path):
    with echo_up() as echo, proxy_up(tmp_path) as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=15)
        try:
            s.sendall(f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\nHost: 127.0.0.1:{eport}\r\n\r\n".encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                assert chunk, "proxy closed before establishing tunnel"
                resp += chunk
            assert resp.startswith(b"HTTP/1.1 200")
            s.sendall(b"opaque-ping")
            assert s.recv(4096) == b"opaque-ping"
        finally:
            s.close()
        events = read_events(run)
        assert len(events) == 1
        ev = events[0]
        assert_pinned_event(ev, persisted=True)
        assert ev["method"] == "CONNECT"
        assert ev["url"] == f"127.0.0.1:{eport}"  # authority only: no scheme, no path
        assert ev["decision"] == "allowed"
        assert "body_redacted" not in ev
        assert len(echo.connections) == 1


def test_connect_authority_userinfo_not_persisted(tmp_path):
    # H2/F9: the module law says credentials never reach disk — the
    # plain-HTTP leg strips userinfo, but the CONNECT leg persisted the
    # raw authority. A hostile client CAN send userinfo in CONNECT.
    with echo_up() as echo, proxy_up(tmp_path) as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=15)
        try:
            s.sendall(
                f"CONNECT user:sup3rpass@127.0.0.1:{eport} HTTP/1.1\r\n\r\n"
                .encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(4096)
                assert chunk, "proxy closed before establishing tunnel"
                resp += chunk
            assert resp.startswith(b"HTTP/1.1 200")
            s.sendall(b"ping")
            assert s.recv(4096) == b"ping"
        finally:
            s.close()
        raw = run.events_path.read_text(encoding="utf-8")
        assert "sup3rpass" not in raw, "CONNECT userinfo leaked to disk"
        assert "user:" not in raw
        ev = read_events(run)[0]
        assert_pinned_event(ev, persisted=True)
        assert ev["url"] == f"127.0.0.1:{eport}"
        assert ev["decision"] == "allowed"


def test_connect_denied_authority_also_masked(tmp_path):
    # The denied legs persist the authority too — same capture law.
    with proxy_up(tmp_path, scope={"in": [], "out": ["127.0.0.1"]}) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(b"CONNECT user:sup3rpass@127.0.0.1:443 HTTP/1.1\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 403")
        raw = run.events_path.read_text(encoding="utf-8")
        assert "sup3rpass" not in raw
        ev = read_events(run)[0]
        assert ev["denial_reason"] == "proxy_oos"
        assert ev["url"] == "127.0.0.1:443"


def test_connect_refused_502_denied_event(tmp_path):
    dead_port = free_port()
    with proxy_up(tmp_path) as (run, server):
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"CONNECT 127.0.0.1:{dead_port} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 502")
        ev = read_events(run)[0]
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "connect_refused"


# --------------------------------------------------------------- scope


def test_scope_out_denied_403_upstream_never_contacted(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, scope={"in": [], "out": ["127.0.0.1"]}) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/secret"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 403
        assert origin.hits == [], "out-of-scope request reached the origin"
        ev = read_events(run)[0]
        assert_pinned_event(ev, persisted=True)
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "proxy_oos"
        assert ev["status"] == 403


def test_scope_in_allowlist_forwarded(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, scope={"in": ["127.0.0.1"], "out": []}) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200
        assert read_events(run)[0]["decision"] == "allowed"


def test_scope_connect_out_denied_403_no_upstream(tmp_path):
    with echo_up() as echo, \
            proxy_up(tmp_path, scope={"in": [], "out": ["127.0.0.1"]}) as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 403")
        assert echo.connections == [], "out-of-scope CONNECT reached the target"
        ev = read_events(run)[0]
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "proxy_oos"


def test_private_host_in_scope_still_rail_denied(tmp_path):
    # M2.2 invariant: scope is the owner-selection layer ABOVE the SSRF
    # rail — putting a private host IN scope never lifts the rail.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=False,
                     scope={"in": ["127.0.0.1"], "out": []}) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/admin"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 403
        assert origin.hits == [], "in-scope private target reached the origin"
        ev = read_events(run)[0]
        assert ev["denial_reason"] == "proxy_private"


def test_private_host_in_scope_forwarded_with_allow_private(tmp_path):
    # --allow-private lifts the RAIL (explicit opt-in), scope still applies.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True,
                     scope={"in": ["127.0.0.1"], "out": []}) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200
        assert read_events(run)[0]["decision"] == "allowed"


def test_allow_private_does_not_lift_scope(tmp_path):
    # out-of-scope stays denied even with the rail opt-in: scope wins
    # first (proxy_oos vocabulary), --allow-private only lifts the rail.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True,
                     scope={"in": [], "out": ["127.0.0.1"]}) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 403
        assert origin.hits == [], "out-of-scope target reached the origin"
        assert read_events(run)[0]["denial_reason"] == "proxy_oos"


def test_private_connect_in_scope_still_rail_denied(tmp_path):
    # both legs: an in-scope private CONNECT is rail-denied, no tunnel.
    with echo_up() as echo, \
            proxy_up(tmp_path, allow_private=False,
                     scope={"in": ["127.0.0.1"], "out": []}) as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 403")
        assert echo.connections == [], "in-scope private CONNECT reached target"
        assert read_events(run)[0]["denial_reason"] == "proxy_private"


# ------------------------------------------------------- M1 SSRF rail


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", True), ("127.5.5.5", True), ("localhost", True),
    ("::1", True), ("10.0.0.1", True), ("172.16.0.1", True),
    ("192.168.1.1", True), ("169.254.169.254", True),
    ("metadata.google.internal", True), ("svc.internal", True),
    ("fe80::1", True), ("fd00::1", True),
    ("example.com", False), ("8.8.8.8", False), ("1.1.1.1", False),
    ("93.184.216.34", False), ("sub.example.com", False),
])
def test_is_private_target(host, expected):
    assert proxy._is_private_target(host) is expected


def test_rail_denies_loopback_origin_no_socket(tmp_path):
    # M1: default-deny — the allow-all scope is a floor for PUBLIC
    # hosts only; a loopback origin is refused BEFORE any socket.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=False) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/admin"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 403
        assert origin.hits == [], "rail target reached the origin"
        ev = read_events(run)[0]
        assert_pinned_event(ev, persisted=True)
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "proxy_private"


@pytest.mark.parametrize("target_host", ["10.0.0.1", "169.254.169.254"])
def test_rail_private_and_metadata_never_open_a_socket(tmp_path, monkeypatch,
                                                       target_host):
    # The done-criterion proof: a request to RFC1918 / cloud metadata
    # is refused with NO upstream socket. The guard trips on the exact
    # target address only (the test client connects to the proxy, a
    # different address, and passes through).
    real_cc = socket.create_connection
    attempts = []

    def guard(address, *a, **k):
        if tuple(address[:2]) == (target_host, 80):
            attempts.append(address)
            raise AssertionError(f"rail opened a socket to {address}")
        return real_cc(address, *a, **k)

    monkeypatch.setattr(proxy.socket, "create_connection", guard)
    with proxy_up(tmp_path, allow_private=False) as (run, server):
        status, _ = http_via_proxy(server.address[1],
                                   f"http://{target_host}/latest/meta-data/")
        assert status == 403
        assert attempts == [], "upstream socket opened for a rail target"
        ev = read_events(run)[0]
        assert ev["denial_reason"] == "proxy_private"


@pytest.mark.parametrize("target_host", [
    "192.168.1.1", "172.16.0.1", "localhost", "metadata.google.internal",
])
def test_rail_denies_private_names_and_ranges(tmp_path, target_host):
    with proxy_up(tmp_path, allow_private=False) as (run, server):
        status, _ = http_via_proxy(server.address[1],
                                   f"http://{target_host}/")
        assert status == 403
        assert read_events(run)[0]["denial_reason"] == "proxy_private"


def test_rail_connect_tunnel_denied_no_socket(tmp_path):
    with echo_up() as echo, \
            proxy_up(tmp_path, allow_private=False) as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 403")
        assert echo.connections == [], "rail CONNECT reached the target"
        assert read_events(run)[0]["denial_reason"] == "proxy_private"


def test_allow_private_overrides_the_rail(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200
        assert read_events(run)[0]["decision"] == "allowed"


def test_scope_out_wins_over_rail_reason(tmp_path):
    # ordering: the scope check runs first — an out-of-scope private
    # host keeps the honest proxy_oos reason (pinned vocabulary).
    with proxy_up(tmp_path, allow_private=False,
                  scope={"in": [], "out": ["127.0.0.1"]}) as (run, server):
        status, _ = http_via_proxy(server.address[1], "http://127.0.0.1:9/")
        assert status == 403
        assert read_events(run)[0]["denial_reason"] == "proxy_oos"


# ------------------------------------------------- bind guard + shutdown


def test_non_loopback_bind_refused_without_flag(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    try:
        with pytest.raises(ValueError):
            proxy.ProxyServer("0.0.0.0", 0, writer=writer, hunt_id=run.hunt_id)
    finally:
        writer.close()


def test_non_loopback_bind_allowed_with_explicit_flag(tmp_path):
    # M2: the explicit bind flag now ALSO requires a client credential
    with proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                  client_token="rig-token") as (run, server):
        assert server.address[0] == "0.0.0.0"


# ------------------------------------------- M2 remote-bind credentials


def test_remote_bind_without_credential_refuses_to_start(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    try:
        with pytest.raises(ValueError) as exc:
            proxy.ProxyServer("0.0.0.0", 0, writer=writer,
                              hunt_id=run.hunt_id, allow_remote_bind=True)
        msg = str(exc.value)
        assert "--client-token" in msg and "--client-allow" in msg
    finally:
        writer.close()


def test_remote_bind_invalid_cidr_refuses(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    try:
        with pytest.raises(ValueError):
            proxy.ProxyServer("0.0.0.0", 0, writer=writer,
                              hunt_id=run.hunt_id, allow_remote_bind=True,
                              client_allow="not-a-cidr")
    finally:
        writer.close()


def test_remote_bind_token_checked_per_request(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_token="s3cret-token") as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        # no credential -> 407, origin untouched
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 407
        assert origin.hits == []
        # wrong credential -> 407
        status, _ = http_via_proxy(server.address[1], url, headers={
            "Proxy-Authorization": "Bearer wrong"})
        assert status == 407
        assert origin.hits == []
        # correct credential -> forwarded; the credential itself is
        # hop-by-hop and must NEVER reach the origin
        status, _ = http_via_proxy(server.address[1], url, headers={
            "Proxy-Authorization": "Bearer s3cret-token"})
        assert status == 200
        assert len(origin.hits) == 1
        assert "proxy-authorization" not in {
            k.lower() for k in origin.hits[0]["headers"]}
        events = read_events(run)
        assert [e["decision"] for e in events] == \
            ["denied", "denied", "allowed"]
        assert events[0]["denial_reason"] == "proxy_auth"
        assert events[0]["status"] == 407


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "BeArEr"])
def test_token_scheme_is_case_insensitive(tmp_path, scheme):
    # R2-D / QA2 N-3: RFC 7235 2.1 — the auth scheme is case-insensitive.
    # The old gate compared the whole "Bearer <token>" string verbatim,
    # so a lowercase scheme failed closed (interop nit). The credential
    # itself is still compared in constant time, exactly once.
    with origin_up() as origin, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_token="s3cret-token") as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        status, _ = http_via_proxy(server.address[1], url, headers={
            "Proxy-Authorization": f"{scheme} s3cret-token"})
        assert status == 200, f"scheme {scheme!r} rejected"
        assert len(origin.hits) == 1
        assert "proxy-authorization" not in {
            k.lower() for k in origin.hits[0]["headers"]}


def test_client_credential_compare_is_constant_time():
    # R2-D source pin: a timing side channel on the proxy token is a
    # regression even though == and compare_digest are behaviourally
    # identical — only a source inspection can kill that mutant. The
    # pin reads the AST BODY (a docstring mention of compare_digest
    # must not satisfy it — the first version of this test did).
    import ast
    import inspect
    import textwrap
    src = textwrap.dedent(inspect.getsource(proxy.ProxyServer._token_admits))
    fn = ast.parse(src).body[0]
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)
            and isinstance(fn.body[0].value.value, str)):
        fn.body = fn.body[1:]
    code = ast.unparse(fn)
    assert "hmac.compare_digest" in code, \
        "credential compare must remain constant-time (R2-D)"


@pytest.mark.parametrize("header", [
    "bearer wrong-token",          # right scheme, wrong credential
    "Basic s3cret-token",          # wrong scheme
    "s3cret-token",                # no scheme
    "Bearer",                      # scheme only, no credential
    "Bearer ",                     # empty credential
])
def test_token_gate_still_fails_closed_on_bad_credentials(tmp_path, header):
    with origin_up() as origin, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_token="s3cret-token") as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        status, _ = http_via_proxy(server.address[1], url, headers={
            "Proxy-Authorization": header})
        assert status == 407
        assert origin.hits == []


def test_remote_bind_client_allow_cidr(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_allow="127.0.0.0/8") as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 200          # client IP inside the allow CIDR
    with origin_up() as origin, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_allow="10.0.0.0/8") as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/x"
        status, _ = http_via_proxy(server.address[1], url)
        assert status == 403          # client IP outside the allow CIDR
        assert origin.hits == []
        ev = read_events(run)[0]
        assert ev["denial_reason"] == "proxy_client_denied"


def test_remote_bind_connect_also_requires_credential(tmp_path):
    with echo_up() as echo, \
            proxy_up(tmp_path, host="0.0.0.0", allow_remote_bind=True,
                     client_token="tok") as (run, server):
        eport = echo.server_address[1]
        s = socket.create_connection(("127.0.0.1", server.address[1]), timeout=10)
        s.sendall(f"CONNECT 127.0.0.1:{eport} HTTP/1.1\r\n\r\n".encode())
        resp = s.recv(4096)
        s.close()
        assert resp.startswith(b"HTTP/1.1 407")
        assert echo.connections == []


def test_stop_request_file_stops_server(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    server = proxy.ProxyServer("127.0.0.1", 0, writer=writer, hunt_id=run.hunt_id,
                               stop_file=run.stop_path)
    server.start()
    try:
        run.request_stop()
        assert server.wait(timeout=5) is True
    finally:
        server.stop()
        writer.close()


def test_stop_event_stops_server(tmp_path):
    with proxy_up(tmp_path) as (run, server):
        stopper = threading.Thread(target=lambda: (time.sleep(0.2), server.stop()))
        stopper.start()
        assert server.wait(timeout=5) is True
        stopper.join(timeout=5)


# ------------------------------------- upstream status is external input


@pytest.mark.parametrize("bad_status", [600, 999])
def test_upstream_out_of_range_status_stays_schema_valid(tmp_path, bad_status):
    # H2/F4: the upstream status line is EXTERNAL input. An out-of-range
    # status (e.g. 999) used to ride into the event verbatim; the engine
    # validator then rejected the WHOLE event at analysis time — silent
    # data loss caused by a hostile/buggy origin. The capture boundary
    # applies the same malformed-status rule as for non-digit lines:
    # fall back to 502, keep the event schema-valid.
    with origin_up(payload=b"weird", status_code=bad_status) as origin:
        with proxy_up(tmp_path) as (run, server):
            status, _ = http_via_proxy(
                server.address[1],
                f"http://127.0.0.1:{origin.server_address[1]}/x")
            assert status == bad_status, "the client sees the raw response"
            events = read_events(run)
            assert len(events) == 1
            assert es.validate_event(events[0]) == [], \
                "origin-controlled status made the event schema-invalid"
            assert events[0]["status"] == 502
            assert_pinned_event(events[0], persisted=True)


def test_upstream_in_range_status_passes_through(tmp_path):
    with origin_up(payload=b"ok", status_code=201) as origin:
        with proxy_up(tmp_path) as (run, server):
            http_via_proxy(server.address[1],
                           f"http://127.0.0.1:{origin.server_address[1]}/x")
            events = read_events(run)
            assert events[0]["status"] == 201
            assert es.validate_event(events[0]) == []


class _CloseOnArrival(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.close()


def test_upstream_io_failure_reason_is_not_connect_refused(tmp_path):
    # H2/F7: the connection SUCCEEDED but the origin closed before
    # answering. The event used to claim denial_reason="connect_refused"
    # — a false failure class in the persisted record. Post-connect I/O
    # failures carry their own honest reason.
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _CloseOnArrival)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        with proxy_up(tmp_path) as (run, server):
            status, _ = http_via_proxy(
                server.address[1],
                f"http://127.0.0.1:{srv.server_address[1]}/x")
            assert status == 502
            ev = read_events(run)[0]
            assert_pinned_event(ev, persisted=True)
            assert ev["decision"] == "denied"
            assert ev["status"] == 502
            assert ev["denial_reason"] == "upstream_io"
    finally:
        srv.shutdown()
        srv.server_close()
        t.join(timeout=5)