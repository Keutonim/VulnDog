"""Fix-round-2 SSRF rail hardening (R2-A/B/C).

R2-A (live-proven in security-r2): the rail classified the hostname
STRING, but the connection resolved DNS separately — a public name
resolving to 127.0.0.1 (localtest.me / 127.0.0.1.nip.io) walked through
the default-deny into a loopback canary. The fix classifies at CONNECT
time against the RESOLVED address and connects to the address it
classified (no second resolution between check and connect).

R2-B: CGNAT 100.64.0.0/10 (RFC 6598) is NOT is_private on Python 3.14
but is non-global shared space — denied explicitly.

R2-C: inet_aton numeric spellings (decimal/hex/octal, short forms) are
rejected by ipaddress.ip_address and by the Windows resolver, but glibc
resolves them — normalized BEFORE classification, platform-independent.

DNS is the external system under attack in R2-A, so the rebinding tests
inject the resolver answer at the socket.getaddrinfo seam (everything
else delegates to the real resolver). The suite stays fully offline.
"""
from __future__ import annotations

import socket

import pytest

from vulndog import proxy

from test_proxy import origin_up, proxy_up, read_events, http_via_proxy


# ------------------------------------------------- R2-B/R2-C classifier


@pytest.mark.parametrize("host", [
    # R2-B: CGNAT / RFC 6598 shared address space (Tailscale-style tailnets)
    "100.64.0.1", "100.127.255.254",
    # R2-C: single-integer decimal / hex / octal spellings of private IPs
    "2130706433",          # 127.0.0.1
    "0x7f000001",          # 127.0.0.1
    "0177.0.0.1",          # 127.0.0.1 (octal first part)
    "0177.0.0.01",         # 127.0.0.1 (octal parts)
    "127.1",               # short form 127.0.0.1
    "2852039166",          # 169.254.169.254 (cloud metadata)
    "0xa9fea9fe",          # 169.254.169.254
    "0251.0376.0251.0376",  # 169.254.169.254 (octal)
    "0xA9.0xFE.0xA9.0xFE",  # 169.254.169.254 (hex parts)
    "169.254.43518",       # short form 169.254.169.254
    "10.1",                # short form 10.0.0.1
    "0x0a000001",          # 10.0.0.1
    # IPv4-mapped IPv6 forms of private addresses
    "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:100.64.0.1",
])
def test_private_spellings_are_classified_private(host):
    assert proxy._is_private_target(host) is True, \
        f"{host!r} slipped the classifier"


@pytest.mark.parametrize("host", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34",
    "100.63.255.255",      # just BELOW the CGNAT block — public
    "100.128.0.0",         # just ABOVE the CGNAT block — public
    "2130706431",          # 126.255.255.255 — public integer spelling
    "0x08080808",          # 8.8.8.8
    "8.8.4510",            # short form 8.8.17.158 — public
    "example.com", "sub.example.com",
    "::ffff:8.8.8.8",      # mapped PUBLIC address stays public
])
def test_public_spellings_are_not_mis_denied(host):
    assert proxy._is_private_target(host) is False, \
        f"{host!r} mis-denied by the classifier"


def test_rail_denies_cgnat_origin_no_socket(tmp_path):
    # R2-B live proof: a CGNAT target is refused BEFORE any socket.
    real_cc = socket.create_connection
    attempts = []

    def guard(address, *a, **k):
        if tuple(address[:2]) == ("100.64.0.1", 80):
            attempts.append(address)
            raise AssertionError("rail opened a socket to a CGNAT target")
        return real_cc(address, *a, **k)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(proxy.socket, "create_connection", guard)
        with proxy_up(tmp_path, allow_private=False) as (run, server):
            status, _ = http_via_proxy(server.address[1],
                                       "http://100.64.0.1/")
            assert status == 403
            assert attempts == []
            assert read_events(run)[0]["denial_reason"] == "proxy_private"


# ------------------------------------------------- R2-A resolved-address


def _resolver_for(name: str, ip: str):
    """A getaddrinfo seam: the rebinding name resolves to `ip`; every
    other lookup delegates to the REAL resolver (offline-safe)."""
    real = socket.getaddrinfo

    def fake(host, port, *a, **k):
        if isinstance(host, str) and host.lower().rstrip(".") == name:
            return real(ip, port, *a, **k)
        return real(host, port, *a, **k)

    return fake


@pytest.mark.parametrize("leg", ["http", "connect"])
def test_rebinding_name_denied_on_resolved_address(tmp_path, leg):
    # R2-A: a PUBLIC name that RESOLVES to loopback must be refused —
    # the check happens on the resolved address, no upstream socket.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=False) as (run, server):
        oport = origin.server_address[1]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo",
                       _resolver_for("rebind.test", "127.0.0.1"))
            if leg == "http":
                status, _ = http_via_proxy(
                    server.address[1], f"http://rebind.test:{oport}/")
                assert status == 403
            else:
                s = socket.create_connection(
                    ("127.0.0.1", server.address[1]), timeout=10)
                s.sendall(f"CONNECT rebind.test:{oport} HTTP/1.1\r\n\r\n"
                          .encode())
                resp = s.recv(4096)
                s.close()
                assert resp.startswith(b"HTTP/1.1 403"), resp[:60]
        assert origin.hits == [], "rebinding name reached the origin"
        ev = read_events(run)[0]
        assert ev["decision"] == "denied"
        assert ev["denial_reason"] == "proxy_private"


def test_rebinding_mixed_records_denied_if_any_private(tmp_path):
    # default-deny: a name with BOTH a public and a private record is
    # refused — the attacker must not be able to offer a public record
    # as a decoy while a private one rides along.
    real = socket.getaddrinfo

    def mixed(host, port, *a, **k):
        if isinstance(host, str) and host.lower() == "mixed.test":
            return (real("93.184.216.34", port, *a, **k)
                    + real("127.0.0.1", port, *a, **k))
        return real(host, port, *a, **k)

    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=False) as (run, server):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo", mixed)
            status, _ = http_via_proxy(
                server.address[1],
                f"http://mixed.test:{origin.server_address[1]}/")
        assert status == 403
        assert origin.hits == []
        assert read_events(run)[0]["denial_reason"] == "proxy_private"


def test_connection_uses_the_classified_address(tmp_path):
    # R2-A done-criterion: the checked address IS the connected address.
    # "public.test" is not a real name — it only resolves through the
    # injected seam to the loopback origin. With --allow-private the
    # request succeeds ONLY if the proxy connects to the resolved IP
    # it classified (a second, real resolution would fail).
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True) as (run, server):
        oport = origin.server_address[1]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo",
                       _resolver_for("public.test", "127.0.0.1"))
            status, body = http_via_proxy(
                server.address[1], f"http://public.test:{oport}/x")
        assert status == 200
        assert body == b"hello"
        assert len(origin.hits) == 1
        # the origin-form request keeps the client's authority verbatim
        assert origin.hits[0]["headers"]["Host"] == f"public.test:{oport}"
        assert read_events(run)[0]["decision"] == "allowed"


def test_no_second_resolution_between_check_and_connect(tmp_path):
    # TOCTOU probe: the FIRST resolution answers public, any LATER
    # resolution of the same name answers private (a rebinding flip).
    # The proxy must connect to the address it classified — the flip
    # must never reach the socket layer. The connect to the public IP
    # is intercepted at the socket layer (simulated refusal): the test
    # generates NO external traffic.
    real = socket.getaddrinfo
    calls = {"n": 0}

    def flip(host, port, *a, **k):
        if isinstance(host, str) and host.lower() == "flip.test":
            calls["n"] += 1
            ip = "93.184.216.34" if calls["n"] == 1 else "127.0.0.1"
            return real(ip, port, *a, **k)
        return real(host, port, *a, **k)

    real_connect = socket.socket.connect
    seen = []

    def connect_guard(sock, address):
        if address[0] == "93.184.216.34":
            seen.append(tuple(address))
            raise ConnectionRefusedError("simulated — no real traffic")
        return real_connect(sock, address)

    with proxy_up(tmp_path, allow_private=False) as (run, server):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo", flip)
            mp.setattr(socket.socket, "connect", connect_guard)
            status, _ = http_via_proxy(server.address[1],
                                       "http://flip.test:80/")
        # the classified (first) answer was public -> the connect goes
        # to THAT address; the name is never resolved a second time.
        assert calls["n"] == 1, "the name was resolved more than once"
        assert seen == [("93.184.216.34", 80)], \
            f"connected to an address other than the classified one: {seen}"
        assert status == 502
        assert read_events(run)[0]["denial_reason"] == "connect_refused"


def test_unresolvable_name_is_connect_refused_not_private(tmp_path):
    # honest failure class: a name that does not resolve is a connect
    # failure (502 connect_refused), never a rail denial.
    with proxy_up(tmp_path, allow_private=False) as (run, server):
        status, _ = http_via_proxy(
            server.address[1], "http://no-such-host.invalid/")
        assert status == 502
        assert read_events(run)[0]["denial_reason"] == "connect_refused"


def test_allow_private_overrides_resolved_address_rail(tmp_path):
    # the explicit opt-in covers the resolved-address leg too.
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True) as (run, server):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo",
                       _resolver_for("rebind.test", "127.0.0.1"))
            status, _ = http_via_proxy(
                server.address[1],
                f"http://rebind.test:{origin.server_address[1]}/")
        assert status == 200
        assert len(origin.hits) == 1


def test_literal_ip_path_still_works_without_dns(tmp_path):
    # the literal path must not depend on DNS at all: a dotted-quad
    # target connects even when the resolver seam would refuse names.
    def no_names(host, port, *a, **k):
        if isinstance(host, str) and not host.replace(".", "").isdigit():
            raise AssertionError(f"literal path resolved a name: {host}")
        return real_gai(host, port, *a, **k)

    real_gai = socket.getaddrinfo
    with origin_up() as origin, \
            proxy_up(tmp_path, allow_private=True) as (run, server):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(proxy.socket, "getaddrinfo", no_names)
            status, _ = http_via_proxy(
                server.address[1],
                f"http://127.0.0.1:{origin.server_address[1]}/")
        assert status == 200
        assert len(origin.hits) == 1