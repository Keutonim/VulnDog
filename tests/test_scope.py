"""Scope module (M2.2, ADR-8): pure match table + pattern compile law.

The match function is PURE (no I/O) — tested as a table per the brief.
Pattern forms per docs/CONFIGURATION.md "Scope / out-of-scope": an
exact hostname or a ``*.suffix`` wildcard (the domain itself and its
subdomains), matched literally, case-insensitive. Out wins over in;
an empty in-list allows all hosts (the allow-all-public default — the
SSRF rail in proxy.py stays the safety floor under it).
"""
from __future__ import annotations

import pytest

from vulndog import scope


# ----------------------------------------------------- pure match table


@pytest.mark.parametrize("host,patterns,expected", [
    # exact hostname
    ("example.com", ["example.com"], True),
    ("example.com", ["other.com"], False),
    ("example.com", [], False),
    # exact does NOT cover subdomains (literal matching per the docs)
    ("sub.example.com", ["example.com"], False),
    # a www. prefix is a literal exact pattern, not a special rule
    ("www.example.com", ["www.example.com"], True),
    ("www.example.com", ["example.com"], False),
    ("example.com", ["www.example.com"], False),
    # wildcard covers the domain itself AND its subdomains
    ("example.com", ["*.example.com"], True),
    ("sub.example.com", ["*.example.com"], True),
    ("a.b.example.com", ["*.example.com"], True),
    # suffix boundary: no partial-label match, no suffix smuggling
    ("evil-example.com", ["*.example.com"], False),
    ("example.com.evil.test", ["*.example.com"], False),
    ("notexample.com", ["*.example.com"], False),
    # case handling (both sides)
    ("EXAMPLE.COM", ["example.com"], True),
    ("example.com", ["EXAMPLE.COM"], True),
    ("Sub.Example.COM", ["*.example.com"], True),
    # trailing dots stripped on both sides
    ("example.com.", ["example.com"], True),
    ("example.com", ["example.com."], True),
    ("sub.example.com.", ["*.example.com"], True),
    # several patterns: any match suffices
    ("b.example.com", ["a.test", "*.example.com"], True),
    ("a.test", ["a.test", "*.example.com"], True),
    ("c.test", ["a.test", "*.example.com"], False),
])
def test_host_matches_table(host, patterns, expected):
    assert scope.host_matches(host, patterns) is expected


@pytest.mark.parametrize("host,scope_cfg,expected", [
    # out wins over in on overlap
    ("example.com", {"in": ["example.com"], "out": ["example.com"]}, False),
    ("api.example.com",
     {"in": ["*.example.com"], "out": ["api.example.com"]}, False),
    ("www.example.com",
     {"in": ["*.example.com"], "out": ["api.example.com"]}, True),
    # out-only list denies the named hosts, allows the rest
    ("evil.test", {"in": [], "out": ["evil.test"]}, False),
    ("good.test", {"in": [], "out": ["evil.test"]}, True),
    # in-list restricts to its patterns
    ("a.example.com", {"in": ["*.example.com"], "out": []}, True),
    ("other.tld", {"in": ["*.example.com"], "out": []}, False),
    # unconfigured scope: allow-all (public floor is the rail's job)
    ("anything.tld", {"in": [], "out": []}, True),
    ("anything.tld", None, True),
    ("anything.tld", {}, True),
    # case handling through the dict form
    ("EXAMPLE.COM", {"in": ["example.com"], "out": []}, True),
    ("example.com", {"in": [], "out": ["EXAMPLE.COM"]}, False),
])
def test_in_scope_table(host, scope_cfg, expected):
    assert scope.in_scope(host, scope_cfg) is expected


def test_compiled_scope_allows_matches_the_dict_form():
    cfg = {"in": ["*.example.com"], "out": ["api.example.com"]}
    compiled = scope.compile_scope(cfg)
    for host in ("example.com", "a.example.com", "api.example.com",
                 "other.tld", "EXAMPLE.COM"):
        assert compiled.allows(host) is scope.in_scope(host, cfg)


def test_compiled_scope_empty_allows_all():
    compiled = scope.compile_scope(None)
    assert compiled.allows("anything.tld") is True
    assert compiled.allows("127.0.0.1") is True  # rail decides private


def test_match_is_pure_no_io(monkeypatch):
    # The match path must not resolve names or touch the network: the
    # SSRF rail owns resolution; scope is literal host-pattern matching.
    def forbid(*a, **k):
        raise AssertionError("scope match performed I/O")

    monkeypatch.setattr("socket.getaddrinfo", forbid)
    monkeypatch.setattr("socket.socket.connect", forbid)
    compiled = scope.compile_scope({"in": ["*.example.com"],
                                    "out": ["api.example.com"]})
    assert compiled.allows("www.example.com") is True
    assert compiled.allows("api.example.com") is False
    assert scope.in_scope("www.example.com",
                          {"in": ["*.example.com"], "out": []}) is True


# ------------------------------------------------- pattern compile law
#
# docs/CONFIGURATION.md: "Patterns are matched literally: an exact
# hostname or a *.suffix wildcard only." A pattern carrying a scheme,
# path, port, userinfo, or an interior wildcard is REJECTED at compile
# time (fail fast, nonzero exit) — never silently normalized into a
# different target.


@pytest.mark.parametrize("bad", [
    "http://example.com",        # scheme
    "https://example.com",       # scheme
    "//example.com",             # scheme-relative
    "example.com/path",          # path component
    "example.com/",              # trailing path separator
    "example.com:8080",          # port
    "user@example.com",          # userinfo
    "user:pass@example.com",     # userinfo with password
    "example.com?q=1",           # query
    "example.com#frag",          # fragment
    "",                          # empty
    "   ",                       # whitespace-only
    ".",                         # root dot only
    "*",                         # bare wildcard
    "*.",                        # wildcard with empty suffix
    "a.*.b",                     # interior wildcard
    "example.*",                 # trailing wildcard
    "*example.com",              # wildcard without the dot
    "exa mple.com",              # interior whitespace
    "example.com\x00",           # interior control character
    "a" * 254,                   # over the hostname length cap
])
def test_compile_rejects_non_literal_patterns(bad):
    with pytest.raises(scope.ScopeError):
        scope.compile_scope({"in": [bad], "out": []})
    with pytest.raises(scope.ScopeError):
        scope.compile_scope({"in": [], "out": [bad]})


def test_scope_error_is_value_error():
    # the shipped CLI usage-error path catches ValueError
    assert issubclass(scope.ScopeError, ValueError)


def test_compile_error_message_names_key_and_pattern():
    with pytest.raises(scope.ScopeError) as exc:
        scope.compile_scope({"in": ["http://example.com"], "out": []})
    msg = str(exc.value)
    assert "scope.in" in msg
    assert "http://example.com" in msg


@pytest.mark.parametrize("raw,normalized", [
    ("EXAMPLE.COM", "example.com"),
    ("  example.com  ", "example.com"),
    ("example.com.", "example.com"),
    ("*.EXAMPLE.COM.", "*.example.com"),
    ("  *.Example.Com  ", "*.example.com"),
])
def test_compile_normalizes_valid_patterns(raw, normalized):
    compiled = scope.compile_scope({"in": [raw], "out": [raw]})
    assert compiled.in_patterns == (normalized,)
    assert compiled.out_patterns == (normalized,)


def test_compile_keeps_config_lists_usable_by_banner():
    # the CLI banner reads the raw config lists; compile must not
    # mutate its input (the config dict is also JSON-serialized).
    cfg = {"in": ["*.Example.com"], "out": []}
    scope.compile_scope(cfg)
    assert cfg == {"in": ["*.Example.com"], "out": []}