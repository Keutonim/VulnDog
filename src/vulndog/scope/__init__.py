"""VulnDog scope module (M2.2, ADR-8) — the owner's target selection.

Compiles user scope patterns (``scope.in`` / ``scope.out``) once at the
boundary and matches hosts with a PURE function (no I/O — name
resolution belongs to the SSRF rail in ``vulndog.proxy``, never here).
Scope is the owner-selection layer ABOVE the rail: the rail stays the
safety floor (private/loopback/link-local/metadata default-deny) and
nothing in this module weakens it.

Pattern forms (docs/CONFIGURATION.md, "Scope / out-of-scope"): an
exact hostname or a ``*.suffix`` wildcard — the wildcard covers the
domain itself AND its subdomains. Matching is literal and
case-insensitive; trailing dots are stripped on both sides. A ``www.``
prefix is an ordinary exact pattern, not a special rule.

Semantics (ADR-8):
- ``out`` wins over ``in`` when a host matches both lists;
- an empty ``in`` list allows all hosts — the unconfigured default is
  allow-all for PUBLIC targets plus a loud startup banner (GAP-2/D15);
  private targets stay denied by the rail under that default;
- invalid patterns fail fast at compile time (``ScopeError``, a
  ``ValueError``) so the CLI exits nonzero BEFORE any capture.
"""
from __future__ import annotations

from dataclasses import dataclass


class ScopeError(ValueError):
    """Invalid scope configuration — fail fast at startup (exit 2).

    A ValueError subclass so the shipped CLI usage-error path
    (cli.main's ValueError catch) handles it without a new seam.
    """


#: RFC 1035 total hostname length cap (presentation form).
_HOSTNAME_CAP = 253


def _normalize_host(host: str) -> str:
    """Hostnames are case-insensitive; a trailing root dot is cosmetic."""
    return host.lower().rstrip(".")


def normalize_pattern(pattern: str, *, key: str = "scope") -> str:
    """Validate and normalize ONE scope pattern (the compile law).

    Accepted forms (docs/CONFIGURATION.md): an exact hostname or a
    ``*.suffix`` wildcard. Normalization: trim surrounding whitespace,
    lowercase, strip the trailing root dot. REJECTED (ScopeError): a
    scheme, path, port, userinfo, query, fragment, interior whitespace
    or control character, an empty pattern, a misplaced/interior
    wildcard, or an over-length hostname — a pattern is matched
    literally, never silently rewritten into a different target.

    Args:
        pattern: the raw pattern string from the config.
        key: config key name for the error message (e.g. "scope.in").

    Raises:
        ScopeError: the pattern is not a literal hostname/wildcard form.
    """
    if not isinstance(pattern, str):
        raise ScopeError(
            f"{key} patterns must be strings, got {type(pattern).__name__}")
    p = pattern.strip().lower().rstrip(".")
    if not p:
        raise ScopeError(f"{key} pattern {pattern!r} is empty")
    if len(p) > _HOSTNAME_CAP:
        raise ScopeError(
            f"{key} pattern {pattern!r} exceeds {_HOSTNAME_CAP} characters")
    if "*" in p:
        suffix = p[2:] if p.startswith("*.") else ""
        if not suffix or "*" in suffix:
            raise ScopeError(
                f"{key} pattern {pattern!r}: wildcard must be the leading "
                "'*.suffix' form")
    body = p[2:] if p.startswith("*.") else p
    for ch in body:
        if ch.isalnum() or ch in "-.":
            continue
        raise ScopeError(
            f"{key} pattern {pattern!r}: only exact hostnames or "
            "'*.suffix' wildcards are allowed (no scheme, path, port, "
            "or userinfo)")
    return p


def _pattern_matches(host: str, pattern: str) -> bool:
    """One pattern against an already-normalized host: exact hostname
    or ``*.suffix`` (the domain itself and its subdomains)."""
    p = pattern.lower().strip().rstrip(".")
    if not p:
        return False
    if p.startswith("*."):
        suffix = p[2:]
        return host == suffix or host.endswith("." + suffix)
    return host == p


def host_matches(host: str, patterns: list[str] | tuple[str, ...]) -> bool:
    """Pure: does the host match ANY pattern (exact or ``*.suffix``)?"""
    h = _normalize_host(host)
    return any(_pattern_matches(h, pattern) for pattern in patterns)


@dataclass(frozen=True)
class Scope:
    """Compiled scope — immutable normalized patterns, pure match.

    ``allows`` is THE match decision (one decision in one place); the
    dict-form ``in_scope`` convenience wrapper delegates here.
    """

    in_patterns: tuple[str, ...] = ()
    out_patterns: tuple[str, ...] = ()

    def allows(self, host: str) -> bool:
        """Pure match (no I/O): out wins over in; an empty in-list
        allows all hosts. The SSRF rail decides private targets —
        this function only answers the owner-selection question."""
        h = _normalize_host(host)
        if any(_pattern_matches(h, p) for p in self.out_patterns):
            return False
        if self.in_patterns and not any(
                _pattern_matches(h, p) for p in self.in_patterns):
            return False
        return True


def compile_scope(scope: dict | None) -> Scope:
    """Compile a ``{"in": [...], "out": [...]}`` config once at startup.

    None / missing keys mean the empty (allow-all) scope. Every pattern
    is validated and normalized by ``normalize_pattern``; the input
    dict is never mutated (the CLI banner and the JSON meta snapshot
    keep reading the raw config lists).

    Raises:
        ScopeError: wrong-typed scope config or a non-literal pattern —
            fail fast BEFORE any capture (the CLI maps this to exit 2).
    """
    if scope is None:
        scope = {}
    if not isinstance(scope, dict):
        raise ScopeError("config scope must be an object with in/out lists")
    normalized: dict[str, tuple[str, ...]] = {}
    for key in ("in", "out"):
        patterns = scope.get(key)
        if patterns is None:
            patterns = []
        if not isinstance(patterns, (list, tuple)):
            raise ScopeError(f"config scope.{key} must be a list of strings")
        normalized[key] = tuple(
            normalize_pattern(p, key=f"scope.{key}") for p in patterns)
    return Scope(in_patterns=normalized["in"],
                 out_patterns=normalized["out"])


def in_scope(host: str, scope: dict | None) -> bool:
    """Pure dict-form convenience: compile then match (out wins).

    Raises ScopeError on an invalid config — the proxy compiles once at
    startup and matches via ``Scope.allows``; this wrapper is the
    test/convenience surface over the same single match decision.
    """
    return compile_scope(scope).allows(host)