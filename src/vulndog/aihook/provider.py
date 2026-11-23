"""AI provider config shape (M2.4, ADR-6 / R9) — the PURE half of the hook.

This module owns the ``ai.*`` boundary: it parses the MERGED ai section
into an immutable :class:`ProviderSettings`, and it produces the run
banner / run-meta disclosure for the configured provider. It imports no
engine module, so the shipped config load path can validate ``ai.*`` at
startup even when the engine half is absent (the CLI's honest-degradation
law). The engine-dependent factory lives in :mod:`vulndog.aihook.embedder`.

GAP-4 decision D15: "optional AI" means PROVIDER CHOICE ONLY (ollama
default vs a custom embedding endpoint). The embedder stays MANDATORY in
the match path — the engine embeds before exact-id pin resolution
(``engine/query.py``), so no provider, no highlights. Nothing here
invents a text-only / no-AI fallback mode.

Default law (ADR-6): the built-in ``ai`` defaults in ``vulndog.config``
reproduce ``engine/embed_client.py`` byte-for-byte; this module never
re-derives them (tests pin the string equality from both sides).

Remote disclosure law (GAP-4 scope — the user's own box): a non-loopback
or ``file://`` ``base_url`` is ACCEPTED when explicitly configured, never
silently. It is reported in the run banner and in ``watchdog-run.json``
because that address receives the TEXT OF THE PROXIED TRAFFIC (redacted
event text). The default stays loopback ``http://127.0.0.1:11434``.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit

#: ADR-6 provider vocabulary. ``custom`` is any endpoint speaking the
#: engine's request/response shape ({"model", "input"} -> {"embeddings"}).
PROVIDERS = ("ollama", "custom")

#: Every key the config layer gap-fills (vulndog.config.VULNDOG_DEFAULTS).
_AI_KEYS = ("provider", "base_url", "model", "dims",
            "doc_prefix", "query_prefix", "timeout_s")


class AiConfigError(ValueError):
    """Invalid ``ai`` configuration — fail fast at startup (exit 2).

    A ValueError subclass so the shipped CLI usage-error path handles it
    without a new seam (the same discipline as scope.ScopeError).
    """


@dataclass(frozen=True)
class ProviderSettings:
    """The parsed provider choice — immutable, no I/O, no engine import.

    ``timeout_s`` is None when the operator kept the engine default; the
    engine-dependent layer resolves it to ``embed_client.DEFAULT_TIMEOUT_S``.
    Strings are carried VERBATIM (no normalization): what the operator
    configured is what the provider receives.
    """

    provider: str
    base_url: str
    model: str
    dims: int
    doc_prefix: str
    query_prefix: str
    timeout_s: float | None


def _require_str(name: str, value, *, allow_empty: bool = False) -> str:
    kind = "a string" if allow_empty else "a non-empty string"
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AiConfigError(f"config ai.{name} must be {kind}, got {value!r}")
    return value


def parse_ai(ai_cfg) -> ProviderSettings:
    """Validate the merged ``ai`` section at the boundary (fail fast).

    Args:
        ai_cfg: the ``ai`` namespace of the resolved config. The config
            layer gap-fills every key, so a missing key is a config-layer
            defect and is reported, never silently defaulted here.

    Raises:
        AiConfigError: wrong type/shape/value (a ValueError).
    """
    if not isinstance(ai_cfg, dict):
        raise AiConfigError("config ai must be an object")
    missing = [k for k in _AI_KEYS if k not in ai_cfg]
    if missing:
        raise AiConfigError(
            "config ai is missing key(s): " + ", ".join(missing)
            + " (the config layer gap-fills the built-in defaults)")

    provider = ai_cfg["provider"]
    if not isinstance(provider, str) or provider not in PROVIDERS:
        raise AiConfigError(
            f"config ai.provider must be one of {list(PROVIDERS)}, "
            f"got {provider!r}")

    base_url = _require_str("base_url", ai_cfg["base_url"])
    model = _require_str("model", ai_cfg["model"])

    dims = ai_cfg["dims"]
    if isinstance(dims, bool) or not isinstance(dims, int) or dims <= 0:
        raise AiConfigError(
            f"config ai.dims must be a positive int, got {dims!r}")

    # Prefixes may legitimately be "" (a model that needs no prefix);
    # they are never mixed and never replaced by the engine's constants.
    doc_prefix = _require_str("doc_prefix", ai_cfg["doc_prefix"],
                              allow_empty=True)
    query_prefix = _require_str("query_prefix", ai_cfg["query_prefix"],
                                allow_empty=True)

    timeout = ai_cfg["timeout_s"]
    if timeout is not None:
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) \
                or timeout <= 0:
            raise AiConfigError(
                "config ai.timeout_s must be a positive number or null, "
                f"got {timeout!r}")
        timeout = float(timeout)

    return ProviderSettings(
        provider=provider, base_url=base_url, model=model, dims=dims,
        doc_prefix=doc_prefix, query_prefix=query_prefix, timeout_s=timeout)


def is_loopback_url(base_url: str) -> bool:
    """True when the configured address stays on this machine.

    Disclosure predicate only — it never refuses a value (GAP-4: the
    user's own box, explicit config). Disclosure is scheme AND authority
    (P2-03): only ``http``/``https`` can be a loopback NETWORK address, so
    any other scheme (``file://``, ``data:``, ``gopher://``, ...) is NOT
    loopback whatever its authority — a loopback hostname must never make
    ``file://127.0.0.1/...`` silent. For http(s), a literal IP must parse
    as loopback and ``localhost`` is loopback; anything else is NOT.
    tests/test_aihook.py pins agreement with the proxy rail's
    ``_is_loopback`` for real http hosts so the two notions cannot drift.
    """
    parts = urlsplit(base_url)
    if (parts.scheme or "").lower() not in ("http", "https"):
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def non_loopback_warning(base_url: str) -> str:
    """The ONE disclosure text (banner and run meta share it)."""
    return (f"ai.base_url is NOT loopback ({base_url}) — redacted event "
            "text is sent to that address (explicit config; the loopback "
            "default keeps it on this machine). See docs/AI-INTEGRATION.md.")


def provider_meta(ai_cfg) -> dict:
    """The ``ai`` section of watchdog-run.json — provider choice made
    visible in the run state, including the non-loopback disclosure."""
    s = parse_ai(ai_cfg)
    loopback = is_loopback_url(s.base_url)
    return {
        "provider": s.provider,
        "base_url": s.base_url,
        "model": s.model,
        "dims": s.dims,
        "loopback": loopback,
        "warning": None if loopback else non_loopback_warning(s.base_url),
    }


def ai_banner_lines(ai_cfg) -> list[str]:
    """Startup banner lines for the provider (1 line, or 2 when the
    configured address is not loopback — never silent)."""
    s = parse_ai(ai_cfg)
    loopback = is_loopback_url(s.base_url)
    lines = [f"  ai:      {s.provider} {s.model} @ {s.base_url}"
             + (" (loopback)" if loopback else "")]
    if not loopback:
        lines.append("  WARNING: " + non_loopback_warning(s.base_url))
    return lines