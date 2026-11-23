"""VulnDog AI hook (M2.4, ADR-6 / R9) — config-driven embedding provider.

Two doors, split along the engine dependency:

- :mod:`vulndog.aihook.provider` — PURE config shape + disclosure. Parses
  the merged ``ai.*`` section (:func:`parse_ai`), classifies the address
  (:func:`is_loopback_url`) and renders the run banner / run-meta lines
  (:func:`ai_banner_lines`, :func:`provider_meta`). No engine import, so
  the config layer can validate ``ai.*`` at startup even when the engine
  half is absent.
- :mod:`vulndog.aihook.embedder` — the engine-dependent factory
  (``build_embedder``): supplies the embedder the engine's match path
  consumes. Imported lazily by the CLI once the engine half is confirmed.

GAP-4 decision D15: "optional AI" = PROVIDER CHOICE ONLY. The embedder
stays mandatory in the match path (the engine embeds BEFORE exact-id pin
resolution); there is no fts-only / no-AI mode in this package, in the
engine, or in the docs. Outage behaviour is the engine's own law:
per-event ``skipped``/``embed-failed`` envelopes with zero matches,
down-mode buffering, in-order replay on recovery.

The engine modules are vendored and READ-ONLY (ADR-1): this package
extends them through their published seams (the injectable transport,
the ``config["embedder"]`` injection key, ``query.make_transient_embedder``)
and never edits them.
"""
from __future__ import annotations

from vulndog.aihook.provider import (
    PROVIDERS,
    AiConfigError,
    ProviderSettings,
    ai_banner_lines,
    is_loopback_url,
    non_loopback_warning,
    parse_ai,
    provider_meta,
)

__all__ = [
    "PROVIDERS",
    "AiConfigError",
    "ProviderSettings",
    "ai_banner_lines",
    "is_loopback_url",
    "non_loopback_warning",
    "parse_ai",
    "provider_meta",
]