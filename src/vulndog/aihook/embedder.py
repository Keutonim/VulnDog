"""The config-driven embedder factory (M2.4, ADR-6 / R9).

Supplies the embedder the engine's match path consumes. The engine is
vendored and READ-ONLY (ADR-1): nothing here edits an engine module.
Extension happens through the engine's OWN published seams:

- ``EmbeddingClient(transport=...)`` — the injectable transport
  (``embed_client.py:83-91``). The provider re-targets the request URL
  through it, so the engine's retry/backoff, batching, stats, response
  shape check and sha cache stay the single implementation.
- ``query.make_transient_embedder()`` — the engine's transient query-side
  door. For the STOCK default provider the factory delegates to it, so
  the engine's law (and its offline stub seam, used by the M1.4 drill)
  stays in charge of the default path instead of being imitated.
- ``config["embedder"]`` — the facade's injection key (``engine/api.py``);
  the CLI hands the factory's result through it.

GAP-4 decision D15: provider choice ONLY. The embedder remains mandatory
in the match path — the engine embeds BEFORE exact-id pin resolution, so
a provider outage yields ``skipped``/``embed-failed`` envelopes with zero
matches (pins included). No fts-only / no-AI mode exists or is claimed.

Cache law (reused, never reimplemented): keys are the engine's
``cache_key(model, prefixed_text)`` sha256, so changing ``ai.model``
auto-invalidates every cached vector; the KB store must be rebuilt with
the same model (docs/VULNERABILITY-DB.md).
"""
from __future__ import annotations

import json
import tempfile
import urllib.request
from functools import partial

from vulndog.aihook.provider import ProviderSettings, parse_ai
from vulndog.engine import embed_client as ec
from vulndog.engine import query as qy


def is_engine_default(settings: ProviderSettings) -> bool:
    """True when every configured value IS the engine's built-in constant
    (ADR-6: the default reproduces ``embed_client.py:31-45`` exactly)."""
    return (settings.provider == "ollama"
            and settings.base_url == ec.OLLAMA_BASE_URL
            and settings.model == ec.DEFAULT_MODEL
            and settings.dims == ec.EXPECTED_DIMS
            and settings.doc_prefix == ec.DOC_PREFIX
            and settings.query_prefix == ec.QUERY_PREFIX
            and settings.timeout_s in (None, ec.DEFAULT_TIMEOUT_S))


# ------------------------------------------- P2-07: capped response read
#
# The engine's _default_transport reads the provider body without a size
# cap (embed_client.py:90-91). The engine is vendored READ-ONLY (ADR-1), so
# the cap lives HERE, at the ProviderEmbedder transport seam. The ceiling
# is the engine's own request shape: one response carries at most
# DEFAULT_BATCH_SIZE vectors of ``dims`` floats (the client validates the
# batch length and every vector's dims), so a legitimate body cannot exceed
# that many JSON numbers. Over-cap -> ProviderResponseTooLarge, which the
# engine's retry loop wraps into EmbeddingError — the SAME fail-closed
# outage path (skipped/embed-failed), never an unbounded allocation.

#: Bytes per JSON number in a vector: a float64 repr is <= 24 chars
#: (e.g. "-1.2345678901234567e-05"); 32 leaves room for sign, digits and
#: the comma separator — a documented, generous per-element ceiling.
_BYTES_PER_JSON_NUMBER = 32
#: Slack for the response envelope ({"embeddings": ...}, provider metadata
#: keys, whitespace) beyond the vector numbers themselves.
_RESPONSE_ENVELOPE_SLACK = 4096


def response_cap_bytes(dims: int) -> int:
    """The provider response read ceiling for a configured dimensionality.

    Derived from the engine's request caps (the ceiling): at most
    ``embed_client.DEFAULT_BATCH_SIZE`` vectors of ``dims`` numbers per
    response, ``_BYTES_PER_JSON_NUMBER`` bytes each, plus envelope slack.
    Scales with the configured dims so a larger model gets a larger — but
    still bounded — ceiling.
    """
    return (ec.DEFAULT_BATCH_SIZE * dims * _BYTES_PER_JSON_NUMBER
            + _RESPONSE_ENVELOPE_SLACK)


class ProviderResponseTooLarge(RuntimeError):
    """The provider response body exceeds the seam's read cap (P2-07).

    A transport-level failure: the engine's retry loop wraps it into
    EmbeddingError after bounded retries, so the match path reports the
    honest skipped/embed-failed envelope (the outage law) — never a crash
    and never an unbounded allocation. The message carries only the cap,
    never the body content (the no-captured-content law).
    """


def _read_capped(resp, cap_bytes: int) -> bytes:
    """Read at most ``cap_bytes`` from a provider response.

    A declared Content-Length over the cap is refused before any body byte
    is read; otherwise the read is bounded to cap+1 bytes so an over-cap
    body (chunked / no declared length) is detected without allocating it
    whole. The +1 distinguishes "exactly at the cap" from "over the cap".
    """
    declared = resp.headers.get("Content-Length")
    if declared is not None:
        try:
            length = int(declared)
        except ValueError:
            length = None  # malformed declared length -> bounded read decides
        if length is not None and length > cap_bytes:
            raise ProviderResponseTooLarge(
                f"provider response Content-Length {declared} exceeds "
                f"the {cap_bytes}-byte read cap")
    body = resp.read(cap_bytes + 1)
    if len(body) > cap_bytes:
        raise ProviderResponseTooLarge(
            f"provider response body exceeds the {cap_bytes}-byte read cap")
    return body


def _capped_transport(url: str, payload: dict, timeout: float, *,
                      cap_bytes: int, opener=None) -> dict:
    """The aihook seam's HTTP transport: the engine's request shape and
    no-proxy opener discipline, with a BOUNDED response read (P2-07).

    The opener is resolved through ``ec.make_no_proxy_opener`` at call time
    (the engine's single no-proxy implementation, and the injectable test
    seam); ``opener`` overrides it for a direct fake-transport test. The
    request mirrors ``embed_client._default_transport`` field for field —
    only the response read is capped.
    """
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    opener = opener if opener is not None else ec.make_no_proxy_opener()
    with opener.open(req, timeout=timeout) as resp:
        return json.loads(_read_capped(resp, cap_bytes).decode("utf-8"))


class ProviderEmbedder(ec.EmbeddingClient):
    """The engine's embedding client, parameterized by ``ai.*``.

    Inherits the engine's transport retry/backoff, token-budget batching,
    sha cache (``cache_key`` / ``_cache_path`` / ``_cache_put``), repair
    log and stats. Four seams are overridden, each because the engine
    hardcodes the corresponding value:

    - the request URL (engine: the single loopback constant) — re-targeted
      through the injectable transport, verbatim ``base_url + EMBED_PATH``;
    - the doc/query prefixes (engine: the EmbeddingGemma constants);
    - the expected dimensionality (engine: 768) — ``_embed_many`` and
      ``_cache_get`` are mirrored with ``self.dims`` passed to the
      engine's OWN ``validate_vector``; every helper they call is the
      engine's, so no cache/batch/validation logic is reimplemented.

    Query vectors are TRANSIENT by default (``use_cache=False`` + a temp
    cache dir), exactly like ``query.make_transient_embedder`` (design
    section 6 / C16). Callers that want the sha cache (doc-side builds,
    cache-invalidation tests) pass ``cache_dir`` and ``use_cache=True``.
    """

    def __init__(self, settings: ProviderSettings, *, cache_dir: str | None = None,
                 use_cache: bool = False, transport=None,
                 max_retries: int | None = None,
                 retry_backoff_s: float | None = None):
        self.settings = settings
        self.dims = settings.dims
        #: VERBATIM concatenation — the engine builds OLLAMA_BASE_URL +
        #: EMBED_PATH; the provider does the same with the configured
        #: string (no normalization: what was configured is what is sent).
        self.embed_url = settings.base_url + ec.EMBED_PATH
        # P2-07: the default transport is the aihook seam's CAPPED variant
        # (_capped_transport) — the engine's _default_transport reads the
        # body uncapped and is vendored READ-ONLY (ADR-1). The capped variant
        # reuses the engine's request shape and its no-proxy opener
        # (ec.make_no_proxy_opener), so the no-proxy discipline stays
        # single-sourced; only the response read is bounded. An injected
        # transport (the test seam) is used verbatim.
        self._response_cap_bytes = response_cap_bytes(settings.dims)
        self._inner_transport = transport if transport is not None \
            else partial(_capped_transport, cap_bytes=self._response_cap_bytes)
        timeout_s = settings.timeout_s if settings.timeout_s is not None \
            else ec.DEFAULT_TIMEOUT_S
        extra = {}
        if max_retries is not None:
            extra["max_retries"] = max_retries
        if retry_backoff_s is not None:
            extra["retry_backoff_s"] = retry_backoff_s
        super().__init__(
            cache_dir=cache_dir or tempfile.mkdtemp(prefix="vkb-aihook-"),
            model=settings.model, timeout_s=timeout_s, use_cache=use_cache,
            transport=self._post, **extra)

    # -- seam 1: the address (the engine passes its loopback constant; the
    #    configured provider address is the one decision, made here once)
    def _post(self, engine_url: str, payload: dict, timeout: float) -> dict:
        """Transport adapter: the engine's constant URL is replaced by the
        configured ``embed_url``; payload and timeout pass through untouched."""
        return self._inner_transport(self.embed_url, payload, timeout)

    # -- seam 2: the trained prefixes (never mixed, C16)
    def embed_documents(self, texts):
        """Document-side embedding with the CONFIGURED ``doc_prefix``."""
        return self._embed_many([self.settings.doc_prefix + t for t in texts])

    def embed_query(self, text: str):
        """Query-side embedding with the CONFIGURED ``query_prefix``."""
        return self._embed_many([self.settings.query_prefix + text])[0]

    # -- seam 3: dimensionality (one decision: self.dims)
    def _validate(self, vec) -> None:
        ec.validate_vector(vec, self.dims)

    def _cache_get(self, key: str):
        """The engine's cache read, validated at the CONFIGURED dims."""
        p = self._cache_path(key)
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            vec = data["v"]
            self._validate(vec)
            return vec
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, KeyError, ec.EmbeddingValidationError):
            return None  # corrupt cache entry -> refetch

    def _embed_many(self, prefixed_texts):
        """The engine's embed orchestration at the CONFIGURED dims.

        Structurally identical to ``EmbeddingClient._embed_many``; the
        only difference is ``self._validate`` (dims) in place of the
        engine's hardcoded 768-dim ``validate_vector`` call. Cache keys,
        cache writes, batching, the API call, the repair log and the
        stats counters are all the inherited engine implementations.
        """
        results = [None] * len(prefixed_texts)
        missing = []
        for i, pt in enumerate(prefixed_texts):
            key = ec.cache_key(self.model, pt)
            vec = self._cache_get(key) if self.use_cache else None
            if vec is not None:
                results[i] = vec
                self.stats["cache_hits"] += 1
            else:
                missing.append((i, pt, key))
        for batch in self._group_batches(missing):
            vectors = self._call_api([pt for _, pt, _ in batch])
            if len(vectors) != len(batch):
                self._log_repair("empty-or-invalid-embedding",
                                 f"batch response length {len(vectors)} != {len(batch)}")
                self.stats["validation_failures"] += 1
                raise ec.EmbeddingValidationError(
                    f"batch response length {len(vectors)} != {len(batch)}")
            for (i, _, key), vec in zip(batch, vectors):
                try:
                    self._validate(vec)
                except ec.EmbeddingValidationError as e:
                    self.stats["validation_failures"] += 1
                    self._log_repair("empty-or-invalid-embedding", str(e))
                    raise
                if self.use_cache:
                    self._cache_put(key, vec)
                results[i] = vec
        return results


def build_embedder(ai_cfg, *, cache_dir: str | None = None,
                   use_cache: bool = False, transport=None,
                   max_retries: int | None = None,
                   retry_backoff_s: float | None = None) -> ec.EmbeddingClient:
    """The provider factory: ``ai.*`` -> the engine's embedder.

    Args:
        ai_cfg: the merged ``ai`` config section (all keys gap-filled by
            vulndog.config). Invalid shape raises AiConfigError.
        cache_dir: sha-cache directory. None + ``use_cache=False`` (the
            match-path default) means transient query vectors.
        use_cache: enable the engine's sha cache (doc-side / cache tests).
        transport: the engine's injectable transport seam (tests).
        max_retries / retry_backoff_s: transport tuning; None keeps the
            engine's defaults (2 retries, 1 s backoff).

    Returns:
        For the STOCK default provider with no caller-specific request
        (no transport, no cache_dir, transient): the engine's own
        ``query.make_transient_embedder()`` result — the default path is
        the engine's, seams included. Otherwise a :class:`ProviderEmbedder`
        carrying the configured values verbatim.
    """
    settings = parse_ai(ai_cfg)
    stock_request = transport is None and cache_dir is None and not use_cache
    if stock_request and is_engine_default(settings):
        return qy.make_transient_embedder()
    return ProviderEmbedder(settings, cache_dir=cache_dir, use_cache=use_cache,
                            transport=transport, max_retries=max_retries,
                            retry_backoff_s=retry_backoff_s)