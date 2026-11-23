"""Loopback-only embedding client for the vuln-watchdog KB (design-spec 5.1, plan F2).

Hard requirements (traced to the design):
- Exactly ONE address: the module constant ``OLLAMA_BASE_URL``
  (http://127.0.0.1:11434). The client constructor deliberately exposes no
  host/url parameter; proxy environment variables are NOT honored
  (``ProxyHandler({})``); no net_gate involvement (C7).
- MANDATORY EmbeddingGemma trained prefixes: documents
  ``"title: none | text: "``, queries ``"task: search result | query: "``.
  The two are never mixed (C16).
- Every returned vector is validated: exactly 768 dims, all finite,
  non-empty (known Ollama empty-embedding bug); failures land in a
  retry/repair log.
- Cache: one file per ``sha256(model + "\\n" + prefixed_text)`` under the
  cache dir; atomic write (tmp + os.replace) so interrupted passes resume
  with zero re-embedding of completed chunks.
- Per-call timeout, default 10 s (Security C-3 / SEC-09); bounded retries
  with backoff, then EmbeddingError (the caller degrades, never hangs).
- Pure stdlib (urllib, json, hashlib, time, os). No new deps (C4).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import time
import urllib.request

# --- the single constant address: loopback only, by construction -----------
OLLAMA_BASE_URL = "http://127.0.0.1:11434"
EMBED_PATH = "/api/embed"

DEFAULT_MODEL = "embeddinggemma:300m"
FALLBACK_MODEL = "nomic-embed-text:latest"  # swap = config change; sha cache auto-invalidates
EXPECTED_DIMS = 768

# EmbeddingGemma trained prefixes (mandatory, never mixed)
DOC_PREFIX = "title: none | text: "
QUERY_PREFIX = "task: search result | query: "

DEFAULT_TIMEOUT_S = 10.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_RETRY_BACKOFF_S = 1.0
DEFAULT_BATCH_SIZE = 32
# Token-budget batching (P0 incident fix 2026-10-15): a fixed-count batch of
# 16 large chunks is ~28k real tokens ~= 17 s at the measured ~1700 tok/s
# prefill rate -- over the 10 s spec timeout (C-3). Batches are therefore
# bounded by BOTH text count and estimated tokens (~4 chars/token), sized so
# a worst-case call stays well under the timeout. The timeout itself is NOT
# raised: it is the design-mandated hang guard.
DEFAULT_BATCH_MAX_EST_TOKENS = 4000


class EmbeddingError(RuntimeError):
    """Transport-level failure (down, hung, bad HTTP) after retries."""


class EmbeddingValidationError(EmbeddingError):
    """The service answered but the vector failed validation."""


def cache_key(model: str, prefixed_text: str) -> str:
    """sha256(model + "\\n" + prefixed_text) -- model swap auto-invalidates."""
    return hashlib.sha256((model + "\n" + prefixed_text).encode("utf-8")).hexdigest()


def make_no_proxy_opener() -> urllib.request.OpenerDirector:
    """Opener that ignores proxy env vars (loopback-only contract)."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def build_embed_request(payload: dict) -> urllib.request.Request:
    req = urllib.request.Request(
        OLLAMA_BASE_URL + EMBED_PATH,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    return req


def _default_transport(url: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with make_no_proxy_opener().open(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def validate_vector(vec, expected_dims: int = EXPECTED_DIMS) -> None:
    """Exactly expected_dims dims, all finite, non-empty. Raises otherwise."""
    if vec is None:
        raise EmbeddingValidationError("empty-or-invalid-embedding: None")
    try:
        n = len(vec)
    except TypeError:
        raise EmbeddingValidationError("empty-or-invalid-embedding: not a list")
    if n == 0:
        raise EmbeddingValidationError("empty-or-invalid-embedding: zero dims")
    if n != expected_dims:
        raise EmbeddingValidationError(
            f"empty-or-invalid-embedding: {n} dims, expected {expected_dims}")
    for x in vec:
        if not isinstance(x, (int, float)) or not math.isfinite(x):
            raise EmbeddingValidationError("empty-or-invalid-embedding: non-finite value")


class EmbeddingClient:
    """Embed via loopback Ollama with prefix discipline, sha cache, validation.

    ``transport(url, payload, timeout) -> dict`` is injectable for tests;
    the default performs a real HTTP POST to the single constant address.
    """

    def __init__(
        self,
        cache_dir: str,
        model: str = DEFAULT_MODEL,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_s: float = DEFAULT_RETRY_BACKOFF_S,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_max_est_tokens: int = DEFAULT_BATCH_MAX_EST_TOKENS,
        transport=None,
        repair_log_path: str | None = None,
        use_cache: bool = True,
    ):
        self.model = model
        self.use_cache = use_cache
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self.batch_size = max(1, int(batch_size))
        self.batch_max_est_tokens = max(1, int(batch_max_est_tokens))
        self._transport = transport or _default_transport
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.repair_log_path = repair_log_path or os.path.join(cache_dir, "repair_log.jsonl")
        # counters (benchmarks read these)
        self.stats = {"cache_hits": 0, "api_texts": 0, "api_calls": 0,
                      "retries": 0, "validation_failures": 0}

    # -- public API (plan F2 interfaces) ------------------------------------

    def embed_documents(self, texts):
        """Document-side embedding. Applies DOC_PREFIX to EVERY text."""
        return self._embed_many([DOC_PREFIX + t for t in texts])

    def embed_query(self, text: str):
        """Query-side embedding. Applies QUERY_PREFIX.

        The sha cache is keyed on the PREFIXED text, so doc-side and
        query-side entries can never cross-contaminate. NOTE: the live
        matching loop (B3) treats query vectors as transient; benchmark
        runs may disable caching by pointing cache_dir at a temp dir.
        """
        return self._embed_many([QUERY_PREFIX + text])[0]

    # -- internals -----------------------------------------------------------

    def _cache_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, key + ".json")

    def _cache_get(self, key: str):
        p = self._cache_path(key)
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            vec = data["v"]
            validate_vector(vec)
            return vec
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, KeyError, EmbeddingValidationError):
            return None  # corrupt cache entry -> refetch

    def _cache_put(self, key: str, vec) -> None:
        p = self._cache_path(key)
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"model": self.model, "v": vec}, f)
        os.replace(tmp, p)  # atomic -> kill-safe resumability

    def _log_repair(self, kind: str, detail: str) -> None:
        try:
            with open(self.repair_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "kind": kind, "model": self.model, "detail": detail[:200],
                }) + "\n")
        except OSError:
            pass  # the repair log must never break the pipeline

    def _embed_many(self, prefixed_texts):
        results = [None] * len(prefixed_texts)
        missing = []
        for i, pt in enumerate(prefixed_texts):
            key = cache_key(self.model, pt)
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
                raise EmbeddingValidationError(
                    f"batch response length {len(vectors)} != {len(batch)}")
            for (i, _, key), vec in zip(batch, vectors):
                try:
                    validate_vector(vec)
                except EmbeddingValidationError as e:
                    self.stats["validation_failures"] += 1
                    self._log_repair("empty-or-invalid-embedding", str(e))
                    raise
                if self.use_cache:
                    self._cache_put(key, vec)
                results[i] = vec
        return results

    def _group_batches(self, missing):
        """Group cache-missing items into API batches bounded by BOTH text
        count (batch_size) and estimated tokens (batch_max_est_tokens,
        ~4 chars/token on the PREFIXED text). A single text over the token
        budget is sent alone (chunking already caps texts at ~2000 est
        tokens, well under the default budget)."""
        batch = []
        budget = 0
        for item in missing:
            cost = -(-len(item[1]) // 4)
            if batch and (len(batch) >= self.batch_size
                          or budget + cost > self.batch_max_est_tokens):
                yield batch
                batch = []
                budget = 0
            batch.append(item)
            budget += cost
        if batch:
            yield batch

    def _call_api(self, prefixed_texts):
        payload = {"model": self.model, "input": list(prefixed_texts)}
        self.stats["api_texts"] += len(prefixed_texts)
        attempt = 0
        while True:
            try:
                self.stats["api_calls"] += 1
                resp = self._transport(OLLAMA_BASE_URL + EMBED_PATH, payload, self.timeout_s)
                if not isinstance(resp, dict) or "embeddings" not in resp:
                    raise EmbeddingValidationError(
                        "empty-or-invalid-embedding: response has no 'embeddings' key")
                return resp["embeddings"]
            except EmbeddingValidationError:
                raise  # validation failures are not retried here (caller logs/raises)
            except Exception as e:  # transport-level: timeout, refused, HTTP, JSON
                if attempt >= self.max_retries:
                    raise EmbeddingError(
                        f"ollama call failed after {attempt + 1} attempts: {e!r}") from e
                attempt += 1
                self.stats["retries"] += 1
                if self.retry_backoff_s:
                    time.sleep(self.retry_backoff_s * attempt)
