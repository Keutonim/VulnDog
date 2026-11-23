"""Tiny KB fixture for the M3.1 `vulndog db` tests (dev-h).

The fixture lives under tests/, never in the package. It REUSES the
engine's own recipe machinery: the four mini archives come from
``vulndog.engine.tests.test_corpus.mini_archives`` (the same hand-
traceable corpus the engine build/corpus suites use), and the embedder
double is the engine suite's FakeTransport pattern (deterministic
per-text vectors through the real EmbeddingClient transport seam).

No test here touches the network or the real 1.93 GiB store. The full
build is an operator action (docs/VULNERABILITY-DB.md); these tests
prove the machinery on a handful of archived records.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from vulndog.engine import embed_client as ec
from vulndog.engine.tests.test_corpus import mini_archives


def text_vector(text: str, dims: int = 768) -> list[float]:
    """Deterministic per-text vector (engine test_build.py pattern)."""
    seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
    return [(((seed + i) % 89) / 89.0) - 0.5 for i in range(dims)]


class FakeTransport:
    """Ollama /api/embed double: deterministic vectors, no network."""

    def __init__(self, dims: int = 768):
        self.dims = dims
        self.calls = 0

    def __call__(self, url, payload, timeout):
        self.calls += 1
        inputs = payload["input"]
        return {"embeddings": [text_vector(t, self.dims) for t in inputs]}


def make_raw_dir(tmp: Path) -> Path:
    """The four mini archives in a fresh directory (engine machinery)."""
    raw = tmp / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    mini_archives(str(raw))
    return raw


def make_embedder(cache_dir: Path) -> ec.EmbeddingClient:
    """A real EmbeddingClient with the fake transport injected — the
    documented offline seam (embed_client transport injection)."""
    return ec.EmbeddingClient(cache_dir=str(cache_dir),
                              transport=FakeTransport(),
                              max_retries=0, retry_backoff_s=0)


def build_fixture_store(raw_dir: Path, store_dir: Path, *,
                        stage: str = "slice", recipe_path=None,
                        embedder=None) -> dict:
    """Build the tiny store through the ENGINE runner + the db-layer
    digest stamp — the same two steps `vulndog db build` performs.
    Returns the run_build summary."""
    from vulndog.engine import build as bd
    from vulndog.db import integrity

    store_dir.mkdir(parents=True, exist_ok=True)
    if embedder is None:
        embedder = make_embedder(store_dir / "embed_cache")
    summary = bd.run_build(stage, raw_dir=str(raw_dir),
                           store_dir=str(store_dir),
                           recipe_path=recipe_path,
                           embedder=embedder, embed_batch=2,
                           commit_every=4, progress_every=1000,
                           embed_max_retries=0, embed_retry_backoff_s=0,
                           log=lambda msg: None)
    if summary["exit_code"] == 0:
        integrity.stamp_store_digest(str(store_dir))
    return summary