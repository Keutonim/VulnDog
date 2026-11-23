"""P2-07 — the provider response read is capped at the aihook transport seam.

The vendored engine's ``_default_transport`` does an uncapped ``resp.read()``
(security-p2 P2-07, probe B10: a 20 MB body was accepted). The engine is
ADR-1 frozen, so the cap lives in the ``ProviderEmbedder`` transport seam
(``aihook/embedder.py``), NOT in ``engine/embed_client.py``. The ceiling is
derived from the engine's request caps (at most ``DEFAULT_BATCH_SIZE``
vectors of ``dims`` floats per response); an over-cap body fails closed
through the SAME outage path (bounded retries -> EmbeddingError ->
``skipped``/``embed-failed``), never an unbounded allocation.

Offline + deterministic: a fake opener serves a fake response object that
records every read size, so "bounded memory" is asserted on the actual
``read(n)`` calls — never on a mock's own behaviour. No network egress.

Boundary (honest): the STOCK default provider delegates to the engine's own
transient door (``query.make_transient_embedder``), which stays the engine's
byte-identical client (ADR-6, pinned elsewhere). The cap applies to the
aihook-owned ``ProviderEmbedder`` transport — the custom-provider path the
finding exercises. Capping the engine's own door would edit the vendored
engine (forbidden) or break the byte-identical default pin.
"""
from __future__ import annotations

import json

import pytest

from vulndog import config
from vulndog.aihook.embedder import build_embedder
from vulndog.engine import embed_client as ec

#: dims=4 keeps the cap small so an oversized body is cheap to build.
PROVIDER_AI = dict(provider="custom", base_url="http://127.0.0.1:11500",
                   model="test-embed:4d", dims=4, doc_prefix="doc: ",
                   query_prefix="query: ", timeout_s=1.0)


def provider_ai() -> dict:
    cfg = config.builtin_defaults()["ai"]
    cfg.update(PROVIDER_AI)
    return cfg


class FakeResponse:
    """A provider response object: records every read size, serves a body.

    ``read(n)`` mirrors urllib's contract (n<0 / omitted -> the whole body).
    ``headers`` is a plain dict (``.get`` works like the real message)."""

    def __init__(self, body: bytes, headers: dict | None = None):
        self.body = body
        self.headers = headers if headers is not None else {}
        self.read_sizes: list[int] = []

    def read(self, n: int = -1) -> bytes:
        self.read_sizes.append(n)
        return self.body if n is None or n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """The no-proxy opener seam: returns the fake response for any request."""

    def __init__(self, response: FakeResponse):
        self.response = response
        self.requests = []

    def open(self, req, timeout=None):
        self.requests.append((req, timeout))
        return self.response


def _patch_opener(monkeypatch, response: FakeResponse) -> FakeOpener:
    opener = FakeOpener(response)
    monkeypatch.setattr(ec, "make_no_proxy_opener", lambda: opener)
    return opener


# ------------------------------------------- over-cap fails closed (bounded)


def test_oversized_provider_response_is_bounded_and_fails_closed(
        tmp_path, monkeypatch):
    """A body over the cap — even VALID embeddings JSON that would otherwise
    succeed — is rejected through the outage path, and every read is bounded
    (never the whole body). The padding key makes the body oversized while
    keeping the vector count/dims valid, so the uncapped path would accept it."""
    body = json.dumps({"embeddings": [[0.5] * 4],
                       "padding": "x" * 20000}).encode("utf-8")
    resp = FakeResponse(body)
    _patch_opener(monkeypatch, resp)
    emb = build_embedder(provider_ai(), retry_backoff_s=0.0)

    with pytest.raises(ec.EmbeddingError):
        emb.embed_query("x")

    assert resp.read_sizes, "the provider response was actually read"
    assert all(0 < n < len(body) for n in resp.read_sizes), \
        "every read is bounded below the full body size (no unbounded read)"


def test_declared_over_cap_content_length_is_rejected_before_reading(
        tmp_path, monkeypatch):
    """A declared Content-Length over the cap is refused before any body
    byte is read (the declared-length check)."""
    resp = FakeResponse(b'{"embeddings": [[0.5, 0.5, 0.5, 0.5]]}',
                        headers={"Content-Length": "999999"})
    _patch_opener(monkeypatch, resp)
    emb = build_embedder(provider_ai(), retry_backoff_s=0.0)

    with pytest.raises(ec.EmbeddingError):
        emb.embed_query("x")

    assert resp.read_sizes == [], "rejected on declared length; body never read"


def test_legitimate_under_cap_response_succeeds(tmp_path, monkeypatch):
    """Negative control: a normal-sized valid response is accepted unchanged
    (the cap must not over-reject legitimate provider answers)."""
    body = json.dumps({"embeddings": [[0.5] * 4]}).encode("utf-8")
    resp = FakeResponse(body, headers={"Content-Length": str(len(body))})
    _patch_opener(monkeypatch, resp)
    emb = build_embedder(provider_ai(), retry_backoff_s=0.0)

    assert emb.embed_query("x") == [0.5] * 4


# ------------------------------------------- the documented ceiling + seam


def test_response_cap_is_derived_from_engine_request_caps():
    """The ceiling is the engine's request shape: DEFAULT_BATCH_SIZE vectors
    of dims numbers, 32 bytes per JSON number, 4 KiB envelope slack. It
    scales with dims and stays above a worst-case legitimate batch."""
    from vulndog.aihook.embedder import response_cap_bytes

    assert response_cap_bytes(768) == ec.DEFAULT_BATCH_SIZE * 768 * 32 + 4096
    assert response_cap_bytes(4) < response_cap_bytes(768)
    # a worst-case legitimate batch (32 x 768 float64 reprs, ~24 bytes each)
    # fits comfortably under the cap — no over-rejection of real answers
    assert response_cap_bytes(768) > ec.DEFAULT_BATCH_SIZE * 768 * 24


def test_default_seam_carries_the_response_cap():
    """The custom-provider default transport is the capped seam variant,
    not the engine's uncapped _default_transport (ADR-1: engine untouched)."""
    from vulndog.aihook.embedder import ProviderEmbedder, response_cap_bytes

    emb = build_embedder(provider_ai())
    assert isinstance(emb, ProviderEmbedder)
    assert emb._response_cap_bytes == response_cap_bytes(4)
    assert emb._inner_transport is not ec._default_transport


def test_capped_transport_rejects_a_fake_oversized_body():
    """The brief's fake-transport test, at the seam directly: a fake opener
    serving an oversized body -> ProviderResponseTooLarge, bounded read."""
    from vulndog.aihook.embedder import (ProviderResponseTooLarge,
                                         _capped_transport, response_cap_bytes)

    cap = response_cap_bytes(4)
    body = (b'{"embeddings": [[0.5, 0.5, 0.5, 0.5]], "padding": "'
            + b"x" * (cap + 100) + b'"}')
    resp = FakeResponse(body)
    with pytest.raises(ProviderResponseTooLarge):
        _capped_transport("http://127.0.0.1:11500" + ec.EMBED_PATH,
                          {"model": "m", "input": ["q"]}, 1.0,
                          cap_bytes=cap, opener=FakeOpener(resp))
    assert resp.read_sizes and all(0 < n <= cap + 1 for n in resp.read_sizes)


def test_over_cap_response_yields_the_outage_envelope(tmp_path, monkeypatch):
    """Over-cap fails closed through the SAME path the outage law uses:
    the match path reports skipped/embed-failed with zero matches AND zero
    pins (never a crash, never a silent zero reported as success)."""
    from vulndog.engine import query as qy
    from vulndog.engine.tests.test_api import build_fixture_store

    store = build_fixture_store(str(tmp_path / "kb.sqlite"))
    body = json.dumps({"embeddings": [[0.5] * 4],
                       "padding": "x" * 20000}).encode("utf-8")
    _patch_opener(monkeypatch, FakeResponse(body))
    emb = build_embedder(provider_ai(), retry_backoff_s=0.0)
    api_obj = qy.QueryAPI(store_path=store, embedder=emb)

    env = api_obj.match("GET /login.php login redirect xss")

    assert env["status"] == "skipped"
    assert env["reason"] == "embed-failed"
    assert env["matches"] == [] and env["pinned"] == 0
    assert "EmbeddingError" in env["detail"]