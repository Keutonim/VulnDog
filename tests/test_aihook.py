"""AI provider abstraction (M2.4, ADR-6 / R9) — config-driven provider glue.

GAP-4 decision D15: "optional AI" = PROVIDER CHOICE ONLY. The embedder
stays mandatory in the match path (engine law: query.py embeds BEFORE
pin resolution); no fts-only / no-AI mode is claimed or tested here.

This module covers the provider factory's data shape and its request
contract. The outage/recovery law (the engine's real behaviour) lives in
tests/test_aihook_outage.py.

Offline + deterministic: a fake transport records the outgoing request;
no Ollama, no network egress.
"""
from __future__ import annotations

import json
import os

import pytest

from vulndog import config
from vulndog.aihook import provider as pv
from vulndog.engine import embed_client as ec


def ai_cfg(**over) -> dict:
    """The merged ai section (the config layer gap-fills every key)."""
    cfg = config.builtin_defaults()["ai"]
    cfg.update(over)
    return cfg


# ------------------------------------------- defaults == engine constants


def test_default_settings_reproduce_engine_constants_byte_for_byte():
    """ADR-6: the ollama default is the engine's built-in client, not a
    re-derived approximation. String equality against embed_client.py."""
    s = pv.parse_ai(ai_cfg())
    assert s.provider == "ollama"
    assert s.base_url == ec.OLLAMA_BASE_URL
    assert s.model == ec.DEFAULT_MODEL
    assert s.doc_prefix == ec.DOC_PREFIX
    assert s.query_prefix == ec.QUERY_PREFIX
    assert s.dims == ec.EXPECTED_DIMS
    # null timeout = keep the engine's per-request default (resolved by
    # the engine-dependent factory layer, never re-derived here)
    assert s.timeout_s is None


def test_config_builtin_ai_defaults_equal_engine_constants():
    """The config layer's ai defaults (M2.1) are the same strings the
    engine ships — one byte-for-byte reproduction, pinned from both sides."""
    ai = config.builtin_defaults()["ai"]
    assert ai["base_url"] == ec.OLLAMA_BASE_URL
    assert ai["model"] == ec.DEFAULT_MODEL
    assert ai["doc_prefix"] == ec.DOC_PREFIX
    assert ai["query_prefix"] == ec.QUERY_PREFIX
    assert ai["dims"] == ec.EXPECTED_DIMS


# ------------------------------------------------------- boundary validation


@pytest.mark.parametrize("over", [
    {"provider": "openai"},          # only ollama | custom (ADR-6)
    {"provider": None},
    {"base_url": ""},
    {"base_url": 123},
    {"model": ""},
    {"model": None},
    {"dims": 0},
    {"dims": -768},
    {"dims": "768"},
    {"dims": True},                  # bool is not a dimensionality
    {"dims": 768.0},
    {"doc_prefix": None},
    {"query_prefix": 5},
    {"timeout_s": 0},
    {"timeout_s": -1.0},
    {"timeout_s": "10"},
])
def test_invalid_ai_config_fails_fast(over):
    with pytest.raises(pv.AiConfigError):
        pv.parse_ai(ai_cfg(**over))


def test_ai_config_error_is_value_error():
    """The CLI's usage-error path catches ValueError (same seam as scope)."""
    assert issubclass(pv.AiConfigError, ValueError)


def test_missing_ai_key_is_reported_not_silently_defaulted():
    cfg = ai_cfg()
    del cfg["model"]
    with pytest.raises(pv.AiConfigError, match="model"):
        pv.parse_ai(cfg)


def test_non_dict_ai_section_fails_fast():
    with pytest.raises(pv.AiConfigError):
        pv.parse_ai(None)


def test_empty_prefixes_are_legal_custom_provider_values():
    """A provider whose model needs no prefix configures "" — the value
    is carried verbatim, never replaced by the engine's prefixes."""
    s = pv.parse_ai(ai_cfg(provider="custom", doc_prefix="", query_prefix=""))
    assert s.doc_prefix == ""
    assert s.query_prefix == ""


def test_config_load_validates_ai_shape_at_startup():
    """One door: the shipped config load path fails fast on a wrong-typed
    ai value (the product fail-fast law, same as proxy/scope)."""
    def loader(path=None, task_id=None):
        return {"ai": {"dims": "768"}}

    with pytest.raises(ValueError):
        config.load_config(loader=loader)


# ------------------------------------------------- loopback / remote disclosure


@pytest.mark.parametrize("url,loopback", [
    ("http://127.0.0.1:11434", True),
    ("http://localhost:11434", True),
    ("http://127.5.5.5:11434", True),
    ("http://[::1]:11434", True),
    ("http://10.0.0.5:11434", False),
    ("https://embed.example.com", False),
    ("file:///tmp/embed.sock", False),
    ("", False),
])
def test_loopback_classification(url, loopback):
    assert pv.is_loopback_url(url) is loopback


def test_loopback_predicate_agrees_with_the_proxy_rail():
    """The disclosure predicate and the SSRF rail's loopback notion must
    not drift apart for real hosts (proxy._is_loopback is the rail's)."""
    from vulndog.proxy import _is_loopback

    for host in ("localhost", "127.0.0.1", "::1", "10.0.0.5",
                 "example.com", "192.168.1.10"):
        url = f"http://{host}:11434" if ":" not in host else f"http://[{host}]:11434"
        assert pv.is_loopback_url(url) == _is_loopback(host), host


def test_default_meta_is_loopback_and_carries_no_warning():
    meta = pv.provider_meta(ai_cfg())
    assert meta["provider"] == "ollama"
    assert meta["base_url"] == ec.OLLAMA_BASE_URL
    assert meta["model"] == ec.DEFAULT_MODEL
    assert meta["dims"] == ec.EXPECTED_DIMS
    assert meta["loopback"] is True
    assert meta["warning"] is None


@pytest.mark.parametrize("url", [
    "http://10.0.0.5:11434",
    "https://embed.example.com/v1",
    "file:///tmp/embed.sock",
])
def test_non_loopback_is_accepted_explicitly_and_never_silent(url):
    """GAP-4 scope: the user's own box — a non-loopback (or file://)
    base_url is ACCEPTED when explicitly configured, but disclosed."""
    s = pv.parse_ai(ai_cfg(provider="custom", base_url=url))
    assert s.base_url == url                      # verbatim, not normalized
    meta = pv.provider_meta(ai_cfg(provider="custom", base_url=url))
    assert meta["loopback"] is False
    assert url in meta["warning"]
    lines = pv.ai_banner_lines(ai_cfg(provider="custom", base_url=url))
    assert any("WARNING" in line and url in line for line in lines)


def test_default_banner_line_names_provider_model_and_address():
    lines = pv.ai_banner_lines(ai_cfg())
    assert len(lines) == 1
    assert "ollama" in lines[0]
    assert ec.DEFAULT_MODEL in lines[0]
    assert ec.OLLAMA_BASE_URL in lines[0]
    assert "WARNING" not in lines[0]


# ------------------------------------- P2-03: scheme is part of disclosure
#
# is_loopback_url inspected only the hostname, so a non-http(s) scheme with
# a loopback authority (file://127.0.0.1/..., file://localhost/...) classified
# as loopback and evaded the D15 "file:// never silent" law. Disclosure is
# scheme AND authority: only http(s) can be a loopback NETWORK address.


@pytest.mark.parametrize("url", [
    "file://127.0.0.1/tmp/embed.json",
    "file://localhost/tmp/embed.json",
    "file://[::1]/tmp/embed.json",
    "data://127.0.0.1/plain;base64,e30=",
    "gopher://127.0.0.1:11434/x",
    "ftp://localhost/embed.json",
])
def test_non_http_scheme_with_loopback_authority_is_disclosed(url):
    """A loopback authority does not make a non-http(s) scheme loopback.
    Every such form is disclosed in meta AND banner, exactly once."""
    assert pv.is_loopback_url(url) is False
    meta = pv.provider_meta(ai_cfg(provider="custom", base_url=url))
    assert meta["loopback"] is False
    assert url in meta["warning"]
    lines = pv.ai_banner_lines(ai_cfg(provider="custom", base_url=url))
    warnings = [line for line in lines if "WARNING" in line]
    assert len(warnings) == 1, "disclosed EXACTLY once (no duplicate warning)"
    assert url in warnings[0]


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:11434",
    "http://localhost:11434",
    "https://[::1]:11434",
])
def test_http_loopback_authority_stays_loopback(url):
    """Negative control: the scheme law must not over-broaden. A real
    http(s) loopback address is still loopback (no warning) — the
    rail-agreement pin (test_loopback_predicate_agrees_with_the_proxy_rail)
    stays green."""
    assert pv.is_loopback_url(url) is True
    assert pv.provider_meta(ai_cfg(provider="custom", base_url=url))["warning"] \
        is None


def test_file_url_embed_through_a_non_file_capable_transport_fails_explicitly():
    """P2-03 companion behaviour pin: an HTTP-only transport (one that
    refuses file://, like a real HTTP client) surfaces an EXPLICIT provider
    error after bounded retries — never a hang, never a silent zero vector.
    The disclosure above is the red-green fix; this pins the fail-closed
    embed path for the file:// case."""
    from vulndog.aihook.embedder import build_embedder

    class HttpOnlyTransport:
        def __init__(self):
            self.calls = []

        def __call__(self, url, payload, timeout):
            self.calls.append(url)
            if not url.startswith(("http://", "https://")):
                raise ValueError(f"unknown url type: {url.split(':', 1)[0]!r}")
            return {"embeddings": [[0.5] * 4]}

    fake = HttpOnlyTransport()
    cfg = ai_cfg(**CUSTOM)
    cfg["base_url"] = "file://127.0.0.1/tmp/embed.json"
    emb = build_embedder(cfg, transport=fake, retry_backoff_s=0.0)
    with pytest.raises(ec.EmbeddingError):
        emb.embed_query("x")
    assert len(fake.calls) == ec.DEFAULT_MAX_RETRIES + 1, "bounded, no hang"


# ------------------------------------------------- the embedder factory (M2.4)
#
# The engine's injectable transport seam (embed_client.py:83-91) is the
# observation point: everything below asserts on the request the provider
# ACTUALLY builds, never on a mock's own behaviour.


class RecordingTransport:
    """Fake transport: records (url, payload, timeout), answers or raises."""

    def __init__(self, vector=None, fail=False):
        self.calls = []
        self.vector = list(vector) if vector is not None else [0.25] * 768
        self.fail = fail

    def __call__(self, url, payload, timeout):
        self.calls.append({"url": url, "payload": json.loads(json.dumps(payload)),
                           "timeout": timeout})
        if self.fail:
            raise OSError("connection refused (fake transport)")
        return {"embeddings": [list(self.vector) for _ in payload["input"]]}


CUSTOM = dict(provider="custom", base_url="http://127.0.0.1:11500",
              model="other-embed:1b", dims=4, doc_prefix="doc: ",
              query_prefix="query: ", timeout_s=2.5)


def test_default_provider_uses_the_engine_transient_door():
    """ADR-6 'extends, never replaces': with the stock defaults the factory
    hands back the ENGINE's own transient query client (use_cache=False,
    temp cache dir) — byte-identical by construction, not by imitation."""
    from vulndog.aihook.embedder import build_embedder

    emb = build_embedder(ai_cfg())
    assert isinstance(emb, ec.EmbeddingClient)
    assert emb.use_cache is False
    assert emb.model == ec.DEFAULT_MODEL
    assert emb.timeout_s == ec.DEFAULT_TIMEOUT_S
    # the engine's OWN transport (loopback constant + no-proxy opener):
    # the default path is not a re-implementation of the engine client
    assert emb._transport is ec._default_transport


def test_default_provider_keeps_the_engine_embedder_seam_in_charge(monkeypatch):
    """The offline stub seam (query.make_transient_embedder, used by the
    M1.4 drill subprocess) must still win on the default provider path."""
    from vulndog.aihook.embedder import build_embedder
    from vulndog.engine import query as qy

    sentinel = object()
    monkeypatch.setattr(qy, "make_transient_embedder",
                        lambda cache_dir=None: sentinel)
    assert build_embedder(ai_cfg()) is sentinel


def test_custom_provider_builds_a_configured_client():
    from vulndog.aihook.embedder import ProviderEmbedder, build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    emb = build_embedder(ai_cfg(**CUSTOM), transport=fake)
    assert isinstance(emb, ProviderEmbedder)
    assert emb.model == "other-embed:1b"
    assert emb.dims == 4


def test_custom_query_request_carries_config_values_verbatim():
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    emb = build_embedder(ai_cfg(**CUSTOM), transport=fake)
    emb.embed_query("GET /login.php params=redirect")
    assert len(fake.calls) == 1
    call = fake.calls[0]
    assert call["url"] == "http://127.0.0.1:11500" + ec.EMBED_PATH
    assert call["payload"] == {
        "model": "other-embed:1b",
        "input": ["query: GET /login.php params=redirect"],
    }
    assert call["timeout"] == 2.5


def test_custom_document_request_carries_the_doc_prefix_verbatim():
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    emb = build_embedder(ai_cfg(**CUSTOM), transport=fake)
    emb.embed_documents(["chunk a", "chunk b"])
    assert fake.calls[0]["payload"]["input"] == ["doc: chunk a", "doc: chunk b"]
    assert fake.calls[0]["payload"]["model"] == "other-embed:1b"


def test_default_settings_request_is_byte_identical_to_the_engine_client(tmp_path):
    """The strongest form of the ADR-6 default law: the provider's outgoing
    request equals the ENGINE client's outgoing request, field for field."""
    from vulndog.aihook.embedder import ProviderEmbedder

    mine, theirs = RecordingTransport(), RecordingTransport()
    ProviderEmbedder(pv.parse_ai(ai_cfg()), cache_dir=str(tmp_path / "a"),
                     transport=mine).embed_query("x")
    ec.EmbeddingClient(cache_dir=str(tmp_path / "b"), use_cache=False,
                       transport=theirs).embed_query("x")
    assert mine.calls == theirs.calls
    assert mine.calls[0]["url"] == ec.OLLAMA_BASE_URL + ec.EMBED_PATH
    assert mine.calls[0]["payload"]["model"] == ec.DEFAULT_MODEL
    assert mine.calls[0]["payload"]["input"] == [ec.QUERY_PREFIX + "x"]
    assert mine.calls[0]["timeout"] == ec.DEFAULT_TIMEOUT_S

    mine_doc, theirs_doc = RecordingTransport(), RecordingTransport()
    ProviderEmbedder(pv.parse_ai(ai_cfg()), cache_dir=str(tmp_path / "c"),
                     transport=mine_doc).embed_documents(["x"])
    ec.EmbeddingClient(cache_dir=str(tmp_path / "d"), use_cache=False,
                       transport=theirs_doc).embed_documents(["x"])
    assert mine_doc.calls == theirs_doc.calls
    assert mine_doc.calls[0]["payload"]["input"] == [ec.DOC_PREFIX + "x"]


def test_null_timeout_keeps_the_engine_default():
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    cfg = ai_cfg(**CUSTOM)
    cfg["timeout_s"] = None
    build_embedder(cfg, transport=fake).embed_query("x")
    assert fake.calls[0]["timeout"] == ec.DEFAULT_TIMEOUT_S


def test_base_url_is_concatenated_verbatim_without_normalization():
    """One decision: the engine builds base_url + EMBED_PATH; the provider
    does the same with the configured string (no rstrip, no rewriting)."""
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    cfg = ai_cfg(**CUSTOM)
    cfg["base_url"] = "http://127.0.0.1:11500/"
    build_embedder(cfg, transport=fake).embed_query("x")
    assert fake.calls[0]["url"] == "http://127.0.0.1:11500/" + ec.EMBED_PATH


def test_non_loopback_provider_is_accepted_by_the_factory():
    """GAP-4 scope: explicit config wins; the factory never refuses the
    address (disclosure is the banner/meta's job, not a silent refusal)."""
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
    cfg = ai_cfg(**CUSTOM)
    cfg["base_url"] = "https://embed.example.com/v1"
    emb = build_embedder(cfg, transport=fake)
    emb.embed_query("x")
    assert fake.calls[0]["url"] == "https://embed.example.com/v1" + ec.EMBED_PATH


@pytest.mark.parametrize("dims,size", [(4, 4), (512, 512), (768, 768)])
def test_configured_dims_are_the_validation_law(dims, size):
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[0.5] * size)
    cfg = ai_cfg(**CUSTOM)
    cfg["dims"] = dims
    emb = build_embedder(cfg, transport=fake)
    assert emb.embed_query("x") == [0.5] * size


def test_wrong_dims_answer_is_rejected_as_a_validation_error():
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(vector=[0.5] * 768)
    cfg = ai_cfg(**CUSTOM)
    cfg["dims"] = 4
    emb = build_embedder(cfg, transport=fake)
    with pytest.raises(ec.EmbeddingValidationError):
        emb.embed_query("x")


def test_transport_failure_raises_embedding_error_after_bounded_retries():
    """The engine's retry/backoff law is reused, not reimplemented."""
    from vulndog.aihook.embedder import build_embedder

    fake = RecordingTransport(fail=True)
    emb = build_embedder(ai_cfg(**CUSTOM), transport=fake, retry_backoff_s=0.0)
    with pytest.raises(ec.EmbeddingError):
        emb.embed_query("x")
    assert len(fake.calls) == ec.DEFAULT_MAX_RETRIES + 1
    assert emb.stats["retries"] == ec.DEFAULT_MAX_RETRIES


# ------------------------------------ sha cache: model change auto-invalidates
#
# The engine's OWN cache logic is reused (embed_client.cache_key =
# sha256(model + "\n" + prefixed_text)); these tests pin that the
# configured model reaches it and that nothing is reimplemented.


def test_model_change_changes_the_cache_key(tmp_path):
    from vulndog.aihook.embedder import build_embedder

    cache = str(tmp_path / "cache")
    cfg_a = ai_cfg(**CUSTOM)
    fake_a = RecordingTransport(vector=[0.5] * 4)
    build_embedder(cfg_a, cache_dir=cache, use_cache=True,
                   transport=fake_a).embed_query("x")
    key_a = ec.cache_key(cfg_a["model"], cfg_a["query_prefix"] + "x")
    assert os.path.isfile(os.path.join(cache, key_a + ".json"))

    cfg_b = dict(cfg_a, model="another-embed:2b")
    fake_b = RecordingTransport(vector=[0.25] * 4)
    emb_b = build_embedder(cfg_b, cache_dir=cache, use_cache=True,
                           transport=fake_b)
    assert emb_b.embed_query("x") == [0.25] * 4
    key_b = ec.cache_key(cfg_b["model"], cfg_b["query_prefix"] + "x")
    assert key_b != key_a, "a model swap must change the sha cache key"
    assert len(fake_b.calls) == 1, "the old model's entry must NOT be reused"
    assert emb_b.stats["cache_hits"] == 0
    entry_b = os.path.join(cache, key_b + ".json")
    assert os.path.isfile(entry_b)
    with open(entry_b, encoding="utf-8") as fh:
        assert json.load(fh)["model"] == cfg_b["model"]


def test_switching_back_to_the_first_model_reuses_its_cache_entry(tmp_path):
    from vulndog.aihook.embedder import build_embedder

    cache = str(tmp_path / "cache")
    cfg_a = ai_cfg(**CUSTOM)
    build_embedder(cfg_a, cache_dir=cache, use_cache=True,
                   transport=RecordingTransport(vector=[0.5] * 4)).embed_query("x")
    build_embedder(dict(cfg_a, model="another-embed:2b"), cache_dir=cache,
                   use_cache=True,
                   transport=RecordingTransport(vector=[0.25] * 4)).embed_query("x")

    fake_back = RecordingTransport(vector=[9.0] * 4)
    emb_back = build_embedder(cfg_a, cache_dir=cache, use_cache=True,
                              transport=fake_back)
    assert emb_back.embed_query("x") == [0.5] * 4   # the CACHED vector
    assert fake_back.calls == []                    # zero re-embedding
    assert emb_back.stats["cache_hits"] == 1


def test_cached_vectors_are_read_back_at_the_configured_dims(tmp_path):
    """A non-768 provider must still resume from its own cache (the engine
    client hardcodes 768 in its cache read; the provider parameterizes it)."""
    from vulndog.aihook.embedder import build_embedder

    cache = str(tmp_path / "cache")
    cfg = ai_cfg(**CUSTOM)                     # dims = 4
    build_embedder(cfg, cache_dir=cache, use_cache=True,
                   transport=RecordingTransport(vector=[1.0, 0.0, 0.0, 0.0])
                   ).embed_query("x")
    fake2 = RecordingTransport(vector=[0.0, 1.0, 0.0, 0.0])
    emb2 = build_embedder(cfg, cache_dir=cache, use_cache=True, transport=fake2)
    assert emb2.embed_query("x") == [1.0, 0.0, 0.0, 0.0]
    assert fake2.calls == []
    assert emb2.stats["cache_hits"] == 1


def test_query_cache_is_transient_by_default(tmp_path):
    """Engine law (design section 6 / C16): match-path query vectors are
    never persisted — the factory default keeps use_cache=False."""
    from vulndog.aihook.embedder import build_embedder

    cache = str(tmp_path / "cache")
    fake = RecordingTransport(vector=[0.5] * 4)
    emb = build_embedder(ai_cfg(**CUSTOM), cache_dir=cache, transport=fake)
    emb.embed_query("x")
    emb.embed_query("x")
    assert len(fake.calls) == 2, "no cache hits on the transient query path"
    assert emb.stats["cache_hits"] == 0
    assert [n for n in os.listdir(cache) if n.endswith(".json")] == []
