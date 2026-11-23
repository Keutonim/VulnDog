"""M2.4 — the MCP query door consumes the same provider choice as the CLI.

`vuln_query` wraps the engine's QueryAPI through
`mcp.tools._default_query_api`. Before M2.4 that door explicitly deferred
ai.base_url wiring ("M2.4, not this milestone"), so a configured custom
provider would have been honoured by `run` analysis and IGNORED by the MCP
query tool — one config, two behaviours. These tests pin the single
provider decision across both doors, plus the MCP never-crash law.

Offline: no Ollama, no store I/O at construction (the engine opens
connections per call).
"""
from __future__ import annotations

from pathlib import Path

from vulndog import config
from vulndog.aihook.embedder import ProviderEmbedder
from vulndog.engine import embed_client as ec
from vulndog.mcp import tools

CUSTOM_AI = {
    "provider": "custom",
    "base_url": "http://127.0.0.1:11500",
    "model": "mcp-embed:4d",
    "dims": 4,
    "doc_prefix": "doc: ",
    "query_prefix": "query: ",
    "timeout_s": 4.0,
}


def cfg(ai=None, **extra):
    base = {"db": {"store_path": "/nonexistent/vulnkb.sqlite"},
            "runs": {"dir": "runs"}}
    if ai is not None:
        base["ai"] = ai
    base.update(extra)
    return base


def test_mcp_query_door_consumes_a_custom_provider():
    api = tools._default_query_api(cfg(ai=CUSTOM_AI))
    emb = api.embedder
    assert isinstance(emb, ProviderEmbedder)
    assert emb.model == "mcp-embed:4d"
    assert emb.embed_url == "http://127.0.0.1:11500" + ec.EMBED_PATH
    assert emb.dims == 4
    assert emb.timeout_s == 4.0
    assert emb.use_cache is False


def test_mcp_query_door_honors_the_injected_embedder_seam():
    stub = object()
    api = tools._default_query_api(cfg(ai=CUSTOM_AI, embedder=stub))
    assert api.embedder is stub


def test_mcp_query_door_default_ai_is_the_engine_transient_client():
    api = tools._default_query_api(cfg(ai=config.builtin_defaults()["ai"]))
    emb = api.embedder
    assert isinstance(emb, ec.EmbeddingClient)
    assert not isinstance(emb, ProviderEmbedder)
    assert emb.model == ec.DEFAULT_MODEL
    assert emb.use_cache is False


def test_mcp_query_door_without_an_ai_section_keeps_the_engine_default():
    """An engine-shaped config (no ai namespace) must keep working: the
    QueryAPI builds its own transient client lazily, exactly as before."""
    api = tools._default_query_api(cfg())
    assert api._embedder is None


def test_mcp_invalid_ai_is_a_disabled_envelope_never_a_crash(tmp_path):
    """The MCP law: a construction failure surfaces as the honest disabled
    envelope with the reason in detail — never an exception out of a tool
    call (and never a silent fallback to a different provider)."""
    bad = dict(CUSTOM_AI, dims="4")
    ctx = tools.ToolContext(Path(tmp_path), cfg(ai=bad))
    assert ctx.query_api() is None
    assert "ai.dims" in ctx._query_api_error

    out = tools.handle_vuln_query(ctx, {"text": "xss in login"})
    assert out["status"] == "disabled"
    assert out["matches"] == []
    assert "ai.dims" in out["detail"]