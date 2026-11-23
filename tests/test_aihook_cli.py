"""M2.4 CLI wiring — the provider factory reaches the shipped match path.

Pins:
- the resolved ``ai.*`` section builds the embedder the facade consumes
  (through the engine's ``config["embedder"]`` injection key);
- the documented OFFLINE seam still wins: an injected ``config["embedder"]``
  is never replaced (the P1 stub seam / M1.4 drill leg 1);
- the default provider stays the engine's transient loopback client;
- a non-loopback (or file://) base_url is ACCEPTED from explicit config and
  disclosed in the run banner AND watchdog-run.json — never silent;
- a wrong-typed ai value fails fast at startup (exit 2, before capture);
- the capture path needs no engine import for the disclosure (pure half);
- end to end: a custom provider whose transport is down exits 4 with the
  honest "not a clean bill of health" line (never a fake success).
"""
from __future__ import annotations

import http.client
import json
import sys
import threading
from pathlib import Path

import pytest

from vulndog import cli
from vulndog.aihook.embedder import ProviderEmbedder
from vulndog.engine import embed_client as ec
from vulndog.engine.tests.test_api import build_fixture_store

from test_cli import FakeAnalyzer, _read_meta, latest_run_dir, wait_for
from test_proxy import origin_up

CUSTOM_AI = {
    "provider": "custom",
    "base_url": "http://127.0.0.1:11500",
    "model": "cli-embed:4d",
    "dims": 4,
    "doc_prefix": "doc: ",
    "query_prefix": "query: ",
    "timeout_s": 3.0,
}


def write_cfg(path: Path, defaults: dict) -> Path:
    path.write_text(json.dumps({"config_version": 1, "defaults": defaults,
                                "tasks": {}}), encoding="utf-8")
    return path


def run_cli(tmp_path, cfg_path, **kw):
    return cli.main(["run", "--project", str(tmp_path), "--config", str(cfg_path),
                     "--port", "0", "--duration", "0.3"], **kw)


def analysis_config(tmp_path, analyzer):
    assert len(analyzer.calls) == 1
    return analyzer.calls[0]["config"]


# ---------------------------------------------------- factory reaches the facade


def test_custom_ai_config_builds_the_embedder_the_facade_receives(tmp_path):
    cfg_path = write_cfg(tmp_path / "ai.json", {"ai": CUSTOM_AI})
    analyzer = FakeAnalyzer()
    assert run_cli(tmp_path, cfg_path, analyzer=analyzer) == 0

    cfg = analysis_config(tmp_path, analyzer)
    emb = cfg["embedder"]
    assert isinstance(emb, ProviderEmbedder)
    assert emb.model == "cli-embed:4d"
    assert emb.embed_url == "http://127.0.0.1:11500" + ec.EMBED_PATH
    assert emb.dims == 4
    assert emb.timeout_s == 3.0
    assert emb.settings.query_prefix == "query: "
    assert emb.settings.doc_prefix == "doc: "
    assert emb.use_cache is False          # transient query vectors (engine law)
    assert cfg["ai"] == CUSTOM_AI          # the config snapshot is untouched


def test_default_ai_config_keeps_the_engine_transient_client(tmp_path):
    cfg_path = write_cfg(tmp_path / "default.json", {})
    analyzer = FakeAnalyzer()
    assert run_cli(tmp_path, cfg_path, analyzer=analyzer) == 0

    emb = analysis_config(tmp_path, analyzer)["embedder"]
    assert isinstance(emb, ec.EmbeddingClient)
    assert not isinstance(emb, ProviderEmbedder)
    assert emb.model == ec.DEFAULT_MODEL
    assert emb.timeout_s == ec.DEFAULT_TIMEOUT_S
    assert emb.use_cache is False


def test_injected_embedder_seam_is_never_replaced(tmp_path):
    """The offline deterministic stub seam (config["embedder"]) wins —
    the P1 suite and the M1.4 drill depend on it."""
    stub = object()

    def loader(path=None, task_id=None):
        return {"ai": CUSTOM_AI, "embedder": stub}

    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"], analyzer=analyzer,
                    config_loader=loader)
    assert code == 0
    assert analysis_config(tmp_path, analyzer)["embedder"] is stub


def test_default_provider_seam_survives_the_cli_path(tmp_path, monkeypatch):
    """The drill's subprocess stub replaces query.make_transient_embedder;
    the CLI's default provider path must go through that same door."""
    from vulndog.engine import query as qy

    stub = object()
    monkeypatch.setattr(qy, "make_transient_embedder",
                        lambda cache_dir=None: stub)
    cfg_path = write_cfg(tmp_path / "default.json", {})
    analyzer = FakeAnalyzer()
    assert run_cli(tmp_path, cfg_path, analyzer=analyzer) == 0
    assert analysis_config(tmp_path, analyzer)["embedder"] is stub


# ------------------------------------------------------- disclosure (banner/meta)


def test_non_loopback_provider_is_disclosed_in_meta_and_banner(tmp_path, capsys):
    url = "http://10.0.0.5:11434"
    cfg_path = write_cfg(tmp_path / "remote.json",
                         {"ai": dict(CUSTOM_AI, base_url=url)})
    analyzer = FakeAnalyzer()
    assert run_cli(tmp_path, cfg_path, analyzer=analyzer) == 0

    meta = _read_meta(tmp_path)
    assert meta["ai"]["provider"] == "custom"
    assert meta["ai"]["base_url"] == url
    assert meta["ai"]["loopback"] is False
    assert url in meta["ai"]["warning"]
    out = capsys.readouterr().out
    assert "WARNING: ai.base_url is NOT loopback" in out
    assert url in out
    # accepted, not refused: the configured address reaches the embedder
    assert analysis_config(tmp_path, analyzer)["embedder"].embed_url == \
        url + ec.EMBED_PATH


def test_file_url_provider_is_accepted_and_disclosed(tmp_path, capsys):
    url = "file:///tmp/embed.sock"
    cfg_path = write_cfg(tmp_path / "file.json",
                         {"ai": dict(CUSTOM_AI, base_url=url)})
    assert run_cli(tmp_path, cfg_path, analyzer=FakeAnalyzer()) == 0
    meta = _read_meta(tmp_path)
    assert meta["ai"]["loopback"] is False
    assert url in meta["ai"]["warning"]
    assert url in capsys.readouterr().out


@pytest.mark.parametrize("url", [
    "file://127.0.0.1/tmp/embed.json",
    "file://localhost/tmp/embed.json",
])
def test_file_url_with_loopback_authority_is_disclosed(tmp_path, capsys, url):
    """P2-03: the loopback-authority file:// form evaded the D15 disclosure
    (is_loopback_url looked only at the hostname). The run banner AND
    watchdog-run.json must carry the warning exactly once — never silent."""
    cfg_path = write_cfg(tmp_path / "file.json",
                         {"ai": dict(CUSTOM_AI, base_url=url)})
    assert run_cli(tmp_path, cfg_path, analyzer=FakeAnalyzer()) == 0
    meta = _read_meta(tmp_path)
    assert meta["ai"]["loopback"] is False
    assert url in meta["ai"]["warning"]
    out = capsys.readouterr().out
    assert out.count("WARNING: ai.base_url is NOT loopback") == 1
    assert url in out


def test_default_provider_meta_and_banner_are_loopback(tmp_path, capsys):
    cfg_path = write_cfg(tmp_path / "default.json", {})
    assert run_cli(tmp_path, cfg_path, analyzer=FakeAnalyzer()) == 0
    meta = _read_meta(tmp_path)
    assert meta["ai"] == {
        "provider": "ollama", "base_url": ec.OLLAMA_BASE_URL,
        "model": ec.DEFAULT_MODEL, "dims": ec.EXPECTED_DIMS,
        "loopback": True, "warning": None,
    }
    out = capsys.readouterr().out
    assert "ai:      ollama" in out
    assert "(loopback)" in out
    assert "WARNING: ai.base_url" not in out


def test_wrong_typed_ai_config_fails_fast_before_capture(tmp_path, capsys):
    cfg_path = write_cfg(tmp_path / "bad.json", {"ai": {"dims": "768"}})
    code = run_cli(tmp_path, cfg_path, analyzer=FakeAnalyzer())
    assert code == cli.EXIT_USAGE
    assert "ai.dims" in capsys.readouterr().err
    assert latest_run_dir(tmp_path) is None, "no run folder before validation"


def test_disclosure_needs_no_engine_import(tmp_path, monkeypatch, capsys):
    """The pure half renders banner/meta even with the engine half absent
    (the CLI's honest-degradation law: capture preserved, exit 3). The
    config reaches it through the injected loader seam — with no loader
    the engine-absent path falls back to builtins (pinned below)."""
    for name in ("vulndog.engine", "vulndog.engine.run", "vulndog.engine.api"):
        monkeypatch.setitem(sys.modules, name, None)
    url = "http://10.0.0.5:11434"

    def loader(path=None, task_id=None):
        return {"ai": dict(CUSTOM_AI, base_url=url)}

    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"], analyzer=None, config_loader=loader)
    assert code == cli.EXIT_ENGINE_ABSENT
    meta = _read_meta(tmp_path)
    assert meta["ai"]["loopback"] is False
    assert url in meta["ai"]["warning"]
    out = capsys.readouterr().out
    assert "WARNING: ai.base_url is NOT loopback" in out
    assert url in out


def test_engine_absent_fallback_keeps_the_loopback_default_disclosed(
        tmp_path, monkeypatch, capsys):
    """Engine absent + no injected loader: the config FILE is ignored (the
    shipped degradation law) and the built-in loopback provider is what
    the banner/meta disclose — never a silently remote address."""
    for name in ("vulndog.engine", "vulndog.engine.run", "vulndog.engine.api"):
        monkeypatch.setitem(sys.modules, name, None)
    cfg_path = write_cfg(tmp_path / "remote.json",
                         {"ai": dict(CUSTOM_AI, base_url="http://10.0.0.5:11434")})
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(cfg_path),
                     "--port", "0", "--duration", "0.3"], analyzer=None)
    assert code == cli.EXIT_ENGINE_ABSENT
    meta = _read_meta(tmp_path)
    assert meta["ai"]["base_url"] == ec.OLLAMA_BASE_URL
    assert meta["ai"]["loopback"] is True
    assert "config file ignored" in capsys.readouterr().err


# ------------------------------------------------- end-to-end outage (exit-4 law)


def test_custom_provider_outage_end_to_end_exits_4(tmp_path, monkeypatch, capsys):
    """The shipped path with a CUSTOM provider: capture works, the match
    path fails honestly, the CLI exits 4 and says so out loud."""
    store = build_fixture_store(str(tmp_path / "kb.sqlite"))
    cfg_path = write_cfg(tmp_path / "outage.json",
                         {"ai": CUSTOM_AI, "db": {"store_path": store}})

    # P2-07: the custom-provider default transport is now the aihook seam's
    # capped variant, which resolves its opener through ec.make_no_proxy_opener
    # at call time. Inject the outage there (the engine's _default_transport
    # is no longer on the custom path); the exit-4 law is unchanged.
    class _RefusingOpener:
        def open(self, req, timeout=None):
            raise OSError("connection refused (provider down)")

    monkeypatch.setattr(ec, "make_no_proxy_opener", lambda: _RefusingOpener())

    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(tmp_path), "--config", str(cfg_path),
             "--port", "0", "--duration", "3.0", "--allow-private"])

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(tmp_path), timeout=10)
        assert meta is not None
        with origin_up(payload=b"login redirect xss",
                       content_type="text/html") as origin:
            conn = http.client.HTTPConnection("127.0.0.1", meta["listen"]["port"],
                                              timeout=10)
            try:
                conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}"
                                    "/advisory/CVE-2024-2000")
                conn.getresponse().read()
            finally:
                conn.close()
    finally:
        t.join(timeout=20)
    assert not t.is_alive()
    assert result["code"] == cli.EXIT_ANALYSIS_FAILED

    captured = capsys.readouterr()
    assert "NOT a clean bill of health" in captured.err
    run_dir = latest_run_dir(tmp_path)
    events = (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(events) == 1, "the capture is preserved during the outage"
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    assert "| mode | ollama-down |" in md
    assert "| highlights | 0 |" in md
    assert "| embed_failures | 1 |" in md
    final_meta = json.loads((run_dir / "watchdog-run.json").read_text(encoding="utf-8"))
    assert final_meta["ai"]["model"] == "cli-embed:4d"