"""M2.4 outage law — the ENGINE's real behaviour, driven by the provider.

GAP-4/D15: provider choice only. These tests pin what the shipped engine
does when the configured embedding provider fails, and what it does when
the provider comes back. Nothing here invents a degrade mode:

- transport raises -> per-event ``skipped``/``embed-failed`` envelope with
  ZERO matches, pins included (query.py embeds BEFORE pin resolution);
- the matcher enters down-mode ONCE, buffers (never drops), and the
  runner's retry clock re-arms (matcher.py _enter_down);
- recovery replays the buffer IN ORDER through ``retry_pending`` (the
  engine runner's door, run.py:459-462): ``recovered>0``, semantic AND
  exact-id highlights return — pins are NOT produced while down;
- the facade reports the outage honestly (status ``skipped``, exit-4 law
  upstream in the CLI) and preserves the capture.

Offline + deterministic: a switchable fake transport on the engine's
injectable seam, a tiny fixture KB built with the engine's OWN
StagedStore + chunker (4-dim orthogonal vectors, same fixture as the
engine's facade tests), a fake clock, and the direct-call deadline path.
No Ollama, no network egress, no sleeps.
"""
from __future__ import annotations

import json
import os

import pytest

from vulndog import config
from vulndog.aihook.embedder import build_embedder
from vulndog.engine import api
from vulndog.engine import embed_client as ec
from vulndog.engine import matcher as mt
from vulndog.engine import query as qy
from vulndog.engine.tests.test_api import E1, build_fixture_store, event

#: A custom provider whose dims match the 4-dim fixture KB — the outage
#: law is exercised through the REAL client path (retries, validation,
#: EmbeddingError), not through a stub that bypasses it.
PROVIDER_AI = dict(provider="custom", base_url="http://127.0.0.1:11500",
                   model="test-embed:4d", dims=4, doc_prefix="doc: ",
                   query_prefix="query: ", timeout_s=1.0)

PIN_URL = "https://t.local/advisory/CVE-2024-2000"
SEMANTIC_URL = "https://t.local/login.php?redirect=<len-4>"


class SwitchableTransport:
    """The engine's transport seam: answers with a fixed vector, or raises
    while ``down`` is set (the outage). Records every attempt."""

    def __init__(self, vector=None, down=False):
        self.vector = list(vector) if vector is not None else list(E1)
        self.down = down
        self.calls = []

    def __call__(self, url, payload, timeout):
        self.calls.append({"url": url, "payload": payload, "timeout": timeout})
        if self.down:
            raise OSError("connection refused (provider down)")
        return {"embeddings": [list(self.vector) for _ in payload["input"]]}


class FakeClock:
    def __init__(self):
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class RecordingAPI:
    """QueryAPI wrapper that keeps every envelope (the evidence that pins
    were never produced while the provider was down)."""

    def __init__(self, inner):
        self.inner = inner
        self.envelopes = []

    def match(self, text, **kw):
        env = self.inner.match(text, **kw)
        self.envelopes.append(env)
        return env


@pytest.fixture
def store_path(tmp_path):
    return build_fixture_store(str(tmp_path / "vulnkb.sqlite"))


@pytest.fixture
def transport():
    return SwitchableTransport()


@pytest.fixture
def provider_ai():
    cfg = config.builtin_defaults()["ai"]
    cfg.update(PROVIDER_AI)
    return cfg


def make_embedder(provider_ai, transport):
    return build_embedder(provider_ai, transport=transport, retry_backoff_s=0.0)


def make_matcher(api_obj, clock):
    # per_event_deadline_s=0 -> the engine's direct-call path (no worker
    # thread): deterministic, and the outage comes from the transport.
    return mt.Matcher(api_obj, clock=clock, backoff_s=60.0,
                      per_event_deadline_s=0)


def pin_event():
    return event(url=PIN_URL, body="advisory reference")


def semantic_event():
    return event(url=SEMANTIC_URL, body="login redirect xss")


# ------------------------------------------- per-event envelope (query law)


def test_outage_envelope_is_skipped_embed_failed_with_zero_matches(
        store_path, provider_ai, transport):
    transport.down = True
    emb = make_embedder(provider_ai, transport)
    api_obj = qy.QueryAPI(store_path=store_path, embedder=emb)

    env = api_obj.match("GET /advisory/CVE-2024-2000 login redirect xss")

    assert env["status"] == "skipped"
    assert env["reason"] == "embed-failed"
    assert env["matches"] == []
    assert env["pinned"] == 0, "pins must NOT be produced while down"
    assert api_obj.skipped_events == 1
    assert transport.calls, "the provider was actually called (not a store skip)"
    assert "EmbeddingError" in env["detail"], "the transport failure is surfaced"


def test_the_same_text_pins_once_the_provider_answers(
        store_path, provider_ai, transport):
    """Negative control for the test above: the pin is absent because the
    EMBED failed, not because the record is missing from the KB."""
    text = "GET /advisory/CVE-2024-2000 login redirect xss"
    transport.down = True
    api_obj = qy.QueryAPI(store_path=store_path,
                          embedder=make_embedder(provider_ai, transport))
    down_env = api_obj.match(text)
    assert down_env["pinned"] == 0 and down_env["matches"] == []

    transport.down = False
    up_env = api_obj.match(text)
    assert up_env["status"] == "ok"
    assert up_env["pinned"] >= 1
    assert any(m["reason"] == "exact-id"
               and m["record_id"] == "CVE-2024-2000"
               for m in up_env["matches"])


def test_wrong_dims_answer_is_an_embed_failure_and_down_mode(
        store_path, provider_ai):
    """A provider that answers with the wrong dimensionality never yields
    a match. Engine law: the client RAISES EmbeddingValidationError inside
    embed_query, so query.py reports reason "embed-failed" (the
    "embed-invalid" reason is the normalize-failure path, pinned below).
    Both reasons are in matcher._EMBED_DOWN_REASONS -> down-mode."""
    bad = SwitchableTransport(vector=[0.5] * 768)   # config says dims=4
    emb = make_embedder(provider_ai, bad)
    api_obj = qy.QueryAPI(store_path=store_path, embedder=emb)
    env = api_obj.match("GET /login.php login redirect xss")
    assert env["status"] == "skipped"
    assert env["reason"] == "embed-failed"
    assert env["matches"] == [] and env["pinned"] == 0
    assert "dims" in env["detail"]

    clock = FakeClock()
    matcher = make_matcher(api_obj, clock)
    assert matcher.process_event(semantic_event()) == []
    assert matcher.mode == mt.MODE_OLLAMA_DOWN


def test_zero_vector_answer_is_embed_invalid_and_down_mode(
        store_path, provider_ai):
    """A vector that passes dims validation but cannot be normalized is
    the engine's "embed-invalid" skip — also a down-mode reason."""
    zero = SwitchableTransport(vector=[0.0] * 4)
    emb = make_embedder(provider_ai, zero)
    api_obj = qy.QueryAPI(store_path=store_path, embedder=emb)
    env = api_obj.match("GET /login.php login redirect xss")
    assert env["status"] == "skipped"
    assert env["reason"] == "embed-invalid"
    assert env["matches"] == [] and env["pinned"] == 0

    matcher = make_matcher(api_obj, FakeClock())
    assert matcher.process_event(semantic_event()) == []
    assert matcher.mode == mt.MODE_OLLAMA_DOWN


# --------------------------------------------- matcher mode machine (law)


def test_matcher_enters_down_mode_once_and_buffers_in_order(
        store_path, provider_ai, transport):
    transport.down = True
    clock = FakeClock()
    recorder = RecordingAPI(qy.QueryAPI(
        store_path=store_path, embedder=make_embedder(provider_ai, transport)))
    matcher = make_matcher(recorder, clock)

    first = pin_event()
    assert matcher.process_event(first) == []
    assert matcher.mode == mt.MODE_OLLAMA_DOWN
    assert matcher.down is True
    assert matcher.status_lines == [mt.LINE_OLLAMA_DOWN]
    assert matcher.pending == [first]
    assert matcher.next_retry == clock.t + 60.0
    assert matcher.stats()["embed_failures"] == 1

    second, third = semantic_event(), pin_event()
    assert matcher.process_event(second) == []
    assert matcher.process_event(third) == []

    stats = matcher.stats()
    assert stats["buffered_while_down"] == 2
    assert stats["highlights"] == 0
    assert stats["pending"] == 3
    assert matcher.pending == [first, second, third], "in-order buffer"
    assert matcher.status_lines == [mt.LINE_OLLAMA_DOWN], "announced ONCE"
    # every envelope produced while down carried zero matches and zero pins
    assert recorder.envelopes
    for env in recorder.envelopes:
        assert env["status"] == "skipped"
        assert env["matches"] == []
        assert env["pinned"] == 0


def test_recovery_replays_buffer_and_restores_pins_and_semantic(
        store_path, provider_ai, transport):
    transport.down = True
    clock = FakeClock()
    api_obj = qy.QueryAPI(store_path=store_path,
                          embedder=make_embedder(provider_ai, transport))
    matcher = make_matcher(api_obj, clock)

    first, second = pin_event(), semantic_event()
    matcher.process_event(first)
    matcher.process_event(second)
    assert matcher.stats()["highlights"] == 0
    assert matcher.stats()["recovered"] == 0

    # the provider comes back; the runner's retry clock elapses
    transport.down = False
    clock.advance(61.0)
    drained, highlights = matcher.retry_pending()

    assert drained is True
    assert matcher.pending == []
    assert matcher.mode == mt.MODE_ENABLED
    assert matcher.down is False
    stats = matcher.stats()
    assert stats["recovered"] > 0
    assert stats["highlights"] > 0
    assert mt.LINE_ENABLED_RECOVERED in matcher.status_lines
    assert matcher.status_lines.count(mt.LINE_OLLAMA_DOWN) == 1

    reasons = {(h["record_id"], h["reason"]) for h in highlights}
    assert ("CVE-2024-2000", "exact-id") in reasons, "pins return on recovery"
    assert ("CVE-2024-1000", "semantic") in reasons
    assert highlights[0]["record_id"] == "CVE-2024-2000", "replay is in order"
    # the buffer counters stay visible as history
    assert stats["buffered_while_down"] == 1
    assert stats["embed_failures"] == 1


def test_recovery_probe_still_down_keeps_the_buffer_and_order(
        store_path, provider_ai, transport):
    transport.down = True
    clock = FakeClock()
    api_obj = qy.QueryAPI(store_path=store_path,
                          embedder=make_embedder(provider_ai, transport))
    matcher = make_matcher(api_obj, clock)
    first, second = pin_event(), semantic_event()
    matcher.process_event(first)
    matcher.process_event(second)

    clock.advance(61.0)
    drained, highlights = matcher.retry_pending()   # provider STILL down
    assert drained is False
    assert highlights == []
    assert matcher.pending == [first, second]
    assert matcher.mode == mt.MODE_OLLAMA_DOWN
    assert matcher.stats()["recovered"] == 0


# ------------------------------------------------- facade (Phase-1 surface)


def write_events(run_dir, events):
    os.makedirs(run_dir, exist_ok=True)
    path = os.path.join(run_dir, "events.jsonl")
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    return path


def test_facade_reports_provider_outage_honestly(tmp_path, store_path,
                                                 provider_ai, transport):
    transport.down = True
    run_dir = str(tmp_path / "20261123-120000-outage")
    events_path = write_events(run_dir, [pin_event(), semantic_event()])
    emb = make_embedder(provider_ai, transport)

    summary = api.analyze_run(events_path=events_path, run_dir=run_dir,
                              store_path=store_path, config={"embedder": emb})

    assert summary["status"] == "skipped"
    assert summary["mode"] == mt.MODE_OLLAMA_DOWN
    assert summary["highlights"] == 0
    assert summary["events_read"] == 2
    assert summary["embed_failures"] == 1
    assert summary["buffered_while_down"] == 1
    # the failed event is buffered by _enter_down, the next one by the
    # down-guard: both stay pending (never dropped) — pending == 2
    assert summary["pending"] == 2
    assert summary["errors"] > 0
    md = open(os.path.join(run_dir, "highlights.md"), encoding="utf-8").read()
    assert "## Run summary" in md
    assert "| mode | ollama-down |" in md
    assert "| highlights | 0 |" in md
    # the capture is preserved (never deleted, never faked)
    assert len(open(events_path, encoding="utf-8").readlines()) == 2


def test_facade_never_fakes_success_when_the_provider_recovers_mid_pass(
        tmp_path, store_path, provider_ai, transport):
    """The shipped facade drives process_event only; in-order replay is the
    RUNNER's door (matcher.retry_pending, run.py:459-462). So a mid-pass
    recovery still leaves the buffer pending and the summary honest —
    zero highlights from an outage is never reported as a clean run."""
    run_dir = str(tmp_path / "20261123-120000-midpass")
    events_path = write_events(run_dir, [pin_event(), semantic_event()])
    emb = make_embedder(provider_ai, transport)

    attempts = []
    outage_attempts = ec.DEFAULT_MAX_RETRIES + 1   # the whole first call fails

    def flaky(url, payload, timeout):
        attempts.append(url)
        if len(attempts) <= outage_attempts:
            raise OSError("connection refused (provider down)")
        return transport(url, payload, timeout)   # recovered afterwards

    emb._inner_transport = flaky
    summary = api.analyze_run(events_path=events_path, run_dir=run_dir,
                              store_path=store_path, config={"embedder": emb})

    assert summary["events_read"] == 2
    assert summary["embed_failures"] == 1
    assert summary["status"] == "skipped"
    assert summary["highlights"] == 0
    assert summary["pending"] >= 1
    assert summary["matcher"]["recovered"] == 0

def test_reanalysis_after_recovery_produces_the_highlights(
        tmp_path, store_path, provider_ai, transport):
    """The shipped Phase-1 recovery path (docs/AI-INTEGRATION.md): the
    facade is idempotent, so re-running the analysis once the provider is
    back re-matches the preserved spool and the highlights appear —
    semantic AND exact-id. No engine change, no fts-only degrade."""
    run_dir = str(tmp_path / "20261123-120000-recover")
    events_path = write_events(run_dir, [pin_event(), semantic_event()])
    emb = make_embedder(provider_ai, transport)

    transport.down = True
    first = api.analyze_run(events_path=events_path, run_dir=run_dir,
                            store_path=store_path, config={"embedder": emb})
    assert first["status"] == "skipped"
    assert first["highlights"] == 0

    transport.down = False
    second = api.analyze_run(events_path=events_path, run_dir=run_dir,
                             store_path=store_path, config={"embedder": emb})
    assert second["status"] == "ok"
    assert second["mode"] == mt.MODE_ENABLED
    assert second["highlights"] > 0
    assert second["errors"] == 0
    with open(os.path.join(run_dir, "highlights.jsonl"), encoding="utf-8") as fh:
        hls = [json.loads(line) for line in fh if line.strip()]
    reasons = {(h["record_id"], h["reason"]) for h in hls}
    assert ("CVE-2024-2000", "exact-id") in reasons
    assert ("CVE-2024-1000", "semantic") in reasons
    assert len(open(events_path, encoding="utf-8").readlines()) == 2
