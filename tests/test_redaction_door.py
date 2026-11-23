"""ONE redaction door (fix-round-1 B1+B2 — the premise removal).

Three independent reviews found the same premise from two ends: the
capture tap wrote RAW bodies/paths/fragments to the spool (B1) and the
matcher built highlights from the PRE-redaction event (B2). Two doors
=> two truths => secrets on disk. The fix routes BOTH artefacts through
the vendored F4 adapter (engine/redaction_adapter.redact_event — the
engine's single enforcement point, precedent engine/tap_sim.py:86):

* the tap redacts every event BEFORE it is persisted (fail-closed:
  a redaction drop is counted, never written raw);
* the facade pre-redacts every consumed event BEFORE matching, so the
  highlight surfaces derive from redacted data even for a legacy raw
  spool (the matcher's own COND-7a re-run stays as defense in depth).

The flagship test below inspects BOTH artefacts of ONE real request:
events.jsonl AND highlights.jsonl/highlights.md (+ the console line
rendered from the same highlight record). A reset JWT in the path, an
OAuth token in the fragment, a query token and body secrets must appear
ONLY redacted — while the origin still receives the real request
(Mode A: observation never modifies traffic).
"""
from __future__ import annotations

import json
import re
import socket

from vulndog import proxy, runs
from vulndog.engine import api
from vulndog.engine import event_schema as es
from vulndog.engine import highlights as hl
from vulndog.engine.tests.test_api import E1, StubEmbedder, build_fixture_store

from event_contract import assert_pinned_event
from test_proxy import origin_up, proxy_up, read_events

# Secret material spanning every capture channel the reviews verified.
RESET_JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyZXNldCJ9."
             "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
QUERY_TOKEN = "RESETQUERYTOKEN123"          # 18 raw chars -> <len-18>
FRAGMENT_TOKEN = "FRAGMENTTOKEN999"
BODY_ENTROPY_TOKEN = "aB3xK9mQ2wR7tY5uZ8vE"  # 3-class opaque run
BODY_HEX_TOKEN = "9f3a7c2e1b8d4f6a"          # 16-hex opaque run
SECRETS = (RESET_JWT, QUERY_TOKEN, FRAGMENT_TOKEN,
           BODY_ENTROPY_TOKEN, BODY_HEX_TOKEN)

ORIGIN_BODY = json.dumps({
    "message": "password reset for bob",
    "reset_token": BODY_ENTROPY_TOKEN,
    "jwt": RESET_JWT,
    "note": "token=" + BODY_HEX_TOKEN,
}).encode("utf-8")


def _raw_get_via_proxy(pport: int, oport: int, target: str) -> bytes:
    """Raw request line (http.client strips fragments; a hostile client
    can send one, so the capture law must hold for the raw form)."""
    s = socket.create_connection(("127.0.0.1", pport), timeout=15)
    try:
        s.sendall(
            f"GET {target} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{oport}\r\nConnection: close\r\n\r\n"
            .encode("latin-1"))
        resp = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            resp += chunk
        return resp
    finally:
        s.close()


def test_one_door_spool_and_highlights_both_redacted(tmp_path):
    """THE premise test: one real request, BOTH artefacts inspected."""
    store = build_fixture_store(str(tmp_path / "kb.sqlite"))
    target = (f"http://127.0.0.1:{{oport}}/account/reset/{RESET_JWT}"
              f"?token={QUERY_TOKEN}#access_token={FRAGMENT_TOKEN}")
    with origin_up(payload=ORIGIN_BODY,
                   content_type="application/json") as origin, \
            proxy_up(tmp_path) as (run, server):
        oport = origin.server_address[1]
        pport = server.address[1]
        resp = _raw_get_via_proxy(pport, oport, target.format(oport=oport))
        # the origin's status line is forwarded VERBATIM (Mode A)
        assert resp.split(b"\r\n", 1)[0].split()[1] == b"200", resp[:100]

        # Mode A: the origin received the REAL request (no modification)
        assert len(origin.hits) == 1
        assert RESET_JWT in origin.hits[0]["path"]
        assert QUERY_TOKEN in origin.hits[0]["path"]

        # --- artefact 1: the spool (B1 — redaction BEFORE persistence)
        raw_spool = run.events_path.read_text(encoding="utf-8")
        for secret in SECRETS:
            assert secret not in raw_spool, \
                f"secret reached events.jsonl verbatim: {secret[:24]}..."
        events = read_events(run)
        assert len(events) == 1
        ev = events[0]
        assert_pinned_event(ev, persisted=True)
        assert es.validate_event(ev) == []
        assert re.search(r"/account/reset/<len-\d+>", ev["url"]), ev["url"]
        # F4 canonical form: secret-named params hit the upstream pattern
        # pass AFTER the structural mask -> token=<redacted>
        assert "token=<redacted>" in ev["url"]
        assert "#" not in ev["url"], "fragment survived capture redaction"
        assert "<redacted>" in ev["body_redacted"]

        # --- artefact 2: the highlight surfaces (B2 — same door)
        summary = api.analyze_run(
            events_path=str(run.events_path), run_dir=str(run.path),
            store_path=store, config={"embedder": StubEmbedder(E1)})
        assert summary["status"] == "ok", summary
        assert summary["highlights"] >= 1
        hls = [json.loads(l) for l in
               (run.path / "highlights.jsonl").read_text(
                   encoding="utf-8").splitlines() if l.strip()]
        md = (run.path / "highlights.md").read_text(encoding="utf-8")
        assert hls
        for secret in SECRETS:
            assert secret not in json.dumps(hls), \
                "secret reached highlights.jsonl"
            assert secret not in md, "secret reached highlights.md"
            for h in hls:
                assert secret not in hl.console_line(h), \
                    "secret reached the console line"
        for h in hls:
            assert re.search(r"/account/reset/<len-\d+>", h["url"])
            assert "#" not in h["url"]


def test_facade_redacts_a_legacy_raw_spool_before_highlights(tmp_path):
    """B2 at the facade alone: even a RAW spool (legacy tap, external
    producer) must yield redacted highlights — the matcher builds them
    from the event it receives, so the facade must pre-redact."""
    store = build_fixture_store(str(tmp_path / "kb.sqlite"))
    run_dir = tmp_path / "20261121-120000-legacy"
    run_dir.mkdir()
    raw_event = {
        "ts": "2026-11-21T12:00:00Z", "hunt_id": run_dir.name,
        "tap_class": "tool_http",
        "url": f"http://t.local/account/reset/{RESET_JWT}?token=<len-4>",
        "method": "GET", "status": 200, "decision": "allowed",
        "provenance": "vulndog.proxy", "content_type": "text/html",
        "body_redacted": "login redirect xss " + BODY_ENTROPY_TOKEN,
    }
    events_path = run_dir / "events.jsonl"
    events_path.write_text(json.dumps(raw_event) + "\n", encoding="utf-8")

    summary = api.analyze_run(
        events_path=str(events_path), run_dir=str(run_dir),
        store_path=store, config={"embedder": StubEmbedder(E1)})
    assert summary["status"] == "ok"
    assert summary["highlights"] >= 1
    hls_raw = (run_dir / "highlights.jsonl").read_text(encoding="utf-8")
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    assert RESET_JWT not in hls_raw
    assert RESET_JWT not in md
    assert BODY_ENTROPY_TOKEN not in hls_raw
    hls = [json.loads(l) for l in hls_raw.splitlines() if l.strip()]
    for h in hls:
        assert re.search(r"/account/reset/<len-\d+>", h["url"])


def test_tap_door_drops_fail_closed_and_counts(tmp_path):
    """The tap's emission door is fail-closed: an event F4 must drop
    (forbidden header-value key) is NEVER written raw; the drop is
    counted. A clean event through the same door IS written."""
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    server = proxy.ProxyServer("127.0.0.1", 0, writer=writer,
                               hunt_id=run.hunt_id)
    try:
        clean = proxy.build_event(hunt_id=run.hunt_id, url="http://h/x",
                                  decision="allowed", method="GET")
        forbidden = dict(clean, headers={"Authorization": "Bearer x"})
        server.emit(clean)
        server.emit(forbidden)
        server.emit(["not", "a", "dict"])   # non-dict: fail-closed too
        assert getattr(server, "redaction_dropped", 0) == 2, \
            "the tap door did not count the fail-closed redaction drops"
        events = read_events(run)
        assert len(events) == 1
        assert "headers" not in events[0]
        assert server.events_emitted == 1
    finally:
        server.stop()
        writer.close()