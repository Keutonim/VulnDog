"""M4 (fix-round-1): the tap's documented bounded queue + resource caps.

docs/RUNS-AND-LOGS.md: "The tap itself is a pure observer with a bounded
queue (capacity 1000, drop-oldest): under burst, the oldest unflushed
events are dropped and counted in a drop_counter meta line — drops are
visible, never silent crashes." Before this round that queue did not
exist (PLAN M1.2 criterion 5 was NOT IMPLEMENTED), connections were
uncapped (one thread per connection) and events.jsonl grew without
bound. These tests pin the documented semantics plus the two new safety
caps (connection cap, bounded spool) — all counted, never a crash, and
the observer never breaks the traffic it observes.
"""
from __future__ import annotations

import json
import socket
import threading
import time

from vulndog import proxy, runs
from vulndog.engine import api
from vulndog.engine.tests.test_api import E1, StubEmbedder, build_fixture_store

from test_proxy import origin_up, proxy_up, read_events, http_via_proxy


def test_documented_queue_capacity_is_1000():
    # the doc contract constant (RUNS-AND-LOGS.md "capacity 1000")
    assert proxy.QUEUE_CAP == 1000


class _GatedWriter:
    """Blocks the FIRST write until released — makes queue overflow
    deterministic: the flusher holds the flush role inside write()
    while the other emitters publish into the bounded queue."""

    def __init__(self, inner):
        self.inner = inner
        self.gate = threading.Event()
        self._first = True

    def write(self, event):
        if self._first:
            self._first = False
            assert self.gate.wait(timeout=10), "test gate never released"
        self.inner.write(event)

    @property
    def count(self):
        return self.inner.count

    def close(self):
        self.inner.close()


def test_queue_overflow_drops_oldest_and_reports_drop_counter(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    gated = _GatedWriter(writer)
    server = proxy.ProxyServer("127.0.0.1", 0, writer=gated,
                               hunt_id=run.hunt_id, queue_cap=8)
    errors = []

    def emit_one(i):
        try:
            server.emit(proxy.build_event(
                hunt_id=run.hunt_id, url=f"http://h/{i}",
                decision="allowed", method="GET"))
        except Exception as exc:          # the observer must NEVER raise
            errors.append(exc)

    threads = [threading.Thread(target=emit_one, args=(i,))
               for i in range(40)]
    try:
        for t in threads:
            t.start()
        # wait until the flusher is inside the gated first write and the
        # queue has overflowed (40 publishes vs cap 8)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if server.queue.drop_count > 0:
                break
            time.sleep(0.02)
        assert server.queue.drop_count > 0, "bounded queue never overflowed"
        gated.gate.set()
        for t in threads:
            t.join(timeout=10)
        assert not any(t.is_alive() for t in threads)
        assert errors == [], f"emit raised into the caller: {errors}"
        # the visible drop_counter meta line(s) account for EVERY drop
        lines = [json.loads(l) for l in
                 run.events_path.read_text(encoding="utf-8").splitlines()]
        meta = [l for l in lines if l.get("type") == "drop_counter"]
        assert meta, "overflow without a drop_counter meta line"
        assert sum(m["dropped"] for m in meta) == server.queue.drop_count
        # drop-OLDEST: the surviving events are the newest ones
        events = [l for l in lines if "url" in l]
        assert len(events) <= 40
        assert events[-1]["url"].endswith("/39")
    finally:
        gated.gate.set()
        server.stop()
        writer.close()


def test_connection_cap_refuses_503_and_recovers(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, max_connections=2) as (run, server):
        pport = server.address[1]
        holders = []
        try:
            # two half-open requests hold both connection slots
            for _ in range(2):
                s = socket.create_connection(("127.0.0.1", pport), timeout=10)
                s.sendall(b"GET http://127.0.0.1:1/ HTTP/1.1\r\n")  # no end
                holders.append(s)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if server.connections_active == 2:
                    break
                time.sleep(0.02)
            assert server.connections_active == 2
            # the third connection is refused with 503 — no handler thread
            s = socket.create_connection(("127.0.0.1", pport), timeout=10)
            resp = s.recv(4096)
            s.close()
            assert resp.startswith(b"HTTP/1.1 503"), resp[:60]
            assert server.connections_refused >= 1
        finally:
            for s in holders:
                s.close()
        # a freed slot serves again (the cap is a brake, not a shutdown)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if server.connections_active == 0:
                break
            time.sleep(0.02)
        status, _ = http_via_proxy(
            pport, f"http://127.0.0.1:{origin.server_address[1]}/")
        assert status == 200


def test_spool_cap_bounds_growth_counts_drops_never_crashes(tmp_path):
    with origin_up() as origin, \
            proxy_up(tmp_path, spool_cap=5) as (run, server):
        url = f"http://127.0.0.1:{origin.server_address[1]}/"
        for _ in range(10):
            status, _ = http_via_proxy(server.address[1], url)
            assert status == 200      # the observer never breaks traffic
        lines = [json.loads(l) for l in
                 run.events_path.read_text(encoding="utf-8").splitlines()]
        events = [l for l in lines if "url" in l]
        meta = [l for l in lines if l.get("type") == "spool_cap"]
        assert len(events) == 5, "spool grew past its cap"
        assert len(meta) == 1, "cap hit without a visible spool_cap marker"
        assert server.spool_dropped == 5
        assert len(origin.hits) == 10   # forwarding unaffected


# ------------------------------------------- R2-E flush-drop visibility


class _FailWriter:
    """Every write fails (OSError) — the observer must survive, count
    the lost events, and keep serving traffic."""

    def __init__(self):
        self.count = 0

    def write(self, event):
        raise OSError("simulated disk full")

    def close(self):
        pass


def test_flush_write_failures_are_counted_and_surfaced(tmp_path):
    # R2-E / QA1 4.3: events lost to a writer failure used to be stderr
    # noise only. They must be COUNTED (flush_dropped) and surfaced in
    # the run-meta counters — never silent.
    from vulndog import cli

    run = runs.create_run(tmp_path / "proj")
    server = proxy.ProxyServer("127.0.0.1", 0, writer=_FailWriter(),
                               hunt_id=run.hunt_id)
    try:
        for i in range(3):
            server.emit(proxy.build_event(
                hunt_id=run.hunt_id, url=f"http://h/{i}",
                decision="allowed", method="GET"))
        assert server.flush_dropped == 3
        assert server.events_emitted == 0
        counters = cli._tap_counters(server)
        assert counters["flush_dropped"] == 3
    finally:
        server.stop()


class _BoomWriter:
    """One event triggers an UNEXPECTED exception (not OSError/ValueError);
    the rest must still reach the spool — the flusher counts the loss
    and continues, it does not abandon the drained batch."""

    def __init__(self, inner):
        self.inner = inner

    @property
    def count(self):
        return self.inner.count

    def write(self, event):
        if event.get("url", "").endswith("/boom"):
            raise RuntimeError("unexpected writer failure")
        self.inner.write(event)

    def close(self):
        self.inner.close()


def test_unexpected_writer_exception_counted_and_flush_continues(tmp_path):
    run = runs.create_run(tmp_path / "proj")
    writer = runs.EventWriter(run.events_path)
    boom = _BoomWriter(writer)
    server = proxy.ProxyServer("127.0.0.1", 0, writer=boom,
                               hunt_id=run.hunt_id)
    try:
        server.emit(proxy.build_event(hunt_id=run.hunt_id,
                                      url="http://h/boom",
                                      decision="allowed", method="GET"))
        server.emit(proxy.build_event(hunt_id=run.hunt_id,
                                      url="http://h/ok",
                                      decision="allowed", method="GET"))
        assert server.flush_dropped == 1
        lines = [json.loads(l) for l in
                 run.events_path.read_text(encoding="utf-8").splitlines()]
        assert [l["url"] for l in lines if "url" in l] == ["http://h/ok"]
    finally:
        server.stop()
        writer.close()


def test_drop_summary_visible_on_console(capsys):
    # R2-E: the operator sees non-zero drop/refusal counters on the
    # console at run end, not only in watchdog-run.json.
    from vulndog import cli

    cli._print_drop_summary({"redaction_dropped": 0, "queue_drops": 0,
                             "spool_dropped": 0, "connections_refused": 0,
                             "flush_dropped": 0})
    assert capsys.readouterr().err == ""
    cli._print_drop_summary({"redaction_dropped": 0, "queue_drops": 2,
                             "spool_dropped": 0, "connections_refused": 0,
                             "flush_dropped": 1})
    err = capsys.readouterr().err
    assert "queue_drops=2" in err and "flush_dropped=1" in err


def test_facade_skips_tap_meta_lines_without_error_pollution(tmp_path):
    store = build_fixture_store(str(tmp_path / "kb.sqlite"))
    run_dir = tmp_path / "20261121-120000-meta"
    run_dir.mkdir()
    event = {
        "ts": "2026-11-21T12:00:00Z", "hunt_id": run_dir.name,
        "tap_class": "tool_http", "url": "https://t.local/login.php",
        "method": "GET", "status": 200, "decision": "allowed",
        "provenance": "vulndog.proxy", "content_type": "text/html",
        "body_redacted": "login redirect xss",
    }
    lines = [json.dumps(event),
             json.dumps({"type": "drop_counter", "dropped": 3,
                         "ts": "2026-11-21T12:00:01Z"}),
             json.dumps({"type": "spool_cap", "cap": 5,
                         "ts": "2026-11-21T12:00:02Z"})]
    (run_dir / "events.jsonl").write_text("\n".join(lines) + "\n",
                                          encoding="utf-8")
    summary = api.analyze_run(
        events_path=str(run_dir / "events.jsonl"), run_dir=str(run_dir),
        store_path=store, config={"embedder": StubEmbedder(E1)})
    assert summary["status"] == "ok"
    assert summary["events_read"] == 3
    assert summary["meta_lines"] == 2
    assert summary["schema_invalid"] == 0   # meta lines are NOT errors
    assert summary["errors"] == 0
    assert summary["highlights"] >= 1