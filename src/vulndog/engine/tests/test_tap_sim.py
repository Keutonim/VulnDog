"""Tests for vuln_watchdog.tap_sim (P0 item 5; design 7 queue/flusher rows).

Standalone simulation of the P2 hook mechanics -- NO upstream source
changes: publish + bounded-queue enqueue (cap 1000, drop-oldest with a
visible counter) and the off-path flusher (pre-truncate SEC-06 ->
redact -> spool append, fail-closed).
"""
import json
import os
import shutil
import tempfile
import unittest

from vulndog.engine import tap_sim


def ev(i, **over):
    e = {
        "ts": "2026-10-15T12:00:00", "hunt_id": "task-1", "tap_class": "python",
        "url": "https://t.local/p/%d?token=xK9mP2qL7vR4tW8yB3nF6jH1z" % i,
        "method": "GET", "decision": "allowed", "status": 200,
        "body_redacted": "<html>ok %d session aB3dE5fG7hI9jK1lM3nO5p</html>" % i,
        "provenance": "sim", "seq": i,
    }
    e.update(over)
    return e


class BoundedDropQueueTest(unittest.TestCase):
    def test_publish_and_drain_order(self):
        q = tap_sim.BoundedDropQueue(cap=10)
        for i in range(5):
            self.assertTrue(q.publish(ev(i)))
        out = q.drain()
        self.assertEqual([e["seq"] for e in out], [0, 1, 2, 3, 4])
        self.assertEqual(q.published_count, 5)

    def test_cap_drops_oldest_and_counts(self):
        q = tap_sim.BoundedDropQueue(cap=3)
        for i in range(5):
            q.publish(ev(i))
        out = q.drain()
        self.assertEqual([e["seq"] for e in out], [2, 3, 4])
        self.assertEqual(q.drop_count, 2)

    def test_default_cap_is_1000(self):
        self.assertEqual(tap_sim.BoundedDropQueue().cap, 1000)

    def test_publish_never_raises_on_internal_failure(self):
        q = tap_sim.BoundedDropQueue(cap=5)
        orig = q._enqueue

        def boom(event):
            raise RuntimeError("simulated internal failure")
        q._enqueue = boom
        self.assertFalse(q.publish(ev(1)))
        self.assertEqual(q.error_count, 1)
        q._enqueue = orig
        self.assertTrue(q.publish(ev(2)))

    def test_drain_respects_max_events(self):
        q = tap_sim.BoundedDropQueue(cap=10)
        for i in range(6):
            q.publish(ev(i))
        out = q.drain(max_events=2)
        self.assertEqual(len(out), 2)
        self.assertEqual(len(q.drain()), 4)


class FlusherTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-tap-test-")
        self.spool = os.path.join(self.tmp, "events.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def read_spool(self):
        with open(self.spool, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def test_flush_writes_redacted_jsonl(self):
        q = tap_sim.BoundedDropQueue(cap=100)
        q.publish(ev(1))
        fl = tap_sim.Flusher(self.spool)
        counts = fl.flush(q)
        self.assertEqual(counts["written"], 1)
        rows = self.read_spool()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("xK9mP2qL7vR4tW8yB3nF6jH1z", rows[0]["url"])
        self.assertNotIn("aB3dE5fG7hI9jK1lM3nO5p", rows[0]["body_redacted"])
        self.assertEqual(rows[0]["seq"], 1)

    def test_pre_truncate_8kb_on_by_default(self):
        q = tap_sim.BoundedDropQueue(cap=10)
        q.publish(ev(1, body_redacted="y" * 20000))
        tap_sim.Flusher(self.spool).flush(q)
        row = self.read_spool()[0]
        self.assertLessEqual(len(row["body_redacted"]), 8192)

    def test_fail_closed_event_dropped_not_written(self):
        q = tap_sim.BoundedDropQueue(cap=10)
        q.publish(ev(1))

        def boom(text):
            raise RuntimeError("redactor exploded")
        counts = tap_sim.Flusher(self.spool, redactor=boom).flush(q)
        self.assertEqual(counts["written"], 0)
        self.assertEqual(counts["dropped_redaction"], 1)
        rows = self.read_spool() if os.path.exists(self.spool) else []
        self.assertEqual(rows, [], "nothing may be persisted raw")

    def test_drop_counter_event_appended_to_spool(self):
        q = tap_sim.BoundedDropQueue(cap=2)
        for i in range(5):
            q.publish(ev(i))
        fl = tap_sim.Flusher(self.spool)
        fl.flush(q)
        rows = self.read_spool()
        drops = [r for r in rows if r.get("type") == "drop_counter"]
        self.assertEqual(len(drops), 1)
        self.assertEqual(drops[0]["dropped"], 3)
        # counter reported once, not repeated on the next flush
        fl.flush(q)
        rows = self.read_spool()
        self.assertEqual(len([r for r in rows if r.get("type") == "drop_counter"]), 1)

    def test_flush_is_append_across_calls(self):
        q = tap_sim.BoundedDropQueue(cap=10)
        fl = tap_sim.Flusher(self.spool)
        q.publish(ev(1))
        fl.flush(q)
        q.publish(ev(2))
        fl.flush(q)
        rows = self.read_spool()
        self.assertEqual([r["seq"] for r in rows], [1, 2])


if __name__ == "__main__":
    unittest.main()
