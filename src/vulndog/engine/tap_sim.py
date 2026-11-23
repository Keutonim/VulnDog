"""Standalone simulation of the P2 tap mechanics for the P0 overhead
micro-benchmark (design section 7: bounded queue cap 1000 drop-oldest with
a VISIBLE counter; off-path flusher: pre-truncate SEC-06 -> redact -> spool
append; fail-closed).

NO upstream source is touched: this mirrors the queue/flusher mechanics of
the shipped watchdog_tap.py (P2); mechanics only, drift-prone by design,
so the measured per-event cost stays representative.
"""
from __future__ import annotations

import json
import threading
import time
from collections import deque

from . import redaction_adapter

DEFAULT_CAP = 1000


class BoundedDropQueue:
    """In-process bounded queue: publish never blocks, never raises.

    Overflow drops the OLDEST event and increments drop_count (the flusher
    surfaces it as a drop_counter spool event -- visible, not silent).
    """

    def __init__(self, cap: int = DEFAULT_CAP):
        self.cap = cap
        self._dq = deque()
        self._lock = threading.Lock()
        self.published_count = 0
        self.drop_count = 0
        self.error_count = 0

    def _enqueue(self, event):
        with self._lock:
            if len(self._dq) >= self.cap:
                self._dq.popleft()
                self.drop_count += 1
            self._dq.append(event)

    def publish(self, event) -> bool:
        """Exception-safe by contract: any internal failure is counted,
        never propagated into the (future) request path."""
        try:
            self._enqueue(event)
            self.published_count += 1
            return True
        except Exception:
            self.error_count += 1
            return False

    def drain(self, max_events: int | None = None):
        out = []
        with self._lock:
            while self._dq and (max_events is None or len(out) < max_events):
                out.append(self._dq.popleft())
        return out

    def __len__(self):
        return len(self._dq)


class Flusher:
    """Off-path consumer: redact (fail-closed) -> append JSONL spool."""

    def __init__(self, spool_path: str, redactor=None,
                 pre_truncate_bytes: int = redaction_adapter.PRE_TRUNCATE_BYTES):
        self.spool_path = spool_path
        self.redactor = redactor
        self.pre_truncate_bytes = pre_truncate_bytes
        self._drops_reported = 0

    def flush(self, queue: BoundedDropQueue, max_events: int | None = None) -> dict:
        counts = {"written": 0, "dropped_redaction": 0, "drops_reported": 0}
        pending = []
        if queue.drop_count > self._drops_reported:
            delta = queue.drop_count - self._drops_reported
            pending.append({"type": "drop_counter", "dropped": delta,
                            "ts": time.strftime("%Y-%m-%dT%H:%M:%S")})
            self._drops_reported = queue.drop_count
            counts["drops_reported"] = delta
        for event in queue.drain(max_events=max_events):
            out, dropped = redaction_adapter.redact_event(
                event, redactor=self.redactor,
                pre_truncate_bytes=self.pre_truncate_bytes)
            if dropped:
                counts["dropped_redaction"] += 1
                continue
            pending.append(out)
            counts["written"] += 1
        if pending:
            # one open handle per flush call (append-only spool, design 6)
            with open(self.spool_path, "a", encoding="utf-8") as f:
                for obj in pending:
                    f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        return counts
