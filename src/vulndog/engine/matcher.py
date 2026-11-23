"""WD-R1 matching half -- the per-event matching loop (design-spec 5.3,
3.4, section 7; P4).

Consumes normalized F3 events (from ``tailers``), builds the design 5.3.1
EVENT TEXT UNIT, embeds it via the WD-E7 query API, suppresses repeats,
and returns design 5.4 highlight records (built by ``highlights``).

Laws implemented here (traced):

- **COND-7a (consumption side, SEC-13):** the spool is NEVER trusted
  blindly -- every consumed event is (1) schema-validated with
  ``event_schema.validate_event`` (invalid -> counted DROP, never
  matched) and (2) passed through a full F4 ``redact_event`` RE-RUN
  (fail-closed: a redaction drop is counted, the text never reaches the
  embedder). The embed text is built ONLY from the re-redacted copy;
  highlight METADATA uses the event as persisted (already F4'd at the
  tap; the spool url is the canonical masked form).
- **COND-7b:** the embed snippet is capped at
  ``event_schema.EMBED_SNIPPET_CAP_CHARS`` (1,200 -- the shared
  constant, never re-derived); the whole text unit is capped at
  ``EMBED_TEXT_CAP_CHARS`` (implementation guard: ~2,048-token
  EmbeddingGemma context at the design's ~4 chars/token estimate).
- **SEC-08 (owner-adopted):** the target HOST never enters the embed
  text -- path + param NAMES only; query VALUES are dropped entirely
  (Security C-1: values are the secret-carrying part; names are the
  matching signal). Host survives as event/highlight metadata.
- **COND-7e:** FTS5 MATCH construction stays inside the query API
  (``kb_index.fts_match_query`` discipline) -- this module NEVER builds
  a MATCH expression; per-event skips (``status="skipped"``, non-embed
  reasons) stay LOCAL (counter, loop continues) -- the global DISABLED
  signal is reserved for store-level failures and Ollama outages.
- **Design section 7 mode machine:** Ollama unreachable/hung ->
  ``matching: DISABLED (ollama unreachable|hung)`` + the event is held
  in a pending buffer (the runner STOPS polling, so the spool/ledger
  offsets do not advance and the backlog accumulates as the "unprocessed
  tail") + 60 s backoff (clock-driven; no sleeps here) + resume IN
  ORDER via ``retry_pending``. KB store-level disabled -> capture-only
  mode (``matching: DISABLED (KB not built)``), events are consumed and
  counted (the cheap per-call ``os.path.exists`` pre-check in the query
  API keeps this free) and the store auto-detects on the next ok match.
- **Per-event deadline (C-3/COND-7d):** the match call runs on a daemon
  worker thread joined with ``per_event_deadline_s``; a hang takes the
  same DISABLED+backoff path as an outage (design 5.1). The client-side
  10 s timeout + bounded retries remain the first guard; the deadline is
  the backstop for sqlite/unknown hangs. Abandoned workers are CAPPED
  (``MAX_ABANDONED_WORKERS``, QA D-2): a persistent hang no longer leaks
  one thread per backoff cycle -- at the cap the attempt takes the hung
  path without spawning, slots free as hung calls return, and the live
  count is surfaced via ``stats()`` (-> run-state counters -> status).
- **Suppression (5.3.6):** the same (url, record_id) pair is highlighted
  once per session; repeats collapse into ``burst_counts`` with a
  visible console notice at 10/100/1k/10k; per-record and per-url mutes
  come from config.
- **Advisory framing (C8/5.3.7):** this module produces CANDIDATES for
  the WD-R2 surfaces; nothing here is a finding, and nothing here ever
  issues a request, touches a rail, or writes hunt state.

Pure stdlib. No target-bound traffic (the only call is the loopback
query API). Prompt-injection discipline (C12): event text is untrusted
DATA -- it is shaped, capped, redacted and embedded; never followed.
"""
from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

from . import event_schema as es
from . import highlights as _hl
from . import redaction_adapter as ra

# ---------------------------------------------------------------- constants

MODE_ENABLED = "enabled"
MODE_OLLAMA_DOWN = "ollama-down"
MODE_OLLAMA_HUNG = "ollama-hung"
MODE_KB_MISSING = "kb-missing"

_DOWN_MODES = (MODE_OLLAMA_DOWN, MODE_OLLAMA_HUNG)

#: Exact status lines (design section 7 / brief P4 item 1).
LINE_OLLAMA_DOWN = "matching: DISABLED (ollama unreachable)"
LINE_OLLAMA_HUNG = "matching: DISABLED (ollama hung)"
LINE_KB_MISSING = "matching: DISABLED (KB not built)"
LINE_ENABLED_RECOVERED = "matching: ENABLED (ollama recovered)"
LINE_ENABLED_KB = "matching: ENABLED (KB detected)"

DEFAULT_BACKOFF_S = 60.0            # design section 7: 60 s retry backoff
DEFAULT_PER_EVENT_DEADLINE_S = 60.0  # backstop above the client's 10 s chain

#: Cap on concurrently ABANDONED (still-alive) deadline workers -- QA D-2
#: (artifacts/qa-p4-1.md): a persistent per-event hang previously leaked
#: one daemon thread (plus its per-call sqlite connection) per backoff
#: cycle, bounded only by a process restart. At the cap no new worker is
#: spawned -- the attempt takes the same hung/backoff path -- and slots
#: free themselves as hung calls return. Each abandoned worker may hold a
#: query connection, so the cap is deliberately small.
MAX_ABANDONED_WORKERS = 4

#: Implementation guard on the WHOLE embed input (~2048-token context at
#: the design's ~4 chars/token estimate; the query prefix rides on top).
EMBED_TEXT_CAP_CHARS = 8000

#: Burst-collapse visibility thresholds (suppressed-repeat counts).
BURST_NOTICE_AT = (10, 100, 1000, 10000)

#: Bounded status-line history kept for run-state/status surfaces.
STATUS_LINES_MAX = 50

#: query.match() skip reasons that mean "Ollama itself failed" (-> down
#: mode). Every other skip reason is a LOCAL per-event skip (COND-7e).
_EMBED_DOWN_REASONS = frozenset({"embed-failed", "embed-invalid"})

_BINARY_CT_PREFIXES = (
    "image/", "audio/", "video/", "font/", "model/", "multipart/",
)
_BINARY_CT_EXACT = frozenset({
    "application/octet-stream", "application/pdf", "application/zip",
    "application/gzip", "application/x-tar", "application/wasm",
    "application/vnd.ms-fontobject", "application/x-shockwave-flash",
})


# ------------------------------------------------------------ text unit 5.3.1

def text_like_content_type(ct) -> bool:
    """Snippet eligibility (design 5.3.1: "text-like content only").

    Missing ct -> eligible (the producer chose to carry a body; safety
    is the redaction's job, not this predicate's). Clearly binary types
    -> not eligible."""
    if not ct or not isinstance(ct, str):
        return True
    low = ct.strip().lower()
    if not low:
        return True
    base = low.split(";", 1)[0].strip()
    if base in _BINARY_CT_EXACT:
        return False
    if base.startswith(_BINARY_CT_PREFIXES):
        return False
    return True


def split_embed_url(url: str):
    """(path, param_names) from a persisted masked url; HOST EXCLUDED
    (SEC-08), query VALUES dropped entirely (C-1: names are the signal).
    Never raises."""
    try:
        parts = urlsplit(url or "")
    except ValueError:
        return ("/", [])
    path = parts.path or "/"
    names = []
    if parts.query:
        for piece in parts.query.split("&"):
            if not piece:
                continue
            name = piece.partition("=")[0]
            if name and name not in names:
                names.append(name)
    return (path, names)


def build_event_text(event: dict,
                     snippet_cap: int = es.EMBED_SNIPPET_CAP_CHARS,
                     total_cap: int = EMBED_TEXT_CAP_CHARS) -> str:
    """Design 5.3.1 event text unit:

        {method} {path} params={names} status={n} ct={ct}
        denial={reason} snippet={<=1200 chars, text-like only}

    Missing components are omitted. COND-7b: the snippet is sliced at
    ``snippet_cap`` (default = the shared 1,200-char constant) and the
    whole unit at ``total_cap``. Whitespace in the snippet is collapsed
    (keeps the unit compact for FTS tokenization + embedding)."""
    parts = []
    method = event.get("method")
    if isinstance(method, str) and method:
        parts.append(method)
    path, names = split_embed_url(event.get("url") or "")
    parts.append(path)
    if names:
        parts.append("params=" + ",".join(names))
    status = event.get("status")
    if isinstance(status, int) and not isinstance(status, bool):
        parts.append("status=%d" % status)
    ct = event.get("content_type")
    if isinstance(ct, str) and ct:
        parts.append("ct=" + ct)
    denial = event.get("denial_reason")
    if isinstance(denial, str) and denial:
        parts.append("denial=" + denial)
    body = event.get("body_redacted")
    if isinstance(body, str) and body and text_like_content_type(ct):
        snippet = " ".join(body[:snippet_cap].split())   # COND-7b cap
        if snippet:
            parts.append("snippet=" + snippet)
    return " ".join(parts)[:total_cap]


# ------------------------------------------------------------------ matcher

class Matcher:
    """Per-event matching + mode machine + suppression.

    ``process_event(event) -> [highlight dicts]`` is the single entry
    point; it NEVER raises for expected failure classes (schema,
    redaction, store, embed, hangs -- all counted). ``retry_pending()``
    drains the outage buffer in order and returns
    ``(drained: bool, highlights: list)``. The runner drives polling
    cadence and the backoff clock; this class contains no sleeps and no
    I/O beyond the injected query API."""

    def __init__(self, api, *, floor=None, top_k=None, filters=None,
                 mute_record_ids=(), mute_url_prefixes=(),
                 console=None, clock=time.monotonic,
                 backoff_s: float = DEFAULT_BACKOFF_S,
                 per_event_deadline_s: float = DEFAULT_PER_EVENT_DEADLINE_S,
                 max_abandoned_workers: int = None):
        self.api = api
        self.floor = floor
        self.top_k = top_k
        self.filters = filters
        self.mute_record_ids = frozenset(mute_record_ids or ())
        self.mute_url_prefixes = tuple(mute_url_prefixes or ())
        self._console = console
        self._clock = clock
        self.backoff_s = float(backoff_s)
        self.per_event_deadline_s = float(per_event_deadline_s)
        self.max_abandoned_workers = int(
            MAX_ABANDONED_WORKERS if max_abandoned_workers is None
            else max_abandoned_workers)

        self.mode = MODE_ENABLED
        self.pending = []            # outage buffer (in-order, F3 events)
        self._abandoned = []         # alive abandoned workers (D-2 cap);
        # touched only from the runner-loop thread (process_event /
        # retry_pending / stats all run on it) -- no lock needed.
        self.next_retry = 0.0        # clock value; runner compares
        self.seen = set()            # (url, record_id) session dedup
        self.burst_counts = {}       # (url, record_id) -> repeats
        self.status_lines = []       # bounded announce history

        self._counters = {
            "events_in": 0, "schema_invalid": 0, "redaction_dropped": 0,
            "matched_ok": 0, "matched_empty": 0, "highlights": 0,
            "suppressed_duplicates": 0, "muted_records": 0,
            "muted_urls": 0, "embed_failures": 0, "hangs": 0,
            "kb_disabled_events": 0, "skipped_events": 0,
            "buffered_while_down": 0, "recovered": 0,
        }
        self._skip_reasons = {}
        self._match_seconds_total = 0.0
        self._match_seconds_max = 0.0

    # ---------------------------------------------------------------- props
    @property
    def down(self) -> bool:
        """True while Ollama is down/hung: the runner must STOP polling
        (offsets stay put; the backlog accumulates as the unprocessed
        spool tail -- design section 7)."""
        return self.mode in _DOWN_MODES

    def stats(self) -> dict:
        out = dict(self._counters)
        out["mode"] = self.mode
        out["pending"] = len(self.pending)
        out["seen_pairs"] = len(self.seen)
        out["skip_reasons"] = dict(self._skip_reasons)
        out["match_seconds_total"] = round(self._match_seconds_total, 3)
        out["match_seconds_max"] = round(self._match_seconds_max, 3)
        # D-2 (QA): live abandoned-worker count -> run-state counters ->
        # the status surface ("surface the count in status").
        out["abandoned_workers"] = sum(1 for t in self._abandoned
                                       if t.is_alive())
        return out

    # -------------------------------------------------------------- announce
    def _announce(self, line: str) -> None:
        self.status_lines.append(line)
        if len(self.status_lines) > STATUS_LINES_MAX:
            del self.status_lines[:len(self.status_lines) - STATUS_LINES_MAX]
        if self._console is not None:
            try:
                self._console(line)
            except Exception:  # noqa: BLE001 -- console never kills the loop
                pass

    # ---------------------------------------------------------------- entry
    def consume(self, events) -> list:
        """Process a polled batch; returns all highlights. When the mode
        flips to down mid-batch the remaining events are buffered into
        ``pending`` (never dropped)."""
        out = []
        for event in events or ():
            out.extend(self.process_event(event))
        return out

    def process_event(self, event, probe: bool = False) -> list:
        """One event -> highlight list ([] when nothing to report).

        ``probe=True`` is the recovery attempt from ``retry_pending``:
        the down-guard is bypassed so the match is actually tried."""
        self._counters["events_in"] += 1
        if self.down and not probe:
            # buffered, not matched (runner stops polling anyway; this is
            # the defensive path for events already in flight)
            self.pending.append(event)
            self._counters["buffered_while_down"] += 1
            return []

        # --- COND-7a part 1: schema validation (never trust the spool)
        if es.validate_event(event):
            self._counters["schema_invalid"] += 1
            return []
        # --- COND-7a part 2: F4 re-run on the consumed text (fail-closed)
        try:
            redacted, dropped = ra.redact_event(dict(event))
        except Exception:  # noqa: BLE001 -- fail-closed by contract
            redacted, dropped = None, True
        if dropped or not isinstance(redacted, dict):
            self._counters["redaction_dropped"] += 1
            return []

        text = build_event_text(redacted)          # COND-7b + SEC-08
        kind, env = self._match_with_deadline(text)

        if kind == "hang":
            self._enter_down(MODE_OLLAMA_HUNG, LINE_OLLAMA_HUNG, event)
            self._counters["hangs"] += 1
            return []
        if kind == "exc":
            # a raise out of the query API is a programming-level fault:
            # LOCAL skip (COND-7e), never a global disable
            self._counters["skipped_events"] += 1
            self._skip_reasons["api-exception"] = \
                self._skip_reasons.get("api-exception", 0) + 1
            return []

        status = env.get("status")
        if status == "disabled":
            # STORE-level failure: capture-only, event consumed (design
            # section 7 "KB cold/missing"); auto-detect on the next ok.
            if self.mode != MODE_KB_MISSING:
                self.mode = MODE_KB_MISSING
                self._announce(LINE_KB_MISSING)
            self._counters["kb_disabled_events"] += 1
            return []
        if status == "skipped":
            reason = env.get("reason")
            if reason in _EMBED_DOWN_REASONS:
                self._enter_down(MODE_OLLAMA_DOWN, LINE_OLLAMA_DOWN, event)
                self._counters["embed_failures"] += 1
                return []
            # COND-7e: per-event skip stays local; the API remains usable
            self._counters["skipped_events"] += 1
            self._skip_reasons[reason or "unknown"] = \
                self._skip_reasons.get(reason or "unknown", 0) + 1
            return []

        # --- status == "ok": recovery announce, then highlights
        if self.mode != MODE_ENABLED:
            self._counters["recovered"] += 1
            self._announce(LINE_ENABLED_KB if self.mode == MODE_KB_MISSING
                           else LINE_ENABLED_RECOVERED)
            self.mode = MODE_ENABLED
        self._counters["matched_ok"] += 1
        matches = env.get("matches") or []
        if not matches:
            self._counters["matched_empty"] += 1
            return []
        return self._to_highlights(event, matches, env.get("corpus_version"))

    def retry_pending(self):
        """Recovery probe: drain ``pending`` IN ORDER. Returns
        ``(drained, highlights)``; on the first embed failure the event
        goes back to the head (order preserved) and ``drained`` is
        False -- the runner re-arms ``next_retry``."""
        out = []
        while self.pending:
            event = self.pending.pop(0)
            out.extend(self.process_event(event, probe=True))
            if self.down:
                # process_event re-appended the failed event: restore order
                if self.pending and self.pending[-1] is event:
                    self.pending.pop()
                self.pending.insert(0, event)
                return False, out
        return True, out

    # -------------------------------------------------------------- internals
    def _enter_down(self, mode: str, line: str, event) -> None:
        first = self.mode != mode
        self.mode = mode
        if first:
            self._announce(line)
        self.pending.append(event)
        self.next_retry = self._clock() + self.backoff_s

    def _match_with_deadline(self, text: str):
        """("result", env) | ("hang", None) | ("exc", exc).

        The match runs on a daemon thread joined with the per-event
        deadline (COND-7d backstop; the embed client's own 10 s timeout
        is the first guard). Abandoned hung workers are tracked and
        CAPPED (D-2, QA qa-p4-1): at ``max_abandoned_workers`` live
        abandonments no new thread is spawned -- the attempt returns
        ("hang", None) immediately and takes the same DISABLED+backoff
        path -- so a persistent hang can no longer leak ~1 thread (+ its
        per-call sqlite connection) per backoff cycle. Slots free
        themselves as hung calls return (reap on the next attempt); the
        workers stay daemons, so a stuck one can never block shutdown."""
        deadline = self.per_event_deadline_s
        t0 = time.monotonic()
        if deadline is None or deadline <= 0:
            try:
                env = self._call_match(text)
            except Exception as exc:  # noqa: BLE001
                return ("exc", exc)
            self._record_time(t0)
            return ("result", env)
        self._reap_abandoned()
        if len(self._abandoned) >= self.max_abandoned_workers:
            # D-2 cap: every worker slot is occupied by an abandoned hung
            # thread; spawning another would grow the leak. Hung path
            # with no new thread (counted by the caller like any hang).
            self._record_time(t0)
            return ("hang", None)
        box = {}

        def run():
            try:
                box["env"] = self._call_match(text)
            except BaseException as exc:  # noqa: BLE001 -- carried to caller
                box["exc"] = exc

        worker = threading.Thread(target=run, name="wd-match-deadline",
                                  daemon=True)
        worker.start()
        worker.join(deadline)
        if worker.is_alive():
            self._abandoned.append(worker)
            self._record_time(t0)
            return ("hang", None)
        self._record_time(t0)
        if "exc" in box:
            return ("exc", box["exc"])
        return ("result", box.get("env") or {"status": "skipped",
                                             "reason": "empty-envelope",
                                             "matches": []})

    def _reap_abandoned(self) -> None:
        """Forget finished abandoned workers (a hung call that eventually
        returned frees its cap slot). Runner-loop-thread only, like every
        other ``_abandoned`` access."""
        if self._abandoned:
            self._abandoned = [t for t in self._abandoned if t.is_alive()]

    def _call_match(self, text: str):
        return self.api.match(text, top_k=self.top_k,
                              filters=self.filters, floor=self.floor)

    def _record_time(self, t0: float) -> None:
        dt = time.monotonic() - t0
        self._match_seconds_total += dt
        if dt > self._match_seconds_max:
            self._match_seconds_max = dt

    def _to_highlights(self, event, matches, corpus_version) -> list:
        """Suppression (5.3.6) + template-filled highlight build (5.4).

        Keys use the event AS PERSISTED (the spool url is the canonical
        masked form; the F4 re-run copy feeds only the embed text)."""
        url = event.get("url") or ""
        out = []
        for m in matches:
            record_id = m.get("record_id") or ""
            if record_id in self.mute_record_ids:
                self._counters["muted_records"] += 1
                continue
            if self.mute_url_prefixes and any(
                    url.startswith(p) for p in self.mute_url_prefixes):
                self._counters["muted_urls"] += 1
                continue
            key = (url, record_id)
            if key in self.seen:
                self._counters["suppressed_duplicates"] += 1
                count = self.burst_counts.get(key, 0) + 1
                self.burst_counts[key] = count
                if count in BURST_NOTICE_AT:
                    shown = url if len(url) <= 120 else url[:117] + "..."
                    self._announce("burst collapsed x%d: %s @ %s"
                                   % (count, record_id, shown))
                continue
            self.seen.add(key)
            out.append(_hl.build_highlight(event, m,
                                           corpus_version=corpus_version))
            self._counters["highlights"] += 1
        return out
