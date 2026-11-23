"""WD-R1 capture half -- resume-safe tailers (design-spec 3.3/3.4/5.0; P2 Track B).

Three tailers feed the P4 matching loop with normalized F3 events. NO
matching logic lives here (P4); this module is capture + normalization +
redaction of TAILED sources only. Pure stdlib; read-only w.r.t. every
watched file; ``poll()`` NEVER raises (per-source errors are counted).

- ``SpoolTailer``: ``evidence/watchdog/<task-id>/events.jsonl`` --
  already redacted at the source (the WD-T1 flusher runs F4 before
  persist). Consumer rules (COND-4, defense in depth with the writer-side
  newline repair): invalid lines are skipped + counted; an UNTERMINATED
  trailing line is never consumed (the offset stays before it until the
  writer completes it); ``drop_counter`` spool meta lines are counted, not
  yielded; a missing ``hunt_id`` is stamped from the spool directory name
  (normalization to full F3 -- tool_http events ride the tap's configured
  task id; the F4 ``<redacted>`` placeholder counts as missing and gets
  the same restamp -- spool-directory metadata, not de-redaction).
  Schema-invalid lines are COUNTED (``schema_invalid``) but still
  yielded: strict validation/rejection + F4 re-run on consumed text is the
  P4 matcher's rule (COND-7a).

- ``LedgerTailer``: ``<task_dir>/guard_log.jsonl`` (written O(1)-append by
  ``request_budget.RequestMeter._write_jsonl``). Ledger lines carry RAW
  urls/notes: each line is mapped with ``event_schema.event_from_ledger``
  (zero-lossy D-2 mapping: ts/task_id/url/decision/engine/denial/reason/
  rule/note/ua_present/cookie_present/count/mode; engine+rule fold into
  provenance+denial_reason; count/mode ride ledger-class events) and then
  F4-redacted BEFORE yield (design 5.3.2 ordering law for tailed sources:
  redact -> persist/embed; fail-closed: a redaction drop skips the event
  and counts it). Over-cap fields are truncated to ``event_schema.
  FIELD_CAPS`` before mapping (counted), so a poisoned/huge line degrades
  to a shorter event instead of a rejection.

- ``EvidenceTailer``: file-watch on ``<evidence_dir>/*.txt`` scanner outputs
  (httpx/katana/nuclei/... -- written at tool completion, not appended
  incrementally: design 6). One evidence-class F3 event per content delta
  (tool-completion granularity); the delta text rides ``body_redacted``
  through the full F4 body pipeline (SEC-06 pre-truncate -> upstream passes
  -> entropy -> persist cap), so a delta bigger than the capture cap
  continues as further events on subsequent polls.

Offsets persist in a small JSON state file beside the watched source
(design 3.4: attach/detach mid-hunt; a restart resumes without
re-processing). State writes are atomic (tmp + ``os.replace``, the
``request_budget._write_guard_log`` precedent). A file that SHRANK below
the stored offset (rewrite/rotation) rewinds to 0 (counted, never a crash).

Prompt-injection discipline (C12): everything tailed is UNTRUSTED DATA --
this module only shapes/redacts it; it never follows instructions found in
it, and downstream consumers keep the C-2 fence rules.
"""
from __future__ import annotations

import fnmatch
import json
import os

from . import event_schema as es
from . import redaction_adapter as ra

# One poll reads at most this many bytes per jsonl source (bounded work per
# cycle; a huge backlog continues on the next poll).
MAX_READ_PER_POLL = 8_000_000

# Evidence delta read cap per file per poll = the F3 body capture cap
# (bytes read <= chars decoded, so make_event's capture-side cap holds).
EVIDENCE_DELTA_CAP_BYTES = es.BODY_CAPTURE_CAP_BYTES

EVIDENCE_PATTERN = "*.txt"

# F4's opaque-run replacement marker (redaction_adapter): a hunt_id that
# WAS a high-entropy value reaches the spool as this literal. SpoolTailer
# treats it as MISSING and restamps the spool-directory task id (local
# metadata only -- no de-redaction happens or is possible here).
REDACTED_HUNT_ID = "<redacted>"

# Ledger component caps: denial+reason+rule fold into one denial_reason
# (cap 2000) -- capping each component at 600 keeps the joined form under
# the cap for any input (600*2 + "rule=" + 600 < 2000; a reason equal to
# the denial is deduped by event_from_ledger anyway).
_LEDGER_COMPONENT_CAP = 600
_LEDGER_PRECAPS = (
    ("url", es.FIELD_CAPS["url"]),
    ("ts", es.FIELD_CAPS["ts"]),
    ("task_id", es.FIELD_CAPS["hunt_id"]),
    ("note", es.FIELD_CAPS["note"]),
    ("mode", es.FIELD_CAPS["mode"]),
    ("engine", _LEDGER_COMPONENT_CAP),
    ("denial", _LEDGER_COMPONENT_CAP),
    ("reason", _LEDGER_COMPONENT_CAP),
    ("rule", _LEDGER_COMPONENT_CAP),
)


class OffsetState:
    """Small JSON offset store with atomic save (tmp + os.replace).

    Corrupt/missing state degrades to a fresh start (counted) -- a broken
    state file must never wedge the watchdog process (design 7: restart
    resumes; worst case the backlog is re-processed once).
    """

    def __init__(self, path):
        self.path = str(path)
        self.data: dict = {}
        self.load_errors = 0
        self.save_errors = 0
        self._load()

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data = loaded
            else:
                self.load_errors += 1
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            self.load_errors += 1

    def get(self, key, default=None):
        value = self.data.get(key)
        return default if value is None else value

    def set(self, key, value) -> None:
        self.data[key] = value

    def save(self) -> None:
        tmp = self.path + ".tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except OSError:
            self.save_errors += 1
            try:
                os.unlink(tmp)
            except OSError:
                pass


class _JsonlTailer:
    """Shared line-oriented tail: complete lines only, from a persisted
    byte offset. An unterminated trailing line stays unconsumed (COND-4
    consumer rule); a shrink below the offset rewinds to 0 (counted)."""

    def __init__(self, path, state_path):
        self.path = str(path)
        self.state = OffsetState(state_path)
        try:
            self._offset = int(self.state.get("offset", 0) or 0)
        except (TypeError, ValueError):
            self._offset = 0
            self.state.load_errors += 1
        self._counters = {"lines_consumed": 0, "invalid_lines": 0,
                          "rewinds": 0, "read_errors": 0}

    def stats(self) -> dict:
        out = dict(self._counters)
        out["offset"] = self._offset
        out["state_load_errors"] = self.state.load_errors
        out["state_save_errors"] = self.state.save_errors
        return out

    def _read_new_lines(self):
        """Complete new lines (str, no newline) since the stored offset;
        [] when the file is missing/unchanged. Never raises."""
        try:
            with open(self.path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size < self._offset:
                    self._counters["rewinds"] += 1
                    self._offset = 0
                fh.seek(self._offset)
                data = fh.read(MAX_READ_PER_POLL)
        except FileNotFoundError:
            return []
        except OSError:
            self._counters["read_errors"] += 1
            return []
        if not data:
            return []
        cut = data.rfind(b"\n")
        if cut < 0:
            return []                    # torn tail only: consume nothing
        block = data[:cut + 1]
        self._offset += len(block)
        self._counters["lines_consumed"] += block.count(b"\n")
        lines = block.decode("utf-8", "replace").split("\n")
        return [ln for ln in lines if ln.strip()]

    def _persist_offset(self, advanced: bool) -> None:
        if advanced:
            self.state.set("offset", self._offset)
        self.state.save()


class SpoolTailer(_JsonlTailer):
    """Tails the WD-T1 redacted spool ``events.jsonl``.

    ``hunt_id`` defaults to the spool directory name (the task id the tap
    wrote under); events missing the field -- or carrying the F4
    ``<redacted>`` placeholder in it -- get the task id stamped
    (normalization to full F3). State file: ``state.json`` beside the
    spool (design 3.4).
    """

    def __init__(self, spool_path, state_path=None, hunt_id=None):
        spool_path = str(spool_path)
        spool_dir = os.path.dirname(spool_path) or "."
        if state_path is None:
            state_path = os.path.join(spool_dir, "state.json")
        super().__init__(spool_path, state_path)
        if hunt_id is None:
            hunt_id = os.path.basename(os.path.normpath(spool_dir))
        self.hunt_id = str(hunt_id or "")
        self._counters.update({"drop_counter_events": 0, "hunt_id_stamped": 0,
                               "schema_invalid": 0, "events": 0})

    def poll(self) -> list:
        """New spool events (dicts) since the last poll; never raises."""
        lines = self._read_new_lines()
        events = []
        for line in lines:
            try:
                obj = json.loads(line)
            except ValueError:
                self._counters["invalid_lines"] += 1     # COND-4 skip rule
                continue
            if not isinstance(obj, dict):
                self._counters["invalid_lines"] += 1
                continue
            if obj.get("type") == "drop_counter":
                self._counters["drop_counter_events"] += 1
                continue
            hunt_id = obj.get("hunt_id")
            if (not hunt_id or hunt_id == REDACTED_HUNT_ID) and self.hunt_id:
                obj["hunt_id"] = self.hunt_id
                self._counters["hunt_id_stamped"] += 1
            if es.validate_event(obj):
                self._counters["schema_invalid"] += 1    # surfaced, not gated
            events.append(obj)
            self._counters["events"] += 1
        self._persist_offset(advanced=bool(lines))
        return events


class LedgerTailer(_JsonlTailer):
    """Tails ``guard_log.jsonl`` -> normalized + F4-redacted F3 events.

    Mapping is ``event_schema.event_from_ledger`` (zero-lossy, D-2). Raw
    ledger text NEVER leaves this class unredacted: fail-closed -- a
    redaction drop skips the event and counts it. State file default:
    ``watchdog_state_ledger.json`` beside the ledger.
    """

    def __init__(self, ledger_path, state_path=None):
        ledger_path = str(ledger_path)
        if state_path is None:
            state_path = os.path.join(os.path.dirname(ledger_path) or ".",
                                      "watchdog_state_ledger.json")
        super().__init__(ledger_path, state_path)
        self._counters.update({"rejected_entries": 0, "truncated_fields": 0,
                               "dropped_redaction": 0, "events": 0})

    def poll(self) -> list:
        lines = self._read_new_lines()
        events = []
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                self._counters["invalid_lines"] += 1
                continue
            if not isinstance(entry, dict):
                self._counters["invalid_lines"] += 1
                continue
            capped = dict(entry)
            for field, cap in _LEDGER_PRECAPS:
                value = capped.get(field)
                if isinstance(value, str) and len(value) > cap:
                    capped[field] = value[:cap]
                    self._counters["truncated_fields"] += 1
            try:
                event = es.event_from_ledger(capped)
            except ValueError:
                self._counters["rejected_entries"] += 1   # stable-code reject
                continue
            try:
                redacted, dropped = ra.redact_event(event)
            except Exception:  # noqa: BLE001 -- fail-closed by contract
                redacted, dropped = None, True
            if dropped or not isinstance(redacted, dict):
                self._counters["dropped_redaction"] += 1  # never pass raw
                continue
            events.append(redacted)
            self._counters["events"] += 1
        self._persist_offset(advanced=bool(lines))
        return events


class EvidenceTailer:
    """File-watch on ``<evidence_dir>/*.txt`` scanner outputs.

    One evidence-class F3 event per content delta (tool-completion
    granularity, design 6); the delta rides ``body_redacted`` through the
    full F4 pipeline (fail-closed: a redaction drop skips the event but
    still advances the offset -- the text is never re-processed raw).
    State file default: ``watchdog_state_evidence.json`` inside the watched
    dir (its name cannot match ``*.txt``). ``poll()`` never raises.
    """

    def __init__(self, evidence_dir, hunt_id, state_path=None,
                 pattern=EVIDENCE_PATTERN):
        self.dir = str(evidence_dir)
        self.hunt_id = str(hunt_id or "")
        self.pattern = pattern
        if state_path is None:
            state_path = os.path.join(self.dir,
                                      "watchdog_state_evidence.json")
        self.state = OffsetState(state_path)
        files = self.state.get("files", {})
        self._files = dict(files) if isinstance(files, dict) else {}
        self._counters = {"events": 0, "rewinds": 0, "read_errors": 0,
                          "dropped_redaction": 0, "make_errors": 0,
                          "files_seen": 0}

    def stats(self) -> dict:
        out = dict(self._counters)
        out["state_load_errors"] = self.state.load_errors
        out["state_save_errors"] = self.state.save_errors
        out["files_tracked"] = len(self._files)
        return out

    def poll(self) -> list:
        try:
            names = sorted(fnmatch.filter(os.listdir(self.dir), self.pattern))
        except OSError:
            self._counters["read_errors"] += 1
            return []
        events = []
        changed = False
        for name in names:
            path = os.path.join(self.dir, name)
            if not os.path.isfile(path):
                continue
            self._counters["files_seen"] += 1
            before = self._files.get(name)
            event = self._poll_file(name, path)
            if event is not None:
                events.append(event)
            if self._files.get(name) != before:
                changed = True
        if changed:
            self.state.set("files", self._files)
            self.state.save()
        return events

    def _poll_file(self, name, path):
        try:
            size = os.path.getsize(path)
        except OSError:
            self._counters["read_errors"] += 1
            return None
        record = self._files.get(name)
        offset = 0
        if isinstance(record, dict):
            try:
                offset = int(record.get("offset", 0) or 0)
            except (TypeError, ValueError):
                offset = 0
        if size < offset:
            self._counters["rewinds"] += 1
            offset = 0
        if size == offset:
            return None
        try:
            with open(path, "rb") as fh:
                fh.seek(offset)
                delta = fh.read(EVIDENCE_DELTA_CAP_BYTES)
        except OSError:
            self._counters["read_errors"] += 1
            return None
        self._files[name] = {"offset": offset + len(delta)}
        if not delta:
            return None
        text = delta.decode("utf-8", "replace")
        try:
            event = es.make_event(
                tap_class="evidence",
                url="file:///" + name.replace("\\", "/"),
                decision="allowed",           # observation, not a gate call
                provenance="evidence:" + name,
                hunt_id=self.hunt_id,
                content_type="text/plain",
                body_redacted=text)
        except ValueError:
            self._counters["make_errors"] += 1
            return None
        try:
            redacted, dropped = ra.redact_event(event)
        except Exception:  # noqa: BLE001 -- fail-closed by contract
            redacted, dropped = None, True
        if dropped or not isinstance(redacted, dict):
            self._counters["dropped_redaction"] += 1
            return None
        self._counters["events"] += 1
        return redacted
