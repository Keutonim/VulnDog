"""F3 -- watchdog event schema (design-spec 5.0; one schema, every tap).

Producers: the P2 tap hooks (upstream net_gate / playwright / tool_proxy
publish through the upstream tap module) and the WD-R1 tailers (ledger,
evidence). Consumers: F4 redaction (the single enforcement point), the
spool, and the P4 matching loop.

Field law (design 5.0):
- ``tap_class`` in {python, browser, tool_http, ledger, evidence};
- ``decision`` in {allowed, denied} -- denials are FIRST-CLASS signal;
- ``ua_present`` / ``cookie_present`` are presence booleans ONLY
  (SEC-12 parity): NO header-value field exists in this schema;
- ``hop`` / ``final`` are PYTHON-leg only: the python leg publishes ONE
  event PER REDIRECT HOP (each hop re-runs the rails) with the 0-based
  hop index; the final hop also sets ``final: True``; browser and
  tool_http legs publish per-response and carry neither;
- ``count`` / ``mode`` / ``note`` ride LEDGER-class events only (the
  tool/browser aggregation lines; QA-2 MD-3);
- ``corpus_version`` is added by the MATCHER at match time, never by a
  tap -- schema-valid, tap-absent;
- ``body_redacted``: ALLOWED responses only; capture cap 200 KB
  (net_gate ceiling), persist cap 4,000 chars post-redaction, embed
  snippet cap 1,200 chars (design 6 / 5.3.1).

``event_from_ledger`` is the ZERO-LOSSY guard_log.jsonl translation
(plan F3 DoD 1): ts/task_id/url/decision/engine/denial/reason/rule/note/
ua_present/cookie_present/count/mode ALL map -- engine -> provenance,
denial+reason+rule -> denial_reason; the ledger's aggregate decisions
``tool`` / ``browser`` are EXECUTED-traffic lines -> decision "allowed"
(the original label survives inside provenance, e.g. ``tool:nuclei``).

Redaction happens AFTER normalization (F4, single enforcement point):
this module never redacts; it only shapes and validates.
"""
from __future__ import annotations

import time

TAP_CLASSES = ("python", "browser", "tool_http", "ledger", "evidence")
DECISIONS = ("allowed", "denied")

EVENT_FIELDS = (
    "ts", "hunt_id", "tap_class", "url", "method", "hop", "final",
    "decision", "status", "denial_reason", "ua_present", "cookie_present",
    "content_type", "body_redacted", "provenance", "corpus_version",
)
LEDGER_EXTRA_FIELDS = ("count", "mode", "note")
REQUIRED_EVENT_FIELDS = ("ts", "hunt_id", "tap_class", "url", "decision",
                         "provenance")
PYTHON_ONLY_FIELDS = ("hop", "final")

# Caps (design 6 / 5.3.1) -- constants so consumers never re-derive them.
BODY_CAPTURE_CAP_BYTES = 200_000    # net_gate body ceiling at capture
BODY_PERSIST_CAP_CHARS = 4000       # event persistence cap, post-redaction
EMBED_SNIPPET_CAP_CHARS = 1200      # embed-input snippet cap

# P2 COND-3 (SCC-03, security-code-review 2026-10-15): per-field length
# caps for EVERY string field, mirrored at the schema side so producers are
# rejected early with a stable ``too_long:<field>`` code. The F4 adapter
# independently caps at persist time (single enforcement point; defense in
# depth). body_redacted carries the CAPTURE-side cap here (pre-redaction
# bodies up to the net_gate 200 KB ceiling are legitimate producer input);
# the 4,000-char PERSIST cap is applied post-redaction by F4 (design 6
# ordering law). hunt_id 128 mirrors the tap task-id law.
DEFAULT_FIELD_CAP = 2000
FIELD_CAPS = {
    "ts": 2000,
    "hunt_id": 128,
    "tap_class": 32,
    "url": 4096,
    "method": 16,
    "denial_reason": 2000,
    "content_type": 2000,
    "body_redacted": BODY_CAPTURE_CAP_BYTES,
    "provenance": 2000,
    "corpus_version": 2000,
    "decision": 32,
    "mode": 2000,
    "note": 2000,
}


def field_cap(field: str) -> int:
    """Length cap for a string field (DEFAULT_FIELD_CAP for unknown keys)."""
    return FIELD_CAPS.get(field, DEFAULT_FIELD_CAP)


def _check_cap(field: str, value: str) -> None:
    if len(value) > field_cap(field):
        _fail(f"too_long:{field}")

# Ledger decision vocabulary -> schema decisions. "tool"/"browser" are
# aggregation lines for traffic that WAS executed/forwarded (request_budget
# record_tool / record_browser_requests) -> allowed; the aggregate label
# survives in provenance (engine).
LEDGER_DECISION_MAP = {
    "allowed": "allowed",
    "denied": "denied",
    "tool": "allowed",
    "browser": "allowed",
}
LEDGER_PROVENANCE_DEFAULT = "guard_log.jsonl"

_STR_FIELDS = ("ts", "hunt_id", "url", "method", "denial_reason",
               "content_type", "body_redacted", "provenance",
               "corpus_version", "mode", "note")
_BOOL_FIELDS = ("final", "ua_present", "cookie_present")


def utc_now_iso() -> str:
    """UTC ISO8601 (second precision), same shape as the guard ledger ts."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _fail(code: str):
    raise ValueError(code)


def make_event(*, tap_class: str, url: str, decision: str, provenance: str,
               hunt_id: str, ts: str | None = None, method: str | None = None,
               status: int | None = None, hop: int | None = None,
               final: bool | None = None, denial_reason: str | None = None,
               ua_present: bool | None = None,
               cookie_present: bool | None = None,
               content_type: str | None = None,
               body_redacted: str | None = None,
               corpus_version: str | None = None,
               count: int | None = None, mode: str | None = None,
               note: str | None = None) -> dict:
    """Build a schema-valid event; raises ValueError with a stable code.

    Optional fields set to None are OMITTED (compact JSONL spool).
    """
    if tap_class is None:
        _fail("missing:tap_class")
    if url is None:
        _fail("missing:url")
    if decision is None:
        _fail("missing:decision")
    if provenance is None:
        _fail("missing:provenance")
    if hunt_id is None:
        _fail("missing:hunt_id")
    if tap_class not in TAP_CLASSES:
        _fail(f"enum:tap_class:{tap_class!r}")
    if decision not in DECISIONS:
        _fail(f"enum:decision:{decision!r}")
    if not isinstance(url, str) or not url:
        _fail("type:url")
    _check_cap("url", url)
    if not isinstance(provenance, str) or not provenance:
        _fail("type:provenance")
    _check_cap("provenance", provenance)
    if not isinstance(hunt_id, str) or not hunt_id:
        _fail("type:hunt_id")
    _check_cap("hunt_id", hunt_id)

    event = {
        "ts": ts if ts is not None else utc_now_iso(),
        "hunt_id": hunt_id,
        "tap_class": tap_class,
        "url": url,
        "decision": decision,
        "provenance": provenance,
    }
    if not isinstance(event["ts"], str) or not event["ts"]:
        _fail("type:ts")
    _check_cap("ts", event["ts"])

    if method is not None:
        if not isinstance(method, str) or not method:
            _fail("type:method")
        _check_cap("method", method)
        event["method"] = method.upper()
    if status is not None:
        if isinstance(status, bool) or not isinstance(status, int) \
                or not (100 <= status <= 599):
            _fail(f"type:status:{status!r}")
        event["status"] = status
    for field, value in (("hop", hop), ("final", final)):
        if value is not None and tap_class != "python":
            _fail(f"python_only:{field}")
    if hop is not None:
        if isinstance(hop, bool) or not isinstance(hop, int) or hop < 0:
            _fail(f"type:hop:{hop!r}")
        event["hop"] = hop
    if final is not None:
        if not isinstance(final, bool):
            _fail(f"type:final:{final!r}")
        event["final"] = final
    if denial_reason is not None:
        if not isinstance(denial_reason, str):
            _fail("type:denial_reason")
        _check_cap("denial_reason", denial_reason)
        event["denial_reason"] = denial_reason
    for field, value in (("ua_present", ua_present),
                         ("cookie_present", cookie_present)):
        if value is not None:
            if not isinstance(value, bool):
                _fail(f"type:{field}:{value!r}")
            event[field] = value
    if content_type is not None:
        if not isinstance(content_type, str):
            _fail("type:content_type")
        _check_cap("content_type", content_type)
        event["content_type"] = content_type
    if body_redacted is not None:
        if not isinstance(body_redacted, str):
            _fail("type:body_redacted")
        _check_cap("body_redacted", body_redacted)
        event["body_redacted"] = body_redacted
    if corpus_version is not None:
        if not isinstance(corpus_version, str):
            _fail("type:corpus_version")
        _check_cap("corpus_version", corpus_version)
        event["corpus_version"] = corpus_version

    # ledger extras -- ledger-class events only (QA-2 MD-3)
    for field, value in (("count", count), ("mode", mode), ("note", note)):
        if value is not None:
            if tap_class != "ledger":
                _fail(f"ledger_only:{field}")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            _fail(f"type:count:{count!r}")
        event["count"] = count
    if mode is not None:
        if not isinstance(mode, str):
            _fail("type:mode")
        _check_cap("mode", mode)
        event["mode"] = mode
    if note is not None:
        if not isinstance(note, str):
            _fail("type:note")
        _check_cap("note", note)
        event["note"] = note
    return event


def validate_event(event) -> list:
    """Pure predicate: the error-code list (``[]`` = schema-valid)."""
    errors: list = []
    if not isinstance(event, dict):
        return ["type:event"]

    allowed = set(EVENT_FIELDS) | set(LEDGER_EXTRA_FIELDS)
    for key in event:
        if key not in allowed:
            errors.append(f"unknown_field:{key}")

    for field in REQUIRED_EVENT_FIELDS:
        value = event.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"missing:{field}")

    if event.get("tap_class") not in TAP_CLASSES:
        errors.append("enum:tap_class")
    if event.get("decision") not in DECISIONS:
        errors.append("enum:decision")

    for field in _STR_FIELDS:
        if field in event and not isinstance(event[field], str):
            errors.append(f"type:{field}")
    # P2 COND-3 mirror: per-field length caps (producers rejected early;
    # the F4 adapter caps independently at persist time).
    for field, cap in FIELD_CAPS.items():
        value = event.get(field)
        if isinstance(value, str) and len(value) > cap:
            errors.append(f"too_long:{field}")
    for field in _BOOL_FIELDS:
        if field in event and not isinstance(event[field], bool):
            errors.append(f"type:{field}")
    for field in ("status", "hop", "count"):
        if field in event:
            value = event[field]
            if isinstance(value, bool) or not isinstance(value, int):
                errors.append(f"type:{field}")

    status = event.get("status")
    if isinstance(status, int) and not isinstance(status, bool) \
            and not (100 <= status <= 599):
        errors.append("type:status")
    hop = event.get("hop")
    if isinstance(hop, int) and not isinstance(hop, bool) and hop < 0:
        errors.append("type:hop")
    count = event.get("count")
    if isinstance(count, int) and not isinstance(count, bool) and count < 0:
        errors.append("type:count")

    if event.get("tap_class") != "python":
        for field in PYTHON_ONLY_FIELDS:
            if field in event:
                errors.append(f"python_only:{field}")
    if event.get("tap_class") != "ledger":
        for field in LEDGER_EXTRA_FIELDS:
            if field in event:
                errors.append(f"ledger_only:{field}")
    return errors


def is_valid_event(event) -> bool:
    return not validate_event(event)


def event_from_ledger(entry: dict) -> dict:
    """Zero-lossy guard_log.jsonl entry -> F3 ledger-class event.

    Mapping: ts->ts, task_id->hunt_id, url->url, decision->{allowed|denied}
    (tool/browser aggregates = executed traffic -> allowed), engine->
    provenance (default ``guard_log.jsonl``), denial+reason+rule->
    denial_reason (deduped, ``rule=<rule>`` fragment), note->note,
    ua_present/cookie_present carried, count/mode ride as ledger extras.
    Raises ValueError (stable code) on an unusable entry.
    """
    if not isinstance(entry, dict):
        _fail("type:entry")
    ts = entry.get("ts")
    if not isinstance(ts, str) or not ts:
        _fail("missing:ts")
    task_id = entry.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        _fail("missing:task_id")
    url = entry.get("url")
    if not isinstance(url, str) or not url:
        _fail("missing:url")
    raw_decision = entry.get("decision")
    if raw_decision not in LEDGER_DECISION_MAP:
        _fail(f"enum:decision:{raw_decision!r}")

    engine = entry.get("engine")
    provenance = engine if isinstance(engine, str) and engine.strip() \
        else LEDGER_PROVENANCE_DEFAULT

    denial = entry.get("denial")
    reason = entry.get("reason")
    rule = entry.get("rule")
    parts = []
    if isinstance(denial, str) and denial.strip():
        parts.append(denial.strip())
    if isinstance(reason, str) and reason.strip() \
            and reason.strip() not in parts:
        parts.append(reason.strip())
    if isinstance(rule, str) and rule.strip():
        parts.append(f"rule={rule.strip()}")

    kwargs = {}
    if parts:
        kwargs["denial_reason"] = "; ".join(parts)
    for field in ("ua_present", "cookie_present"):
        if field in entry:
            kwargs[field] = bool(entry[field])
    note = entry.get("note")
    if isinstance(note, str) and note:
        kwargs["note"] = note
    count = entry.get("count")
    if count is not None:
        kwargs["count"] = int(count)
    mode = entry.get("mode")
    if isinstance(mode, str) and mode:
        kwargs["mode"] = mode

    return make_event(tap_class="ledger", url=url,
                      decision=LEDGER_DECISION_MAP[raw_decision],
                      provenance=provenance, hunt_id=task_id, ts=ts,
                      **kwargs)
