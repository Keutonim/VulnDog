"""Test-only mirror of the PINNED event contract (brief + engine event_schema).

MERGE NOTE (tech-lead, candidate branch): pre-merge this module mirrored the
pinned contract by hand, because the engine package did not exist in the
capture half's worktree. The halves ARE merged now, so the authoritative
validator IS importable — and PLAN.md M1.2 acceptance criterion (1) asks
literally for "1 valid event row (``event_schema.validate_event`` true)".

The mirror stays (it encodes two pinned-brief rules the engine validator
does NOT enforce: a tap must never write ``corpus_version``, and
``ua_present``/``cookie_present`` are presence booleans), but every event
asserted through ``assert_pinned_event`` is NOW also validated by the
engine's own ``vulndog.engine.event_schema.validate_event`` — one decision
in one place, no drift between the mirror and the real schema.
"""
from __future__ import annotations

from vulndog.engine import event_schema as _es

EVENT_FIELDS = frozenset({
    "ts", "hunt_id", "tap_class", "url", "method", "hop", "final",
    "decision", "status", "denial_reason", "ua_present", "cookie_present",
    "content_type", "body_redacted", "provenance", "corpus_version",
})
REQUIRED_EVENT_FIELDS = frozenset({
    "ts", "hunt_id", "tap_class", "url", "decision", "provenance",
})
TAP_CLASSES = frozenset({"python", "browser", "tool_http", "ledger", "evidence"})
DECISIONS = frozenset({"allowed", "denied"})

URL_CAP = 4096
HUNT_ID_CAP = 128
METHOD_CAP = 16
BODY_CAPTURE_CAP = 200_000
BODY_PERSIST_CAP = 4_000


def assert_pinned_event(event: dict, *, persisted: bool = False) -> None:
    """Assert one event against the pinned contract (raises AssertionError)."""
    assert isinstance(event, dict), f"event must be a dict, got {type(event)}"
    extra = set(event) - EVENT_FIELDS
    assert not extra, f"fields outside the pinned contract: {extra}"
    missing = REQUIRED_EVENT_FIELDS - set(event)
    assert not missing, f"missing required fields: {missing}"

    assert event["tap_class"] in TAP_CLASSES, f"bad tap_class: {event['tap_class']}"
    assert event["decision"] in DECISIONS, f"bad decision: {event['decision']}"

    # the matcher owns corpus_version — a tap must NEVER write it
    assert "corpus_version" not in event, "tap wrote corpus_version (matcher-only field)"

    for field in ("ts", "hunt_id", "url", "provenance"):
        assert isinstance(event[field], str) and event[field].strip(), f"empty {field}"

    assert len(event["url"]) <= URL_CAP, "url exceeds capture cap"
    assert len(event["hunt_id"]) <= HUNT_ID_CAP, "hunt_id exceeds cap"

    if "method" in event:
        assert isinstance(event["method"], str) and len(event["method"]) <= METHOD_CAP
    if "status" in event:
        assert isinstance(event["status"], int) and not isinstance(event["status"], bool)
        assert 100 <= event["status"] <= 599
    for field in ("ua_present", "cookie_present"):
        if field in event:
            assert isinstance(event[field], bool), f"{field} must be a presence BOOLEAN"
    if "denial_reason" in event:
        assert isinstance(event["denial_reason"], str)
    if "content_type" in event:
        assert isinstance(event["content_type"], str)
    if "body_redacted" in event:
        assert isinstance(event["body_redacted"], str)
        cap = BODY_PERSIST_CAP if persisted else BODY_CAPTURE_CAP
        assert len(event["body_redacted"]) <= cap, "body_redacted exceeds cap"

    # hop/final are PYTHON-leg only; the proxy tap is tool_http
    if event["tap_class"] != "python":
        assert "hop" not in event and "final" not in event, "python-only fields on non-python tap"
    # ledger extras never ride proxy events
    assert not ({"count", "mode", "note"} & set(event)), "ledger-only fields on proxy event"

    # AUTHORITATIVE check (merge fix): the engine's own validator must
    # accept the event. This is the plan's M1.2 criterion (1) — the mirror
    # above may drift, the engine schema may not.
    engine_errors = _es.validate_event(event)
    assert not engine_errors, (
        f"engine event_schema.validate_event rejected the event: {engine_errors}"
    )