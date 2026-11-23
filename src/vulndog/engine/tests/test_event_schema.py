"""Tests for vuln_watchdog.event_schema (F3; design 5.0, brief P1 item 2).

Contract under test:
- ONE schema for every tap class: ts, hunt_id, tap_class
  (python/browser/tool_http/ledger/evidence), url, method, hop, final,
  decision (allowed/denied), status, denial_reason, ua_present,
  cookie_present, content_type, body_redacted, provenance,
  corpus_version (added by the MATCHER, not the tap);
- ledger extras count/mode (+note) ride LEDGER-class events only (QA-2 MD-3);
- per-hop redirect semantics: python leg = one event per hop with the
  0-based hop index; the final hop sets final=True; hop/final are
  python-only fields;
- event_from_ledger: ZERO-LOSSY translation of guard_log.jsonl entries
  (ts/task_id/url/decision/engine/denial/reason/rule/note/ua_present/
  cookie_present/count/mode); engine -> provenance, denial+reason+rule ->
  denial_reason; ledger decisions tool/browser are executed-traffic
  aggregation lines -> decision "allowed";
- presence booleans ONLY -- no header-value field exists in the schema.
"""
import unittest

from vulndog.engine import event_schema as es


def ev(**over):
    e = {
        "ts": "2026-10-15T12:00:00Z",
        "hunt_id": "task-42",
        "tap_class": "python",
        "url": "https://t.local/search?q=shoes",
        "method": "GET",
        "decision": "allowed",
        "status": 200,
        "provenance": "net_guarded_request",
    }
    e.update(over)
    return e


class MakeEventTest(unittest.TestCase):
    def test_minimal_event_defaults_ts(self):
        e = es.make_event(tap_class="python", url="https://t.local/a",
                          decision="allowed", provenance="net_guarded_request",
                          hunt_id="task-1")
        self.assertTrue(e["ts"])
        self.assertEqual(e["tap_class"], "python")
        # optional Nones are omitted (compact JSONL)
        self.assertNotIn("status", e)
        self.assertNotIn("hop", e)

    def test_full_python_hop_event(self):
        e = es.make_event(tap_class="python", url="https://t.local/r",
                          decision="allowed", provenance="net_guarded_request",
                          hunt_id="task-1", method="get", status=302, hop=1,
                          final=False, ua_present=True, cookie_present=False,
                          content_type="text/html")
        self.assertEqual(e["method"], "GET")  # normalized uppercase
        self.assertEqual(e["hop"], 1)
        self.assertIs(e["final"], False)

    def test_missing_required_raises(self):
        for missing in ("tap_class", "url", "decision", "provenance",
                        "hunt_id"):
            kwargs = dict(tap_class="python", url="https://t.local/a",
                          decision="allowed", provenance="p",
                          hunt_id="task-1")
            kwargs[missing] = None
            with self.assertRaises(ValueError) as ctx:
                es.make_event(**kwargs)
            self.assertIn(f"missing:{missing}", str(ctx.exception))

    def test_bad_tap_class_raises(self):
        with self.assertRaises(ValueError) as ctx:
            es.make_event(tap_class="proxy", url="https://t.local/a",
                          decision="allowed", provenance="p", hunt_id="t")
        self.assertIn("enum:tap_class", str(ctx.exception))

    def test_bad_decision_raises(self):
        with self.assertRaises(ValueError) as ctx:
            es.make_event(tap_class="python", url="https://t.local/a",
                          decision="maybe", provenance="p", hunt_id="t")
        self.assertIn("enum:decision", str(ctx.exception))

    def test_hop_final_python_only(self):
        with self.assertRaises(ValueError) as ctx:
            es.make_event(tap_class="browser", url="https://t.local/a",
                          decision="allowed", provenance="p", hunt_id="t",
                          hop=0)
        self.assertIn("python_only:hop", str(ctx.exception))

    def test_count_mode_note_ledger_only(self):
        for field, value in (("count", 5), ("mode", "exact"), ("note", "n")):
            with self.assertRaises(ValueError) as ctx:
                es.make_event(tap_class="python", url="https://t.local/a",
                              decision="allowed", provenance="p", hunt_id="t",
                              **{field: value})
            self.assertIn(f"ledger_only:{field}", str(ctx.exception))

    def test_ledger_class_accepts_count_mode_note(self):
        e = es.make_event(tap_class="ledger", url="https://t.local/a",
                          decision="allowed", provenance="tool:nuclei",
                          hunt_id="t", count=17, mode="estimate", note="x")
        self.assertEqual(e["count"], 17)
        self.assertEqual(e["mode"], "estimate")

    def test_status_range_checked(self):
        with self.assertRaises(ValueError):
            es.make_event(tap_class="python", url="https://t.local/a",
                          decision="allowed", provenance="p", hunt_id="t",
                          status=42)

    def test_negative_hop_rejected(self):
        with self.assertRaises(ValueError):
            es.make_event(tap_class="python", url="https://t.local/a",
                          decision="allowed", provenance="p", hunt_id="t",
                          hop=-1)


class ValidateEventTest(unittest.TestCase):
    def test_valid_event_no_errors(self):
        self.assertEqual(es.validate_event(ev()), [])

    def test_unknown_field_flagged(self):
        errs = es.validate_event(ev(headers={"Cookie": "x"}))
        self.assertIn("unknown_field:headers", errs)

    def test_missing_required_flagged(self):
        e = ev()
        del e["provenance"]
        self.assertIn("missing:provenance", es.validate_event(e))

    def test_enum_violations_flagged(self):
        self.assertIn("enum:tap_class", es.validate_event(ev(tap_class="proxy")))
        self.assertIn("enum:decision", es.validate_event(ev(decision="tool")))

    def test_type_violations_flagged(self):
        self.assertIn("type:status", es.validate_event(ev(status="200")))
        self.assertIn("type:ua_present", es.validate_event(ev(ua_present="yes")))
        self.assertIn("type:url", es.validate_event(ev(url=123)))
        self.assertIn("type:final", es.validate_event(ev(hop=0, final="true")))

    def test_bool_is_not_status(self):
        self.assertIn("type:status", es.validate_event(ev(status=True)))

    def test_non_dict_event(self):
        self.assertEqual(es.validate_event("nope"), ["type:event"])

    def test_hop_on_non_python_flagged(self):
        self.assertIn("python_only:hop",
                      es.validate_event(ev(tap_class="browser", hop=0)))

    def test_ledger_extras_on_non_ledger_flagged(self):
        self.assertIn("ledger_only:count", es.validate_event(ev(count=3)))
        self.assertIn("ledger_only:mode", es.validate_event(ev(mode="exact")))
        self.assertIn("ledger_only:note", es.validate_event(ev(note="n")))

    def test_corpus_version_allowed_by_schema(self):
        # added by the MATCHER at match time -- schema-valid on the event
        self.assertEqual(es.validate_event(ev(corpus_version="pilot-1")), [])

    def test_schema_has_no_header_value_field(self):
        # SEC-12 parity: presence booleans only; no header-value field exists
        forbidden = {"headers", "request_headers", "response_headers",
                     "cookie", "set_cookie", "authorization", "user_agent"}
        self.assertEqual(forbidden & set(es.EVENT_FIELDS), set())
        self.assertIn("ua_present", es.EVENT_FIELDS)
        self.assertIn("cookie_present", es.EVENT_FIELDS)
        self.assertIn("content_type", es.EVENT_FIELDS)


class ConstantsTest(unittest.TestCase):
    def test_tap_classes_match_design(self):
        self.assertEqual(set(es.TAP_CLASSES),
                         {"python", "browser", "tool_http", "ledger", "evidence"})

    def test_decisions_match_design(self):
        self.assertEqual(set(es.DECISIONS), {"allowed", "denied"})

    def test_caps_match_design(self):
        self.assertEqual(es.BODY_CAPTURE_CAP_BYTES, 200_000)   # net_gate ceiling
        self.assertEqual(es.BODY_PERSIST_CAP_CHARS, 4000)      # design 6
        self.assertEqual(es.EMBED_SNIPPET_CAP_CHARS, 1200)     # design 5.3.1

    def test_event_fields_match_design_table(self):
        self.assertEqual(set(es.EVENT_FIELDS), {
            "ts", "hunt_id", "tap_class", "url", "method", "hop", "final",
            "decision", "status", "denial_reason", "ua_present",
            "cookie_present", "content_type", "body_redacted", "provenance",
            "corpus_version"})

    def test_ledger_extra_fields(self):
        self.assertEqual(set(es.LEDGER_EXTRA_FIELDS), {"count", "mode", "note"})


class EventFromLedgerTest(unittest.TestCase):
    def allowed_entry(self, **over):
        e = {"ts": "2026-10-15T10:00:00Z", "task_id": "task-9",
             "url": "https://t.local/x", "decision": "allowed",
             "engine": "net_guarded_request", "ua_present": True,
             "cookie_present": False}
        e.update(over)
        return e

    def test_allowed_entry_maps(self):
        out = es.event_from_ledger(self.allowed_entry())
        self.assertEqual(es.validate_event(out), [])
        self.assertEqual(out["hunt_id"], "task-9")
        self.assertEqual(out["tap_class"], "ledger")
        self.assertEqual(out["decision"], "allowed")
        self.assertEqual(out["provenance"], "net_guarded_request")
        self.assertIs(out["ua_present"], True)
        self.assertIs(out["cookie_present"], False)
        self.assertEqual(out["ts"], "2026-10-15T10:00:00Z")

    def test_denial_entry_folds_denial_reason_rule(self):
        out = es.event_from_ledger({
            "ts": "2026-10-15T10:00:00Z", "task_id": "task-9",
            "url": "https://t.local/admin", "decision": "denied",
            "denial": "path", "reason": "forbidden_paths hit",
            "engine": "scope", "rule": "deny-path"})
        self.assertEqual(es.validate_event(out), [])
        self.assertEqual(out["decision"], "denied")
        self.assertIn("path", out["denial_reason"])
        self.assertIn("forbidden_paths hit", out["denial_reason"])
        self.assertIn("rule=deny-path", out["denial_reason"])
        self.assertEqual(out["provenance"], "scope")

    def test_denial_dedupes_reason_equal_to_denial(self):
        # request_budget writes reason = reason or denial -> often identical
        out = es.event_from_ledger({
            "ts": "t", "task_id": "task-9", "url": "u", "decision": "denied",
            "denial": "rate", "reason": "rate", "engine": "", "rule": ""})
        self.assertEqual(out["denial_reason"], "rate")

    def test_tool_aggregate_rides_ledger_class(self):
        out = es.event_from_ledger({
            "ts": "t", "task_id": "task-9", "url": "https://t.local",
            "decision": "tool", "engine": "tool:nuclei", "count": 42,
            "mode": "proxy-exact", "note": "wave-1"})
        self.assertEqual(es.validate_event(out), [])
        self.assertEqual(out["decision"], "allowed")  # executed traffic
        self.assertEqual(out["provenance"], "tool:nuclei")
        self.assertEqual(out["count"], 42)
        self.assertEqual(out["mode"], "proxy-exact")
        self.assertEqual(out["note"], "wave-1")

    def test_browser_aggregate_rides_ledger_class(self):
        out = es.event_from_ledger({
            "ts": "t", "task_id": "task-9", "url": "https://t.local/page",
            "decision": "browser", "engine": "browser:playwright", "count": 3})
        self.assertEqual(es.validate_event(out), [])
        self.assertEqual(out["decision"], "allowed")
        self.assertEqual(out["provenance"], "browser:playwright")

    def test_missing_engine_defaults_provenance(self):
        out = es.event_from_ledger(self.allowed_entry(engine=""))
        self.assertEqual(out["provenance"], "guard_log.jsonl")

    def test_missing_task_id_raises(self):
        entry = self.allowed_entry()
        del entry["task_id"]
        with self.assertRaises(ValueError):
            es.event_from_ledger(entry)

    def test_unknown_ledger_decision_raises(self):
        with self.assertRaises(ValueError):
            es.event_from_ledger(self.allowed_entry(decision="oos"))

    def test_non_dict_raises(self):
        with self.assertRaises(ValueError):
            es.event_from_ledger("line")

    def test_missing_url_raises(self):
        entry = self.allowed_entry()
        del entry["url"]
        with self.assertRaises(ValueError):
            es.event_from_ledger(entry)


class UtcNowTest(unittest.TestCase):
    def test_iso8601_shape(self):
        ts = es.utc_now_iso()
        self.assertRegex(ts, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


# ---------------------------------------------------------------------------
# P2 COND-3 mirror (SCC-03): per-field length caps at the SCHEMA side --
# producers are rejected early with a stable too_long:<field> code; the F4
# adapter independently caps at persist time (defense in depth).
# ---------------------------------------------------------------------------


class Cond3SchemaCapsTest(unittest.TestCase):
    def test_field_caps_constant_values(self):
        caps = es.FIELD_CAPS
        self.assertEqual(caps["url"], 4096)
        self.assertEqual(caps["method"], 16)
        self.assertEqual(caps["hunt_id"], 128)
        for field in ("ts", "denial_reason", "content_type", "provenance",
                      "mode", "note"):
            self.assertEqual(caps[field], 2000, field)
        self.assertEqual(es.DEFAULT_FIELD_CAP, 2000)
        # body_redacted: capture-side cap (pre-redaction); the 4,000-char
        # persist cap lives in the F4 adapter (design 6 ordering).
        self.assertEqual(caps["body_redacted"], es.BODY_CAPTURE_CAP_BYTES)

    def test_make_event_rejects_overlong_url(self):
        with self.assertRaises(ValueError) as cm:
            es.make_event(tap_class="python", url="u" * 5000,
                          decision="allowed", provenance="p", hunt_id="h")
        self.assertIn("too_long:url", str(cm.exception))

    def test_make_event_accepts_url_at_cap(self):
        event = es.make_event(tap_class="python", url="u" * 4096,
                              decision="allowed", provenance="p", hunt_id="h")
        self.assertEqual(len(event["url"]), 4096)

    def test_make_event_rejects_overlong_method_and_hunt_id(self):
        with self.assertRaises(ValueError) as cm:
            es.make_event(tap_class="python", url="https://t.local/a",
                          method="G" * 17, decision="allowed",
                          provenance="p", hunt_id="h")
        self.assertIn("too_long:method", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            es.make_event(tap_class="python", url="https://t.local/a",
                          decision="allowed", provenance="p",
                          hunt_id="h" * 129)
        self.assertIn("too_long:hunt_id", str(cm.exception))

    def test_make_event_accepts_body_at_capture_cap(self):
        event = es.make_event(
            tap_class="python", url="https://t.local/a", decision="allowed",
            provenance="p", hunt_id="h",
            body_redacted="b" * es.BODY_CAPTURE_CAP_BYTES)
        self.assertEqual(len(event["body_redacted"]),
                         es.BODY_CAPTURE_CAP_BYTES)

    def test_make_event_rejects_body_over_capture_cap(self):
        with self.assertRaises(ValueError) as cm:
            es.make_event(
                tap_class="python", url="https://t.local/a",
                decision="allowed", provenance="p", hunt_id="h",
                body_redacted="b" * (es.BODY_CAPTURE_CAP_BYTES + 1))
        self.assertIn("too_long:body_redacted", str(cm.exception))

    def test_validate_event_flags_too_long_fields(self):
        errors = es.validate_event(ev(note="n" * 2001))
        self.assertIn("too_long:note", errors)
        errors = es.validate_event(ev(url="u" * 4097))
        self.assertIn("too_long:url", errors)

    def test_validate_event_accepts_fields_at_cap(self):
        self.assertNotIn("too_long:note",
                         es.validate_event(ev(note="n" * 2000)))
        self.assertEqual(es.validate_event(ev()), [])

    def test_ledger_entry_with_overlong_url_raises_stable_code(self):
        entry = {"ts": "2026-10-15T10:00:00Z", "task_id": "t1",
                 "url": "https://t.local/" + "u" * 5000,
                 "decision": "allowed"}
        with self.assertRaises(ValueError) as cm:
            es.event_from_ledger(entry)
        self.assertIn("too_long:url", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
