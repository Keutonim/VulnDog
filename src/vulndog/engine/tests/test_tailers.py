"""Tests for vuln_watchdog.tailers (WD-R1 capture half; design 3.3/3.4/5.0).

Contract under test (brief MaxQwenAgent-004 item 3):
- SpoolTailer: reads events.jsonl from a PERSISTED offset (state.json beside
  the spool), resume-safe across restarts; consumer rules (COND-4): invalid
  lines skipped + counted, an unterminated trailing line is never consumed;
  drop_counter meta lines counted, not yielded; missing hunt_id stamped from
  the spool dir (normalization to full F3).
- LedgerTailer: tails guard_log.jsonl, maps lines to F3 via
  event_schema.event_from_ledger (zero-lossy D-2 mapping: count/mode ride
  ledger-class events; engine+rule -> provenance+denial_reason), then F4
  redaction BEFORE yield (design 5.3.2: tailed text is redacted in the
  tailer); unusable lines rejected + counted, never fatal.
- EvidenceTailer: file-watch on <evidence_dir>/*.txt (tool-completion
  granularity): one evidence-class F3 event per content delta, delta text
  F4-redacted, per-file offsets, shrink rewinds, delta read cap.
- OffsetState: atomic persist (tmp + os.replace), corrupt state -> fresh
  start, counted.
- poll() NEVER raises on missing/corrupt sources; NO matching logic here.

All secrets SYNTHETIC; loopback/local files only.
"""
import json
import os
import shutil
import tempfile
import unittest

from vulndog.engine import event_schema as es
from vulndog.engine import redaction_adapter as ra
from vulndog.engine import tailers as tl

SECRET_Q = "8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh"          # 30ch opaque query value
SECRET_BODY = "aB3dE5fG7hI9jK1lM3nO5p"                # 22ch 3-class token
SECRET_HEX = "9f86d081884c7d659a2feaa0c55ad015"      # md5-shaped (hex rule)


def spool_event(seq=0, **over):
    e = {"ts": "2026-10-15T12:00:00Z", "hunt_id": "task-spool",
         "tap_class": "python", "url": "https://t.local/p?q=shoes",
         "method": "GET", "decision": "allowed", "status": 200,
         "provenance": "net_gate.guarded_request", "seq": seq}
    e.update(over)
    return e


class TailerTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-tailers-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_lines(self, path, lines, mode="a"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode, encoding="utf-8") as f:
            for line in lines:
                f.write(line if line.endswith("\n") else line + "\n")

    def spool_path(self, task="task-spool"):
        return os.path.join(self.tmp, "watchdog", task, "events.jsonl")


class OffsetStateTest(TailerTestCase):
    def test_roundtrip_and_offset_resume_value(self):
        path = os.path.join(self.tmp, "state.json")
        st = tl.OffsetState(path)
        st.set("offset", 123)
        st.set("files", {"a.txt": {"offset": 5}})
        st.save()
        self.assertFalse(os.path.exists(path + ".tmp"), "tmp cleaned by replace")
        st2 = tl.OffsetState(path)
        self.assertEqual(st2.get("offset"), 123)
        self.assertEqual(st2.get("files"), {"a.txt": {"offset": 5}})
        self.assertIsNone(st2.get("missing"))
        self.assertEqual(st2.get("missing", 7), 7)

    def test_corrupt_state_fresh_start_counted(self):
        path = os.path.join(self.tmp, "state.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write("{corrupt!!")
        st = tl.OffsetState(path)
        self.assertEqual(st.get("offset", 0), 0)
        self.assertGreaterEqual(st.load_errors, 1)

    def test_missing_state_file_is_clean_start(self):
        st = tl.OffsetState(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(st.load_errors, 0)
        self.assertEqual(st.get("offset", 0), 0)


class SpoolTailerTest(TailerTestCase):
    def make(self, task="task-spool", **kw):
        path = self.spool_path(task)
        return tl.SpoolTailer(path, **kw), path

    def test_reads_events_and_persists_offset(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(spool_event(i)) for i in range(3)])
        events = tailer.poll()
        self.assertEqual(len(events), 3)
        self.assertEqual([e["seq"] for e in events], [0, 1, 2])
        self.assertEqual(tailer.poll(), [], "offset advanced: no re-yield")
        state_path = os.path.join(os.path.dirname(path), "state.json")
        self.assertTrue(os.path.exists(state_path))
        with open(state_path, encoding="utf-8") as f:
            self.assertEqual(json.load(f)["offset"], os.path.getsize(path))

    def test_resume_across_restart(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(spool_event(0))])
        self.assertEqual(len(tailer.poll()), 1)
        # "restart": a fresh instance with the same persisted state
        tailer2, _ = self.make()
        self.assertEqual(tailer2.poll(), [], "restart must not re-process")
        self.write_lines(path, [json.dumps(spool_event(1))])
        events = tailer2.poll()
        self.assertEqual([e["seq"] for e in events], [1])

    def test_invalid_lines_skipped_and_counted(self):
        tailer, path = self.make()
        self.write_lines(path, [
            json.dumps(spool_event(0)),
            '{"torn": ',                       # invalid JSON (COND-4 rule)
            "[1, 2]",                          # valid JSON, not an event
            json.dumps(spool_event(1)),
        ])
        events = tailer.poll()
        self.assertEqual([e["seq"] for e in events], [0, 1])
        self.assertEqual(tailer.stats()["invalid_lines"], 2)

    def test_unterminated_trailing_line_not_consumed(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(spool_event(0))])
        with open(path, "a", encoding="utf-8") as f:
            f.write('{"seq": 1, "ts": "t"')     # torn tail, no newline
        events = tailer.poll()
        self.assertEqual([e["seq"] for e in events], [0])
        with open(path, "a", encoding="utf-8") as f:
            f.write(', "hunt_id": "task-spool", "tap_class": "python",')
            f.write(' "url": "u", "decision": "allowed",')
            f.write(' "provenance": "p"}\n')    # writer completes the line
        events = tailer.poll()
        self.assertEqual([e["seq"] for e in events], [1])
        self.assertEqual(tailer.stats()["invalid_lines"], 0)

    def test_drop_counter_line_counted_not_yielded(self):
        tailer, path = self.make()
        self.write_lines(path, [
            json.dumps({"type": "drop_counter", "dropped": 500,
                        "hunt_id": "task-spool", "ts": "t"}),
            json.dumps(spool_event(0)),
        ])
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertEqual(tailer.stats()["drop_counter_events"], 1)

    def test_missing_hunt_id_stamped_from_spool_dir(self):
        tailer, path = self.make(task="task-stamp")
        ev = spool_event(0)
        del ev["hunt_id"]
        self.write_lines(path, [json.dumps(ev)])
        events = tailer.poll()
        self.assertEqual(events[0]["hunt_id"], "task-stamp")
        self.assertEqual(tailer.stats()["hunt_id_stamped"], 1)
        self.assertEqual([e for e in es.validate_event(events[0])
                          if e != "unknown_field:seq"], [])

    def test_schema_invalid_counted_but_yielded(self):
        # COND-7a strict validation/rejection is the P4 matcher's decision;
        # the capture half surfaces the signal and passes the event through.
        tailer, path = self.make()
        self.write_lines(path, [json.dumps({"tap_class": "nope"})])
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertEqual(tailer.stats()["schema_invalid"], 1)

    def test_missing_file_polls_empty_then_starts(self):
        tailer, path = self.make(task="task-later")
        self.assertEqual(tailer.poll(), [])
        self.assertEqual(tailer.poll(), [])
        self.write_lines(path, [json.dumps(spool_event(0))])
        self.assertEqual(len(tailer.poll()), 1)

    def test_file_rewrite_rewinds(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(spool_event(i)) for i in range(3)])
        self.assertEqual(len(tailer.poll()), 3)
        with open(path, "w", encoding="utf-8") as f:    # rewrite (shrink)
            f.write(json.dumps(spool_event(9)) + "\n")
        events = tailer.poll()
        self.assertEqual([e["seq"] for e in events], [9])
        self.assertEqual(tailer.stats()["rewinds"], 1)


LEDGER_ALLOWED = {
    "ts": "2026-10-15T10:00:00Z", "task_id": "task-ledger",
    "url": f"https://t.local/p?sid={SECRET_Q}", "decision": "allowed",
    "engine": "fuzzer", "ua_present": True, "cookie_present": False,
}
LEDGER_DENIED = {
    "ts": "2026-10-15T10:00:01Z", "task_id": "task-ledger",
    "url": "https://t.local/admin", "decision": "denied",
    "denial": "scope", "reason": "ScopeViolation: host not in scope",
    "engine": "", "rule": "SEC-01",
}
LEDGER_TOOL = {
    "ts": "2026-10-15T10:00:02Z", "task_id": "task-ledger",
    "url": "https://t.local/", "decision": "tool",
    "engine": "tool:nuclei", "count": 42, "mode": "proxy-exact",
}
LEDGER_BROWSER = {
    "ts": "2026-10-15T10:00:03Z", "task_id": "task-ledger",
    "url": "https://t.local/page", "decision": "browser",
    "engine": "browser:playwright", "count": 1,
}


class LedgerTailerTest(TailerTestCase):
    def make(self):
        path = os.path.join(self.tmp, "taskdir", "guard_log.jsonl")
        return tl.LedgerTailer(path), path

    def test_allowed_line_maps_to_redacted_f3(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(LEDGER_ALLOWED)])
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(es.validate_event(ev), [])
        self.assertEqual(ev["tap_class"], "ledger")
        self.assertEqual(ev["decision"], "allowed")
        self.assertEqual(ev["hunt_id"], "task-ledger")
        self.assertIs(ev["ua_present"], True)
        self.assertIs(ev["cookie_present"], False)
        # F4 applied to the tailed text: the raw query value never survives
        self.assertNotIn(SECRET_Q, json.dumps(ev))
        self.assertIn("sid=<len-28>", ev["url"])

    def test_denied_line_folds_denial_reason_rule(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(LEDGER_DENIED)])
        ev = tailer.poll()[0]
        self.assertEqual(ev["decision"], "denied")
        self.assertIn("scope", ev["denial_reason"])
        self.assertIn("ScopeViolation", ev["denial_reason"])
        self.assertIn("rule=SEC-01", ev["denial_reason"])
        self.assertEqual(ev["provenance"], "guard_log.jsonl")

    def test_tool_and_browser_aggregates_ride_extras(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(LEDGER_TOOL),
                                json.dumps(LEDGER_BROWSER)])
        events = tailer.poll()
        tool, browser = events
        self.assertEqual(tool["decision"], "allowed")   # executed traffic
        self.assertEqual(tool["provenance"], "tool:nuclei")
        self.assertEqual(tool["count"], 42)
        self.assertEqual(tool["mode"], "proxy-exact")
        self.assertEqual(browser["provenance"], "browser:playwright")
        self.assertEqual(browser["count"], 1)
        for ev in events:
            self.assertEqual(es.validate_event(ev), [])

    def test_invalid_and_unusable_lines_counted(self):
        tailer, path = self.make()
        self.write_lines(path, [
            "{not json",                                # invalid_lines
            json.dumps({"ts": "t", "task_id": "x"}),    # no url -> rejected
            json.dumps(LEDGER_ALLOWED),
        ])
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        stats = tailer.stats()
        self.assertEqual(stats["invalid_lines"], 1)
        self.assertEqual(stats["rejected_entries"], 1)

    def test_overlong_url_truncated_not_rejected(self):
        tailer, path = self.make()
        entry = dict(LEDGER_ALLOWED, url="https://t.local/" + "u" * 10000)
        self.write_lines(path, [json.dumps(entry)])
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertLessEqual(len(events[0]["url"]), es.FIELD_CAPS["url"])
        self.assertGreaterEqual(tailer.stats()["truncated_fields"], 1)

    def test_note_secret_redacted_before_yield(self):
        tailer, path = self.make()
        entry = dict(LEDGER_ALLOWED,
                     note=f"leaked Cookie: PHPSESSID={SECRET_BODY} in log")
        self.write_lines(path, [json.dumps(entry)])
        ev = tailer.poll()[0]
        blob = json.dumps(ev)
        self.assertNotIn(SECRET_BODY, blob)
        self.assertNotIn(f"PHPSESSID={SECRET_BODY}", blob)

    def test_resume_across_restart(self):
        tailer, path = self.make()
        self.write_lines(path, [json.dumps(LEDGER_ALLOWED)])
        self.assertEqual(len(tailer.poll()), 1)
        tailer2 = tl.LedgerTailer(path)
        self.assertEqual(tailer2.poll(), [])
        self.write_lines(path, [json.dumps(LEDGER_DENIED)])
        self.assertEqual(len(tailer2.poll()), 1)


class EvidenceTailerTest(TailerTestCase):
    def make(self, hunt_id="task-ev", **kw):
        ev_dir = os.path.join(self.tmp, "evidence")
        os.makedirs(ev_dir, exist_ok=True)
        return tl.EvidenceTailer(ev_dir, hunt_id=hunt_id, **kw), ev_dir

    def test_new_file_yields_redacted_evidence_event(self):
        tailer, ev_dir = self.make()
        with open(os.path.join(ev_dir, "httpx_output.txt"), "w",
                  encoding="utf-8") as f:
            f.write(f"https://t.local/a?sid={SECRET_Q}\n"
                    f"body token {SECRET_BODY} and hash {SECRET_HEX}\n")
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(es.validate_event(ev), [])
        self.assertEqual(ev["tap_class"], "evidence")
        self.assertEqual(ev["decision"], "allowed")
        self.assertEqual(ev["provenance"], "evidence:httpx_output.txt")
        self.assertEqual(ev["url"], "file:///httpx_output.txt")
        self.assertEqual(ev["hunt_id"], "task-ev")
        self.assertEqual(ev["content_type"], "text/plain")
        blob = json.dumps(ev)
        self.assertNotIn(SECRET_Q, blob)
        self.assertNotIn(SECRET_BODY, blob)
        self.assertNotIn(SECRET_HEX, blob)
        # body channel: the opaque query VALUE is entropy/hex-scrubbed
        self.assertIn("<redacted>", ev["body_redacted"])

    def test_delta_only_after_first_read(self):
        tailer, ev_dir = self.make()
        path = os.path.join(ev_dir, "katana_output.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("OLD-MARKER line\n")
        self.assertEqual(len(tailer.poll()), 1)
        self.assertEqual(tailer.poll(), [], "no change -> no event")
        with open(path, "a", encoding="utf-8") as f:
            f.write("NEW-MARKER line\n")
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertIn("NEW-MARKER", events[0]["body_redacted"])
        self.assertNotIn("OLD-MARKER", events[0]["body_redacted"])

    def test_tool_completion_granularity_one_event_per_changed_file(self):
        tailer, ev_dir = self.make()
        for name in ("a_output.txt", "b_output.txt", "c_output.md"):
            with open(os.path.join(ev_dir, name), "w", encoding="utf-8") as f:
                f.write(f"content of {name}\n")
        events = tailer.poll()
        self.assertEqual(sorted(e["provenance"] for e in events),
                         ["evidence:a_output.txt", "evidence:b_output.txt"])

    def test_delta_cap_splits_large_growth(self):
        tailer, ev_dir = self.make()
        path = os.path.join(ev_dir, "big_output.txt")
        chunk = tl.EVIDENCE_DELTA_CAP_BYTES + 5000
        with open(path, "w", encoding="utf-8") as f:
            f.write("z" * chunk + "\n")
        events1 = tailer.poll()
        self.assertEqual(len(events1), 1)
        self.assertLessEqual(len(events1[0]["body_redacted"]),
                             ra.PERSIST_CAP_CHARS)
        events2 = tailer.poll()          # remainder on the next poll
        self.assertEqual(len(events2), 1)
        self.assertEqual(tailer.poll(), [])

    def test_shrink_rewinds(self):
        tailer, ev_dir = self.make()
        path = os.path.join(ev_dir, "a_output.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("x" * 100 + "\n")
        self.assertEqual(len(tailer.poll()), 1)
        with open(path, "w", encoding="utf-8") as f:
            f.write("fresh start\n")
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertIn("fresh start", events[0]["body_redacted"])
        self.assertEqual(tailer.stats()["rewinds"], 1)

    def test_missing_dir_never_raises(self):
        ev_dir = os.path.join(self.tmp, "no-such-dir")
        tailer = tl.EvidenceTailer(ev_dir, hunt_id="task-ev")
        self.assertEqual(tailer.poll(), [])
        self.assertEqual(tailer.poll(), [])

    def test_directories_named_txt_ignored(self):
        tailer, ev_dir = self.make()
        os.makedirs(os.path.join(ev_dir, "weird.txt"), exist_ok=True)
        self.assertEqual(tailer.poll(), [])


if __name__ == "__main__":
    unittest.main()
