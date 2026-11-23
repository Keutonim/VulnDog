"""Tests for vuln_watchdog.matcher (WD-R1 matching half; design-spec
5.3/3.4/7, P4). Contract under test:

- event text unit (5.3.1): "{method} {path} params={names} status={n}
  ct={ct} denial={reason} snippet={...}" -- HOST EXCLUDED from the embed
  text (SEC-08, owner-adopted), query VALUES dropped entirely (param
  NAMES only, Security C-1), snippet capped at
  event_schema.EMBED_SNIPPET_CAP_CHARS=1200 (COND-7b), text-like content
  only, total input capped;
- COND-7a: EVERY consumed spool event is schema-validated
  (validate_event) AND F4-redaction is RE-RUN on the consumed text --
  the spool is never trusted blindly; fail-closed drop is counted;
- mode machine (design section 7): ollama down/hung -> explicit
  "matching: DISABLED (...)" line + pending buffer + 60 s backoff
  (clock-driven) + resume IN ORDER on recovery; KB missing -> capture-
  only "KB not built" mode with auto-detect on the next ok match;
  per-event query errors stay LOCAL skips (COND-7e -- never a global
  disable); per-event processing deadline -> the hung path;
- suppression (5.3.6): same (url, record_id) once per session; bursts
  collapse with a counter + a visible console notice at thresholds;
  per-record / per-url mutes via config;
- highlights are built through highlights.build_highlight (5.4 format)
  with corpus_version stamped from the match envelope;
- hung-thread cap (QA D-2, artifacts/qa-p4-1.md): a persistent per-event
  hang must not leak one daemon worker (+ its per-call sqlite connection)
  per backoff cycle -- abandoned deadline workers are bounded by
  MAX_ABANDONED_WORKERS, at the cap the attempt takes the hung path
  without spawning, finished workers free their slot, and stats()
  surfaces the live abandoned count.
"""
import threading
import time
import unittest

from vulndog.engine import event_schema as es
from vulndog.engine import highlights as hl
from vulndog.engine import matcher as mt

SECRET = "8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh"        # 28ch opaque 3-class token


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def ok_env(matches=(), corpus_version="vkb1-fake", pinned=0, hits=10):
    return {"status": "ok", "reason": None, "matches": list(matches),
            "prefilter_hits": hits, "pinned": pinned,
            "corpus_version": corpus_version}


def skip_env(reason="query-error"):
    return {"status": "skipped", "reason": reason, "matches": [],
            "prefilter_hits": 0, "pinned": 0, "corpus_version": None}


def disabled_env(reason="store-missing"):
    return {"status": "disabled", "reason": reason, "matches": [],
            "prefilter_hits": 0, "pinned": 0, "corpus_version": None}


def m_entry(record_id="CVE-2026-72557", score=0.61, **over):
    m = {"record_id": record_id, "kind": "cve", "title": "T " + record_id,
         "score": score, "reason": "semantic", "cwe_ids": ["cwe-434"],
         "owasp_categories": ["A04:2021-Insecure-Design"],
         "cvss": {"score": 8.8, "severity": "HIGH"},
         "exploit_available": False,
         "matched_snippet": "snippet of " + record_id}
    m.update(over)
    return m


class FakeAPI:
    """query.QueryAPI protocol double: scripted envelopes, captured calls.
    A callable script item receives the text and returns an envelope."""

    def __init__(self, script=None, default=None):
        self.script = list(script or [])
        self.default = default if default is not None else ok_env([])
        self.calls = []

    def match(self, text, top_k=None, filters=None, floor=None, **kw):
        self.calls.append({"text": text, "top_k": top_k,
                           "filters": filters, "floor": floor})
        if self.script:
            item = self.script.pop(0)
        else:
            item = self.default
        return item(text) if callable(item) else item


class HangingAPI:
    def __init__(self, sleep_s=1.0):
        self.sleep_s = sleep_s
        self.calls = 0

    def match(self, text, **kw):
        self.calls += 1
        time.sleep(self.sleep_s)
        return ok_env([])


def make_event(**over):
    ev = {
        "ts": "2026-10-16T02:00:00Z",
        "hunt_id": "task-42",
        "tap_class": "python",
        "url": "http://target.example.com/upload?file=<len-3>&token=<len-8>",
        "method": "POST",
        "decision": "allowed",
        "status": 200,
        "content_type": "text/html; charset=utf-8",
        "body_redacted": "uploaded php file executed unrestricted upload",
        "provenance": "net_gate.guarded_request",
    }
    ev.update(over)
    return ev


def make_matcher(api=None, **kw):
    kw.setdefault("clock", FakeClock())
    kw.setdefault("console", None)
    return mt.Matcher(api if api is not None else FakeAPI(), **kw)


# ------------------------------------------------------------- text unit 5.3.1

class TextUnitTest(unittest.TestCase):
    def test_full_python_event_format(self):
        text = mt.build_event_text(make_event())
        self.assertEqual(
            text,
            "POST /upload params=file,token status=200 "
            "ct=text/html; charset=utf-8 "
            "snippet=uploaded php file executed unrestricted upload")

    def test_host_excluded_sec08(self):
        text = mt.build_event_text(make_event())
        self.assertNotIn("target.example.com", text)

    def test_query_values_never_in_text(self):
        text = mt.build_event_text(
            make_event(url="http://h/p?sid=<len-24>&debug&q=<len-3>"))
        self.assertNotIn("<len-", text)
        self.assertIn("params=sid,debug,q", text)

    def test_snippet_cap_1200_cond7b(self):
        body = "A" * 1500
        text = mt.build_event_text(make_event(body_redacted=body))
        self.assertIn("snippet=" + "A" * es.EMBED_SNIPPET_CAP_CHARS, text)
        self.assertNotIn("A" * (es.EMBED_SNIPPET_CAP_CHARS + 1), text)

    def test_snippet_cap_parameter(self):
        text = mt.build_event_text(make_event(body_redacted="A" * 400),
                                   snippet_cap=50)
        self.assertIn("snippet=" + "A" * 50, text)
        self.assertNotIn("A" * 51, text)

    def test_binary_content_type_has_no_snippet(self):
        for ct in ("image/png", "application/octet-stream", "video/mp4",
                   "font/woff2", "application/pdf"):
            text = mt.build_event_text(make_event(content_type=ct))
            self.assertNotIn("snippet=", text, ct)

    def test_text_like_and_missing_ct_keep_snippet(self):
        for ct in ("text/html", "application/json", "application/xml",
                   "text/plain", None):
            text = mt.build_event_text(make_event(content_type=ct))
            self.assertIn("snippet=", text, repr(ct))

    def test_denial_reason_included(self):
        ev = make_event(decision="denied", status=None,
                        body_redacted=None,
                        denial_reason="scheme; rule=SEC-01")
        del ev["status"]
        text = mt.build_event_text(ev)
        self.assertIn("denial=scheme; rule=SEC-01", text)
        self.assertNotIn("status=", text)
        self.assertNotIn("snippet=", text)

    def test_ledger_event_without_method(self):
        ev = {"ts": "t", "hunt_id": "h", "tap_class": "ledger",
              "url": "http://h/acct/7?view=1", "decision": "denied",
              "denial_reason": "forbidden_paths", "provenance": "guard"}
        text = mt.build_event_text(ev)
        self.assertTrue(text.startswith("/acct/7 params=view"), text)

    def test_total_cap(self):
        ev = make_event(url="http://h/" + "p" * 4000,
                        denial_reason="d" * 2000,
                        body_redacted="b" * 4000)
        text = mt.build_event_text(ev)
        self.assertLessEqual(len(text), mt.EMBED_TEXT_CAP_CHARS)

    def test_snippet_whitespace_collapsed(self):
        text = mt.build_event_text(make_event(body_redacted="a\n\nb  c\r\nd"))
        self.assertIn("snippet=a b c d", text)

    def test_text_like_predicate(self):
        self.assertTrue(mt.text_like_content_type("TEXT/HTML; x=1"))
        self.assertTrue(mt.text_like_content_type(None))
        self.assertFalse(mt.text_like_content_type("image/gif"))


# ------------------------------------------------------------------ COND-7a

class Cond7aValidationTest(unittest.TestCase):
    def test_schema_invalid_event_rejected_before_match(self):
        api = FakeAPI()
        m = make_matcher(api)
        bad = make_event()
        del bad["hunt_id"]                      # required field missing
        self.assertEqual(m.process_event(bad), [])
        self.assertEqual(m.stats()["schema_invalid"], 1)
        self.assertEqual(api.calls, [])

    def test_unknown_field_rejected(self):
        api = FakeAPI()
        m = make_matcher(api)
        self.assertEqual(m.process_event(make_event(smuggled=1)), [])
        self.assertEqual(m.stats()["schema_invalid"], 1)
        self.assertEqual(api.calls, [])

    def test_f4_rerun_scrubs_smuggled_secret(self):
        api = FakeAPI(default=ok_env([]))
        m = make_matcher(api)
        # hand-poisoned spool line: schema-valid but NOT redacted
        ev = make_event(body_redacted="reset token " + SECRET + " end")
        m.process_event(ev)
        sent = api.calls[0]["text"]
        self.assertNotIn(SECRET, sent)
        self.assertIn("<redacted>", sent)

    def test_f4_rerun_failclosed_drop_counted(self):
        api = FakeAPI()
        m = make_matcher(api)
        # urlsplit raises ValueError on this url -> redact_event drops
        ev = make_event(url="http://[::1:99/path")
        self.assertEqual(m.process_event(ev), [])
        self.assertEqual(m.stats()["redaction_dropped"], 1)
        self.assertEqual(api.calls, [])

    def test_non_dict_event_counted(self):
        m = make_matcher(FakeAPI())
        self.assertEqual(m.process_event("not-an-event"), [])
        self.assertEqual(m.process_event(None), [])
        self.assertEqual(m.stats()["schema_invalid"], 2)


# ------------------------------------------------------- modes (design sec 7)

class ModeMachineTest(unittest.TestCase):
    def test_ollama_down_transition(self):
        clock = FakeClock()
        api = FakeAPI(default=skip_env("embed-failed"))
        lines = []
        m = mt.Matcher(api, clock=clock, console=lines.append, backoff_s=60.0)
        ev = make_event()
        self.assertEqual(m.process_event(ev), [])
        self.assertEqual(m.mode, mt.MODE_OLLAMA_DOWN)
        self.assertTrue(m.down)
        self.assertIn(mt.LINE_OLLAMA_DOWN, lines)
        self.assertEqual(m.pending, [ev])
        self.assertAlmostEqual(m.next_retry, clock() + 60.0)
        self.assertEqual(m.stats()["embed_failures"], 1)

    def test_embed_invalid_also_down(self):
        m = make_matcher(FakeAPI(default=skip_env("embed-invalid")))
        m.process_event(make_event())
        self.assertEqual(m.mode, mt.MODE_OLLAMA_DOWN)

    def test_down_line_announced_once(self):
        lines = []
        m = mt.Matcher(FakeAPI(default=skip_env("embed-failed")),
                       console=lines.append, clock=FakeClock())
        m.process_event(make_event(url="http://h/a"))
        m.process_event(make_event(url="http://h/b"))   # buffered, no api
        self.assertEqual(lines.count(mt.LINE_OLLAMA_DOWN), 1)

    def test_events_while_down_are_buffered_not_matched(self):
        api = FakeAPI(default=skip_env("embed-failed"))
        m = mt.Matcher(api, clock=FakeClock())
        m.process_event(make_event(url="http://h/a"))
        calls_after_first = len(api.calls)
        ev2 = make_event(url="http://h/b")
        self.assertEqual(m.process_event(ev2), [])
        self.assertEqual(len(api.calls), calls_after_first)  # no api call
        self.assertEqual(m.pending[-1], ev2)
        self.assertEqual(m.stats()["buffered_while_down"], 1)

    def test_retry_pending_failure_keeps_order(self):
        ev1 = make_event(url="http://h/a")
        ev2 = make_event(url="http://h/b")
        api = FakeAPI(default=skip_env("embed-failed"))
        m = mt.Matcher(api, clock=FakeClock())
        m.process_event(ev1)
        m.process_event(ev2)
        drained, hls = m.retry_pending()
        self.assertFalse(drained)
        self.assertEqual(hls, [])
        self.assertEqual(m.pending, [ev1, ev2])
        self.assertIs(m.pending[0], ev1)

    def test_recovery_drains_pending_in_order(self):
        ev1 = make_event(url="http://h/a", body_redacted="one")
        ev2 = make_event(url="http://h/b", body_redacted="two")
        # call 1: ev1 -> embed-failed (down); ev2 is buffered WITHOUT an
        # api call; retry: call 2 -> ok(CVE-1), call 3 -> ok(CVE-2)
        api = FakeAPI(script=[skip_env("embed-failed"),
                              ok_env([m_entry("CVE-1")]),
                              ok_env([m_entry("CVE-2")])])
        lines = []
        m = mt.Matcher(api, clock=FakeClock(), console=lines.append)
        m.process_event(ev1)
        m.process_event(ev2)
        self.assertTrue(m.down)
        drained, hls = m.retry_pending()
        self.assertTrue(drained)
        self.assertFalse(m.down)
        self.assertEqual(m.mode, mt.MODE_ENABLED)
        self.assertEqual(m.pending, [])
        self.assertEqual([h["record_id"] for h in hls], ["CVE-1", "CVE-2"])
        self.assertTrue(any(l.startswith("matching: ENABLED") for l in lines),
                        lines)

    def test_hang_deadline_triggers_hung_mode(self):
        lines = []
        clock = FakeClock()
        m = mt.Matcher(HangingAPI(sleep_s=2.0), clock=clock,
                       console=lines.append, per_event_deadline_s=0.15)
        t0 = time.monotonic()
        ev = make_event()
        self.assertEqual(m.process_event(ev), [])
        self.assertLess(time.monotonic() - t0, 1.5)   # deadline, not sleep
        self.assertEqual(m.mode, mt.MODE_OLLAMA_HUNG)
        self.assertIn(mt.LINE_OLLAMA_HUNG, lines)
        self.assertEqual(m.pending, [ev])
        self.assertEqual(m.stats()["hangs"], 1)

    def test_kb_missing_capture_only_and_autodetect(self):
        api = FakeAPI(script=[disabled_env("store-missing"),
                              ok_env([m_entry("CVE-9")])])
        lines = []
        m = mt.Matcher(api, clock=FakeClock(), console=lines.append)
        self.assertEqual(m.process_event(make_event()), [])
        self.assertEqual(m.mode, mt.MODE_KB_MISSING)
        self.assertIn(mt.LINE_KB_MISSING, lines)
        self.assertFalse(m.down)                 # runner keeps polling
        self.assertEqual(m.pending, [])          # event consumed, not held
        self.assertEqual(m.stats()["kb_disabled_events"], 1)
        # store appears -> auto-detect on the NEXT match (design sec 7)
        hls = m.process_event(make_event(url="http://h/next"))
        self.assertEqual(m.mode, mt.MODE_ENABLED)
        self.assertEqual([h["record_id"] for h in hls], ["CVE-9"])
        self.assertTrue(any("KB detected" in l for l in lines), lines)

    def test_per_event_skip_stays_local_cond7e(self):
        api = FakeAPI(script=[skip_env("query-error"),
                              ok_env([m_entry("CVE-5")])])
        lines = []
        m = mt.Matcher(api, clock=FakeClock(), console=lines.append)
        self.assertEqual(m.process_event(make_event()), [])
        self.assertEqual(m.mode, mt.MODE_ENABLED)      # NO global disable
        self.assertEqual(m.stats()["skipped_events"], 1)
        hls = m.process_event(make_event(url="http://h/two"))
        self.assertEqual(len(hls), 1)
        self.assertFalse(any("DISABLED" in l for l in lines), lines)


# ------------------------------------------------------- suppression 5.3.6

class SuppressionTest(unittest.TestCase):
    def test_same_url_record_once_per_session(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1")]))
        m = make_matcher(api)
        first = m.process_event(make_event())
        second = m.process_event(make_event())
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        s = m.stats()
        self.assertEqual(s["suppressed_duplicates"], 1)
        self.assertEqual(m.burst_counts[("http://target.example.com/upload"
                                         "?file=<len-3>&token=<len-8>",
                                         "CVE-1")], 1)

    def test_different_url_same_record_emits(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1")]))
        m = make_matcher(api)
        self.assertEqual(len(m.process_event(make_event())), 1)
        self.assertEqual(
            len(m.process_event(make_event(url="http://h/other"))), 1)

    def test_mute_record_and_url(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1")]))
        m = make_matcher(api, mute_record_ids=["CVE-1"])
        self.assertEqual(m.process_event(make_event()), [])
        self.assertEqual(m.stats()["muted_records"], 1)
        m2 = make_matcher(api, mute_url_prefixes=["http://target.example"])
        self.assertEqual(m2.process_event(make_event()), [])
        self.assertEqual(m2.stats()["muted_records"], 0)
        self.assertEqual(m2.stats()["muted_urls"], 1)

    def test_burst_notice_at_threshold(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1")]))
        lines = []
        m = mt.Matcher(api, console=lines.append, clock=FakeClock())
        for _ in range(11):
            m.process_event(make_event())
        notices = [l for l in lines if l.startswith("burst collapsed")]
        self.assertEqual(len(notices), 1)
        self.assertIn("x10", notices[0])
        self.assertIn("CVE-1", notices[0])

    def test_multiple_matches_one_event(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1"), m_entry("CVE-2")]))
        m = make_matcher(api)
        hls = m.process_event(make_event())
        self.assertEqual([h["record_id"] for h in hls], ["CVE-1", "CVE-2"])


# ------------------------------------------------------------- highlight glue

class HighlightGlueTest(unittest.TestCase):
    def test_highlight_is_54_format_with_corpus_version(self):
        api = FakeAPI(default=ok_env([m_entry("CVE-1")],
                                     corpus_version="vkb1-glue"))
        m = make_matcher(api)
        h = m.process_event(make_event())[0]
        for key in hl.HIGHLIGHT_FIELDS:
            self.assertIn(key, h)
        self.assertEqual(h["corpus_version"], "vkb1-glue")
        self.assertEqual(h["url"], make_event()["url"])   # persisted (masked)
        self.assertEqual(h["tap_class"], "python")

    def test_exact_id_reason_passthrough(self):
        api = FakeAPI(default=ok_env(
            [m_entry("CVE-2026-4352", reason="exact-id", score=0.54)]))
        m = make_matcher(api)
        h = m.process_event(make_event())[0]
        self.assertEqual(h["reason"], "exact-id")

    def test_config_passed_to_api(self):
        api = FakeAPI(default=ok_env([]))
        m = make_matcher(api, floor=0.42, top_k=5, filters={"kind": "cve"})
        m.process_event(make_event())
        call = api.calls[0]
        self.assertEqual(call["floor"], 0.42)
        self.assertEqual(call["top_k"], 5)
        self.assertEqual(call["filters"], {"kind": "cve"})


class ConsumeAndStatsTest(unittest.TestCase):
    def test_consume_batch_stops_into_pending_when_down(self):
        api = FakeAPI(script=[ok_env([m_entry("CVE-1")]),
                              skip_env("embed-failed")])
        m = mt.Matcher(api, clock=FakeClock())
        evs = [make_event(url="http://h/1"), make_event(url="http://h/2"),
               make_event(url="http://h/3")]
        hls = m.consume(evs)
        self.assertEqual(len(hls), 1)
        self.assertTrue(m.down)
        # ev2 failed -> pending; ev3 buffered without an api call
        self.assertEqual(len(m.pending), 2)
        self.assertEqual(len(api.calls), 2)

    def test_stats_keys(self):
        m = make_matcher(FakeAPI(default=ok_env([m_entry("CVE-1")])))
        m.process_event(make_event())
        s = m.stats()
        for key in ("events_in", "schema_invalid", "redaction_dropped",
                    "matched_ok", "highlights", "suppressed_duplicates",
                    "embed_failures", "hangs", "kb_disabled_events",
                    "skipped_events", "muted_records", "muted_urls",
                    "buffered_while_down", "recovered"):
            self.assertIn(key, s)
        self.assertEqual(s["events_in"], 1)
        self.assertEqual(s["highlights"], 1)
        self.assertEqual(s["matched_ok"], 1)

    def test_status_lines_bounded(self):
        m = make_matcher(FakeAPI(default=skip_env("embed-failed")))
        for i in range(80):     # force transitions down<->enabled
            m.process_event(make_event(url="http://h/%d" % i))
            m.mode = mt.MODE_ENABLED     # simulate recovery between events
        self.assertLessEqual(len(m.status_lines), mt.STATUS_LINES_MAX)


# --------------------------------------------------- hung-thread cap (QA D-2)

class BlockingAPI:
    """Persistent-hang double for the QA D-2 scenario: match() blocks
    until released (deadline fires, worker is abandoned still alive --
    exactly the Ollama-outage/sqlite-hang retry loop that leaked one
    daemon thread + its per-call connection per backoff cycle)."""

    def __init__(self, timeout_s=30.0):
        self.release = threading.Event()
        self.timeout_s = timeout_s
        self.calls = 0
        self._lock = threading.Lock()

    def match(self, text, **kw):
        with self._lock:
            self.calls += 1
        self.release.wait(timeout=self.timeout_s)
        return ok_env([])


class HungThreadCapTest(unittest.TestCase):
    """D-2 (artifacts/qa-p4-1.md): abandoned deadline workers are BOUNDED.
    A simulated persistent-outage sequence (consume attempt + backoff
    retry probe per cycle, the runner's design-section-7 loop) must not
    grow `wd-match-deadline` threads beyond MAX_ABANDONED_WORKERS; at the
    cap the attempt still takes the hung/backoff path WITHOUT spawning;
    finished workers free their slot; stats() surfaces the live count
    (-> run-state counters -> status)."""

    def _outage_cycles(self, m, cycles):
        for i in range(cycles):
            m.process_event(make_event(url="http://h/%d" % i))
            m.retry_pending()        # the runner's backoff retry probe

    def _alive_deadline_threads(self, baseline):
        return [t for t in threading.enumerate()
                if t.name == "wd-match-deadline" and t not in baseline
                and t.is_alive()]

    def test_outage_sequence_does_not_grow_threads_beyond_cap(self):
        api = BlockingAPI()
        self.addCleanup(api.release.set)
        m = mt.Matcher(api, clock=FakeClock(), per_event_deadline_s=0.05)
        baseline = set(threading.enumerate())
        self._outage_cycles(m, 12)       # 24 deadline attempts pre-fix
        alive = self._alive_deadline_threads(baseline)
        self.assertLessEqual(len(alive), mt.MAX_ABANDONED_WORKERS)
        # the mode machine is untouched by the cap: still hung + pending
        self.assertEqual(m.mode, mt.MODE_OLLAMA_HUNG)
        self.assertEqual(m.stats()["abandoned_workers"], len(alive))
        self.assertLessEqual(m.stats()["abandoned_workers"],
                             mt.MAX_ABANDONED_WORKERS)

    def test_at_cap_new_attempt_takes_hung_path_without_new_thread(self):
        api = BlockingAPI()
        self.addCleanup(api.release.set)
        m = mt.Matcher(api, clock=FakeClock(), per_event_deadline_s=0.05)
        self._outage_cycles(m, 2 * mt.MAX_ABANDONED_WORKERS)   # cap reached
        self.assertEqual(m.stats()["abandoned_workers"],
                         mt.MAX_ABANDONED_WORKERS)
        calls_at_cap = api.calls
        # a further event while down is buffered (defensive path), and the
        # retry probe hits the cap: hung path WITHOUT a new worker/api call
        self.assertEqual(m.process_event(make_event(url="http://h/over")),
                         [])
        drained, hls = m.retry_pending()
        self.assertFalse(drained)
        self.assertEqual(hls, [])
        self.assertEqual(api.calls, calls_at_cap)   # no new worker entered
        self.assertEqual(m.mode, mt.MODE_OLLAMA_HUNG)
        self.assertGreaterEqual(m.stats()["hangs"], 1)
        # the pending buffer keeps every event (nothing dropped by the cap)
        self.assertEqual(len(m.pending),
                         2 * mt.MAX_ABANDONED_WORKERS + 1)

    def test_cap_slot_freed_when_hung_call_returns(self):
        api = BlockingAPI()
        self.addCleanup(api.release.set)
        m = mt.Matcher(api, clock=FakeClock(), per_event_deadline_s=0.05)
        self._outage_cycles(m, 2 * mt.MAX_ABANDONED_WORKERS)
        self.assertEqual(m.stats()["abandoned_workers"],
                         mt.MAX_ABANDONED_WORKERS)
        api.release.set()                          # the outage heals
        for t in list(m._abandoned):
            t.join(timeout=10)
            self.assertFalse(t.is_alive())
        self.assertEqual(m.stats()["abandoned_workers"], 0)
        calls_before = api.calls
        drained, hls = m.retry_pending()           # runner's recovery probe
        self.assertTrue(drained)
        self.assertEqual(hls, [])
        self.assertEqual(m.mode, mt.MODE_ENABLED)  # recovered + reclaimed
        self.assertGreater(api.calls, calls_before)


if __name__ == "__main__":
    unittest.main()
