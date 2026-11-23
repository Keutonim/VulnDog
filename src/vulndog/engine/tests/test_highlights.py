"""Tests for vuln_watchdog.highlights (WD-R2; design-spec 5.4/5.5, P4).

Contract under test:
- build_highlight: TEMPLATE-FILLED record (design 5.4 field set) from an
  F3 event + a query.match() entry -- KB fields only, event metadata only;
  matched_snippet hard-capped at 200 chars;
- console line: compact ``score | record_id | kind | cwe/owasp label |
  exploit?`` (+ method/url metadata) -- id/label-only, NEVER a snippet
  (Security C-2/SEC-04); advisory wording locked ("candidate");
- HighlightsWriter: incremental ``highlights.md`` (human, table blocks) +
  ``highlights.jsonl`` (machine, one 5.4-format JSON per line); the md
  header is written exactly once (resume-safe); matched_snippet renders
  ONLY inside the labeled untrusted-data fence (COND-7c) and is
  fence-escaped (backticks/newlines neutralized);
- advisory wording law: entries are "candidate"/"possible direction",
  never "finding" (the only allowed "finding" occurrence is the lock
  phrase "never a finding" itself);
- observer law: EVERY writer I/O failure is counted, never raised
  (a highlights failure can never crash the watchdog loop);
- run summary block (write_summary) with counters + burst table.
"""
import json
import math
import os
import shutil
import tempfile
import unittest

from vulndog.engine import highlights as hl


def make_event(**over):
    ev = {
        "ts": "2026-10-16T02:00:00Z",
        "hunt_id": "task-42",
        "tap_class": "python",
        "url": "http://127.0.0.1:9/upload?file=<len-3>",
        "method": "POST",
        "decision": "allowed",
        "status": 200,
        "content_type": "text/html",
        "provenance": "net_gate.guarded_request",
    }
    ev.update(over)
    return ev


def make_match(**over):
    m = {
        "record_id": "CVE-2026-72557",
        "kind": "cve",
        "title": "Cockpit CMS - Unrestricted File Upload",
        "score": 0.595548,
        "reason": "semantic",
        "cwe_ids": ["cwe-434"],
        "owasp_categories": ["A04:2021-Insecure-Design"],
        "cvss": {"score": 8.8, "severity": "HIGH"},
        "exploit_available": False,
        "matched_snippet": "An unrestricted file upload vulnerability ...",
    }
    m.update(over)
    return m


class BuildHighlightTest(unittest.TestCase):
    def test_field_set_and_values(self):
        h = hl.build_highlight(make_event(), make_match(),
                               corpus_version="vkb1-test")
        # design 5.4 canonical keys all present
        for key in ("ts", "hunt_id", "url", "method", "status", "score",
                    "reason", "record_id", "kind", "title", "cwe_ids",
                    "owasp_categories", "cvss", "exploit_available",
                    "matched_snippet", "corpus_version", "tap_class",
                    "provenance"):
            self.assertIn(key, h)
        self.assertEqual(h["ts"], "2026-10-16T02:00:00Z")   # event ts
        self.assertIn("matched_at", h)                       # emit ts
        self.assertEqual(h["hunt_id"], "task-42")
        self.assertEqual(h["record_id"], "CVE-2026-72557")
        self.assertEqual(h["score"], 0.595548)
        self.assertEqual(h["reason"], "semantic")
        self.assertEqual(h["corpus_version"], "vkb1-test")
        self.assertEqual(h["tap_class"], "python")
        self.assertEqual(h["provenance"], "net_gate.guarded_request")
        self.assertIs(h["exploit_available"], False)
        self.assertEqual(h["cwe_ids"], ["cwe-434"])

    def test_snippet_capped_200(self):
        m = make_match(matched_snippet="x" * 500)
        h = hl.build_highlight(make_event(), m)
        self.assertEqual(len(h["matched_snippet"]), 200)

    def test_missing_optional_event_fields_are_none(self):
        ev = make_event()
        del ev["method"]
        del ev["status"]
        h = hl.build_highlight(ev, make_match())
        self.assertIsNone(h["method"])
        self.assertIsNone(h["status"])

    def test_corpus_version_falls_back_to_event(self):
        ev = make_event(corpus_version="vkb1-fromevent")
        h = hl.build_highlight(ev, make_match())
        self.assertEqual(h["corpus_version"], "vkb1-fromevent")

    def test_non_scalar_match_lists_are_copied(self):
        m = make_match()
        h = hl.build_highlight(make_event(), m)
        h["cwe_ids"].append("cwe-999")
        self.assertEqual(m["cwe_ids"], ["cwe-434"])   # source untouched


class LabelsTest(unittest.TestCase):
    def test_labels_join_cwe_and_owasp(self):
        h = hl.build_highlight(make_event(), make_match())
        self.assertEqual(hl.labels_of(h),
                         "cwe-434,A04:2021-Insecure-Design")

    def test_labels_empty(self):
        h = hl.build_highlight(make_event(),
                               make_match(cwe_ids=[], owasp_categories=[]))
        self.assertEqual(hl.labels_of(h), "-")


class ConsoleLineTest(unittest.TestCase):
    def test_format_and_no_snippet(self):
        h = hl.build_highlight(make_event(), make_match())
        line = hl.console_line(h)
        # compact design-5.5.1 format: score | id | kind | labels | exploit?
        self.assertIn("0.5955", line)
        self.assertIn("CVE-2026-72557", line)
        self.assertIn("cve", line)
        self.assertIn("cwe-434", line)
        self.assertIn("exploit:no", line)
        # advisory wording locked
        self.assertIn("candidate", line)
        # C-2: NEVER a snippet on the console
        self.assertNotIn("unrestricted file upload vulnerability", line)
        self.assertNotIn(h["matched_snippet"], line)
        # pipe-separated compact shape
        parts = [p.strip() for p in line.split("|")]
        self.assertGreaterEqual(len(parts), 5)

    def test_exploit_yes(self):
        h = hl.build_highlight(make_event(), make_match(exploit_available=True))
        self.assertIn("exploit:yes", hl.console_line(h))

    def test_no_word_finding(self):
        h = hl.build_highlight(make_event(), make_match())
        self.assertNotIn("finding", hl.console_line(h).lower())


class WriterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-r2-")
        self.lines = []
        self.w = hl.HighlightsWriter(self.tmp, "task-42",
                                     console=self.lines.append)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def paths(self):
        return (os.path.join(self.tmp, "highlights.md"),
                os.path.join(self.tmp, "highlights.jsonl"))

    def read(self, p):
        with open(p, encoding="utf-8") as f:
            return f.read()

    def test_emit_writes_jsonl_54_format(self):
        md, jsonl = self.paths()
        self.w.emit(hl.build_highlight(make_event(), make_match(),
                                       corpus_version="vkb1-t"))
        rows = [json.loads(l) for l in self.read(jsonl).splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["record_id"], "CVE-2026-72557")
        self.assertEqual(r["corpus_version"], "vkb1-t")
        self.assertEqual(r["score"], 0.595548)

    def test_emit_writes_md_with_fence_and_advisory(self):
        md, _ = self.paths()
        self.w.emit(hl.build_highlight(make_event(), make_match()))
        text = self.read(md)
        # header written once, advisory wording locked
        self.assertIn("ADVISORY", text)
        self.assertIn("candidate", text.lower())
        self.assertIn("possible direction", text.lower())
        # the ONLY allowed "finding" mention is the lock phrase itself
        self.assertEqual(text.lower().count("finding"),
                         text.lower().count("never a finding"))
        # COND-7c: snippet ONLY inside the labeled untrusted fence
        self.assertIn(hl.FENCE_LABEL, text)
        fenced = text.split("```")
        # odd splits: [pre, inside1, post...] -- snippet inside a fenced block
        inside = fenced[1]
        self.assertIn("unrestricted file upload", inside)
        # snippet appears NOWHERE outside the fence
        outside = "".join(fenced[0::2])
        self.assertNotIn("unrestricted file upload", outside)
        # table present (human-readable field table per highlight)
        self.assertIn("| field | value |", text)
        self.assertIn("CVE-2026-72557", text)

    def test_console_line_emitted(self):
        self.w.emit(hl.build_highlight(make_event(), make_match()))
        self.assertEqual(len(self.lines), 1)
        self.assertIn("CVE-2026-72557", self.lines[0])
        self.assertIn("candidate", self.lines[0])

    def test_header_written_once_across_writers(self):
        md, _ = self.paths()
        self.w.emit(hl.build_highlight(make_event(), make_match()))
        w2 = hl.HighlightsWriter(self.tmp, "task-42",
                                 console=self.lines.append)
        w2.emit(hl.build_highlight(make_event(url="http://127.0.0.1:9/other"),
                                   make_match(record_id="CVE-2026-72592")))
        text = self.read(md)
        self.assertEqual(text.count("# Watchdog highlights"), 1)
        self.assertIn("H-0001", text)
        self.assertIn("H-0002", text)   # sequential ids across writers

    def test_fence_escape_backticks_and_newlines(self):
        md, jsonl = self.paths()
        evil = "a```b\nINJECT\n```\ncode `x`"
        self.w.emit(hl.build_highlight(make_event(),
                                       make_match(matched_snippet=evil)))
        text = self.read(md)
        fenced = text.split("```")
        # exactly one fenced block => 3 parts; the snippet cannot break out
        self.assertEqual(len(fenced), 3, text)
        inside = fenced[1]
        self.assertNotIn("```", inside)
        self.assertNotIn("\nINJECT\n", inside)
        # jsonl stays one valid line, control chars escaped by json
        lines = [l for l in self.read(jsonl).splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        json.loads(lines[0])

    def test_md_cell_pipe_escape(self):
        md, _ = self.paths()
        self.w.emit(hl.build_highlight(
            make_event(url="http://h/p?a=1|2"),
            make_match(title="bad | title")))
        text = self.read(md)
        self.assertNotIn("bad | title", text)      # escaped in table cells
        self.assertIn("bad \\| title", text)

    def test_nan_score_counted_not_written(self):
        md, jsonl = self.paths()
        h = hl.build_highlight(make_event(), make_match(score=float("nan")))
        self.w.emit(h)                              # must not raise
        self.assertEqual(self.w.stats()["write_errors"], 1)
        # the corrupt line never lands in the jsonl
        self.assertFalse(os.path.exists(jsonl)
                         and self.read(jsonl).strip())

    def test_write_failure_never_raises(self):
        blocked = os.path.join(self.tmp, "file-not-dir")
        with open(blocked, "w", encoding="utf-8") as f:
            f.write("x")
        w = hl.HighlightsWriter(blocked, "task-42", console=None)
        w.emit(hl.build_highlight(make_event(), make_match()))  # no raise
        self.assertGreaterEqual(w.stats()["write_errors"], 1)
        self.assertEqual(w.stats()["emitted"], 1)   # counted, loop survives

    def test_write_summary(self):
        md, _ = self.paths()
        self.w.emit(hl.build_highlight(make_event(), make_match()))
        self.w.write_summary({"events_in": 7, "highlights": 1,
                              "suppressed_duplicates": 2},
                             bursts={("http://u", "CVE-1"): 5})
        text = self.read(md)
        self.assertIn("Run summary", text)
        self.assertIn("events_in", text)
        self.assertIn("CVE-1", text)
        self.assertIn("x5", text)

    def test_stats_counters(self):
        self.w.emit(hl.build_highlight(make_event(), make_match()))
        s = self.w.stats()
        self.assertEqual(s["emitted"], 1)
        self.assertEqual(s["write_errors"], 0)


if __name__ == "__main__":
    unittest.main()
