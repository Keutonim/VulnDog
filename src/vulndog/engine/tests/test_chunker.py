"""Tests for vuln_watchdog.chunker (WD-E3; design-spec 5.2, plan A3).

Contract under test:
- ~4 chars/token estimate (no tokenizer dep, C4); chunks cut at FIELD
  boundaries (cve/cwe/exploit) or HEADING boundaries (owasp_doc),
  packed greedily below SOFT_CAP 1800 est tokens;
- a lone unit above the soft cap rides alone; above HARD_CAP 2000 it
  is hard-truncated (<= 8000 chars) with truncated=True;
- E3 cleanup lives HERE (design 4.1: entities flagged in F1, cleaned in
  E3): html.unescape + nbsp + whitespace normalization before sizing;
- doc-prefix discipline hook: every chunk carries record_id + part
  index (chunk_index/parts_total); embed_text() applies the DOCUMENT
  prefix and never the query prefix (C16);
- poc_body is NEVER chunked in v1 (index-only, design 4.2);
- excluded_from_index / empty text -> zero chunks (store keeps the
  record, the embedding index does not); A3 length floor configurable;
- pilot-scale run over artifacts/p0-pilot-corpus.jsonl (3003 records).

The P0 benchmark module chunking.py stays untouched; chunker.py is the
production module (adds cleanup, prefix hook, floor, poc law).
"""
import json
import os
import unittest

from vulndog.engine import chunker as ck

# Optional pilot corpus artifact (env-driven; absent -> skipped).
PILOT = os.environ.get("VULNDOG_PILOT_CORPUS",
                       os.path.join("artifacts", "p0-pilot-corpus.jsonl"))
HAS_PILOT = os.path.exists(PILOT)


def rec(**over):
    r = {
        "id": "CVE-2024-0001", "kind": "cve", "title": "t",
        "text_fields": ["Some description text."],
        "excluded_from_index": False,
    }
    r.update(over)
    return r


class TokenEstimateTest(unittest.TestCase):
    def test_estimate_ceil_4chars(self):
        self.assertEqual(ck.estimate_tokens(""), 0)
        self.assertEqual(ck.estimate_tokens("abc"), 1)
        self.assertEqual(ck.estimate_tokens("abcd"), 1)
        self.assertEqual(ck.estimate_tokens("abcde"), 2)

    def test_caps_are_design_values(self):
        self.assertEqual(ck.CHARS_PER_TOKEN, 4)
        self.assertEqual(ck.SOFT_CAP_TOKENS, 1800)
        self.assertEqual(ck.HARD_CAP_TOKENS, 2000)


class CleanTextTest(unittest.TestCase):
    def test_entities_and_whitespace(self):
        self.assertEqual(ck.clean_text("Value&nbsp;with &amp; entity."),
                         "Value with & entity.")
        self.assertEqual(ck.clean_text("a\xa0b"), "a b")
        self.assertEqual(ck.clean_text("a   b\t\tc"), "a b c")
        self.assertEqual(ck.clean_text("a\n\n\n\nb"), "a\n\nb")
        self.assertEqual(ck.clean_text("  x  "), "x")
        self.assertEqual(ck.clean_text("&lt;script&gt;"), "<script>")

    def test_idempotent(self):
        once = ck.clean_text("A &amp; B&nbsp;\n\n\n C")
        self.assertEqual(ck.clean_text(once), once)


class ChunkShapeTest(unittest.TestCase):
    def test_single_chunk_fields_and_order(self):
        chunks = ck.chunk_record(rec(text_fields=["alpha", "beta", "gamma"]))
        self.assertEqual(len(chunks), 1)
        c = chunks[0]
        self.assertEqual(c["record_id"], "CVE-2024-0001")
        self.assertEqual(c["kind"], "cve")
        self.assertEqual(c["chunk_index"], 0)
        self.assertEqual(c["parts_total"], 1)
        self.assertEqual(c["text"], "alpha\nbeta\ngamma")
        self.assertEqual(c["est_tokens"], ck.estimate_tokens(c["text"]))
        self.assertFalse(c["truncated"])

    def test_soft_cap_packing_splits_at_field_boundaries(self):
        units = ["x" * 4000 for _ in range(3)]  # est 1000 each
        chunks = ck.chunk_record(rec(text_fields=units))
        self.assertEqual(len(chunks), 3)
        for i, c in enumerate(chunks):
            self.assertEqual(c["chunk_index"], i)
            self.assertEqual(c["parts_total"], 3)
            self.assertEqual(c["text"], "x" * 4000)
            self.assertLessEqual(c["est_tokens"], ck.SOFT_CAP_TOKENS)
            self.assertFalse(c["truncated"])

    def test_greedy_packing_fills_below_soft_cap(self):
        units = ["y" * 2000 for _ in range(4)]  # est 500 each; 3 fit (1500)
        chunks = ck.chunk_record(rec(text_fields=units))
        self.assertEqual([c["est_tokens"] for c in chunks],
                         [ck.estimate_tokens("\n".join(units[:3])),
                          ck.estimate_tokens(units[3])])
        self.assertEqual(len(chunks), 2)

    def test_lone_unit_between_caps_rides_alone_untruncated(self):
        unit = "z" * 7300  # est 1825: > soft, <= hard
        chunks = ck.chunk_record(rec(text_fields=["small", unit]))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0]["text"], "small")
        self.assertEqual(chunks[1]["text"], unit)
        self.assertFalse(chunks[1]["truncated"])

    def test_hard_truncate_with_flag(self):
        unit = "w" * 10000  # est 2500 > hard cap
        chunks = ck.chunk_record(rec(text_fields=[unit]))
        self.assertEqual(len(chunks), 1)
        self.assertTrue(chunks[0]["truncated"])
        self.assertEqual(len(chunks[0]["text"]), ck.HARD_CAP_TOKENS * 4)
        self.assertEqual(chunks[0]["est_tokens"], ck.HARD_CAP_TOKENS)

    def test_cleaning_happens_before_sizing(self):
        # 9000 '&' entities: raw len 45000 (est 11250 -> would truncate),
        # cleaned len 9001 (est 2251 -> still truncates, but on CLEANED
        # text; smaller case proves sizing uses cleaned length)
        small = "&amp;" * 100  # raw 500 -> cleaned 100 chars, est 25
        chunks = ck.chunk_record(rec(text_fields=[small]))
        self.assertEqual(chunks[0]["text"], "&" * 100)
        self.assertEqual(chunks[0]["est_tokens"], 25)
        self.assertFalse(chunks[0]["truncated"])


class HeadingBoundaryTest(unittest.TestCase):
    def test_owasp_doc_splits_at_headings(self):
        body = ("# Title\n\nintro text\n\n## Section A\n\naaa\n\n"
                "## Section B\n\nbbb\n")
        chunks = ck.chunk_record(rec(id="owasp-2021-A01_X", kind="owasp_doc",
                                     text_fields=[body]))
        # small doc -> greedy packing merges heading units below the soft
        # cap into one chunk (boundaries are cut points, not forced cuts)
        self.assertEqual(len(chunks), 1)
        # sections individually above the soft cap -> one chunk per section
        big = ("# Title\n\nintro\n\n## A\n\n" + "a" * 7300 +
               "\n\n## B\n\n" + "b" * 7300 + "\n")
        chunks = ck.chunk_record(rec(id="owasp-2021-A02_Y", kind="owasp_doc",
                                     text_fields=[big]))
        self.assertEqual(len(chunks), 3)
        self.assertTrue(chunks[0]["text"].startswith("# Title"))
        self.assertTrue(chunks[1]["text"].startswith("## A"))
        self.assertTrue(chunks[2]["text"].startswith("## B"))
        # greedy merge proof: a mid-size section pair packs together
        mid = ("# T\n\nintro\n\n## A\n\n" + "a" * 4000 +
               "\n\n## B\n\n" + "b" * 4000 + "\n")
        chunks = ck.chunk_record(rec(id="owasp-2021-A03_Z", kind="owasp_doc",
                                     text_fields=[mid]))
        self.assertEqual(len(chunks), 2)
        self.assertIn("## A", chunks[0]["text"])
        self.assertTrue(chunks[1]["text"].startswith("## B"))

    def test_non_owasp_kinds_do_not_heading_split(self):
        body = "# H1\ntext\n## H2\nmore"
        chunks = ck.chunk_record(rec(kind="cve", text_fields=[body]))
        self.assertEqual(len(chunks), 1)
        self.assertIn("## H2", chunks[0]["text"])


class LawTest(unittest.TestCase):
    def test_poc_body_never_chunked(self):
        chunks = ck.chunk_record(rec(
            id="edb-1", kind="exploit",
            text_fields=["description text"],
            poc_body="SUPER-SECRET-POC-MARKER " * 100))
        for c in chunks:
            self.assertNotIn("SUPER-SECRET-POC-MARKER", c["text"])

    def test_excluded_from_index_yields_no_chunks(self):
        self.assertEqual(ck.chunk_record(rec(excluded_from_index=True)), [])
        self.assertEqual(ck.chunk_record(rec(text_fields=[])), [])
        self.assertEqual(ck.chunk_record(rec(text_fields=["   ", "\n"])), [])

    def test_min_total_tokens_floor(self):
        r = rec(text_fields=["tiny"])  # est 1 token
        self.assertEqual(len(ck.chunk_record(r, min_total_tokens=10)), 0)
        self.assertEqual(len(ck.chunk_record(r)), 1)

    def test_doc_prefix_hook(self):
        chunks = ck.chunk_record(rec(text_fields=["alpha"]))
        embedded = ck.embed_text(chunks[0])
        self.assertTrue(embedded.startswith(ck.DOC_PREFIX))
        self.assertEqual(embedded, ck.DOC_PREFIX + "alpha")
        self.assertNotIn(ck.QUERY_PREFIX, embedded)
        self.assertNotEqual(ck.DOC_PREFIX, ck.QUERY_PREFIX)

    def test_chunk_ids_traceable(self):
        chunks = ck.chunk_record(rec(text_fields=["a" * 8000, "b" * 8000]))
        for c in chunks:
            self.assertEqual(c["record_id"], "CVE-2024-0001")
        self.assertEqual([c["chunk_index"] for c in chunks],
                         list(range(len(chunks))))


@unittest.skipUnless(HAS_PILOT, "pilot corpus artifact absent")
class PilotScaleTest(unittest.TestCase):
    """Tested at pilot scale (brief item 4): all 3003 pilot records."""

    @classmethod
    def setUpClass(cls):
        cls.records = []
        with open(PILOT, encoding="utf-8") as f:
            for line in f:
                cls.records.append(json.loads(line))

    def test_pilot_chunking_invariants(self):
        self.assertEqual(len(self.records), 3003)
        total_chunks = 0
        per_kind = {}
        ids_seen = set()
        for r in self.records:
            chunks = ck.chunk_record(r)
            ids_seen.add(r["id"])
            per_kind.setdefault(r["kind"], 0)
            per_kind[r["kind"]] += len(chunks)
            total_chunks += len(chunks)
            if r.get("text_fields") and not r.get("excluded_from_index"):
                self.assertGreaterEqual(len(chunks), 1, r["id"])
            for i, c in enumerate(chunks):
                self.assertEqual(c["chunk_index"], i)
                self.assertEqual(c["parts_total"], len(chunks))
                self.assertEqual(c["record_id"], r["id"])
                self.assertLessEqual(c["est_tokens"], ck.HARD_CAP_TOKENS)
                self.assertLessEqual(len(c["text"]), ck.HARD_CAP_TOKENS * 4)
                self.assertTrue(c["text"].strip())
                if c["truncated"]:
                    self.assertEqual(len(c["text"]), ck.HARD_CAP_TOKENS * 4)
        self.assertEqual(len(ids_seen), 3003)
        # OWASP docs chunk into multiple heading units (design: 5-10/doc)
        self.assertGreater(per_kind["owasp_doc"], 34)
        # poc bodies never leak into chunk text
        for r in self.records:
            if r.get("poc_body"):
                marker = r["poc_body"][:60].strip()
                if marker:
                    for c in ck.chunk_record(r):
                        self.assertNotIn(marker, c["text"])
        self.assertGreater(total_chunks, 3003)


if __name__ == "__main__":
    unittest.main()
