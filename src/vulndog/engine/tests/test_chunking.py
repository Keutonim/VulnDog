"""Tests for vuln_watchdog.chunking (design-spec 5.2 / plan A3).

TDD: written BEFORE the implementation.
"""
import unittest

from vulndog.engine import chunking as ch


def rec(kind, fields, **extra):
    r = {"id": extra.pop("rid", "test-1"), "kind": kind, "text_fields": fields}
    r.update(extra)
    return r


class TokenEstimateTest(unittest.TestCase):
    def test_four_chars_per_token_ceiling(self):
        self.assertEqual(ch.estimate_tokens(""), 0)
        self.assertEqual(ch.estimate_tokens("abcd"), 1)
        self.assertEqual(ch.estimate_tokens("abcde"), 2)
        self.assertEqual(ch.estimate_tokens("a" * 7200), 1800)

    def test_caps_are_spec_values(self):
        self.assertEqual(ch.SOFT_CAP_TOKENS, 1800)
        self.assertEqual(ch.HARD_CAP_TOKENS, 2000)


class BasicChunkingTest(unittest.TestCase):
    def test_small_record_one_chunk_preserves_all_fields_in_order(self):
        r = rec("cve", ["desc text", "title: t", "affected: v p"])
        chunks = ch.chunk_record(r)
        self.assertEqual(len(chunks), 1)
        c = chunks[0]
        self.assertEqual(c["record_id"], "test-1")
        self.assertEqual(c["kind"], "cve")
        self.assertEqual(c["chunk_index"], 0)
        self.assertFalse(c["truncated"])
        for f in r["text_fields"]:
            self.assertIn(f, c["text"])
        self.assertLess(c["text"].index("desc text"), c["text"].index("title: t"))

    def test_est_tokens_metadata_matches_text(self):
        r = rec("cwe", ["x" * 400])
        c = ch.chunk_record(r)[0]
        self.assertEqual(c["est_tokens"], ch.estimate_tokens(c["text"]))

    def test_empty_text_fields_yield_no_chunks(self):
        self.assertEqual(ch.chunk_record(rec("cve", [])), [])
        self.assertEqual(ch.chunk_record(rec("cve", ["", "  "])), [])

    def test_poc_body_never_embedded(self):
        r = rec("webapps", ["desc", "tags: msf"], poc_body="SECRETPOCMARKER12345")
        for c in ch.chunk_record(r):
            self.assertNotIn("SECRETPOCMARKER12345", c["text"])


class BoundaryAndCapTest(unittest.TestCase):
    def test_split_at_field_boundaries_never_midfield(self):
        f1 = "A" * 5000   # 1250 tokens
        f2 = "B" * 5000
        f3 = "C" * 5000
        chunks = ch.chunk_record(rec("cwe", [f1, f2, f3]))
        self.assertEqual(len(chunks), 3)
        self.assertEqual(chunks[0]["text"], f1)
        self.assertEqual(chunks[1]["text"], f2)
        self.assertEqual(chunks[2]["text"], f3)
        self.assertEqual([c["chunk_index"] for c in chunks], [0, 1, 2])

    def test_small_fields_packed_under_soft_cap(self):
        fields = [("f%02d " % i) + "x" * 394 for i in range(40)]  # ~100 tok each
        chunks = ch.chunk_record(rec("cve", fields))
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(c["est_tokens"], ch.SOFT_CAP_TOKENS)
        # every field survives exactly once across chunks
        joined = "\n".join(c["text"] for c in chunks)
        for f in fields:
            self.assertIn(f, joined)

    def test_oversized_single_unit_hard_truncated_with_flag(self):
        big = "y" * 40000  # 10000 tokens
        chunks = ch.chunk_record(rec("cve", [big]))
        self.assertEqual(len(chunks), 1)
        self.assertTrue(chunks[0]["truncated"])
        self.assertLessEqual(chunks[0]["est_tokens"], ch.HARD_CAP_TOKENS)
        self.assertEqual(len(chunks[0]["text"]), ch.HARD_CAP_TOKENS * 4)

    def test_unit_between_soft_and_hard_cap_not_truncated(self):
        mid = "z" * (1900 * 4)  # 1900 tokens: > soft, <= hard
        chunks = ch.chunk_record(rec("cve", [mid]))
        self.assertEqual(len(chunks), 1)
        self.assertFalse(chunks[0]["truncated"])
        self.assertEqual(chunks[0]["text"], mid)


class OwaspHeadingTest(unittest.TestCase):
    DOC = ("# Intro\n\nwelcome text\n\n"
           + "## Section A\n\n" + "a" * 3000 + "\n\n"
           + "## Section B\n\n" + "b" * 3000 + "\n\n"
           + "## Section C\n\n" + "c" * 3000 + "\n")

    def test_owasp_split_at_heading_boundaries(self):
        chunks = ch.chunk_record(rec("owasp_doc", [self.DOC], rid="owasp-1"))
        self.assertGreater(len(chunks), 1)
        for c in chunks:
            self.assertLessEqual(c["est_tokens"], ch.SOFT_CAP_TOKENS)
        # section bodies never split mid-section (each < soft cap)
        joined = "\n".join(c["text"] for c in chunks)
        self.assertIn("a" * 3000, joined)
        self.assertIn("b" * 3000, joined)
        self.assertIn("c" * 3000, joined)

    def test_owasp_chunk_starts_at_heading_or_doc_start(self):
        chunks = ch.chunk_record(rec("owasp_doc", [self.DOC], rid="owasp-1"))
        self.assertTrue(chunks[0]["text"].startswith("#"))
        for c in chunks[1:]:
            self.assertTrue(c["text"].startswith("#"),
                            f"chunk must start at a heading: {c['text'][:40]!r}")

    def test_non_owasp_kinds_do_not_heading_split(self):
        # a CVE description containing '#' must stay a single field unit
        r = rec("cve", ["# not a heading, one field " + "q" * 100])
        chunks = ch.chunk_record(r)
        self.assertEqual(len(chunks), 1)


if __name__ == "__main__":
    unittest.main()
