"""Tests for vuln_watchdog.vecmath, vuln_watchdog.kb_index, vuln_watchdog.benchutil.

TDD: written BEFORE the implementation. Uses small-dimension vectors --
dim validation is embed_client's job; kb_index must be dim-agnostic.
"""
import math
import os
import shutil
import sqlite3
import tempfile
import unittest

from vulndog.engine import vecmath, kb_index, benchutil


class VecmathTest(unittest.TestCase):
    def test_dot(self):
        self.assertAlmostEqual(vecmath.dot([1.0, 2.0, 3.0], [4.0, 5.0, 6.0]), 32.0)

    def test_norm_and_normalize(self):
        n = vecmath.normalize([3.0, 4.0])
        self.assertAlmostEqual(math.sqrt(sum(x * x for x in n)), 1.0)
        self.assertAlmostEqual(n[0], 0.6)
        self.assertAlmostEqual(n[1], 0.8)

    def test_normalize_zero_vector_returns_none(self):
        self.assertIsNone(vecmath.normalize([0.0, 0.0, 0.0]))

    def test_cosine_known_value(self):
        self.assertAlmostEqual(vecmath.cosine([1.0, 0.0], [1.0, 1.0]),
                               math.sqrt(2) / 2, places=6)

    def test_cosine_zero_vector_returns_zero(self):
        self.assertEqual(vecmath.cosine([0.0, 0.0], [1.0, 2.0]), 0.0)


def docs():
    return [
        {"record_id": "CVE-2024-0001", "kind": "cve", "chunk_index": 0,
         "text": "buffer overflow in sendmail debug command allows root"},
        {"record_id": "cwe-79", "kind": "cwe", "chunk_index": 0,
         "text": "cross site scripting improper neutralization of input"},
        {"record_id": "edb-1", "kind": "webapps", "chunk_index": 0,
         "text": "wordpress plugin sql injection exploit payload"},
    ]


def vecs():
    return [
        [1.0, 0.0, 0.0, 0.0],
        [0.0, 1.0, 0.0, 0.0],
        [0.6, 0.8, 0.0, 0.0],
    ]


class FtsQueryBuildTest(unittest.TestCase):
    def test_terms_are_individually_double_quoted(self):
        q = kb_index.fts_match_query("GET /admin login")
        self.assertEqual(q, '"GET" OR "admin" OR "login"')

    def test_fts5_operators_are_neutralized(self):
        q = kb_index.fts_match_query('NEAR(a b) AND c:d {e} f* "g" NOT h')
        # every emitted term is a quoted alnum token; no bare operators survive
        for piece in q.split(" OR "):
            self.assertTrue(piece.startswith('"') and piece.endswith('"'), piece)
            self.assertNotIn(":", piece)
            self.assertNotIn("*", piece)
            self.assertNotIn("{", piece)

    def test_embedded_quotes_stripped_by_tokenization(self):
        q = kb_index.fts_match_query('a"b""c')
        self.assertEqual(q, '"a" OR "b" OR "c"')

    def test_dedupe_and_cap(self):
        text = " ".join("tok%d" % i for i in range(200)) + " tok0"
        q = kb_index.fts_match_query(text, max_terms=64)
        terms = q.split(" OR ")
        self.assertEqual(len(terms), 64)
        self.assertEqual(len(set(terms)), 64)

    def test_no_tokens_yields_empty_string(self):
        self.assertEqual(kb_index.fts_match_query("!!! ... ///"), "")


class KbIndexTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-kb-test-")
        self.db = os.path.join(self.tmp, "kb.sqlite")
        kb_index.build_index(self.db, docs(), vecs())
        self.conn = kb_index.open_index(self.db)

    def tearDown(self):
        self.conn.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_build_stores_all_rows(self):
        n = self.conn.execute("SELECT count(*) FROM chunks").fetchone()[0]
        self.assertEqual(n, 3)

    def test_vectors_stored_unit_normalized_float32(self):
        rows = kb_index.load_all_vectors(self.conn)
        for rowid, v in rows.items():
            self.assertAlmostEqual(math.sqrt(sum(x * x for x in v)), 1.0, places=5)
        # roundtrip precision (float32)
        orig = vecmath.normalize(vecs()[2])
        got = rows[3]
        for a, b in zip(orig, got):
            self.assertLess(abs(a - b), 1e-6)

    def test_prefilter_returns_relevant_rowids(self):
        hits = kb_index.prefilter(self.conn, "buffer overflow sendmail", limit=500)
        self.assertIn(1, hits)  # rowid of doc 1

    def test_prefilter_respects_limit(self):
        hits = kb_index.prefilter(self.conn, "overflow OR scripting OR injection", limit=2)
        self.assertLessEqual(len(hits), 2)

    def test_prefilter_no_tokens_returns_empty(self):
        self.assertEqual(kb_index.prefilter(self.conn, "!!!", limit=500), [])

    def test_rerank_orders_by_cosine_and_applies_floor(self):
        q = vecmath.normalize([1.0, 0.0, 0.0, 0.0])
        ranked = kb_index.rerank(self.conn, [1, 2, 3], q, top_k=3, floor=0.55)
        # doc1 cosine 1.0, doc3 cosine 0.6, doc2 cosine 0.0 -> floor cuts doc2
        self.assertEqual([r["rowid"] for r in ranked], [1, 3])
        self.assertAlmostEqual(ranked[0]["score"], 1.0, places=5)
        self.assertAlmostEqual(ranked[1]["score"], 0.6, places=5)

    def test_match_end_to_end(self):
        q = vecmath.normalize([1.0, 0.0, 0.0, 0.0])
        res = kb_index.match(self.conn, "buffer overflow in sendmail", q,
                             top_k=3, floor=0.55)
        self.assertTrue(res["candidates"])
        self.assertEqual(res["candidates"][0]["record_id"], "CVE-2024-0001")
        self.assertEqual(res["candidates"][0]["kind"], "cve")
        self.assertEqual(res["skipped"], False)

    def test_match_zero_vector_query_yields_no_candidates(self):
        res = kb_index.match(self.conn, "buffer overflow", [0.0, 0.0, 0.0, 0.0],
                             top_k=3, floor=0.55)
        self.assertEqual(res["candidates"], [])

    def test_index_size_reported(self):
        self.assertEqual(kb_index.index_size(self.conn), 3)


class BenchutilTest(unittest.TestCase):
    def test_percentile_interpolated(self):
        self.assertAlmostEqual(benchutil.percentile([1, 2, 3, 4], 50), 2.5)
        self.assertAlmostEqual(
            benchutil.percentile(list(range(1, 101)), 95), 95.05)
        self.assertAlmostEqual(benchutil.percentile([5], 50), 5)
        self.assertAlmostEqual(benchutil.percentile([5], 95), 5)

    def test_percentile_empty_raises(self):
        with self.assertRaises(ValueError):
            benchutil.percentile([], 50)

    def test_replicate_to_size_cycles(self):
        d, v = docs(), vecs()
        d2, v2 = benchutil.replicate_to_size(d, v, 8)
        self.assertEqual(len(d2), 8)
        self.assertEqual(len(v2), 8)
        self.assertEqual(d2[3]["record_id"], d[0]["record_id"])
        self.assertEqual(v2[4], v[1])

    def test_replicate_smaller_than_source_takes_prefix(self):
        d2, v2 = benchutil.replicate_to_size(docs(), vecs(), 2)
        self.assertEqual(len(d2), 2)
        self.assertEqual(d2[1]["record_id"], "cwe-79")

    def test_machine_state_has_required_keys(self):
        st = benchutil.machine_state()
        for key in ("python", "platform", "cpu", "cpu_count", "ram_bytes",
                    "sqlite_version"):
            self.assertIn(key, st)
        self.assertGreater(st["ram_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
