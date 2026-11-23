"""Tests for vuln_watchdog.query (WD-E7; design-spec 5.3, plan A8).

Contract under test:
- match() envelope: {"status": ok|skipped|disabled, "reason", "matches":
  [{record_id, kind, title, score, reason, cwe_ids, owasp_categories,
  cvss, exploit_available, matched_snippet(<=200)}], ...};
- retrieval law (5.3.3): FTS5 prefilter top-500 (BM25) -> pure-Python
  cosine re-rank -> top-K (default 3) with score floor (default 0.55,
  DEFAULT-TO-CALIBRATE, configurable);
- SEC C-4 quoting: untrusted text can never steer the FTS5 query shape
  or raise a malformed-query error; adversarial syntax degrades to
  individually quoted alphanumeric terms;
- exact-id pin law (5.3.5): verbatim CVE-\\d{4}-\\d{4,} / CWE-\\d+ tokens
  pin those records (reason=exact-id) IN ADDITION to semantic matches;
  pins bypass floor and filters; unknown ids ignored; bounded count;
- STORE-level failure -> explicit DISABLED signal, never a crash;
  PER-EVENT errors (embed failure, sqlite error) -> skip + counter,
  the API stays usable for the next event;
- QUERY prefix law (C16): the query text reaches Ollama with the query
  prefix, never the document prefix; query vectors transient
  (use_cache=False);
- connections are per-call (Windows swap semantics documented in
  test_store.py): a store swap between calls is picked up.
"""
import json
import math
import os
import shutil
import sqlite3
import tempfile
import unittest

from vulndog.engine import embed_client as ec
from vulndog.engine import query as qy
from vulndog.engine import store as st

MANIFEST = {"manifest_version": 1, "corpus_version": "vkb1-qtest",
            "counts": {}}


def unit(*vals):
    n = math.sqrt(sum(v * v for v in vals)) or 1.0
    return [v / n for v in vals]


class FakeEmbedder:
    """embed_query protocol double: returns a fixed vector or raises."""

    def __init__(self, vector=None, fail=False):
        self.vector = vector if vector is not None else unit(1, 0, 0, 0)
        self.fail = fail
        self.calls = []

    def embed_query(self, text):
        self.calls.append(text)
        if self.fail:
            raise ec.EmbeddingError("ollama unreachable (test)")
        return self.vector


def rec(rid, kind="cve", title=None, **over):
    r = {
        "id": rid, "kind": kind, "title": title or rid,
        "text_fields": ["t"], "cwe_ids": [], "cvss": None,
        "owasp_categories": [], "exploit_refs": [], "cve_refs": [],
        "dates": {}, "confidence": "documented", "source_path": "s",
        "corpus_version": "vkb1-qtest",
        "evidence": {"src": "s.zip", "note": "n"},
        "excluded_from_index": False,
    }
    r.update(over)
    return r


class StoreFixture(unittest.TestCase):
    """Small deterministic store:

    CVE-2024-1000  xss login      chunk vec e1=(1,0,0,0)  cwe-79, 9.8,
                   exploit_refs=[edb-1], owasp A03 label
    CVE-2024-2000  sql injection  chunk vec e2=(0,1,0,0)  cwe-89, 8.1
    CVE-2024-3000  buffer overflow chunk vec e3=(0,0,1,0) cwe-120, 5.5
    cwe-79         catalog        chunk vec (0,0,0,1)
    edb-1          exploit        chunk vec e1
    CVE-2024-9999  excluded, NO chunks (pin-without-chunk target)
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e7-")
        self.path = os.path.join(self.tmp, "vulnkb.sqlite")
        self.build_store()

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def build_store(self):
        with st.StagedStore(self.path) as s:
            s.add_record(rec("CVE-2024-1000", title="XSS in login page",
                             cwe_ids=["cwe-79"],
                             cvss={"score": 9.8, "severity": "CRITICAL"},
                             exploit_refs=["edb-1"],
                             owasp_categories=["A03:2021-Injection"],
                             text_fields=["reflected cross-site scripting "
                                          "in the login page"]))
            s.add_chunk("CVE-2024-1000", 0, 1,
                        "reflected cross-site scripting in the login page",
                        [1.0, 0.0, 0.0, 0.0])
            s.add_record(rec("CVE-2024-2000", title="SQLi in search",
                             cwe_ids=["cwe-89"],
                             cvss={"score": 8.1, "severity": "HIGH"},
                             text_fields=["sql injection in search endpoint"]))
            s.add_chunk("CVE-2024-2000", 0, 1,
                        "sql injection in the search endpoint",
                        [0.0, 1.0, 0.0, 0.0])
            s.add_record(rec("CVE-2024-3000", title="Overflow in desktop app",
                             cwe_ids=["cwe-120"],
                             cvss={"score": 5.5, "severity": "MEDIUM"},
                             text_fields=["buffer overflow in desktop app"]))
            s.add_chunk("CVE-2024-3000", 0, 1,
                        "classic stack buffer overflow in a desktop binary",
                        [0.0, 0.0, 1.0, 0.0])
            s.add_record(rec("cwe-79", kind="cwe",
                             title="Cross-site Scripting",
                             related_cwe_ids=[],
                             text_fields=["xss weakness catalog entry"]))
            s.add_chunk("cwe-79", 0, 1,
                        "the product does not neutralize user input xss",
                        [0.0, 0.0, 0.0, 1.0])
            s.add_record(rec("edb-1", kind="exploit", title="XSS PoC",
                             cve_refs=["CVE-2024-1000"],
                             exploit_verified=True,
                             text_fields=["xss proof of concept"]))
            s.add_chunk("edb-1", 0, 1, "reflected xss proof of concept",
                        [1.0, 0.0, 0.0, 0.0])
            s.add_record(rec("CVE-2024-9999", title="No text record",
                             text_fields=[], excluded_from_index=True))
            s.finish(MANIFEST)
            s.swap_into_dest()

    def api(self, vector=None, **kw):
        emb = FakeEmbedder(vector)
        a = qy.QueryAPI(store_path=self.path, embedder=emb, **kw)
        return a, emb


class EnvelopeShapeTest(StoreFixture):
    def test_ok_envelope_and_match_fields(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("reflected xss in login page")
        self.assertEqual(out["status"], "ok")
        self.assertIsNone(out["reason"])
        self.assertEqual(out["corpus_version"], "vkb1-qtest")
        self.assertGreaterEqual(out["prefilter_hits"], 1)
        self.assertTrue(out["matches"])
        m = out["matches"][0]
        for field in ("record_id", "kind", "title", "score", "reason",
                      "cwe_ids", "owasp_categories", "cvss",
                      "exploit_available", "matched_snippet"):
            self.assertIn(field, m)
        self.assertEqual(m["record_id"], "CVE-2024-1000")
        self.assertEqual(m["reason"], "semantic")
        self.assertEqual(m["kind"], "cve")
        self.assertIsInstance(m["cwe_ids"], list)
        self.assertEqual(m["cwe_ids"], ["cwe-79"])
        self.assertEqual(m["owasp_categories"], ["A03:2021-Injection"])
        self.assertEqual(m["cvss"]["score"], 9.8)
        self.assertTrue(m["exploit_available"])
        self.assertLessEqual(len(m["matched_snippet"]), 200)
        self.assertIn("scripting", m["matched_snippet"])
        self.assertAlmostEqual(m["score"], 1.0, places=5)

    def test_empty_text_no_embed_call(self):
        a, emb = self.api()
        out = a.match("!!! ??? ...")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["matches"], [])
        self.assertEqual(emb.calls, [])  # shortcut: nothing to retrieve

    def test_snippet_capped_at_200(self):
        long_text = "xss " + ("word " * 300)
        with st.StagedStore(self.path) as s:  # swap in a one-record store
            s.add_record(rec("CVE-2024-1000", title="long",
                             text_fields=[long_text]))
            s.add_chunk("CVE-2024-1000", 0, 1, long_text,
                        [1.0, 0.0, 0.0, 0.0])
            s.finish(MANIFEST)
            s.swap_into_dest()
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("xss word")
        self.assertEqual(len(out["matches"][0]["matched_snippet"]), 200)


class SemanticRankingTest(StoreFixture):
    def test_ranking_and_scores(self):
        # query 45 degrees between e1 (xss) and e2 (sqli)
        a, _ = self.api(unit(1, 1, 0, 0))
        out = a.match("cross-site scripting sql injection")
        ids = [m["record_id"] for m in out["matches"]]
        self.assertEqual(ids[:2], ["CVE-2024-1000", "CVE-2024-2000"])
        for m in out["matches"][:2]:
            self.assertAlmostEqual(m["score"], 0.7071, places=3)

    def test_top_k_caps_semantic(self):
        a, _ = self.api(unit(1, 1, 1, 1), top_k=2)
        out = a.match("scripting injection overflow xss", floor=0.3)
        sem = [m for m in out["matches"] if m["reason"] == "semantic"]
        self.assertLessEqual(len(sem), 2)

    def test_top_k_argument_override(self):
        a, _ = self.api(unit(1, 1, 1, 1), top_k=5)
        out = a.match("scripting injection overflow xss login search",
                      top_k=1, floor=0.2)
        sem = [m for m in out["matches"] if m["reason"] == "semantic"]
        self.assertEqual(len(sem), 1)

    def test_floor_filters_low_scores(self):
        a, _ = self.api(unit(1, 1, 0, 0))  # 0.707 vs e1/e2, 0 vs e3
        out = a.match("scripting injection overflow", floor=0.75)
        self.assertEqual(out["matches"], [])
        out = a.match("scripting injection overflow", floor=0.7)
        self.assertEqual(len(out["matches"]), 2)

    def test_floor_boundary_inclusive(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        # "reflected" overlaps BOTH e1 chunks (CVE-2024-1000, edb-1)
        out = a.match("reflected scripting", floor=1.0)
        self.assertEqual(len(out["matches"]), 2)  # cosine exactly 1.0

    def test_default_constants(self):
        self.assertEqual(qy.DEFAULT_TOP_K, 3)
        self.assertAlmostEqual(qy.DEFAULT_SCORE_FLOOR, 0.55)
        self.assertEqual(qy.PREFILTER_LIMIT, 500)

    def test_prefilter_limit_param(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("xss", prefilter_limit=1)
        self.assertLessEqual(out["prefilter_hits"], 1)


class PinLawTest(StoreFixture):
    def test_pin_in_addition_to_semantic(self):
        a, _ = self.api(unit(1, 0, 0, 0), top_k=2)
        # CVE-2024-3000 has ZERO token overlap with the xss query text
        out = a.match("reflected xss scripting CVE-2024-3000")
        ids = [m["record_id"] for m in out["matches"]]
        reasons = {m["record_id"]: m["reason"] for m in out["matches"]}
        self.assertIn("CVE-2024-3000", ids)
        self.assertEqual(reasons["CVE-2024-3000"], "exact-id")
        self.assertIn("CVE-2024-1000", ids)
        self.assertEqual(reasons["CVE-2024-1000"], "semantic")
        # pinned FIRST, semantic top_k still delivered in addition
        self.assertEqual(out["matches"][0]["record_id"], "CVE-2024-3000")
        self.assertEqual(out["pinned"], 1)

    def test_pin_below_floor_still_pinned(self):
        a, _ = self.api(unit(1, 0, 0, 0))  # e3 cosine = 0.0
        out = a.match("xss CVE-2024-3000", floor=0.9)
        pins = [m for m in out["matches"] if m["reason"] == "exact-id"]
        self.assertEqual(len(pins), 1)
        self.assertEqual(pins[0]["record_id"], "CVE-2024-3000")
        self.assertLess(pins[0]["score"], 0.9)

    def test_pin_cwe_token_normalizes(self):
        a, _ = self.api(unit(0, 0, 0, 1))
        out = a.match("CWE-79 weakness")
        ids = [m["record_id"] for m in out["matches"]]
        self.assertIn("cwe-79", ids)
        m = [x for x in out["matches"] if x["record_id"] == "cwe-79"][0]
        self.assertEqual(m["reason"], "exact-id")
        self.assertEqual(m["kind"], "cwe")

    def test_pin_case_insensitive_verbatim_token(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("xss cve-2024-2000")
        pins = [m for m in out["matches"] if m["reason"] == "exact-id"]
        self.assertEqual([p["record_id"] for p in pins], ["CVE-2024-2000"])

    def test_pin_unknown_id_ignored(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("xss CVE-1999-0001 CWE-12345")
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["pinned"], 0)

    def test_pin_without_chunks(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("anything CVE-2024-9999")
        pins = [m for m in out["matches"] if m["reason"] == "exact-id"]
        self.assertEqual(len(pins), 1)
        self.assertEqual(pins[0]["record_id"], "CVE-2024-9999")
        self.assertEqual(pins[0]["score"], 0.0)
        self.assertTrue(pins[0]["matched_snippet"])  # title fallback

    def test_pin_and_semantic_same_record_single_entry(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("reflected scripting CVE-2024-1000")
        entries = [m for m in out["matches"]
                   if m["record_id"] == "CVE-2024-1000"]
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["reason"], "exact-id")
        self.assertAlmostEqual(entries[0]["score"], 1.0, places=5)

    def test_pin_bypasses_filters(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("xss CWE-79", filters={"kind": "cve"})
        pins = [m["record_id"] for m in out["matches"]
                if m["reason"] == "exact-id"]
        self.assertIn("cwe-79", pins)  # pin law beats filters (documented)

    def test_pin_extract_bounds_and_shapes(self):
        ids = qy.extract_pin_ids("CVE-2024-1234 and cve-2024-1234 dup")
        self.assertEqual(ids, ["CVE-2024-1234"])
        # embedded in a longer word -> NOT verbatim -> no pin
        self.assertEqual(qy.extract_pin_ids("XCVE-2024-1234"), [])
        self.assertEqual(qy.extract_pin_ids("CWE-79x"), [])
        many = " ".join(f"CVE-2020-{i:05d}" for i in range(100))
        self.assertEqual(len(qy.extract_pin_ids(many)), qy.MAX_PINS)

    def test_pinned_score_uses_semantic_when_higher(self):
        # e1-aligned query; edb-1 chunk is also e1 -> pinned via token
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("reflected concept edb-1")  # edb-1 not a pin pattern
        sem = [m for m in out["matches"] if m["reason"] == "semantic"]
        self.assertIn("edb-1", [m["record_id"] for m in sem])


class FtsQuotingTest(StoreFixture):
    """SEC C-4: untrusted text never steers query shape, never raises."""

    ADVERSARIAL = [
        'xss OR sql NEAR/2 (a b) "quoted"* col:term ^start {a} NOT x',
        '"""', "''', DROP TABLE records; --",
        "a AND b OR c NOT d NEAR(e f, 3)",
        "col1:xss AND (a OR b) ^boost",
        "\x00\x01 binary junk",
        "CVE-2024-1000* OR scripting~",
    ]

    def test_match_never_raises_on_syntax(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        for text in self.ADVERSARIAL:
            out = a.match(text)
            self.assertIn(out["status"], ("ok", "skipped"), text)
            self.assertNotEqual(out["status"], "disabled", text)

    def test_query_construction_quotes_terms(self):
        q = qy.build_fts_query('xss OR (sql NEAR/2 "injection")*')
        # every term individually double-quoted; no bare operators survive
        self.assertIn('"xss"', q)
        self.assertIn('"OR"', q)
        self.assertIn('"sql"', q)
        self.assertIn('"NEAR"', q)
        for tok in q.split(" OR "):
            t = tok.strip()
            self.assertTrue(t.startswith('"') and t.endswith('"'),
                            f"unquoted term: {t!r}")

    def test_query_with_only_syntax_chars_is_empty(self):
        self.assertEqual(qy.build_fts_query('"()*:^~{}'), "")

    def test_cyrillic_and_unicode_safe(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = a.match("уязвимость xss")
        self.assertEqual(out["status"], "ok")


class FiltersTest(StoreFixture):
    def test_kind_filter(self):
        a, _ = self.api(unit(1, 1, 0, 0.5))
        out = a.match("xss scripting injection", floor=0.2,
                      filters={"kind": "cve"})
        self.assertTrue(all(m["kind"] == "cve" for m in out["matches"]))
        out = a.match("xss scripting injection", floor=0.2,
                      filters={"kind": ["cve", "exploit"]})
        self.assertTrue(all(m["kind"] in ("cve", "exploit")
                            for m in out["matches"]))

    def test_min_cvss_filter(self):
        a, _ = self.api(unit(1, 1, 1, 0))
        out = a.match("scripting injection overflow", floor=0.2,
                      filters={"min_cvss": 7.0})
        ids = {m["record_id"] for m in out["matches"]}
        self.assertNotIn("CVE-2024-3000", ids)  # 5.5 filtered out

    def test_exploit_available_filter(self):
        a, _ = self.api(unit(1, 1, 1, 1))
        out = a.match("scripting injection overflow xss", floor=0.2,
                      filters={"exploit_available": True})
        self.assertTrue(all(m["exploit_available"] for m in out["matches"]))

    def test_unknown_filter_key_raises(self):
        a, _ = self.api()
        with self.assertRaises(ValueError):
            a.match("xss", filters={"nonsense": 1})


class DisabledSignalTest(StoreFixture):
    def test_missing_store_disabled(self):
        a = qy.QueryAPI(store_path=os.path.join(self.tmp, "none.sqlite"),
                        embedder=FakeEmbedder())
        out = a.match("xss scripting")
        self.assertEqual(out["status"], "disabled")
        self.assertEqual(out["reason"], "store-missing")
        self.assertEqual(out["matches"], [])

    def test_corrupt_store_disabled(self):
        p = os.path.join(self.tmp, "corrupt.sqlite")
        with open(p, "wb") as f:
            f.write(b"not a database at all " * 50)
        a = qy.QueryAPI(store_path=p, embedder=FakeEmbedder())
        out = a.match("xss scripting")
        self.assertEqual(out["status"], "disabled")
        self.assertEqual(out["reason"], "store-corrupt")

    def test_schema_mismatch_disabled(self):
        p = os.path.join(self.tmp, "other.sqlite")
        conn = sqlite3.connect(p)
        conn.execute("CREATE TABLE x (y)")
        conn.commit()
        conn.close()
        a = qy.QueryAPI(store_path=p, embedder=FakeEmbedder())
        out = a.match("xss")
        self.assertEqual(out["status"], "disabled")
        self.assertEqual(out["reason"], "schema-mismatch")

    def test_match_never_raises_storeerror(self):
        a = qy.QueryAPI(store_path=os.path.join(self.tmp, "none.sqlite"),
                        embedder=FakeEmbedder(fail=True))
        out = a.match("xss CVE-2024-1000")
        # store failure wins over embed failure: DISABLED, not crash
        self.assertEqual(out["status"], "disabled")


class PerEventSkipTest(StoreFixture):
    def test_embed_failure_skips_event_only(self):
        a, emb = self.api(unit(1, 0, 0, 0))
        emb.fail = True
        out = a.match("reflected scripting")
        self.assertEqual(out["status"], "skipped")
        self.assertEqual(out["reason"], "embed-failed")
        self.assertEqual(out["matches"], [])
        self.assertEqual(a.skipped_events, 1)
        # next event with the embedder healthy works again (no global
        # disable -- C-4: per-event skip, counter, stay usable)
        emb.fail = False
        out = a.match("reflected scripting")
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out["matches"])
        self.assertEqual(a.skipped_events, 1)

    def test_sqlite_error_skips_event(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        orig = a._open_conn

        def boom():
            raise sqlite3.OperationalError("disk I/O error (injected)")

        a._open_conn = boom
        out = a.match("reflected scripting")
        self.assertEqual(out["status"], "skipped")
        self.assertEqual(out["reason"], "query-error")
        self.assertEqual(a.skipped_events, 1)
        a._open_conn = orig
        out = a.match("reflected scripting")
        self.assertEqual(out["status"], "ok")


class SwapDetectionTest(StoreFixture):
    def test_store_swap_between_calls_picked_up(self):
        a, _ = self.api(unit(0, 0, 1, 0))
        out = a.match("overflow desktop binary")
        self.assertIn("CVE-2024-3000",
                      [m["record_id"] for m in out["matches"]])
        # replace the store (stage-2 swap simulation)
        with st.StagedStore(self.path) as s:
            s.add_record(rec("CVE-2030-7777", title="new era",
                             text_fields=["brand new overflow record"]))
            s.add_chunk("CVE-2030-7777", 0, 1,
                        "brand new overflow record", [0.0, 0.0, 1.0, 0.0])
            s.finish({"corpus_version": "vkb1-swap"})
            s.swap_into_dest()
        out = a.match("overflow desktop binary")
        ids = [m["record_id"] for m in out["matches"]]
        self.assertEqual(ids, ["CVE-2030-7777"])
        self.assertEqual(out["corpus_version"], "vkb1-swap")


class PrefixLawTest(StoreFixture):
    """C16: query prefix, never doc prefix; transient query vectors."""

    def test_default_embedder_uses_query_prefix_and_no_cache(self):
        captured = []

        def transport(url, payload, timeout):
            captured.append((url, payload))
            n = len(payload["input"])
            return {"embeddings": [[0.0] * 767 + [1.0]] * n}

        tmpcache = tempfile.mkdtemp(prefix="wd-e7-cache-")
        try:
            client = ec.EmbeddingClient(cache_dir=tmpcache,
                                        transport=transport,
                                        use_cache=False)
            a = qy.QueryAPI(store_path=self.path, embedder=client)
            a.match("reflected scripting in login")
            # transient: nothing cached to disk for the query vector
            self.assertEqual([n for n in os.listdir(tmpcache)
                              if n.endswith(".json")], [])
        finally:
            shutil.rmtree(tmpcache, True)
        self.assertTrue(captured)
        text = captured[0][1]["input"][0]
        self.assertTrue(text.startswith(ec.QUERY_PREFIX))
        self.assertFalse(text.startswith(ec.DOC_PREFIX))
        self.assertEqual(ec.QUERY_PREFIX.count(ec.DOC_PREFIX), 0)

    def test_transient_embedder_factory_contract(self):
        client = qy.make_transient_embedder()
        try:
            self.assertIsInstance(client, ec.EmbeddingClient)
            self.assertFalse(client.use_cache)
            self.assertEqual(client.model, ec.DEFAULT_MODEL)
        finally:
            shutil.rmtree(client.cache_dir, True)


class ModuleLevelApiTest(StoreFixture):
    def test_module_match_delegates(self):
        a, _ = self.api(unit(1, 0, 0, 0))
        out = qy.match("reflected scripting", api=a)
        self.assertEqual(out["status"], "ok")
        self.assertTrue(out["matches"])

    def test_default_api_lazy_and_resettable(self):
        qy.reset_default_api()
        api = qy.get_default_api(store_path=self.path,
                                 embedder=FakeEmbedder(unit(1, 0, 0, 0)))
        self.assertIsInstance(api, qy.QueryAPI)
        self.assertIs(qy.get_default_api(), api)
        qy.reset_default_api()
        self.assertIsNot(qy.get_default_api(store_path=self.path,
                                            embedder=FakeEmbedder()), api)

    def test_close_is_safe(self):
        a, _ = self.api()
        a.close()  # no-op safety, never raises
        a.close()


class DimsAgnosticTest(StoreFixture):
    def test_768d_real_shape_path(self):
        """The unit contract does not hardcode dims: a 768-d store works
        end to end (real builds are 768-d via embed_client validation)."""
        p = os.path.join(self.tmp, "big.sqlite")
        v1 = [1.0] + [0.0] * 767
        v2 = [0.0] * 768
        v2[500] = 1.0
        with st.StagedStore(p) as s:
            s.add_record(rec("CVE-2024-1000", text_fields=["a"]))
            s.add_chunk("CVE-2024-1000", 0, 1, "alpha payload text", v1)
            s.add_record(rec("CVE-2024-2000", text_fields=["b"]))
            s.add_chunk("CVE-2024-2000", 0, 1, "beta payload text", v2)
            s.finish(MANIFEST)
            s.swap_into_dest()
        a = qy.QueryAPI(store_path=p, embedder=FakeEmbedder(v1))
        out = a.match("alpha payload")
        self.assertEqual(out["matches"][0]["record_id"], "CVE-2024-1000")
        self.assertAlmostEqual(out["matches"][0]["score"], 1.0, places=5)


if __name__ == "__main__":
    unittest.main()
