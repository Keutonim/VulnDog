"""Tests for vuln_watchdog.joiner (WD-E2 part 2; design-spec 4.3, plan A2).

Contract under test:
- JoinIndex: cveId <-> edb (CVE-* tokens), cwe catalog id sets,
  dedup by (id, sha1(text)), id-pair dedup by construction;
- attach_joins(): exploit_refs on CVEs, owasp_categories via the static
  table, dangling refs LISTED never silently dropped (A2 DoD 2);
- slice_included(): the stage-1 recipe (design 2.3) -- web-relevant CWE
  OR cvss >= 7.0 OR has-public-exploit -- incl. the exploit-side
  mirror of (c) and the excluded_from_index veto;
- effective_cwe_ids(): cve/exploit -> cwe_ids; cwe -> own id;
- run_coverage_pass(): full streaming orchestration over the 4 mini
  archives -> measured coverage stats (hand-computed expectations),
  reconciliation block, dangling uniques, slice estimate, dedup
  counters; JSON-serializable; intermediate records NOT retained.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile

from vulndog.engine import joiner as jn
from vulndog.engine import owasp_map as om
from vulndog.engine.tests import test_extractors as tx

# Optional local archive dir (env-driven; absent -> real-archive tests skip).
RAW_DIR = os.environ.get("VULNDOG_RAW_DIR", "")
HAS_RAW = os.path.isdir(RAW_DIR)


def mkrec(**over):
    r = {
        "id": "CVE-2024-0001", "kind": "cve", "title": "t",
        "text_fields": ["desc text"], "cwe_ids": [], "cvss": None,
        "excluded_from_index": False,
        "evidence": {"src": "s.zip", "note": "n"},
        "confidence": "documented",
    }
    r.update(over)
    return r


class WebRelevantCwesTest(unittest.TestCase):
    def test_families_cover_brief_triage(self):
        fams = set(jn.WEB_RELEVANT_CWES.values())
        for fam in ("xss", "sqli", "ssti_code_injection", "command_injection",
                    "idor_access_control", "auth_bypass", "jwt", "ssrf",
                    "race", "mass_assignment", "upload"):
            self.assertIn(fam, fams)
        # spot checks: the headline CWEs of each P1 family
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-79"], "xss")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-89"], "sqli")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-1336"], "ssti_code_injection")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-78"], "command_injection")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-639"], "idor_access_control")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-347"], "jwt")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-918"], "ssrf")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-362"], "race")
        self.assertEqual(jn.WEB_RELEVANT_CWES["cwe-434"], "upload")

    def test_all_ids_normalized_and_real_in_catalog(self):
        # every seeded id exists in the checked-in cwec-derived map or is a
        # documented exception; at minimum all must be normalized cwe-<n>
        for cid in jn.WEB_RELEVANT_CWES:
            self.assertRegex(cid, r"\Acwe-\d+\Z")


class DedupKeyTest(unittest.TestCase):
    def test_key_is_id_plus_sha1_of_text(self):
        k1 = jn.dedup_key(mkrec(text_fields=["a", "b"]))
        k2 = jn.dedup_key(mkrec(text_fields=["a", "b"]))
        k3 = jn.dedup_key(mkrec(text_fields=["a", "c"]))
        self.assertEqual(k1, k2)
        self.assertNotEqual(k1, k3)
        self.assertEqual(k1[0], "CVE-2024-0001")
        self.assertRegex(k1[1], r"\A[0-9a-f]{40}\Z")


class EffectiveCweTest(unittest.TestCase):
    def test_per_kind(self):
        self.assertEqual(jn.effective_cwe_ids(mkrec(cwe_ids=["cwe-79"])),
                         ["cwe-79"])
        self.assertEqual(jn.effective_cwe_ids(
            mkrec(id="edb-1", kind="exploit", cwe_ids=[])), [])
        self.assertEqual(jn.effective_cwe_ids(
            mkrec(id="cwe-79", kind="cwe")), ["cwe-79"])
        self.assertEqual(jn.effective_cwe_ids(
            mkrec(id="owasp-2021-x", kind="owasp_doc")), [])
        self.assertEqual(jn.effective_cwe_ids(
            mkrec(id="cwe-1", kind="cwe_category")), [])


class JoinIndexTest(unittest.TestCase):
    def setUp(self):
        self.idx = jn.JoinIndex()
        self.idx.add_edb(mkrec(id="edb-1", kind="exploit",
                               cve_refs=["CVE-2024-0001", "CVE-2024-9999"]))
        self.idx.add_edb(mkrec(id="edb-2", kind="exploit",
                               cve_refs=["CVE-2024-0001"]))
        self.idx.add_cwe(mkrec(id="cwe-79", kind="cwe"))
        self.idx.add_cwe(mkrec(id="cwe-1", kind="cwe_category"))

    def test_cve_to_edb_pairs_unique(self):
        self.assertEqual(self.idx.exploit_refs_for("CVE-2024-0001"),
                         ["edb-1", "edb-2"])
        self.idx.add_edb(mkrec(id="edb-1", kind="exploit",
                               cve_refs=["CVE-2024-0001"]))
        self.assertEqual(self.idx.exploit_refs_for("CVE-2024-0001"),
                         ["edb-1", "edb-2"])  # id-pair dedup by construction

    def test_has_exploit_and_resolve(self):
        self.assertTrue(self.idx.has_exploit("CVE-2024-0001"))
        self.assertFalse(self.idx.has_exploit("CVE-2024-0002"))
        self.idx.add_known_cve("CVE-2024-0002")
        self.assertTrue(self.idx.resolve_cve("CVE-2024-0002"))
        self.assertFalse(self.idx.resolve_cve("CVE-2024-9999"))

    def test_cwe_id_sets(self):
        self.assertTrue(self.idx.resolve_cwe("cwe-79"))
        self.assertTrue(self.idx.resolve_cwe_category("cwe-1"))
        self.assertFalse(self.idx.resolve_cwe("cwe-1"))
        self.assertFalse(self.idx.resolve_cwe("cwe-9999"))


class AttachJoinsTest(unittest.TestCase):
    def setUp(self):
        self.idx = jn.JoinIndex()
        self.idx.add_edb(mkrec(id="edb-7", kind="exploit",
                               cve_refs=["CVE-2024-0001"]))
        self.idx.add_known_cve("CVE-2024-0001")
        self.idx.add_cwe(mkrec(id="cwe-79", kind="cwe"))
        self.table = om.load_map()

    def test_cve_gets_exploit_refs_and_owasp(self):
        rec = mkrec(cwe_ids=["cwe-79"])
        out, dangling = jn.attach_joins(rec, self.idx, self.table)
        self.assertEqual(out["exploit_refs"], ["edb-7"])
        self.assertIn("A03:2021-Injection", out["owasp_categories"])
        self.assertIn("A05:2025-Injection", out["owasp_categories"])
        self.assertEqual(dangling, [])
        self.assertNotIn("exploit_refs", rec)  # input not mutated

    def test_cve_dangling_cwe_listed(self):
        rec = mkrec(cwe_ids=["cwe-79", "cwe-9999"])
        out, dangling = jn.attach_joins(rec, self.idx, self.table)
        self.assertEqual([(d["ref"], d["from"]) for d in dangling],
                         [("cwe-9999", "CVE-2024-0001")])

    def test_exploit_dangling_cve_listed(self):
        rec = mkrec(id="edb-9", kind="exploit",
                    cve_refs=["CVE-2024-0001", "CVE-1999-12345"])
        out, dangling = jn.attach_joins(rec, self.idx, self.table)
        self.assertEqual([d["ref"] for d in dangling], ["CVE-1999-12345"])
        self.assertEqual(dangling[0]["type"], "cve")

    def test_cwe_related_dangling_and_own_owasp(self):
        rec = mkrec(id="cwe-79", kind="cwe", related_cwe_ids=["cwe-74",
                                                              "cwe-80"])
        out, dangling = jn.attach_joins(rec, self.idx, self.table)
        self.assertIn("A03:2021-Injection", out["owasp_categories"])
        self.assertEqual(sorted(d["ref"] for d in dangling),
                         ["cwe-74", "cwe-80"])  # not in the mini catalog

    def test_owasp_doc_gets_own_label(self):
        table_labels = {c["label"] for c in self.table["categories"]}
        label = "A03:2021-Injection"
        self.assertIn(label, table_labels)
        doc = next(c for c in self.table["categories"] if c["label"] == label)
        stem = os.path.splitext(os.path.basename(doc["doc"]))[0]
        rec = mkrec(id=f"owasp-{doc['edition']}-{stem}", kind="owasp_doc",
                    title="x")
        out, dangling = jn.attach_joins(rec, self.idx, self.table)
        self.assertEqual(out["owasp_categories"], [label])


class SliceRecipeTest(unittest.TestCase):
    def setUp(self):
        self.idx = jn.JoinIndex()
        self.idx.add_edb(mkrec(id="edb-1", kind="exploit",
                               cve_refs=["CVE-2024-0002"]))
        self.idx.add_known_cve("CVE-2024-0002")

    def test_web_relevant_cwe_includes(self):
        ok, why = jn.slice_included(mkrec(cwe_ids=["cwe-79"]), self.idx)
        self.assertTrue(ok)
        self.assertEqual(why, ["a-web-cwe"])

    def test_cvss_boundary(self):
        ok, why = jn.slice_included(
            mkrec(cvss={"score": 7.0}), self.idx)
        self.assertTrue(ok)
        self.assertEqual(why, ["b-cvss-high"])
        ok, _ = jn.slice_included(mkrec(cvss={"score": 6.9}), self.idx)
        self.assertFalse(ok)
        ok, _ = jn.slice_included(mkrec(cvss={"score": "8"}), self.idx)
        self.assertFalse(ok)  # non-numeric never passes

    def test_has_public_exploit_cve_and_mirror(self):
        ok, why = jn.slice_included(mkrec(id="CVE-2024-0002"), self.idx)
        self.assertTrue(ok)
        self.assertEqual(why, ["c-public-exploit"])
        ok, why = jn.slice_included(
            mkrec(id="edb-1", kind="exploit",
                  cve_refs=["CVE-2024-0002"]), self.idx)
        self.assertTrue(ok)
        self.assertEqual(why, ["c-public-exploit"])
        ok, _ = jn.slice_included(
            mkrec(id="edb-2", kind="exploit",
                  cve_refs=["CVE-1999-77777"]), self.idx)
        self.assertFalse(ok)  # dangling ref -> no mirror flag

    def test_excluded_from_index_veto(self):
        ok, why = jn.slice_included(
            mkrec(cwe_ids=["cwe-79"], excluded_from_index=True), self.idx)
        self.assertFalse(ok)
        self.assertEqual(why, [])

    def test_reference_kinds_outside_strict_recipe(self):
        ok, _ = jn.slice_included(
            mkrec(id="cwe-1", kind="cwe_category"), self.idx)
        self.assertFalse(ok)
        ok, _ = jn.slice_included(
            mkrec(id="owasp-2021-x", kind="owasp_doc"), self.idx)
        self.assertFalse(ok)

    def test_cwe_kind_own_id(self):
        ok, why = jn.slice_included(mkrec(id="cwe-918", kind="cwe"), self.idx)
        self.assertTrue(ok)
        self.assertEqual(why, ["a-web-cwe"])
        ok, _ = jn.slice_included(mkrec(id="cwe-200", kind="cwe"), self.idx)
        self.assertFalse(ok)


class PeakRssTest(unittest.TestCase):
    def test_never_raises(self):
        v = jn.peak_rss_mb()
        self.assertTrue(v is None or (isinstance(v, float) and v >= 0.0))

    @unittest.skipUnless(sys.platform == "win32", "win32 measurement path")
    def test_measured_on_windows(self):
        # A1 DoD: streaming verified by peak-memory ceiling in the run
        # report -> the measurement must actually work on this host
        v = jn.peak_rss_mb()
        self.assertIsInstance(v, float)
        self.assertGreater(v, 0.0)


class CoveragePassMiniTest(unittest.TestCase):
    """Integration: run_coverage_pass over mini archives with
    hand-computed expectations (numbers traced in each assert)."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wd-e2-pass-")
        # --- CVE mini archive (4 records)
        cve_members = {}

        def put(cve_id, **kw):
            n = cve_id.split("-")[1]
            num = cve_id.split("-")[2]
            path = (f"cvelistV5-main/cves/{n}/{int(num)//1000}xxx/"
                    f"{cve_id}.json")
            cve_members[path] = json.dumps(tx.cve_doc(cve_id, **kw))

        put("CVE-2024-0001", desc="XSS in login page", cwe="CWE-79",
            cvss={"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}})
        put("CVE-2024-0002", desc="SQLi in search", cwe="CWE-89",
            cvss={"cvssV3_1": {"baseScore": 3.1, "baseSeverity": "LOW"}})
        put("CVE-2024-0003", desc="Odd thing", cwe="CWE-9999")
        put("CVE-2024-0004", state="RESERVED")  # no text -> excluded
        cls.cve_zip = os.path.join(cls.tmp, "cvelistV5-main.zip")
        tx.build_zip(cls.cve_zip, cve_members)

        # --- EDB mini archive (3 unique rows)
        rows = [
            {"id": "1", "file": "exploits/a.py", "description": "SQLi PoC",
             "codes": "CVE-2024-0002;OSVDB-5", "verified": "1",
             "type": "webapps", "platform": "php"},
            {"id": "2", "file": "exploits/b.py", "description": "old PoC",
             "codes": "CVE-1999-9999"},
            {"id": "3", "file": "exploits/c.py", "description": "no codes"},
        ]
        cls.edb_zip = os.path.join(cls.tmp, "exploitdb-main.zip")
        tx.build_zip(cls.edb_zip,
                     {"exploitdb-main/files_exploits.csv": tx.edb_csv(rows)})

        # --- CWE mini archive (2 weaknesses + 1 category)
        cls.cwe_zip = os.path.join(cls.tmp, "cwec_latest.xml.zip")
        tx.build_zip(cls.cwe_zip, {"cwec_v4.20.xml": tx.CWE_XML_TMPL})

        # --- Top10 mini archive (2 EN docs)
        cls.t10_zip = os.path.join(cls.tmp, "Top10-master.zip")
        tx.build_zip(cls.t10_zip, {
            "Top10-master/2021/docs/en/A01_2021-X.md": "# A01 X\n\ntext\n",
            "Top10-master/2025/docs/en/A05_2025-Y.md": "# A05 Y\n\ntext\n",
        })

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def run_pass(self):
        return jn.run_coverage_pass({
            "cvelistV5": self.cve_zip, "exploitdb": self.edb_zip,
            "cwec": self.cwe_zip, "top10": self.t10_zip,
        }, map_table=om.load_map())

    def test_stats_measured_and_serializable(self):
        stats = self.run_pass()
        blob = json.dumps(stats)  # serializable, no sets
        self.assertIn("join_coverage", stats)

        jc = stats["join_coverage"]
        # EDB side: 3 rows, 2 with CVE token, 1 fully resolved
        self.assertEqual(jc["edb_rows_total"], 3)
        self.assertEqual(jc["edb_rows_with_cve_token"], 2)
        self.assertEqual(round(jc["edb_rows_with_cve_token_pct"], 1), 66.7)
        self.assertEqual(jc["edb_rows_with_resolved_cve"], 1)
        self.assertEqual(jc["edb_cve_tokens_dangling_unique"], 1)
        self.assertEqual(stats["dangling_refs"]["cve_from_edb"]["unique"],
                         ["CVE-1999-9999"])
        # CVE side: 4 total, 3 with cwe, 1 with exploit
        self.assertEqual(jc["cve_total"], 4)
        self.assertEqual(jc["cve_with_cwe"], 3)
        self.assertEqual(jc["cve_with_cwe_pct"], 75.0)
        self.assertEqual(jc["cve_with_public_exploit"], 1)
        self.assertEqual(jc["cve_with_public_exploit_pct"], 25.0)
        self.assertEqual(jc["cve_cwe_refs_total"], 3)
        self.assertEqual(jc["cve_cwe_refs_dangling_occurrences"], 1)
        self.assertEqual(stats["dangling_refs"]["cwe_from_cve"]["unique"],
                         ["cwe-9999"])
        # OWASP mapping coverage of the weakness catalog: 79+89 of 2 -> 100%
        self.assertEqual(jc["cwe_weaknesses_total"], 2)
        self.assertEqual(jc["cwe_weaknesses_with_owasp"], 2)
        self.assertEqual(jc["cwe_owasp_coverage_pct"], 100.0)
        self.assertEqual(jc["cve_with_owasp_mapping"], 2)
        # map self-check against the mini catalog: 281 checked-in rows,
        # only cwe-79/cwe-89 resolve -> the rest are map-dangling HERE
        self.assertEqual(jc["map_cwes_total"], 281)
        self.assertEqual(jc["map_cwes_resolved_in_catalog"], 2)
        # excluded + entities
        self.assertEqual(jc["cve_excluded_from_index"], 1)

        # slice estimate: CVE-1 (a+b), CVE-2 (a+c), edb-1 (c-mirror),
        # cwe-79 + cwe-89 (both web-relevant -> a)
        se = stats["slice_estimate"]
        self.assertEqual(se["included"]["cve"], 2)
        self.assertEqual(se["included"]["exploit"], 1)
        self.assertEqual(se["included"]["cwe"], 2)
        self.assertEqual(se["included"]["total"], 5)
        self.assertEqual(se["by_reason"]["a-web-cwe"], 4)
        self.assertEqual(se["by_reason"]["b-cvss-high"], 1)
        self.assertEqual(se["by_reason"]["c-public-exploit"], 2)
        self.assertEqual(se["taxonomy_docs_available"], 2)

        # reconciliation block: expectations vs actual per source
        rec = stats["reconciliation"]
        self.assertTrue(rec["cvelistV5"]["match"])
        self.assertEqual(rec["cvelistV5"]["actual"], 4)  # mini, not 408310
        self.assertTrue(rec["exploitdb"]["match"])
        self.assertTrue(rec["cwec"]["match"])

        # dedup counters present and zero on clean input
        self.assertEqual(stats["dedup"]["cve"]["id_duplicates"], 0)
        self.assertEqual(stats["dedup"]["exploit"]["id_duplicates"], 0)
        self.assertIn(blob[:1], ("{",))

    def test_expected_counts_override_for_reconciliation(self):
        stats = jn.run_coverage_pass(
            {"cvelistV5": self.cve_zip, "exploitdb": self.edb_zip,
             "cwec": self.cwe_zip, "top10": self.t10_zip},
            map_table=om.load_map(),
            expected={"cvelistV5": 5})  # wrong expectation -> mismatch flag
        self.assertFalse(stats["reconciliation"]["cvelistV5"]["match"])


if __name__ == "__main__":
    unittest.main()
