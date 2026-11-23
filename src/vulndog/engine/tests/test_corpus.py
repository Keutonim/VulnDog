"""Tests for vuln_watchdog.corpus (WD-E4; design-spec 2.3/3.2, plan A4).

Contract under test:
- recipe config is DATA (checked-in JSON, versioned): load/validate,
  bad shapes rejected with error codes, never KeyError-crashes;
- record_included(): the TIGHTENED stage-1 predicate a AND (b OR c)
  (director ruling D3/A4 2026-10-15), the design-2.3 UNION predicate
  (consistency vs joiner.slice_included), and FULL (everything);
  excluded_from_index veto per recipe; exploit inclusion via the
  configurable mirror (sliced-cve / resolved-cve / all / none);
  reference kinds (cwe web-relevant, cwe_category, owasp_doc) per
  include_reference (A4 manifest config choice);
- CorpusAssembler.iter_records(): STREAMING generator over the 4 mini
  archives (never a materialized list), deterministic order, per-kind
  seen/included counters, by-reason counts, join attachment
  (exploit_refs / owasp_categories) on emitted records;
- input_fingerprint()/corpus_version(): sha256 of every archive,
  deterministic version id (same recipe+inputs -> same id; any change
  -> new id);
- build_manifest()/write_manifest_atomic(): record+chunk counts, input
  shas, corpus_version, recipe embedded; atomic write leaves no tmp
  file and never writes a partial manifest.
"""
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import types

from vulndog.engine import corpus as cp
from vulndog.engine import joiner as jn
from vulndog.engine import owasp_map as om
from vulndog.engine.tests import test_extractors as tx


def mini_archives(tmp):
    """4 mini archives with hand-traceable recipe outcomes.

    CVEs:
      0001 cwe-79(a) cvss 9.8(b) + edb-1 exploit(c)  -> tightened IN
      0002 cwe-89(a) cvss 3.1(-b) + edb-2 exploit(c) -> tightened IN
      0003 cwe-9999(-a) cvss 9.8(b), edb-3 (c)       -> tightened OUT (no a)
      0004 cwe-79(a) no cvss(-b) no exploit(-c)      -> tightened OUT
      0005 RESERVED, no text -> excluded_from_index  -> vetoed (slice),
                                                        store-only (full)
    EDB rows:
      edb-1 codes CVE-2024-0001 (sliced)   -> mirror IN
      edb-2 codes CVE-2024-0002 (sliced)   -> mirror IN
      edb-3 codes CVE-2024-0003 (NOT sliced) -> mirror OUT; union
            resolved-cve mirror IN
      edb-4 codes CVE-1999-9999 (dangling) -> OUT everywhere but full
    CWE catalog: cwe-79 + cwe-89 (web-relevant -> reference IN),
      category cwe-1 (OUT by default, IN on full)
    Top10: 2 EN docs (reference IN when configured)
    """
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
    put("CVE-2024-0003", desc="Odd desktop thing", cwe="CWE-9999",
        cvss={"cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}})
    put("CVE-2024-0004", desc="Reflected issue", cwe="CWE-79")
    put("CVE-2024-0005", state="RESERVED")

    paths = {}
    paths["cvelistV5"] = os.path.join(tmp, "cvelistV5-main.zip")
    tx.build_zip(paths["cvelistV5"], cve_members)

    rows = [
        {"id": "1", "file": "exploits/a.py", "description": "XSS PoC",
         "codes": "CVE-2024-0001", "verified": "1", "type": "webapps"},
        {"id": "2", "file": "exploits/b.py", "description": "SQLi PoC",
         "codes": "CVE-2024-0002", "type": "webapps"},
        {"id": "3", "file": "exploits/c.py", "description": "desktop PoC",
         "codes": "CVE-2024-0003"},
        {"id": "4", "file": "exploits/d.py", "description": "old PoC",
         "codes": "CVE-1999-9999"},
    ]
    paths["exploitdb"] = os.path.join(tmp, "exploitdb-main.zip")
    tx.build_zip(paths["exploitdb"],
                 {"exploitdb-main/files_exploits.csv": tx.edb_csv(rows)})

    paths["cwec"] = os.path.join(tmp, "cwec_latest.xml.zip")
    tx.build_zip(paths["cwec"], {"cwec_v4.20.xml": tx.CWE_XML_TMPL})

    paths["top10"] = os.path.join(tmp, "Top10-master.zip")
    tx.build_zip(paths["top10"], {
        "Top10-master/2021/docs/en/A01_2021-X.md": "# A01 X\n\ntext\n",
        "Top10-master/2025/docs/en/A05_2025-Y.md": "# A05 Y\n\ntext\n",
    })
    return paths


def recipe(logic="tightened", **over):
    base = {
        "recipe_id": "test", "recipe_version": "1.0.0", "stage": "slice",
        "logic": logic, "cvss_min": 7.0,
        "web_relevant_cwes_version": jn.WEB_RELEVANT_CWES_VERSION,
        "exploit_mirror": "sliced-cve",
        "include_reference": {"cwe_web_relevant": True,
                              "cwe_category": False, "owasp_doc": True},
        "excluded_from_index_veto": True,
        "min_total_tokens": 1, "years": None,
    }
    base.update(over)
    return base


class RecipeConfigTest(unittest.TestCase):
    def test_checked_in_recipes_valid(self):
        for stage in ("slice", "full"):
            r = cp.load_recipe(stage=stage)
            self.assertEqual(cp.validate_recipe(r), [])
        self.assertEqual(cp.load_recipe(stage="slice")["logic"], "tightened")
        self.assertEqual(cp.load_recipe(stage="slice")["cvss_min"], 7.0)
        self.assertEqual(cp.load_recipe(stage="full")["logic"], "full")
        self.assertEqual(cp.load_recipe(stage="full")["exploit_mirror"], "all")

    def test_stage1_recipe_matches_director_ruling(self):
        r = cp.load_recipe(stage="slice")
        # ruling: a AND (b OR c), cvss >= 7, tightened from the 213,152 union
        self.assertEqual(r["logic"], "tightened")
        self.assertEqual(r["cvss_min"], 7.0)
        self.assertEqual(r["web_relevant_cwes_version"],
                         jn.WEB_RELEVANT_CWES_VERSION)

    def test_load_by_name_and_path(self):
        by_name = cp.load_recipe("stage1")
        path = os.path.join(cp.RECIPE_DIR, "recipe_stage1.json")
        by_path = cp.load_recipe(path)
        self.assertEqual(by_name, by_path)

    def test_load_unknown_raises_corpus_error(self):
        with self.assertRaises(cp.CorpusError):
            cp.load_recipe("no-such-recipe")
        with self.assertRaises(cp.CorpusError):
            cp.load_recipe(stage="nope")

    def test_validate_rejects_bad_shapes(self):
        errs = cp.validate_recipe({"recipe_id": "x"})
        self.assertTrue(any(e.startswith("missing:") for e in errs))
        bad = recipe(logic="nonsense")
        self.assertTrue(any(e.startswith("bad_logic:")
                            for e in cp.validate_recipe(bad)))
        bad = recipe(exploit_mirror="nonsense")
        self.assertTrue(any(e.startswith("bad_exploit_mirror:")
                            for e in cp.validate_recipe(bad)))
        bad = recipe(cvss_min="high")
        self.assertTrue(any(e.startswith("bad_cvss_min:")
                            for e in cp.validate_recipe(bad)))
        bad = recipe(include_reference="yes")
        self.assertTrue(any(e.startswith("bad_include_reference:")
                            for e in cp.validate_recipe(bad)))

    def test_load_recipe_file_invalid_json_raises(self):
        tmp = tempfile.mkdtemp(prefix="wd-e4-")
        try:
            p = os.path.join(tmp, "r.json")
            with open(p, "w", encoding="utf-8") as f:
                f.write("{not json")
            with self.assertRaises(cp.CorpusError):
                cp.load_recipe(p)
        finally:
            shutil.rmtree(tmp, True)


class BranchesTest(unittest.TestCase):
    def setUp(self):
        self.index = jn.JoinIndex()
        self.index.add_known_cve("CVE-2024-0001")
        self.index.cve_to_edb.setdefault("CVE-2024-0001", set()).add("edb-1")

    def rec(self, **over):
        r = {"id": "CVE-2024-0001", "kind": "cve", "title": "t",
             "text_fields": ["x"], "cwe_ids": [], "cvss": None,
             "excluded_from_index": False}
        r.update(over)
        return r

    def test_branch_flags(self):
        r = self.rec(cwe_ids=["cwe-79"],
                     cvss={"score": 9.8, "severity": "CRITICAL"})
        br = cp.recipe_branches(r, self.index, recipe())
        self.assertEqual(br, {"a": True, "b": True, "c": True})
        # negative case: an id WITHOUT an exploit join
        r = self.rec(id="CVE-2024-0002", cwe_ids=["cwe-9999"],
                     cvss={"score": 3.1})
        br = cp.recipe_branches(r, self.index, recipe())
        self.assertEqual(br, {"a": False, "b": False, "c": False})
        # c comes from the join, not the record
        r = self.rec(cwe_ids=[], cvss=None)
        self.assertTrue(cp.recipe_branches(r, self.index, recipe())["c"])

    def test_cvss_min_config_tightening(self):
        r = self.rec(cvss={"score": 7.5})
        self.assertTrue(cp.recipe_branches(r, self.index,
                                           recipe(cvss_min=7.0))["b"])
        self.assertFalse(cp.recipe_branches(r, self.index,
                                            recipe(cvss_min=8.0))["b"])

    def test_null_cvss_is_below_threshold(self):
        r = self.rec(cvss=None)
        self.assertFalse(cp.recipe_branches(r, self.index, recipe())["b"])
        r = self.rec(cvss={})
        self.assertFalse(cp.recipe_branches(r, self.index, recipe())["b"])


class RecordIncludedTest(unittest.TestCase):
    def setUp(self):
        self.index = jn.JoinIndex()
        self.index.add_known_cve("CVE-2024-0001")
        self.index.add_known_cve("CVE-2024-0002")
        self.index.cve_to_edb.setdefault("CVE-2024-0001", set()).add("edb-1")
        self.sliced = {"CVE-2024-0001"}

    def rec(self, **over):
        r = {"id": "CVE-2024-0002", "kind": "cve", "title": "t",
             "text_fields": ["x"], "cwe_ids": [], "cvss": None,
             "excluded_from_index": False}
        r.update(over)
        return r

    def test_tightened_truth_table(self):
        cases = [
            # (a, b, c) -> included under a AND (b OR c)
            (True, True, True, True),
            (True, True, False, True),
            (True, False, True, True),
            (True, False, False, False),
            (False, True, True, False),
            (False, True, False, False),
            (False, False, True, False),
            (False, False, False, False),
        ]
        for a, b, c, want in cases:
            r = self.rec(
                cwe_ids=["cwe-79"] if a else ["cwe-9999"],
                cvss={"score": 9.8} if b else None,
                id=("CVE-2024-0001" if c else "CVE-2024-0002"),
            )
            got, reasons = cp.record_included(r, self.index, recipe(),
                                              sliced_cve_ids=self.sliced)
            self.assertEqual(got, want, f"a={a} b={b} c={c}")
            if got:
                self.assertTrue(reasons)

    def test_excluded_veto(self):
        r = self.rec(cwe_ids=["cwe-79"], cvss={"score": 9.8},
                     excluded_from_index=True)
        self.assertEqual(
            cp.record_included(r, self.index, recipe())[0], False)
        # veto off (full-style recipe) -> kept, flag preserved downstream
        got, _ = cp.record_included(r, self.index,
                                    recipe(excluded_from_index_veto=False))
        self.assertTrue(got)

    def test_full_logic_includes_everything(self):
        r = self.rec(excluded_from_index=True)
        self.assertEqual(cp.record_included(r, self.index,
                                            recipe(logic="full"))[0], True)

    def test_exploit_mirror_modes(self):
        e_in = self.rec(id="edb-1", kind="exploit",
                        cve_refs=["CVE-2024-0001"])
        e_out = self.rec(id="edb-3", kind="exploit",
                         cve_refs=["CVE-2024-0002"])
        e_dangling = self.rec(id="edb-4", kind="exploit",
                              cve_refs=["CVE-1999-9999"])
        # sliced-cve mirror: only refs inside the slice set
        self.assertTrue(cp.record_included(
            e_in, self.index, recipe(), sliced_cve_ids=self.sliced)[0])
        self.assertFalse(cp.record_included(
            e_out, self.index, recipe(), sliced_cve_ids=self.sliced)[0])
        self.assertFalse(cp.record_included(
            e_dangling, self.index, recipe(), sliced_cve_ids=self.sliced)[0])
        # resolved-cve mirror (design-2.3 union semantics)
        m = recipe(exploit_mirror="resolved-cve")
        self.assertTrue(cp.record_included(e_out, self.index, m)[0])
        self.assertFalse(cp.record_included(e_dangling, self.index, m)[0])
        # all / none
        self.assertTrue(cp.record_included(
            e_dangling, self.index, recipe(exploit_mirror="all"))[0])
        self.assertFalse(cp.record_included(
            e_in, self.index, recipe(exploit_mirror="none"))[0])

    def test_reference_kinds(self):
        cwe_web = self.rec(id="cwe-79", kind="cwe")
        cwe_other = self.rec(id="cwe-1234", kind="cwe")
        cat = self.rec(id="cwe-1", kind="cwe_category",
                       excluded_from_index=True)
        doc = self.rec(id="owasp-2021-x", kind="owasp_doc")
        r = recipe()
        self.assertTrue(cp.record_included(cwe_web, self.index, r)[0])
        self.assertFalse(cp.record_included(cwe_other, self.index, r)[0])
        self.assertFalse(cp.record_included(cat, self.index, r)[0])
        self.assertTrue(cp.record_included(doc, self.index, r)[0])
        r2 = recipe(include_reference={"cwe_web_relevant": False,
                                       "cwe_category": True,
                                       "owasp_doc": False})
        self.assertFalse(cp.record_included(cwe_web, self.index, r2)[0])
        # category veto: excluded_from_index + veto -> out even if configured
        self.assertFalse(cp.record_included(cat, self.index, r2)[0])
        r3 = recipe(include_reference={"cwe_web_relevant": False,
                                       "cwe_category": True,
                                       "owasp_doc": False},
                    excluded_from_index_veto=False)
        self.assertTrue(cp.record_included(cat, self.index, r3)[0])
        self.assertFalse(cp.record_included(doc, self.index, r3)[0])

    def test_union_matches_joiner_slice_included(self):
        """Consistency law: logic=union + resolved-cve mirror +
        cwe_web_relevant reproduces joiner.slice_included booleans for
        cve/exploit/cwe kinds (the design-2.3 strict recipe)."""
        r = recipe(logic="union", exploit_mirror="resolved-cve")
        recs = [
            self.rec(id="CVE-2024-0001", cwe_ids=["cwe-79"],
                     cvss={"score": 9.8}),
            self.rec(id="CVE-2024-0002", cwe_ids=["cwe-9999"], cvss=None),
            self.rec(id="CVE-2024-0003", cwe_ids=[], cvss=None,
                     excluded_from_index=True),
            self.rec(id="edb-1", kind="exploit",
                     cve_refs=["CVE-2024-0001"]),
            self.rec(id="edb-9", kind="exploit", cve_refs=[]),
            self.rec(id="cwe-79", kind="cwe"),
            self.rec(id="cwe-1234", kind="cwe"),
        ]
        for rec in recs:
            want = jn.slice_included(rec, self.index)[0]
            got = cp.record_included(rec, self.index, r)[0]
            self.assertEqual(got, want, rec["id"])


class AssemblerMiniTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wd-e4-asm-")
        cls.paths = mini_archives(cls.tmp)
        cls.table = om.load_map()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def assemble(self, rec, **kw):
        a = cp.CorpusAssembler(self.paths, rec, map_table=self.table, **kw)
        out = list(a.iter_records())
        return out, a

    def test_tightened_slice_counts_hand_computed(self):
        out, a = self.assemble(recipe())
        ids = [r["id"] for r in out]
        # CVE-0001 (a+b+c), CVE-0002 (a+c) | edb-1, edb-2 (mirror) |
        # cwe-79, cwe-89 (ref) | 2 owasp docs (ref) = 8 records
        self.assertEqual(sorted(ids), sorted([
            "CVE-2024-0001", "CVE-2024-0002", "edb-1", "edb-2",
            "cwe-79", "cwe-89", "owasp-2021-A01_2021-X",
            "owasp-2025-A05_2025-Y"]))
        st = a.stats
        self.assertEqual(st["included_total"], 8)
        self.assertEqual(st["kinds"]["cve"]["included"], 2)
        self.assertEqual(st["kinds"]["exploit"]["included"], 2)
        self.assertEqual(st["kinds"]["cwe"]["included"], 2)
        self.assertEqual(st["kinds"]["owasp_doc"]["included"], 2)
        self.assertEqual(st["kinds"]["cwe_category"]["included"], 0)
        self.assertEqual(st["kinds"]["cve"]["seen"], 5)
        self.assertEqual(st["kinds"]["exploit"]["seen"], 4)
        # excluded veto counted (CVE-2024-0005)
        self.assertEqual(st["excluded_vetoed"], 1)
        # reasons tallied
        self.assertEqual(st["by_reason"]["a-web-cwe"], 2)
        self.assertEqual(st["by_reason"]["mirror-sliced-cve"], 2)
        self.assertEqual(st["by_reason"]["ref-web-cwe"], 2)
        self.assertEqual(st["by_reason"]["ref-owasp-doc"], 2)

    def test_joins_attached_on_emitted_records(self):
        out, _ = self.assemble(recipe())
        by_id = {r["id"]: r for r in out}
        cve1 = by_id["CVE-2024-0001"]
        self.assertEqual(cve1["exploit_refs"], ["edb-1"])
        # cwe-79 -> OWASP 2021/2025 injection labels via the static table
        self.assertTrue(any("Injection" in c
                            for c in cve1["owasp_categories"]))
        self.assertTrue(by_id["edb-1"]["cve_refs"])

    def test_full_recipe_includes_everything(self):
        out, a = self.assemble(recipe(logic="full", exploit_mirror="all",
                                      excluded_from_index_veto=False,
                                      include_reference={
                                          "cwe_web_relevant": True,
                                          "cwe_category": True,
                                          "owasp_doc": True}))
        kinds = {}
        for r in out:
            kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        self.assertEqual(kinds, {"cve": 5, "exploit": 4, "cwe": 2,
                                 "cwe_category": 1, "owasp_doc": 2})
        self.assertEqual(a.stats["included_total"], 14)
        flags = {r["id"]: r.get("excluded_from_index") for r in out}
        self.assertTrue(flags["CVE-2024-0005"])   # kept, flagged
        self.assertTrue(flags["cwe-1"])

    def test_streaming_generator_not_list(self):
        a = cp.CorpusAssembler(self.paths, recipe(), map_table=self.table)
        it = a.iter_records()
        self.assertIsInstance(it, types.GeneratorType)
        first = next(it)
        self.assertIn("id", first)
        it.close()

    def test_deterministic_order(self):
        out1, _ = self.assemble(recipe())
        out2, _ = self.assemble(recipe())
        self.assertEqual([r["id"] for r in out1], [r["id"] for r in out2])

    def test_years_filter_smoke(self):
        out, _ = self.assemble(recipe(logic="full", exploit_mirror="all",
                                      excluded_from_index_veto=False),
                               years={"2023"})
        self.assertEqual([r["id"] for r in out if r["kind"] == "cve"], [])

    def test_union_slice_matches_joiner_booleans(self):
        r = recipe(logic="union", exploit_mirror="resolved-cve")
        out, _ = self.assemble(r)
        ids = {x["id"] for x in out}
        self.assertIn("CVE-2024-0003", ids)   # b-branch only
        self.assertIn("edb-3", ids)           # resolved-cve mirror
        self.assertNotIn("edb-4", ids)        # dangling only
        self.assertIn("CVE-2024-0004", ids)   # a-branch alone suffices
        self.assertNotIn("CVE-2024-0005", ids)  # excluded veto


class FingerprintVersionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="wd-e4-fp-")
        cls.paths = mini_archives(cls.tmp)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_fingerprint_sha256(self):
        fp = cp.input_fingerprint(self.paths)
        self.assertEqual(sorted(fp), sorted(self.paths))
        for name, entry in fp.items():
            h = hashlib.sha256()
            with open(self.paths[name], "rb") as f:
                for block in iter(lambda: f.read(1 << 16), b""):
                    h.update(block)
            self.assertEqual(entry["sha256"], h.hexdigest())
            self.assertEqual(entry["path"], self.paths[name])
            self.assertGreater(entry["size_bytes"], 0)

    def test_corpus_version_deterministic(self):
        fp = cp.input_fingerprint(self.paths)
        r = recipe()
        v1 = cp.corpus_version(r, fp)
        v2 = cp.corpus_version(recipe(), cp.input_fingerprint(self.paths))
        self.assertEqual(v1, v2)
        self.assertTrue(v1.startswith("vkb1-"))

    def test_corpus_version_changes_with_recipe(self):
        fp = cp.input_fingerprint(self.paths)
        v1 = cp.corpus_version(recipe(), fp)
        v2 = cp.corpus_version(recipe(cvss_min=8.0), fp)
        self.assertNotEqual(v1, v2)

    def test_fingerprint_missing_archive_raises(self):
        bad = dict(self.paths)
        bad["cwec"] = os.path.join(self.tmp, "nope.zip")
        with self.assertRaises(cp.CorpusError):
            cp.input_fingerprint(bad)


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e4-man-")

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def test_build_manifest_shape(self):
        r = recipe()
        fp = {"cvelistV5": {"path": "p", "sha256": "aa", "size_bytes": 1}}
        stats = {"included_total": 10,
                 "kinds": {"cve": {"seen": 20, "included": 10}},
                 "by_reason": {"a-web-cwe": 4},
                 "excluded_vetoed": 2}
        chunks = {"chunks_total": 12, "chunks_by_kind": {"cve": 12},
                  "chunks_truncated": 1}
        m = cp.build_manifest(r, fp, stats, chunks)
        self.assertEqual(m["manifest_version"], cp.MANIFEST_VERSION)
        self.assertEqual(m["recipe"], r)
        self.assertEqual(m["inputs"], fp)
        self.assertEqual(m["counts"]["records_total"], 10)
        self.assertEqual(m["counts"]["chunks_total"], 12)
        self.assertEqual(m["counts"]["chunks_truncated"], 1)
        self.assertEqual(m["corpus_version"], cp.corpus_version(r, fp))
        self.assertIn("created_at", m)
        json.dumps(m)  # serializable

    def test_write_manifest_atomic_ok(self):
        p = os.path.join(self.tmp, "manifest.json")
        cp.write_manifest_atomic(p, {"a": 1})
        with open(p, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"a": 1})
        self.assertEqual([n for n in os.listdir(self.tmp)
                          if n.startswith("manifest.json.tmp")], [])

    def test_write_manifest_atomic_failure_leaves_no_partial(self):
        p = os.path.join(self.tmp, "manifest.json")
        cp.write_manifest_atomic(p, {"a": 1})

        class Unserializable:
            pass

        with self.assertRaises(Exception):
            cp.write_manifest_atomic(p, {"bad": Unserializable()})
        # previous content survives; no tmp files left behind
        with open(p, encoding="utf-8") as f:
            self.assertEqual(json.load(f), {"a": 1})
        self.assertEqual([n for n in os.listdir(self.tmp) if ".tmp" in n],
                         [])


class DefaultPathsTest(unittest.TestCase):
    def test_default_archive_paths_shape(self):
        paths = cp.default_archive_paths("X:/raw")
        self.assertEqual(sorted(paths),
                         ["cvelistV5", "cwec", "exploitdb", "top10"])
        self.assertTrue(all(p.startswith("X:/raw") or p.startswith("X:\\raw")
                            for p in paths.values()))

    def test_default_raw_dir_is_portable(self):
        # FINAL-01: no absolute developer path may ship in the wheel.
        # The default is unconfigured (None); the build CLI requires an
        # explicit --raw-dir, so a missing one is an loud input error.
        self.assertIsNone(cp.DEFAULT_RAW_DIR)

    def test_default_archive_paths_unconfigured_is_input_error(self):
        # FINAL-01: an unconfigured raw dir (default / None / empty) is
        # an explicit CorpusError, never a silent developer-path join.
        for raw in (None, ""):
            with self.assertRaises(cp.CorpusError) as ctx:
                cp.default_archive_paths(raw)
            self.assertIn("no archive directory configured",
                          str(ctx.exception))
        with self.assertRaises(cp.CorpusError) as ctx:
            cp.default_archive_paths()  # the portable default itself
        self.assertIn("no archive directory configured",
                      str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
