"""Tests for vuln_watchdog.owasp_map (WD-E2 part 1; brief P2-A item 2).

Contract under test:
- the static CWE->OWASP table is a CHECKED-IN, VERSIONED ASCII JSON file
  (vuln_watchdog/data/cwe_owasp_map.json) with a PER-ROW rationale note;
- seeded from the OWASP-published per-category "List of Mapped CWEs"
  sections shipped in the LOCAL Top10 archive (2021 + 2025 EN category
  docs A01..A10) -- fully offline (C1); the CWE catalog's own
  Taxonomy_Mappings only cover OWASP 2004/2007 (probed 2026-10-15), so
  the Top10 docs are the authoritative local seed;
- labels are edition-disambiguated: "<code>:<edition>-<Title-Slug>"
  (e.g. A03:2021-Injection vs A05:2025-Injection -- the 2025 renumber
  makes bare "A03-injection" ambiguous);
- build_seed_from_top10() regenerates the table from the archive and
  FAILS LOUD when an edition does not yield exactly 10 category docs
  (layout-change signal for the A7 refresh);
- load_map() validates the checked-in table shape; lookups accept
  'cwe-79' and 'CWE-79' and return [] for unmapped ids.
"""
import json
import os
import shutil
import tempfile
import unittest
import zipfile

from vulndog.engine import owasp_map as om

# Optional local archive dir (env-driven; absent -> real-archive tests skip).
RAW_DIR = os.environ.get("VULNDOG_RAW_DIR", "")
HAS_TOP10 = os.path.exists(os.path.join(RAW_DIR, "Top10-master.zip"))
MAP_PATH = om.DEFAULT_MAP_PATH


def mini_doc(code, edition, cwes, heading="## List of Mapped CWEs"):
    lines = [f"# {code}:{edition} - Test Category", "", "Body.", "", heading, ""]
    for n in cwes:
        lines.append(f"* [CWE-{n} Name {n}](https://cwe.mitre.org/data/"
                     f"definitions/{n}.html)")
        lines.append("")
    return "\n".join(lines)


def build_mini_zip(path, edition_cwes):
    members = {}
    for edition, mapping in edition_cwes.items():
        for code, cwes in mapping.items():
            name = f"Test Category {code}"
            fname = f"{code}_{edition}-{name.replace(' ', '_')}.md"
            members[f"Top10-master/{edition}/docs/en/{fname}"] = \
                mini_doc(code, edition, cwes)
        # a non-category EN doc that must be ignored for mapping
        members[f"Top10-master/{edition}/docs/en/index.md"] = "# index\n"
    with zipfile.ZipFile(path, "w") as zf:
        for n, d in members.items():
            zf.writestr(n, d.encode("utf-8"))


class SeedParseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e2-map-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_parse_two_editions(self):
        p = os.path.join(self.tmp, "t.zip")
        build_mini_zip(p, {
            "2021": {f"A{i:02d}": [79, 89] if i == 3 else [20]
                     for i in range(1, 11)},
            "2025": {f"A{i:02d}": [79] if i == 5 else [20]
                     for i in range(1, 11)},
        })
        table = om.build_seed_from_top10(p)
        self.assertEqual(table["map_version"], om.MAP_VERSION)
        self.assertEqual(len(table["categories"]), 20)
        labels = {c["label"] for c in table["categories"]}
        self.assertIn("A03:2021-Test-Category-A03", labels)
        idx = om.cwe_to_categories(table)
        self.assertEqual(idx["cwe-79"],
                         ["A03:2021-Test-Category-A03",
                          "A05:2025-Test-Category-A05"])
        row79 = [r for r in table["rows"] if r["cwe"] == "cwe-79"][0]
        self.assertIn("rationale", row79)
        self.assertIn("2021", row79["rationale"])
        self.assertIn("2025", row79["rationale"])

    def test_section_stops_at_next_heading(self):
        p = os.path.join(self.tmp, "t2.zip")
        members = {}
        for i in range(1, 11):
            code = f"A{i:02d}"
            doc = mini_doc(code, "2021", [20])
            if i == 1:
                doc += ("\n## Something Else\n\nMentioned in prose CWE-9999 "
                        "must NOT be mapped.\n")
            members[f"Top10-master/2021/docs/en/{code}_2021-Cat_{code}.md"] = doc
        for i in range(1, 11):
            code = f"A{i:02d}"
            members[f"Top10-master/2025/docs/en/{code}_2025-Cat_{code}.md"] = \
                mini_doc(code, "2025", [20])
        with zipfile.ZipFile(p, "w") as zf:
            for n, d in members.items():
                zf.writestr(n, d.encode("utf-8"))
        table = om.build_seed_from_top10(p)
        idx = om.cwe_to_categories(table)
        self.assertNotIn("cwe-9999", idx)

    def test_missing_category_fails_loud(self):
        p = os.path.join(self.tmp, "t3.zip")
        build_mini_zip(p, {"2021": {f"A{i:02d}": [20] for i in range(1, 10)}})
        with self.assertRaises(om.OwaspMapError):
            om.build_seed_from_top10(p)  # 9 categories + no 2025 edition


class ValidateAndLookupTest(unittest.TestCase):
    def test_validate_table_reports_shape_errors(self):
        errs = om.validate_table({"map_version": "x"})
        self.assertTrue(any("categories" in e for e in errs))
        self.assertTrue(any("rows" in e for e in errs))
        good = {
            "map_version": om.MAP_VERSION,
            "categories": [{"label": "A01:2021-X", "edition": "2021",
                            "code": "A01", "title": "X", "doc": "d.md"}],
            "rows": [{"cwe": "cwe-79", "categories": ["A01:2021-X"],
                      "rationale": "r"}],
        }
        self.assertEqual(om.validate_table(good), [])
        bad_row = json.loads(json.dumps(good))
        bad_row["rows"][0]["cwe"] = "CWE-79"  # not normalized
        self.assertTrue(om.validate_table(bad_row))
        dangling = json.loads(json.dumps(good))
        dangling["rows"][0]["categories"] = ["A99:2021-Nope"]
        self.assertTrue(any("dangling" in e
                            for e in om.validate_table(dangling)))

    def test_categories_for_cwe_normalizes_input(self):
        table = {
            "map_version": om.MAP_VERSION,
            "categories": [{"label": "A03:2021-Injection", "edition": "2021",
                            "code": "A03", "title": "Injection",
                            "doc": "d.md"}],
            "rows": [{"cwe": "cwe-79", "categories": ["A03:2021-Injection"],
                      "rationale": "r"}],
        }
        self.assertEqual(om.categories_for_cwe("CWE-79", table),
                         ["A03:2021-Injection"])
        self.assertEqual(om.categories_for_cwe("cwe-79", table),
                         ["A03:2021-Injection"])
        self.assertEqual(om.categories_for_cwe(" 79 ", table),
                         ["A03:2021-Injection"])
        self.assertEqual(om.categories_for_cwe("cwe-12345", table), [])
        self.assertEqual(om.categories_for_cwe(None, table), [])

    def test_load_map_rejects_broken_file(self):
        tmp = tempfile.mkdtemp(prefix="wd-e2-load-")
        self.addCleanup(shutil.rmtree, tmp, True)
        p = os.path.join(tmp, "broken.json")
        with open(p, "w", encoding="utf-8") as f:
            f.write('{"map_version": "1.0.0"}')
        with self.assertRaises(om.OwaspMapError):
            om.load_map(p)


class CheckedInTableTest(unittest.TestCase):
    """The checked-in artifact vuln_watchdog/data/cwe_owasp_map.json."""

    @classmethod
    def setUpClass(cls):
        with open(MAP_PATH, "rb") as f:
            cls.raw = f.read()
        cls.table = json.loads(cls.raw.decode("ascii"))

    def test_file_is_ascii(self):
        self.assertTrue(all(b < 128 for b in self.raw))

    def test_shape_valid(self):
        self.assertEqual(om.validate_table(self.table), [])

    def test_versioned_with_provenance(self):
        self.assertEqual(self.table["map_version"], om.MAP_VERSION)
        src = self.table["source"]
        self.assertEqual(src["archive"], "Top10-master.zip")
        self.assertRegex(src["archive_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertEqual(sorted(src["editions"]), ["2021", "2025"])

    def test_twenty_categories_ten_per_edition(self):
        cats = self.table["categories"]
        self.assertEqual(len(cats), 20)
        per = {}
        for c in cats:
            per.setdefault(c["edition"], set()).add(c["code"])
        self.assertEqual({k: len(v) for k, v in per.items()},
                         {"2021": 10, "2025": 10})
        labels = [c["label"] for c in cats]
        self.assertEqual(len(set(labels)), 20)

    def test_every_row_has_rationale_and_normalized_cwe(self):
        self.assertGreater(len(self.table["rows"]), 100)
        for r in self.table["rows"]:
            self.assertRegex(r["cwe"], r"\Acwe-\d+\Z")
            self.assertTrue(r["rationale"].strip())
            self.assertTrue(r["categories"])

    def test_known_public_mappings_present(self):
        idx = om.cwe_to_categories(self.table)
        # XSS + SQLi: Injection in both editions (2021 A03, 2025 A05)
        self.assertIn("A03:2021-Injection", idx["cwe-79"])
        self.assertIn("A05:2025-Injection", idx["cwe-79"])
        self.assertIn("A03:2021-Injection", idx["cwe-89"])
        self.assertIn("A05:2025-Injection", idx["cwe-89"])
        # SSRF is its own 2021 category
        ssrf = [l for l in idx["cwe-918"] if l.startswith("A10:2021")]
        self.assertTrue(ssrf)
        # CSRF + path traversal under 2021 A01 Broken Access Control
        a01 = "A01:2021-Broken-Access-Control"
        self.assertIn(a01, idx["cwe-352"])
        self.assertIn(a01, idx["cwe-22"])
        # XXE moved out of Injection in 2021 (A05 Security Misconfiguration)
        self.assertTrue(any(l.startswith("A05:2021") for l in idx["cwe-611"]))

    @unittest.skipUnless(HAS_TOP10, "raw Top10 archive absent")
    def test_regeneration_matches_checked_in_table(self):
        rebuilt = om.build_seed_from_top10(
            os.path.join(RAW_DIR, "Top10-master.zip"))
        self.assertEqual(rebuilt["categories"], self.table["categories"])
        self.assertEqual(rebuilt["rows"], self.table["rows"])
        self.assertEqual(rebuilt["source"]["archive_sha256"],
                         self.table["source"]["archive_sha256"])


if __name__ == "__main__":
    unittest.main()
