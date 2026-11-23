"""Tests for vuln_watchdog.extractors (WD-E1; design-spec 4.2, brief P2-A item 1).

Contract under test:
- streaming per-source extractors yielding F1-normalized records
  (record_schema.normalize_record); one bad unit never kills the stream;
- cvelistV5: per-CVE JSON walk from the zip, deltaLog/delta skipped,
  EN descriptions, adp-container merge (problemTypes+metrics when cna
  lacks them, provenance noted), HTML entities FLAGGED not cleaned
  (E3 cleans), refs carried non-embedded, years filter for scale tests;
- exploitdb: CSV stream, id dedup (first wins, counted), CVE-* tokens
  from codes -> cve_refs (+ aliases scan, counted separately), non-CVE
  tokens -> other_codes, verified=1 -> confidence "verified", poc_body
  only on demand with an 8 KB cap, files_shellcodes.csv NEVER exported;
- cwec: XML pull-parse, 969 Weakness kind=cwe + 422 Category
  kind=cwe_category reference-only (empty text_fields ->
  excluded_from_index, F1 law);
- Top10: EN markdown docs only, id=owasp-<edition>-<slug> with a
  slugify rule so every id passes the F1 pattern (the pilot's raw-slug
  '(SSRF)' id FAILS F1 - production must not regress);
- D6: cvejson.json exclusion encoded - guard_excluded_source raises,
  every extractor refuses an excluded source path;
- count reconciliation against artifacts/vulndb-inventory.json
  (408,310 / 47,170 rows -> 46,698 unique / 969 + 422 / Top10 EN
  MEASURED) on synthetic fixtures + real-archive tests (auto-skip when
  the raw folder is absent), incl. the >= 1 full CVE year bucket scale
  smoke test (1999: 1,579 records).

Raw-archive text is UNTRUSTED DATA (C12): tests assert it is carried as
strings only and that stats aggregate anomaly/error CODES, never values.
"""
import io
import os
import csv
import json
import shutil
import tempfile
import unittest
import zipfile

from vulndog.engine import extractors as ex
from vulndog.engine import record_schema as rs

# Optional local archive dir (env-driven; absent -> real-archive tests skip).
RAW_DIR = os.environ.get("VULNDOG_RAW_DIR", "")
HAS_RAW = os.path.isdir(RAW_DIR) and os.path.exists(
    os.path.join(RAW_DIR, "cvelistV5-main.zip"))


def build_zip(path, members):
    """members: {zip-relative name: str|bytes}"""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            if isinstance(data, str):
                data = data.encode("utf-8")
            zf.writestr(name, data)


def cve_doc(cve_id, title=None, desc=None, lang="en", cwe=None, cvss=None,
            affected=None, solutions=None, refs=None, state="PUBLISHED",
            containers_extra=None):
    cna = {"providerMetadata": {"orgId": "x", "shortName": "test"}}
    if desc is not None:
        cna["descriptions"] = [{"lang": lang, "value": desc}]
    if title is not None:
        cna["title"] = title
    if cwe is not None:
        cna["problemTypes"] = [{"descriptions": [
            {"lang": "en", "description": "t", "cweId": cwe, "type": "CWE"}]}]
    if cvss is not None:
        cna["metrics"] = [cvss]
    if affected is not None:
        cna["affected"] = affected
    if solutions is not None:
        cna["solutions"] = [{"lang": "en", "value": solutions}]
    if refs is not None:
        cna["references"] = [{"url": u} for u in refs]
    containers = {"cna": cna}
    if containers_extra:
        containers.update(containers_extra)
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {
            "cveId": cve_id, "assignerOrgId": "org",
            "assignerShortName": "test", "state": state,
            "dateReserved": "2024-01-01T00:00:00.000Z",
            "datePublished": "2024-06-01T00:00:00.000Z",
            "dateUpdated": "2024-06-02T00:00:00.000Z",
        },
        "containers": containers,
    }


def edb_csv(rows):
    """rows: list of dicts with the files_exploits.csv columns."""
    cols = ["id", "file", "description", "date_published", "author", "type",
            "platform", "port", "date_added", "date_updated", "verified",
            "codes", "tags", "aliases", "screenshot_url", "application_url",
            "source_url"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, cols, lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: r.get(c, "") for c in cols})
    return buf.getvalue()


CWE_XML_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Name="CWE" Version="4.20">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Draft">
      <Description>The product does not neutralize user input before placing it in output.</Description>
      <Extended_Description>There are three main kinds of XSS.</Extended_Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000" Ordinal="Primary"/>
      </Related_Weaknesses>
      <Common_Consequences>
        <Consequence Scope="Confidentiality" Impact="Read Application Data">
          <Note>Attackers can read session data.</Note>
        </Consequence>
      </Common_Consequences>
      <Demonstrative_Examples>
        <Demonstrative_Example>
          <Intro_Text>Example intro.</Intro_Text>
          <Body_Text>&lt;script&gt;alert(1)&lt;/script&gt; is reflected.</Body_Text>
        </Demonstrative_Example>
      </Demonstrative_Examples>
    </Weakness>
    <Weakness ID="89" Name="SQL Injection" Abstraction="Base" Status="Incomplete">
      <Description>The product constructs SQL using externally-influenced input.</Description>
    </Weakness>
  </Weaknesses>
  <Categories>
    <Category ID="1" Name="DEPRECATED: Location" Status="Deprecated">
      <Summary>This category has been deprecated.</Summary>
    </Category>
  </Categories>
</Weakness_Catalog>
"""


class ExtractStatsTest(unittest.TestCase):
    def test_stats_aggregates_codes_not_values(self):
        s = ex.ExtractStats("test")
        s.reject(["id_format:SECRET-VALUE-abc"])
        s.anomaly(["cwe_id_dropped:'<script>alert(1)</script>'"])
        self.assertEqual(s.rejected["id_format"], 1)
        self.assertEqual(s.anomalies["cwe_id_dropped"], 1)
        blob = json.dumps(s.as_dict())
        self.assertNotIn("SECRET", blob)
        self.assertNotIn("script", blob)

    def test_as_dict_shape(self):
        s = ex.ExtractStats("cvelistV5")
        s.emitted_ok()
        d = s.as_dict()
        self.assertEqual(d["source"], "cvelistV5")
        self.assertEqual(d["emitted"], 1)


class GuardExcludedSourceTest(unittest.TestCase):
    def test_cvejson_guard_raises(self):
        for p in ("C:/x/cvejson.json", "cvejson.json", "a\\b\\CVEJSON.JSON"):
            with self.assertRaises(ex.ExcludedSourceError):
                ex.guard_excluded_source(p)

    def test_normal_paths_pass(self):
        ex.guard_excluded_source("C:/x/cvelistV5-main.zip")  # no raise


class CveExtractorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e1-cve-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.zip = os.path.join(self.tmp, "cvelistV5-main.zip")

    def extract(self, members, **kw):
        build_zip(self.zip, members)
        stats = ex.ExtractStats("cvelistV5")
        recs = list(ex.iter_cve_records(self.zip, stats, **kw))
        return recs, stats

    def test_plain_cna_record_maps_fields(self):
        doc = cve_doc(
            "CVE-2024-5000", title="CODESYS buffer bug",
            desc="An unauthenticated remote attacker can trigger DoS.",
            cwe="CWE-120", cvss={"cvssV3_1": {
                "baseScore": 7.5, "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N"}},
            affected=[{"vendor": "CODESYS", "product": "Control",
                       "versions": [{"version": "1.0", "status": "affected"},
                                    {"version": "n/a"}]}],
            solutions="Upgrade to 4.12.",
            refs=["https://example.com/advisory"])
        recs, stats = self.extract(
            {"cvelistV5-main/cves/2024/5xxx/CVE-2024-5000.json":
             json.dumps(doc)})
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r["id"], "CVE-2024-5000")
        self.assertEqual(r["kind"], "cve")
        self.assertEqual(r["title"], "CODESYS buffer bug")
        self.assertIn("An unauthenticated remote attacker", r["text_fields"][0])
        self.assertIn("title: CODESYS buffer bug", r["text_fields"])
        self.assertIn("solution: Upgrade to 4.12.", r["text_fields"])
        self.assertIn("affected: CODESYS Control", r["text_fields"])
        self.assertEqual(r["cwe_ids"], ["cwe-120"])
        self.assertEqual(r["cvss"]["score"], 7.5)
        self.assertEqual(r["cvss"]["severity"], "HIGH")
        self.assertEqual(r["affected"][0]["versions"], ["1.0"])  # n/a dropped
        self.assertEqual(r["refs"], ["https://example.com/advisory"])
        self.assertNotIn("https://example.com/advisory",
                         " ".join(r["text_fields"]))  # refs non-embedded
        self.assertEqual(r["dates"]["published"], "2024-06-01T00:00:00.000Z")
        self.assertEqual(r["source_path"], "cves/2024/5xxx/CVE-2024-5000.json")
        self.assertEqual(r["evidence"]["src"], "cvelistV5-main.zip")
        self.assertEqual(r["cve_state"], "PUBLISHED")
        self.assertFalse(r["excluded_from_index"])
        self.assertEqual(stats.emitted, 1)
        self.assertEqual(stats.rejected_total(), 0)

    def test_adp_merge_when_cna_lacks(self):
        adp = {"adp": [{
            "providerMetadata": {"orgId": "adp"},
            "descriptions": [{"lang": "en", "value": "ADP description text."}],
            "problemTypes": [{"descriptions": [
                {"lang": "en", "cweId": "CWE-89", "type": "CWE"}]}],
            "metrics": [{"cvssV3_1": {"baseScore": 9.8,
                                      "baseSeverity": "CRITICAL"}}],
        }]}
        doc = cve_doc("CVE-2025-0001", containers_extra=adp)
        recs, _ = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0001.json": json.dumps(doc)})
        r = recs[0]
        self.assertIn("ADP description text.", r["text_fields"][0])
        self.assertEqual(r["cwe_ids"], ["cwe-89"])
        self.assertEqual(r["cvss"]["score"], 9.8)
        self.assertIn("adp", r["evidence"]["note"].lower())

    def test_cna_wins_over_adp(self):
        adp = {"adp": [{
            "problemTypes": [{"descriptions": [{"cweId": "CWE-999"}]}],
            "metrics": [{"cvssV3_1": {"baseScore": 1.0}}],
        }]}
        doc = cve_doc("CVE-2025-0002", desc="cna desc", cwe="CWE-79",
                      cvss={"cvssV3_1": {"baseScore": 8.1}},
                      containers_extra=adp)
        recs, _ = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0002.json": json.dumps(doc)})
        r = recs[0]
        self.assertIn("cwe-79", r["cwe_ids"])
        self.assertNotIn("cwe-999", r["cwe_ids"])
        self.assertEqual(r["cvss"]["score"], 8.1)

    def test_html_entities_flagged_not_cleaned(self):
        doc = cve_doc("CVE-2025-0003",
                      desc="Value&nbsp;with &amp; entities &lt;here&gt;.")
        recs, stats = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0003.json": json.dumps(doc)})
        r = recs[0]
        self.assertTrue(r["html_entities"])
        self.assertIn("&nbsp;", r["text_fields"][0])  # E3 cleans, not E1
        self.assertGreaterEqual(stats.anomalies.get("html_entities_flagged", 0), 1)

    def test_delta_files_skipped(self):
        doc = cve_doc("CVE-2025-0004", desc="d")
        recs, stats = self.extract({
            "cvelistV5-main/cves/2025/0xxx/CVE-2025-0004.json": json.dumps(doc),
            "cvelistV5-main/cves/deltaLog.json": '{"changes": []}',
            "cvelistV5-main/cves/delta.json": "{}",
            "cvelistV5-main/README.md": "# readme",
        })
        self.assertEqual(len(recs), 1)
        self.assertEqual(stats.seen, 1)

    def test_broken_json_counted_and_stream_continues(self):
        good = json.dumps(cve_doc("CVE-2025-0005", desc="ok"))
        recs, stats = self.extract({
            "cvelistV5-main/cves/2025/0xxx/CVE-2025-0005.json": good,
            "cvelistV5-main/cves/2025/0xxx/CVE-2025-0006.json": "{not json",
        })
        self.assertEqual(len(recs), 1)
        self.assertEqual(stats.rejected["parse_error"], 1)

    def test_missing_cve_id_rejected(self):
        doc = cve_doc("CVE-2025-0007", desc="d")
        del doc["cveMetadata"]["cveId"]
        recs, stats = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0007.json": json.dumps(doc)})
        self.assertEqual(recs, [])
        self.assertEqual(stats.rejected_total(), 1)

    def test_no_text_record_kept_but_excluded_from_index(self):
        # RESERVED-style record: no description, no title -> F1 keeps it with
        # excluded_from_index (production does NOT inject pilot fallback text)
        doc = cve_doc("CVE-2025-0008", state="RESERVED")
        recs, stats = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0008.json": json.dumps(doc)})
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0]["excluded_from_index"])
        self.assertEqual(recs[0]["title"], "CVE-2025-0008")
        self.assertEqual(recs[0]["cve_state"], "RESERVED")
        self.assertEqual(stats.anomalies["no_embeddable_text"], 1)

    def test_non_en_description_not_used_but_other_lang_falls_back(self):
        doc = cve_doc("CVE-2025-0009", desc="Beschreibung auf Deutsch.", lang="de")
        recs, _ = self.extract(
            {"cvelistV5-main/cves/2025/0xxx/CVE-2025-0009.json": json.dumps(doc)})
        # EN-first policy; only description available -> carried (pilot rule)
        self.assertIn("Beschreibung", recs[0]["text_fields"][0])

    def test_excluded_source_refused(self):
        p = os.path.join(self.tmp, "cvejson.json")
        build_zip(p, {"a.json": "{}"})
        with self.assertRaises(ex.ExcludedSourceError):
            list(ex.iter_cve_records(p, ex.ExtractStats("x")))

    def test_years_filter(self):
        members = {
            "cvelistV5-main/cves/1999/0xxx/CVE-1999-0001.json":
                json.dumps(cve_doc("CVE-1999-0001", desc="a")),
            "cvelistV5-main/cves/2025/0xxx/CVE-2025-0010.json":
                json.dumps(cve_doc("CVE-2025-0010", desc="b")),
        }
        recs, stats = self.extract(members, years={"1999"})
        self.assertEqual([r["id"] for r in recs], ["CVE-1999-0001"])
        self.assertEqual(stats.seen, 1)


class EdbExtractorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e1-edb-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.zip = os.path.join(self.tmp, "exploitdb-main.zip")

    def extract(self, members, **kw):
        build_zip(self.zip, members)
        stats = ex.ExtractStats("exploitdb")
        recs = list(ex.iter_edb_records(self.zip, stats, **kw))
        return recs, stats

    def base_members(self, rows, poc_files=None):
        members = {"exploitdb-main/files_exploits.csv": edb_csv(rows)}
        for name, body in (poc_files or {}).items():
            members["exploitdb-main/" + name] = body
        return members

    def test_row_maps_fields_and_codes_split(self):
        rows = [{"id": "16929", "file": "exploits/aix/dos/16929.rb",
                 "description": "AIX Calendar Manager - Buffer Overflow",
                 "date_published": "2009-10-01", "author": "x", "type": "dos",
                 "platform": "aix", "verified": "1",
                 "codes": "CVE-2009-3699;OSVDB-58726", "tags": "metasploit",
                 "date_updated": "2009-10-02"}]
        recs, stats = self.extract(self.base_members(rows))
        r = recs[0]
        self.assertEqual(r["id"], "edb-16929")
        self.assertEqual(r["kind"], "exploit")
        self.assertEqual(r["title"], "AIX Calendar Manager - Buffer Overflow")
        self.assertEqual(r["cve_refs"], ["CVE-2009-3699"])
        self.assertEqual(r["other_codes"], ["OSVDB-58726"])
        self.assertEqual(r["platform"], "aix")
        self.assertEqual(r["type"], "dos")
        self.assertTrue(r["exploit_verified"])
        self.assertEqual(r["confidence"], "verified")  # design 4.1
        self.assertEqual(r["text_fields"],
                         ["AIX Calendar Manager - Buffer Overflow",
                          "tags: metasploit"])
        self.assertEqual(r["source_path"], "exploits/aix/dos/16929.rb")
        self.assertEqual(r["dates"], {"published": "2009-10-01",
                                      "updated": "2009-10-02"})
        self.assertEqual(stats.emitted, 1)

    def test_unverified_row_confidence_documented(self):
        rows = [{"id": "1", "file": "exploits/x.py", "description": "d",
                 "verified": "0"}]
        recs, _ = self.extract(self.base_members(rows))
        self.assertEqual(recs[0]["confidence"], "documented")
        self.assertFalse(recs[0]["exploit_verified"])

    def test_duplicate_id_first_wins_counted(self):
        rows = [
            {"id": "100", "file": "exploits/a.py", "description": "first",
             "codes": "CVE-2020-1"},
            {"id": "100", "file": "exploits/b.py", "description": "second"},
        ]
        recs, stats = self.extract(self.base_members(rows))
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0]["title"], "first")
        self.assertEqual(stats.seen, 2)
        self.assertEqual(stats.extras["rows_dropped_duplicate_id"], 1)

    def test_aliases_scanned_for_cve_tokens_counted_separately(self):
        rows = [{"id": "200", "file": "exploits/a.py", "description": "d",
                 "codes": "OSVDB-1", "aliases": "CVE-2011-4885 altname"}]
        recs, stats = self.extract(self.base_members(rows))
        self.assertEqual(recs[0]["cve_refs"], ["CVE-2011-4885"])
        self.assertEqual(recs[0]["other_codes"], ["OSVDB-1"])
        self.assertEqual(stats.extras["cve_tokens_from_aliases"], 1)

    def test_poc_body_only_on_demand_and_capped(self):
        rows = [{"id": "300", "file": "exploits/big.py", "description": "d"}]
        members = self.base_members(rows, {"exploits/big.py": "X" * 9000})
        recs, _ = self.extract(members)
        self.assertNotIn("poc_body", recs[0])
        recs, stats = self.extract(members, read_poc=True)
        self.assertEqual(len(recs[0]["poc_body"]), 8192)
        self.assertEqual(stats.extras["poc_bodies_read"], 1)

    def test_poc_cap_configurable_and_missing_file_counted(self):
        rows = [{"id": "301", "file": "exploits/missing.py",
                 "description": "d"}]
        recs, stats = self.extract(self.base_members(rows), read_poc=True)
        self.assertNotIn("poc_body", recs[0])
        self.assertEqual(stats.anomalies["poc_read_error"], 1)

    def test_shellcodes_csv_never_exported(self):
        rows = [{"id": "400", "file": "exploits/a.py", "description": "d"}]
        members = self.base_members(rows)
        members["exploitdb-main/files_shellcodes.csv"] = edb_csv(
            [{"id": "999", "file": "shellcodes/x.asm", "description": "sh"}])
        recs, stats = self.extract(members)
        self.assertEqual([r["id"] for r in recs], ["edb-400"])
        self.assertTrue(stats.extras["shellcodes_csv_present"])
        self.assertFalse(stats.extras["shellcodes_exported"])

    def test_bad_row_counted_stream_continues(self):
        members = {"exploitdb-main/files_exploits.csv":
                   "id,file,description,date_published,author,type,platform,"
                   "port,date_added,date_updated,verified,codes,tags,aliases,"
                   "screenshot_url,application_url,source_url\n"
                   "notanumber,e.py,bad,,,,,,0,,,,,,,,\n"
                   "500,e.py,good,,,,,,1,,,,,,,,\n"}
        recs, stats = self.extract(members)
        self.assertEqual([r["id"] for r in recs], ["edb-500"])
        self.assertEqual(stats.rejected_total(), 1)

    def test_excluded_source_refused(self):
        p = os.path.join(self.tmp, "cvejson.json")
        build_zip(p, {"files_exploits.csv": "id\n1\n"})
        with self.assertRaises(ex.ExcludedSourceError):
            list(ex.iter_edb_records(p, ex.ExtractStats("x")))


class CweExtractorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e1-cwe-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.zip = os.path.join(self.tmp, "cwec_latest.xml.zip")

    def extract(self, xml_text, **kw):
        build_zip(self.zip, {"cwec_v4.20.xml": xml_text})
        stats = ex.ExtractStats("cwec")
        recs = list(ex.iter_cwe_records(self.zip, stats, **kw))
        return recs, stats

    def test_weakness_and_category_records(self):
        recs, stats = self.extract(CWE_XML_TMPL)
        by_id = {r["id"]: r for r in recs}
        self.assertEqual(set(by_id), {"cwe-79", "cwe-89", "cwe-1"})
        w79 = by_id["cwe-79"]
        self.assertEqual(w79["kind"], "cwe")
        self.assertEqual(w79["title"], "Cross-site Scripting")
        self.assertIn("The product does not neutralize", w79["text_fields"][0])
        self.assertIn("There are three main kinds of XSS.", w79["text_fields"])
        self.assertIn("Attackers can read session data.", w79["text_fields"])
        self.assertTrue(any("reflected" in t for t in w79["text_fields"]))
        self.assertEqual(w79["related_cwe_ids"], ["cwe-74"])
        self.assertEqual(w79["abstraction"], "Base")
        self.assertEqual(w79["status"], "Draft")
        self.assertFalse(w79["excluded_from_index"])
        # production rule: cwe records carry NO cwe_ids (design 4.1: field is
        # for cve/exploit kinds; pilot's self-reference is not carried)
        self.assertNotIn("cwe_ids", w79)
        cat = by_id["cwe-1"]
        self.assertEqual(cat["kind"], "cwe_category")
        self.assertEqual(cat["text_fields"], [])       # reference-only
        self.assertTrue(cat["excluded_from_index"])    # F1 law, not rejection
        self.assertEqual(stats.extras["weaknesses"], 2)
        self.assertEqual(stats.extras["categories"], 1)

    def test_demo_body_capped(self):
        xml = CWE_XML_TMPL.replace(
            "<Body_Text>&lt;script&gt;alert(1)&lt;/script&gt; is reflected."
            "</Body_Text>",
            "<Body_Text>" + "y" * 5000 + "</Body_Text>")
        recs, _ = self.extract(xml)
        w79 = [r for r in recs if r["id"] == "cwe-79"][0]
        self.assertTrue(any(len(t) <= 2000 and "yyyy" in t
                            for t in w79["text_fields"]))

    def test_no_namespace_variant_supported(self):
        xml = CWE_XML_TMPL.replace(' xmlns="http://cwe.mitre.org/cwe-7"', "")
        recs, stats = self.extract(xml)
        self.assertEqual(stats.extras["weaknesses"], 2)
        self.assertEqual(len(recs), 3)

    def test_broken_xml_raises_structural_error(self):
        with self.assertRaises(ex.ExtractorError):
            self.extract("<Weakness_Catalog><Weaknesses>")

    def test_excluded_source_refused(self):
        p = os.path.join(self.tmp, "cvejson.json")
        build_zip(p, {"cwec_v4.20.xml": CWE_XML_TMPL})
        with self.assertRaises(ex.ExcludedSourceError):
            list(ex.iter_cwe_records(p, ex.ExtractStats("x")))


class Top10ExtractorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e1-t10-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.zip = os.path.join(self.tmp, "Top10-master.zip")

    def extract(self, members, **kw):
        build_zip(self.zip, members)
        stats = ex.ExtractStats("top10")
        recs = list(ex.iter_top10_records(self.zip, stats, **kw))
        return recs, stats

    def test_en_only_rule_and_id_format(self):
        members = {
            "Top10-master/2021/docs/en/A01_2021-Broken_Access_Control.md":
                "# A01:2021 - Broken Access Control\n\nBody text.\n",
            "Top10-master/2021/docs/fr/A01.md": "# French\n",
            "Top10-master/2017/en/0xa1-injection.md": "# A1 Injection\n",
            "Top10-master/2021/Data/CWE-Guidance.md": "# guidance\n",
            "Top10-master/README.md": "# readme\n",
            "Top10-master/2021/docs/en/assets/pic.md": "# asset\n",
        }
        recs, stats = self.extract(members)
        ids = sorted(r["id"] for r in recs)
        self.assertEqual(ids, ["owasp-2017-0xa1-injection",
                               "owasp-2021-A01_2021-Broken_Access_Control"])
        for r in recs:
            self.assertEqual(rs.validate_record(r), [])
            self.assertEqual(r["kind"], "owasp_doc")
        a01 = [r for r in recs if "A01" in r["id"]][0]
        self.assertEqual(a01["title"], "A01:2021 - Broken Access Control")
        self.assertEqual(a01["edition"], "2021")
        self.assertIn("Body text.", a01["text_fields"][0])
        self.assertEqual(a01["source_path"],
                         "2021/docs/en/A01_2021-Broken_Access_Control.md")
        self.assertEqual(stats.seen, 2)

    def test_slugify_makes_f1_valid_ids(self):
        members = {
            "Top10-master/2021/docs/en/A10 (SSRF) final.md": "# A10 SSRF\n",
            "Top10-master/2025/docs/en/.hidden.md": "# hidden\n",
        }
        recs, stats = self.extract(members)
        for r in recs:
            self.assertEqual(rs.validate_record(r), [], r["id"])
        ids = {r["id"] for r in recs}
        self.assertIn("owasp-2021-A10-SSRF-final", ids)

    def test_title_falls_back_to_slug_and_image_markup_stripped(self):
        members = {
            "Top10-master/2021/docs/en/A03_2021-Injection.md":
                "# A03:2021 - Injection   ![icon](assets/i.png){: x}\n\nT\n",
            "Top10-master/2021/docs/en/noheading.md": "plain body\n",
        }
        recs, _ = self.extract(members)
        by_id = {r["id"]: r for r in recs}
        self.assertEqual(by_id["owasp-2021-A03_2021-Injection"]["title"],
                         "A03:2021 - Injection")
        self.assertEqual(by_id["owasp-2021-noheading"]["title"],
                         "owasp-2021-noheading")

    def test_empty_doc_excluded_from_index_not_rejected(self):
        members = {"Top10-master/2021/docs/en/empty.md": "   \n"}
        recs, stats = self.extract(members)
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0]["excluded_from_index"])
        self.assertEqual(stats.anomalies["no_embeddable_text"], 1)

    def test_excluded_source_refused(self):
        p = os.path.join(self.tmp, "cvejson.json")
        build_zip(p, {"Top10-master/2021/docs/en/a.md": "# a"})
        with self.assertRaises(ex.ExcludedSourceError):
            list(ex.iter_top10_records(p, ex.ExtractStats("x")))


@unittest.skipUnless(HAS_RAW, "raw vuln-db archives absent")
class RealArchiveReconciliationTest(unittest.TestCase):
    """Count reconciliation vs artifacts/vulndb-inventory.json (EXACT for
    cvelistV5 year-1999 bucket / cwec / exploitdb CSV; Top10 EN MEASURED).
    Streams only - never loads a whole archive."""

    def test_cve_year_1999_bucket_scale_smoke(self):
        stats = ex.ExtractStats("cvelistV5")
        n = 0
        first = None
        for rec in ex.iter_cve_records(
                os.path.join(RAW_DIR, "cvelistV5-main.zip"), stats,
                years={"1999"}):
            n += 1
            if first is None:
                first = rec
            self.assertEqual(rec["kind"], "cve")
        # frozen-drop fact: inventory/pilot manifest stratification_detail
        self.assertEqual(stats.seen, 1579)
        self.assertEqual(n, stats.emitted)
        self.assertEqual(stats.emitted + stats.rejected_total(), 1579)
        self.assertEqual(first["id"], "CVE-1999-0001")

    def test_cwec_counts_exact(self):
        stats = ex.ExtractStats("cwec")
        kinds = {"cwe": 0, "cwe_category": 0}
        for rec in ex.iter_cwe_records(
                os.path.join(RAW_DIR, "cwec_latest.xml.zip"), stats):
            kinds[rec["kind"]] += 1
        self.assertEqual(kinds["cwe"], 969)
        self.assertEqual(kinds["cwe_category"], 422)
        self.assertEqual(stats.emitted, 1391)
        self.assertEqual(stats.rejected_total(), 0)

    def test_edb_csv_counts_exact(self):
        stats = ex.ExtractStats("exploitdb")
        n = 0
        for _ in ex.iter_edb_records(
                os.path.join(RAW_DIR, "exploitdb-main.zip"), stats):
            n += 1
        self.assertEqual(stats.seen, 47170)          # inventory exact
        self.assertEqual(stats.extras["rows_dropped_duplicate_id"], 472)
        self.assertEqual(n, 46698)                    # pilot manifest fact
        self.assertTrue(stats.extras["shellcodes_csv_present"])
        self.assertFalse(stats.extras["shellcodes_exported"])

    def test_top10_en_measured(self):
        stats = ex.ExtractStats("top10")
        editions = {}
        for rec in ex.iter_top10_records(
                os.path.join(RAW_DIR, "Top10-master.zip"), stats):
            editions[rec["edition"]] = editions.get(rec["edition"], 0) + 1
            self.assertEqual(rs.validate_record(rec), [])
        # MEASURED rule: <edition>/(docs/)?en/*.md -> 2017:27 2021:18 2025:16
        self.assertEqual(editions, {"2017": 27, "2021": 18, "2025": 16})
        self.assertEqual(stats.emitted, 61)
        self.assertEqual(stats.rejected_total(), 0)


if __name__ == "__main__":
    unittest.main()
