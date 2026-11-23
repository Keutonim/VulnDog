"""Tests for vuln_watchdog.record_schema (F1; design 4.1/4.2, brief P1 item 1).

Contract under test:
- required: id / kind / title / text_fields; evidence {src, note} required;
- kinds: cve / exploit / cwe / cwe_category / owasp_doc; unknown -> reject;
- confidence enum {documented, verified, inferred}; default "documented";
  anything else -> reject;
- reject: missing id, id not matching its kind's canonical format;
- EMPTY text_fields -> record KEPT + excluded_from_index=True (NOT rejection,
  design 4.1 supersedes plan F1 DoD item 2 per QA-1 m-3);
- cwe_ids normalized to `cwe-<n>`; invalid entries dropped + anomaly;
- cvss partial allowed ({score?}/{severity?}/{} -> kept; null allowed);
- cvejson.json excluded BY RULE (D6) via source_path/evidence.src;
- HTML entities flagged (html_entities=True) for E3 cleanup, NOT rejected;
- unknown fields pass through (forward compat for A1-A4 extractors);
- normalize_record returns (record|None, errors, anomalies) -- errors reject,
  anomalies are counted data-quality notes (R8).
"""
import unittest

from vulndog.engine import record_schema as rs


def rec(**over):
    r = {
        "id": "CVE-2024-50001",
        "kind": "cve",
        "title": "Product X allows SQL injection via the search parameter",
        "text_fields": ["Product X allows SQL injection via the search parameter."],
        "cwe_ids": ["CWE-89"],
        "cvss": {"score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N"},
        "source_path": "cves/2024/50xxx/CVE-2024-50001.json",
        "corpus_version": "pilot-2026-10-15",
        "evidence": {"src": "cvelistV5-main.zip", "note": "cna container"},
        "confidence": "documented",
    }
    r.update(over)
    return r


class ValidRecordTest(unittest.TestCase):
    def test_valid_cve_record_no_errors(self):
        out, errors, anomalies = rs.normalize_record(rec())
        self.assertEqual(errors, [])
        self.assertIsNotNone(out)
        self.assertEqual(out["id"], "CVE-2024-50001")
        self.assertFalse(out["excluded_from_index"])

    def test_validate_record_returns_empty_errors(self):
        self.assertEqual(rs.validate_record(rec()), [])

    def test_confidence_defaults_to_documented(self):
        r = rec()
        del r["confidence"]
        out, errors, _ = rs.normalize_record(r)
        self.assertEqual(errors, [])
        self.assertEqual(out["confidence"], "documented")

    def test_confidence_verified_and_inferred_accepted(self):
        for c in ("verified", "inferred"):
            out, errors, _ = rs.normalize_record(rec(confidence=c))
            self.assertEqual(errors, [], c)
            self.assertEqual(out["confidence"], c)

    def test_all_five_kinds_accepted(self):
        cases = [
            ("cve", "CVE-2024-50001"),
            ("exploit", "edb-41234"),
            ("cwe", "cwe-79"),
            ("cwe_category", "cwe-1000"),
            ("owasp_doc", "owasp-2021-a03-injection"),
        ]
        for kind, rid in cases:
            out, errors, _ = rs.normalize_record(rec(kind=kind, id=rid))
            self.assertEqual(errors, [], f"{kind}: {errors}")
            self.assertEqual(out["kind"], kind)

    def test_unknown_fields_pass_through(self):
        out, errors, _ = rs.normalize_record(rec(custom_flag=42))
        self.assertEqual(errors, [])
        self.assertEqual(out["custom_flag"], 42)


class RejectionTest(unittest.TestCase):
    def codes(self, r):
        _, errors, _ = rs.normalize_record(r)
        return errors

    def test_missing_id_rejected(self):
        r = rec()
        del r["id"]
        self.assertIn("missing:id", self.codes(r))

    def test_empty_id_rejected(self):
        self.assertIn("missing:id", self.codes(rec(id="  ")))

    def test_unknown_kind_rejected(self):
        errs = self.codes(rec(kind="malware"))
        self.assertTrue(any(e.startswith("unknown_kind:") for e in errs), errs)

    def test_missing_kind_rejected(self):
        r = rec()
        del r["kind"]
        self.assertIn("missing:kind", self.codes(r))

    def test_bad_confidence_rejected(self):
        errs = self.codes(rec(confidence="guessed"))
        self.assertTrue(any(e.startswith("bad_confidence:") for e in errs), errs)

    def test_missing_title_rejected(self):
        r = rec()
        del r["title"]
        self.assertIn("missing:title", self.codes(r))

    def test_empty_title_rejected(self):
        self.assertIn("missing:title", self.codes(rec(title="   ")))

    def test_missing_text_fields_rejected(self):
        r = rec()
        del r["text_fields"]
        self.assertIn("missing:text_fields", self.codes(r))

    def test_text_fields_wrong_type_rejected(self):
        self.assertIn("type:text_fields", self.codes(rec(text_fields="one string")))

    def test_text_fields_non_string_member_rejected(self):
        self.assertIn("type:text_fields", self.codes(rec(text_fields=["ok", 42])))

    def test_missing_evidence_rejected(self):
        r = rec()
        del r["evidence"]
        self.assertIn("missing:evidence", self.codes(r))

    def test_evidence_missing_src_rejected(self):
        self.assertIn("missing:evidence.src", self.codes(rec(evidence={"note": "x"})))

    def test_evidence_src_empty_rejected(self):
        self.assertIn("missing:evidence.src", self.codes(rec(evidence={"src": "", "note": "x"})))

    def test_evidence_note_defaults_to_empty_string(self):
        out, errors, _ = rs.normalize_record(rec(evidence={"src": "cvelistV5-main.zip"}))
        self.assertEqual(errors, [])
        self.assertEqual(out["evidence"], {"src": "cvelistV5-main.zip", "note": ""})

    def test_id_format_must_match_kind(self):
        self.assertTrue(any(e.startswith("id_format:")
                            for e in self.codes(rec(kind="cve", id="edb-5"))))
        self.assertTrue(any(e.startswith("id_format:")
                            for e in self.codes(rec(kind="exploit", id="CVE-2024-1"))))
        self.assertTrue(any(e.startswith("id_format:")
                            for e in self.codes(rec(kind="cwe", id="cwe-abc"))))
        self.assertTrue(any(e.startswith("id_format:")
                            for e in self.codes(rec(kind="owasp_doc", id="owasp-doc"))))

    def test_non_dict_record_rejected(self):
        out, errors, _ = rs.normalize_record("not a dict")
        self.assertIsNone(out)
        self.assertIn("type:record", errors)

    def test_cvejson_source_excluded_by_rule(self):
        # D6: the invalid source can never enter the corpus (design 4.2)
        errs = self.codes(rec(source_path="cvejson.json"))
        self.assertTrue(any(e.startswith("excluded_source:") for e in errs), errs)

    def test_cvejson_evidence_src_excluded_by_rule(self):
        errs = self.codes(rec(evidence={"src": "cvejson.json", "note": ""}))
        self.assertTrue(any(e.startswith("excluded_source:") for e in errs), errs)

    def test_cvejson_path_fragment_excluded(self):
        errs = self.codes(rec(source_path="archives/cvejson.JSON"))
        self.assertTrue(any(e.startswith("excluded_source:") for e in errs), errs)


class EmptyTextFieldsTest(unittest.TestCase):
    def test_empty_text_fields_kept_with_flag(self):
        out, errors, _ = rs.normalize_record(rec(kind="cwe_category",
                                                 id="cwe-1000", text_fields=[]))
        self.assertEqual(errors, [])
        self.assertIsNotNone(out)
        self.assertTrue(out["excluded_from_index"])

    def test_whitespace_only_entries_collapse_to_excluded(self):
        out, errors, anomalies = rs.normalize_record(rec(text_fields=["  ", ""]))
        self.assertEqual(errors, [])
        self.assertTrue(out["excluded_from_index"])
        self.assertTrue(any(a.startswith("empty_text_field") for a in anomalies))

    def test_non_empty_text_fields_not_excluded(self):
        out, _, _ = rs.normalize_record(rec())
        self.assertFalse(out["excluded_from_index"])


class NormalizationTest(unittest.TestCase):
    def test_cwe_ids_normalized_lowercase(self):
        out, errors, _ = rs.normalize_record(rec(cwe_ids=["CWE-79", "cwe-89"]))
        self.assertEqual(errors, [])
        self.assertEqual(out["cwe_ids"], ["cwe-79", "cwe-89"])

    def test_cwe_ids_dedupe_preserves_order(self):
        out, _, _ = rs.normalize_record(rec(cwe_ids=["CWE-79", "cwe-79", "CWE-89"]))
        self.assertEqual(out["cwe_ids"], ["cwe-79", "cwe-89"])

    def test_invalid_cwe_id_dropped_with_anomaly(self):
        out, errors, anomalies = rs.normalize_record(rec(cwe_ids=["CWE-79", "NVD-CWE-noinfo"]))
        self.assertEqual(errors, [])
        self.assertEqual(out["cwe_ids"], ["cwe-79"])
        self.assertTrue(any(a.startswith("cwe_id_dropped:") for a in anomalies), anomalies)

    def test_missing_cwe_ids_is_anomaly_not_error_for_cve(self):
        # R8: missing cweId is a KNOWN anomaly -> empty list + counter
        r = rec()
        del r["cwe_ids"]
        out, errors, anomalies = rs.normalize_record(r)
        self.assertEqual(errors, [])
        self.assertEqual(out["cwe_ids"], [])
        self.assertTrue(any(a == "missing_cwe_ids" for a in anomalies), anomalies)

    def test_lowercase_cve_id_uppercased(self):
        out, errors, _ = rs.normalize_record(rec(id="cve-2024-50001"))
        self.assertEqual(errors, [])
        self.assertEqual(out["id"], "CVE-2024-50001")

    def test_cwe_id_uppercase_normalized_lowercase(self):
        out, errors, _ = rs.normalize_record(rec(kind="cwe", id="CWE-79"))
        self.assertEqual(errors, [])
        self.assertEqual(out["id"], "cwe-79")

    def test_cvss_partial_allowed(self):
        for cvss in ({"score": 7.5}, {"severity": "HIGH"}, {"vector": "AV:N"}, {}, None):
            out, errors, _ = rs.normalize_record(rec(cvss=cvss))
            self.assertEqual(errors, [], cvss)
            self.assertIsNotNone(out)

    def test_cvss_score_out_of_range_dropped_with_anomaly(self):
        out, errors, anomalies = rs.normalize_record(rec(cvss={"score": 11.0, "severity": "X"}))
        self.assertEqual(errors, [])
        self.assertNotIn("score", out["cvss"])
        self.assertTrue(any(a.startswith("cvss_score_invalid") for a in anomalies), anomalies)

    def test_cvss_wrong_type_rejected(self):
        self.assertIn("type:cvss", rs.validate_record(rec(cvss="9.8")))

    def test_cvss_empty_dict_normalizes_to_none(self):
        out, _, _ = rs.normalize_record(rec(cvss={}))
        self.assertIsNone(out["cvss"])

    def test_title_stripped(self):
        out, _, _ = rs.normalize_record(rec(title="  padded title  "))
        self.assertEqual(out["title"], "padded title")

    def test_text_fields_stripped(self):
        out, _, _ = rs.normalize_record(rec(text_fields=["  a  ", "b"]))
        self.assertEqual(out["text_fields"], ["a", "b"])

    def test_html_entities_flagged_not_rejected(self):
        # A3 trap: entities are cleaned in E3; F1 only flags (design 4.1)
        out, errors, _ = rs.normalize_record(
            rec(text_fields=["Description with &nbsp; entity and &#39; numeric"]))
        self.assertEqual(errors, [])
        self.assertTrue(out["html_entities"])

    def test_html_entities_flag_false_when_clean(self):
        out, _, _ = rs.normalize_record(rec())
        self.assertFalse(out["html_entities"])

    def test_html_entities_detected_in_title(self):
        out, _, _ = rs.normalize_record(rec(title="Bug &amp; Co"))
        self.assertTrue(out["html_entities"])

    def test_cve_refs_normalized_uppercase_invalid_dropped(self):
        out, errors, anomalies = rs.normalize_record(
            rec(kind="exploit", id="edb-41234", cve_refs=["cve-2024-1234", "OSVDB-99"]))
        self.assertEqual(errors, [])
        self.assertEqual(out["cve_refs"], ["CVE-2024-1234"])
        self.assertTrue(any(a.startswith("cve_ref_dropped:") for a in anomalies), anomalies)

    def test_exploit_refs_validated(self):
        out, errors, anomalies = rs.normalize_record(rec(exploit_refs=["edb-5", "edb-x"]))
        self.assertEqual(errors, [])
        self.assertEqual(out["exploit_refs"], ["edb-5"])
        self.assertTrue(any(a.startswith("exploit_ref_dropped:") for a in anomalies))

    def test_related_cwe_ids_normalized(self):
        out, _, _ = rs.normalize_record(rec(kind="cwe", id="cwe-79",
                                            related_cwe_ids=["CWE-80"]))
        self.assertEqual(out["related_cwe_ids"], ["cwe-80"])

    def test_dates_wrong_type_rejected(self):
        self.assertIn("type:dates", rs.validate_record(rec(dates="2024-01-01")))

    def test_dates_non_string_value_dropped_with_anomaly(self):
        out, errors, anomalies = rs.normalize_record(rec(dates={"published": 123}))
        self.assertEqual(errors, [])
        self.assertEqual(out["dates"], {})
        self.assertTrue(any(a.startswith("dates_field_dropped:") for a in anomalies))

    def test_exploit_verified_must_be_bool(self):
        self.assertIn("type:exploit_verified",
                      rs.validate_record(rec(kind="exploit", id="edb-1",
                                             exploit_verified="yes")))

    def test_affected_non_dict_entry_dropped_with_anomaly(self):
        out, errors, anomalies = rs.normalize_record(
            rec(affected=[{"vendor": "v", "product": "p", "versions": ["1.0"]}, "junk"]))
        self.assertEqual(errors, [])
        self.assertEqual(len(out["affected"]), 1)
        self.assertTrue(any(a.startswith("affected_entry_dropped") for a in anomalies))

    def test_affected_wrong_type_rejected(self):
        self.assertIn("type:affected", rs.validate_record(rec(affected="vendor p")))

    def test_source_path_wrong_type_rejected(self):
        self.assertIn("type:source_path", rs.validate_record(rec(source_path=42)))

    def test_owasp_categories_non_string_dropped(self):
        out, errors, anomalies = rs.normalize_record(rec(owasp_categories=["A03", 7]))
        self.assertEqual(errors, [])
        self.assertEqual(out["owasp_categories"], ["A03"])
        self.assertTrue(any(a.startswith("owasp_category_dropped") for a in anomalies))

    def test_normalize_does_not_mutate_input(self):
        r = rec(cwe_ids=["CWE-79"])
        snapshot = repr(r)
        rs.normalize_record(r)
        self.assertEqual(repr(r), snapshot)


class SchemaConstantsTest(unittest.TestCase):
    def test_kind_enum_matches_design(self):
        self.assertEqual(set(rs.KINDS),
                         {"cve", "exploit", "cwe", "cwe_category", "owasp_doc"})

    def test_confidence_enum_matches_design(self):
        self.assertEqual(set(rs.CONFIDENCES), {"documented", "verified", "inferred"})

    def test_excluded_sources_contains_cvejson(self):
        self.assertIn("cvejson.json", rs.EXCLUDED_SOURCES)

    def test_validate_record_is_pure_predicate(self):
        self.assertTrue(rs.is_valid(rec()))
        self.assertFalse(rs.is_valid(rec(kind="nope")))


if __name__ == "__main__":
    unittest.main()
