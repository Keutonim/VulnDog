"""Tests for the P1 formalization of vuln_watchdog.redaction_adapter (F4).

New F4 behaviors on top of the P0 adapter (which stays API-compatible):
- mask_url: query VALUES -> length-only mask (`sid=<len-24>`, design 5.0),
  param NAMES survive; opaque path segments -> length-only mask; ordinary
  words and CVE/CWE exact-id pins survive; URL userinfo credentials masked;
  fragment dropped; host+port preserved (SEC-08: host is event metadata);
- header law (C-1 / SEC-12): find_forbidden_fields flags any header-value-
  carrying key; redact_event DROPS (fail-closed) events with forbidden
  keys or non-scalar values (dict/list/bytes smuggling guard);
- body pipeline: SEC-06 pre-truncate 8 KB -> upstream sanitize_snapshot
  (storage-line drop + redact) -> upstream scrub (partial-JWT kill) ->
  entropy scrub -> 4,000-char persist cap;
- P0 compatibility: redact_text/entropy_scrub/constants unchanged; custom
  redactor injection still replaces the string pass.

All secrets in this file are SYNTHETIC test vectors (design 6 list).
"""
import unittest

from vulndog.engine import event_schema as es
from vulndog.engine import redaction_adapter as ra

OPAQUE = "8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh"          # 30 chars, 3-class
OPAQUE_Q = "a8Xk29LmPq47ZwTvB3cR6yHn"             # 24 chars query value


class MaskUrlTest(unittest.TestCase):
    def test_query_values_length_only_names_survive(self):
        out = ra.mask_url(f"https://t.local/s?q=shoes&sid={OPAQUE_Q}")
        self.assertEqual(out, "https://t.local/s?q=<len-5>&sid=<len-24>")
        self.assertNotIn(OPAQUE_Q, out)

    def test_query_value_content_never_survives(self):
        out = ra.mask_url("https://t.local/s?token=xK9mP2qL7vR4tW8yB3nF6jH1z")
        self.assertNotIn("xK9mP2qL7vR4tW8yB3nF6jH1z", out)
        self.assertIn("token=<len-", out)

    def test_blank_and_valueless_params(self):
        self.assertEqual(ra.mask_url("https://t.local/s?debug"),
                         "https://t.local/s?debug")
        self.assertEqual(ra.mask_url("https://t.local/s?debug="),
                         "https://t.local/s?debug=<len-0>")

    def test_duplicate_param_order_preserved(self):
        out = ra.mask_url("https://t.local/s?a=1&a=22&b=333")
        self.assertEqual(out, "https://t.local/s?a=<len-1>&a=<len-2>&b=<len-3>")

    def test_opaque_path_segment_length_masked(self):
        out = ra.mask_url(f"https://t.local/account/reset-password/{OPAQUE}")
        self.assertNotIn(OPAQUE, out)
        self.assertIn(f"<len-{len(OPAQUE)}>", out)
        self.assertIn("/account/reset-password/", out)

    def test_embedded_opaque_run_in_segment_scrubbed(self):
        out = ra.mask_url(f"https://t.local/reset-{OPAQUE}/done")
        self.assertNotIn(OPAQUE, out)

    def test_ordinary_path_words_survive(self):
        url = "https://t.local/product/wireless-headphones/reviews"
        self.assertEqual(ra.mask_url(url), url)

    def test_vuln_id_pins_survive_in_path(self):
        # exact-id pin signal (design 5.3 item 5) must never be eaten
        for url in ("https://t.local/advisory/CVE-2024-50001",
                    "https://t.local/cwe/CWE-79/detail"):
            self.assertEqual(ra.mask_url(url), url)

    def test_host_and_port_preserved(self):
        out = ra.mask_url("https://t.local:8443/p?a=secretvalue123")
        self.assertTrue(out.startswith("https://t.local:8443/p?"))

    def test_userinfo_credentials_masked(self):
        out = ra.mask_url("https://admin:Sup3rS3cretPass@t.local/p")
        self.assertNotIn("Sup3rS3cretPass", out)
        self.assertNotIn("admin:", out)
        self.assertIn("t.local/p", out)

    def test_fragment_dropped(self):
        out = ra.mask_url("https://t.local/p#access_token=abc123def456ghi")
        self.assertNotIn("access_token", out)
        self.assertFalse(out.endswith("#"))

    def test_relative_url_masked(self):
        self.assertEqual(ra.mask_url("/a/b?x=1y2"), "/a/b?x=<len-3>")

    def test_percent_encoded_long_segment_masked(self):
        seg = "aGVsbG8%20world%20opaque%20value"  # %XX-bearing, >= 16 chars
        out = ra.mask_url(f"https://t.local/d/{seg}")
        self.assertNotIn(seg, out)
        self.assertIn("<len-", out)

    def test_short_percent_encoding_survives(self):
        self.assertEqual(ra.mask_url("https://t.local/a%20b/c"),
                         "https://t.local/a%20b/c")

    def test_empty_and_pathless_urls(self):
        self.assertEqual(ra.mask_url(""), "")
        self.assertEqual(ra.mask_url("https://t.local"), "https://t.local")
        self.assertEqual(ra.mask_url("https://t.local/"), "https://t.local/")


class RedactUrlTest(unittest.TestCase):
    def test_mask_then_pattern_pass(self):
        out = ra.redact_url(f"https://t.local/cb?sid={OPAQUE_Q}&q=shoes")
        self.assertNotIn(OPAQUE_Q, out)
        self.assertIn("sid=<len-24>", out)
        self.assertIn("q=<len-5>", out)

    def test_pattern_secrets_in_url_scrubbed(self):
        # php pattern-surface (token=) killed by the upstream pattern pass
        out = ra.redact_url("https://t.local/cb?token=xK9mP2qL7vR4tW8y")
        self.assertNotIn("xK9mP2qL7vR4tW8y", out)


class ForbiddenFieldsTest(unittest.TestCase):
    def test_header_carrying_keys_flagged(self):
        for key in ("headers", "request_headers", "response_headers",
                    "Cookie", "set_cookie", "authorization", "x-api-key",
                    "user_agent", "referer", "X-Forwarded-For",
                    "My-Custom-Header", "session_id", "token", "password"):
            found = ra.find_forbidden_fields({key: "whatever"})
            self.assertEqual(found, [key], key)

    def test_schema_fields_never_flagged(self):
        event = es.make_event(tap_class="python", url="https://t.local/a",
                              decision="allowed", provenance="p",
                              hunt_id="t", ua_present=True,
                              cookie_present=True, content_type="text/html",
                              body_redacted="x", method="GET", status=200)
        self.assertEqual(ra.find_forbidden_fields(event), [])

    def test_presence_booleans_not_flagged(self):
        self.assertEqual(
            ra.find_forbidden_fields({"ua_present": True,
                                      "cookie_present": False}), [])

    def test_benchmark_extras_not_flagged(self):
        # P0 tap_sim/benchmark events carry "seq" -- must keep working
        self.assertEqual(ra.find_forbidden_fields({"seq": 1, "note": "n"}), [])


class RedactEventV2Test(unittest.TestCase):
    def event(self, **over):
        e = es.make_event(tap_class="python", hunt_id="task-1",
                          url=f"https://t.local/reset/{OPAQUE}?q=shoes&sid={OPAQUE_Q}",
                          method="GET", decision="allowed", status=200,
                          provenance="net_guarded_request",
                          content_type="text/html",
                          body_redacted="<html>ok</html>")
        e.update(over)
        return e

    def test_url_param_names_survive_values_masked(self):
        out, dropped = ra.redact_event(self.event())
        self.assertFalse(dropped)
        self.assertIn("q=<len-5>", out["url"])
        self.assertIn("sid=<len-24>", out["url"])
        self.assertNotIn(OPAQUE, out["url"])
        self.assertNotIn(OPAQUE_Q, out["url"])

    def test_forbidden_key_drops_event(self):
        for key in ("headers", "Cookie", "authorization", "x-api-key"):
            out, dropped = ra.redact_event(self.event(**{key: "value"}))
            self.assertIsNone(out, key)
            self.assertTrue(dropped, key)

    def test_dict_value_drops_event(self):
        out, dropped = ra.redact_event(self.event(meta={"a": "b"}))
        self.assertIsNone(out)
        self.assertTrue(dropped)

    def test_list_value_drops_event(self):
        out, dropped = ra.redact_event(self.event(items=["a"]))
        self.assertIsNone(out)
        self.assertTrue(dropped)

    def test_bytes_value_drops_event(self):
        out, dropped = ra.redact_event(self.event(raw=b"secret"))
        self.assertIsNone(out)
        self.assertTrue(dropped)

    def test_non_dict_drops(self):
        out, dropped = ra.redact_event("not-an-event")
        self.assertIsNone(out)
        self.assertTrue(dropped)

    def test_body_storage_lines_dropped(self):
        body = ("keep-this-line\n"
                "var x = document.cookie; // PHPSESSID=aB3dE5fG7hI9jK1l\n"
                "localStorage.setItem('k','v')\n"
                "keep-this-too")
        out, dropped = ra.redact_event(self.event(body_redacted=body))
        self.assertFalse(dropped)
        self.assertNotIn("document.cookie", out["body_redacted"])
        self.assertNotIn("localStorage", out["body_redacted"])
        self.assertIn("keep-this-line", out["body_redacted"])
        self.assertIn("keep-this-too", out["body_redacted"])

    def test_body_jwt_killed(self):
        body = "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.AbCdEf1234567890 done"
        out, _ = ra.redact_event(self.event(body_redacted=body))
        self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", out["body_redacted"])
        self.assertNotIn("AbCdEf1234567890", out["body_redacted"])

    def test_body_caps_hold(self):
        out, _ = ra.redact_event(self.event(body_redacted="z" * 20000))
        self.assertLessEqual(len(out["body_redacted"]), ra.PERSIST_CAP_CHARS)

    def test_custom_redactor_still_injected(self):
        calls = []

        def spy(text):
            calls.append(text)
            return "MASKED"
        out, dropped = ra.redact_event(self.event(body_redacted="b" * 10),
                                       redactor=spy)
        self.assertFalse(dropped)
        self.assertEqual(out["body_redacted"], "MASKED")
        self.assertEqual(out["denial_reason"] if "denial_reason" in out else None,
                         None)
        self.assertTrue(calls)

    def test_custom_redactor_exception_fail_closed(self):
        def boom(text):
            raise RuntimeError("redactor exploded")
        out, dropped = ra.redact_event(self.event(), redactor=boom)
        self.assertIsNone(out)
        self.assertTrue(dropped)

    def test_roundtrip_f3_event_stays_valid(self):
        out, dropped = ra.redact_event(self.event(hop=0, final=True,
                                                  ua_present=True,
                                                  cookie_present=False))
        self.assertFalse(dropped)
        self.assertEqual(es.validate_event(out), [])

    def test_ledger_event_extras_survive(self):
        e = es.event_from_ledger({
            "ts": "2026-10-15T10:00:00Z", "task_id": "task-9",
            "url": "https://t.local/x?a=1", "decision": "tool",
            "engine": "tool:nuclei", "count": 42, "mode": "exact",
            "note": "wave"})
        out, dropped = ra.redact_event(e)
        self.assertFalse(dropped)
        self.assertEqual(out["count"], 42)
        self.assertEqual(out["mode"], "exact")
        self.assertEqual(out["note"], "wave")


class P0ApiCompatTest(unittest.TestCase):
    def test_p0_exports_present(self):
        for name in ("redact_text", "entropy_scrub", "shannon_entropy",
                     "redact_event", "PRE_TRUNCATE_BYTES", "PERSIST_CAP_CHARS",
                     "ENTROPY_THRESHOLD", "ENTROPY_MIN_LEN"):
            self.assertTrue(hasattr(ra, name), name)
        self.assertEqual(ra.PRE_TRUNCATE_BYTES, 8192)
        self.assertEqual(ra.PERSIST_CAP_CHARS, 4000)

    def test_redact_body_exported(self):
        out = ra.redact_body("y" * 9000 + "TAIL")
        self.assertLessEqual(len(out), ra.PERSIST_CAP_CHARS)


# ---------------------------------------------------------------------------
# P2 COND-1 (SCC-01/SCC-04, security-code-review 2026-10-15): short/hex/
# hyphenated opaque-token leak closure. Probe vectors from
# artifacts/sec-code-probes/probe_01/02/07/08 pinned as regressions.
# ---------------------------------------------------------------------------

UUID_V4 = "550e8400-e29b-41d4-a716-446655440000"


class Cond1ShortOpaqueSegmentTest(unittest.TestCase):
    """COND-1(a): mixed letter+digit segments >= SEGMENT_OPACITY_FLOOR are
    length-masked REGARDLESS of entropy; calibrated must-survive controls."""

    MUST_KILL = [
        ("https://t.local/reset/8fKx2QpLm9Z", "8fKx2QpLm9Z"),
        ("https://t.local/act/Ab3dEf7h9jK2m", "Ab3dEf7h9jK2m"),
        ("https://t.local/act/aB3dE5fG7hI9jK1", "aB3dE5fG7hI9jK1"),
        ("https://t.local/s/" + UUID_V4, UUID_V4),
        ("https://t.local/d/ab%41cd1234567", "ab%41cd1234567"),
    ]

    def test_short_opaque_segments_length_masked(self):
        for url, secret in self.MUST_KILL:
            out = ra.mask_url(url)
            self.assertNotIn(secret, out, url)
            self.assertIn("<len-", out, url)

    def test_short_opaque_segments_masked_at_event_level(self):
        for url, secret in self.MUST_KILL:
            ev = {"ts": "2026-10-15T00:00:00Z", "hunt_id": "cond-1",
                  "tap_class": "python", "url": url,
                  "decision": "allowed", "provenance": "test"}
            out, dropped = ra.redact_event(ev)
            self.assertFalse(dropped, url)
            self.assertNotIn(secret, out["url"], url)

    MUST_SURVIVE = [
        "https://t.local/advisory/CVE-2024-50001",
        "https://t.local/cwe/CWE-79",
        "https://t.local/edb/edb-48263",
        "https://t.local/api/v2/users",
        "https://t.local/dl/sha256/sums",
        "https://t.local/v/mp4",
        "https://t.local/product/wireless-headphones/reviews",
        "https://t.local/a%20b/c",
        "https://t.local/blog/2024-10-15/post",
        "https://t.local/orders/12345678",
    ]

    def test_control_segments_survive(self):
        for url in self.MUST_SURVIVE:
            self.assertEqual(ra.mask_url(url), url, url)


class Cond1FlagAndParamNameTest(unittest.TestCase):
    """COND-1(b): flag-position tokens and mixed letter+digit param NAMES
    >= floor are length-masked; alpha-only / short names survive."""

    def test_flag_param_opaque_token_masked(self):
        for token in ("8fKx2QpLm9Z", "8fKx2QpLm9ZrTv4W"):
            out = ra.mask_url(f"https://t.local/activate?{token}")
            self.assertNotIn(token, out, token)
            self.assertIn(f"<len-{len(token)}>", out)

    def test_secret_as_param_name_masked(self):
        out = ra.mask_url("https://t.local/p?8fKx2QpLm9ZrTv4Wb7Ns=1")
        self.assertNotIn("8fKx2QpLm9ZrTv4Wb7Ns", out)
        self.assertIn("=<len-1>", out)

    def test_flag_and_name_controls_survive(self):
        self.assertEqual(ra.mask_url("https://t.local/s?debug"),
                         "https://t.local/s?debug")
        self.assertEqual(ra.mask_url("https://t.local/s?utf8"),
                         "https://t.local/s?utf8")
        self.assertEqual(ra.mask_url("https://t.local/s?page2=3"),
                         "https://t.local/s?page2=<len-1>")
        self.assertEqual(ra.mask_url("https://t.local/s?q=shoes&sid=x"),
                         "https://t.local/s?q=<len-5>&sid=<len-1>")


class Cond1HexAlphabetTest(unittest.TestCase):
    """COND-1(c): pure-hex runs >= 16 are opaque REGARDLESS of Shannon
    entropy (16-symbol alphabet sits just under the 3.7 threshold)."""

    def test_pure_hex_16_plus_is_opaque(self):
        for s in ("9f86d081884c7d659a2feaa0c55ad015",           # md5-shaped
                  "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",   # sha1-shaped
                  "0123456789abcdef",                           # low entropy
                  "ABCDEF0123456789ABCDEF0123456789"):          # upper hex
            self.assertTrue(ra._is_opaque(s), s)

    def test_hex_catch_rate_is_total(self):
        import random
        rng = random.Random(20261015)
        for n in (16, 24, 32, 40, 64):
            caught = sum(1 for _ in range(200)
                         if ra._is_opaque("".join(
                             rng.choice("0123456789abcdef")
                             for _ in range(n))))
            self.assertEqual(caught, 200, f"hex len {n} catch rate")

    def test_hex_token_scrubbed_in_body(self):
        out = ra.redact_text("hash 9f86d081884c7d659a2feaa0c55ad015 done")
        self.assertNotIn("9f86d081884c7d659a2feaa0c55ad015", out)

    def test_short_hex_below_16_survives(self):
        self.assertEqual(ra.entropy_scrub("deadbeef cafe123 abc"),
                         "deadbeef cafe123 abc")


class Cond1SeparatorTolerantTest(unittest.TestCase):
    """COND-1(d): entropy test is separator-tolerant -- '-'/'/'/'.' are
    stripped from candidate spans, the test runs on the CONCATENATED form,
    and the WHOLE original span is replaced."""

    def test_hyphen_split_token_fully_scrubbed(self):
        out = ra.entropy_scrub("token: 8fKx2QpLm9ZrTv4-b7NsYc1Jd6GhA end")
        self.assertNotIn("8fKx2QpLm9ZrTv4", out)
        self.assertNotIn("b7NsYc1Jd6GhA", out)

    def test_uuid_scrubbed_in_body(self):
        out = ra.entropy_scrub(f"session {UUID_V4} active")
        self.assertNotIn(UUID_V4, out)
        self.assertNotIn("446655440000", out)

    def test_base64_slash_fragments_scrubbed(self):
        out = ra.entropy_scrub("blob QUJDREVGR0hJSktMTU5PUFFSU1RV/oldm5c2Vy done")
        self.assertNotIn("QUJDREVGR0hJSktMTU5PUFFSU1RV", out)
        self.assertNotIn("oldm5c2Vy", out)

    def test_vuln_id_pins_survive_concatenation_rule(self):
        # CVE-2024-50001 concatenated = 12 chars, under the 16 floor
        text = "see CVE-2024-50001 and CWE-79 plus CVE-2017-5638 in refs"
        self.assertEqual(ra.entropy_scrub(text), text)

    def test_natural_dotted_and_hyphenated_words_survive(self):
        text = "the quick-brown fox.txt jumps over 1.2.3 lazy dogs"
        self.assertEqual(ra.entropy_scrub(text), text)

    def test_pathlike_text_survives(self):
        text = "upstream/src/runtime/net_gate.py module"
        self.assertEqual(ra.entropy_scrub(text), text)


class Cond1UrlChannelStructureTest(unittest.TestCase):
    """URL channel law: separator concatenation must NEVER eat URL
    structure or exact-id pins (design 5.3.5 pin signal; review lens-1
    'param names survive'). '/' is structural in URLs: the url-channel
    entropy pass does not merge across it; pin-bearing spans fall back to
    per-run scrubbing in the body channel."""

    def test_redact_url_preserves_cve_pin(self):
        u = "https://t.local/advisory/CVE-2024-50001"
        self.assertEqual(ra.redact_url(u), u)

    def test_redact_event_url_preserves_cve_pin(self):
        ev = {"ts": "2026-10-15T00:00:00Z", "hunt_id": "pin-1",
              "tap_class": "python",
              "url": "https://t.local/advisory/CVE-2024-50001",
              "decision": "allowed", "provenance": "test"}
        out, dropped = ra.redact_event(ev)
        self.assertFalse(dropped)
        self.assertEqual(out["url"], "https://t.local/advisory/CVE-2024-50001")

    def test_redact_url_preserves_ordinary_mixed_case_path(self):
        u = "https://t.local/Product/Details/View"
        self.assertEqual(ra.redact_url(u), u)

    def test_cve_pin_inside_body_url_survives(self):
        text = "see https://t.local/advisory/CVE-2024-50001 for details"
        out = ra.redact_text(text)
        self.assertIn("CVE-2024-50001", out)

    def test_pin_fallback_still_scrubs_token_runs_in_same_span(self):
        text = "ref CVE-2024-50001/8fKx2QpLm9ZrTv4Wb7Ns tail"
        out = ra.entropy_scrub(text)
        self.assertIn("CVE-2024-50001", out)
        self.assertNotIn("8fKx2QpLm9ZrTv4Wb7Ns", out)

    def test_secret_hostname_scrubbed_in_url(self):
        out = ra.redact_url("https://xK9mP2qL7vR4tW8yB3nF6jH1z.tld/p")
        self.assertNotIn("xK9mP2qL7vR4tW8yB3nF6jH1z", out)

    def test_hyphen_split_token_in_hostname_scrubbed(self):
        out = ra.redact_url("https://xK9mP2qL-7vR4tW8yB3.tld/p")
        self.assertNotIn("xK9mP2qL-7vR4tW8yB3", out)
        self.assertNotIn("xK9mP2qL", out)


# ---------------------------------------------------------------------------
# P2 COND-2 (SCC-02): case-insensitive url/body_redacted structural handling.
# ---------------------------------------------------------------------------


class Cond2KeyCaseTest(unittest.TestCase):
    def test_uppercase_url_key_gets_structural_mask(self):
        out, dropped = ra.redact_event(
            {"URL": "https://t.local/p?sid=8fKx2QpLm9Z"})
        self.assertFalse(dropped)
        self.assertNotIn("8fKx2QpLm9Z", out["URL"])
        self.assertIn("sid=<len-11>", out["URL"])

    def test_mixed_case_url_key_masked(self):
        out, dropped = ra.redact_event(
            {"Url": "https://t.local/p?sid=8fKx2QpLm9Z"})
        self.assertFalse(dropped)
        self.assertIn("sid=<len-11>", out["Url"])

    def test_mixed_case_body_redacted_key_capped_and_redacted(self):
        out, dropped = ra.redact_event(
            {"Body_Redacted": "PHPSESSID=aB3dE5fG7hI9jK1lM3nO5p "
                              + "y" * 10000})
        self.assertFalse(dropped)
        self.assertNotIn("aB3dE5fG7hI9jK1lM3nO5p", out["Body_Redacted"])
        self.assertLessEqual(len(out["Body_Redacted"]), ra.PERSIST_CAP_CHARS)

    def test_original_key_case_preserved_in_output(self):
        out, _ = ra.redact_event({"URL": "https://t.local/a"})
        self.assertIn("URL", out)
        self.assertNotIn("url", out)


# ---------------------------------------------------------------------------
# P2 COND-3 (SCC-03): per-field length caps on EVERY string field.
# ---------------------------------------------------------------------------


class Cond3FieldCapsTest(unittest.TestCase):
    def test_note_capped_at_2000(self):
        # non-hex filler: the CAP (not the hex rule) is the active mechanism
        out, dropped = ra.redact_event({"note": "N" * 2_000_000})
        self.assertFalse(dropped)
        self.assertEqual(len(out["note"]), 2000)

    def test_per_field_caps_applied(self):
        out, _ = ra.redact_event({
            "url": "https://t.local/" + "u" * 10000,
            "denial_reason": "R" * 200_000,
            "method": "G" * 100,
            "hunt_id": "h" * 500,
            "provenance": "p" * 5000,
            "content_type": "text" + "H" * 5000,
            "ts": "t" * 5000,
        })
        self.assertLessEqual(len(out["url"]), 4096)
        self.assertLessEqual(len(out["denial_reason"]), 2000)
        self.assertLessEqual(len(out["method"]), 16)
        self.assertLessEqual(len(out["hunt_id"]), 128)
        self.assertLessEqual(len(out["provenance"]), 2000)
        self.assertLessEqual(len(out["content_type"]), 2000)
        self.assertLessEqual(len(out["ts"]), 2000)

    def test_unknown_string_field_gets_default_cap(self):
        out, _ = ra.redact_event({"rand_extra": "z" * 50_000})
        self.assertLessEqual(len(out["rand_extra"]), 2000)

    def test_cap_wall_time_bounded(self):
        import time
        t0 = time.perf_counter()
        ra.redact_event({"note": "A" * 2_000_000,
                         "denial_reason": "B" * 200_000})
        dt = time.perf_counter() - t0
        self.assertLess(dt, 0.25, f"redaction wall {dt:.3f}s exceeds bound")

    def test_caps_do_not_break_short_fields(self):
        ev = {"ts": "2026-10-15T00:00:00Z", "hunt_id": "t",
              "tap_class": "python", "url": "https://t.local/a?q=1",
              "decision": "allowed", "provenance": "p", "method": "GET"}
        out, dropped = ra.redact_event(ev)
        self.assertFalse(dropped)
        self.assertEqual(out["url"], "https://t.local/a?q=<len-1>")
        self.assertEqual(out["method"], "GET")


if __name__ == "__main__":
    unittest.main()
