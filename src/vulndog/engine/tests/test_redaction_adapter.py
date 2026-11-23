"""Tests for vuln_watchdog.redaction_adapter (design 6 / plan F4; P0 item 6).

Vector list from the brief, ALL SYNTHETIC (no real secrets anywhere):
PHPSESSID/JSESSIONID cookies, full + partial JWTs, Authorization/X-Api-Key
headers, token=/password=/api_key fields, AKIA/ghp_/sk-/AIza-class keys,
PEM blocks, reset-token-in-path, opaque query value, Bearer-without-header.

The adapter = the upstream redaction module (import-only, used as-is, C2) PLUS
the stdlib Shannon-entropy scrubber for opaque non-pattern tokens
(Security C-1/SEC-01). Fail-closed: a redaction exception DROPS the event.
"""
import unittest

from vulndog.engine import redaction_adapter as ra

# (label, text-with-secret, [secret substrings that MUST NOT survive])
VECTORS = [
    ("phpsessid-cookie",
     "Cookie: PHPSESSID=aB3dE5fG7hI9jK1lM3nO5p; path=/",
     ["aB3dE5fG7hI9jK1lM3nO5p"]),
    ("jsessionid",
     "URL rewritten with jsessionid=Qw9Er8Ty7Ui6Op5As4Df3Gh2Jk1L by container",
     ["Qw9Er8Ty7Ui6Op5As4Df3Gh2Jk1L"]),
    ("full-jwt",
     "state eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMyJ9.AbCdEf1234567890abcdefGHIJKL end",
     ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "AbCdEf1234567890abcdefGHIJKL"]),
    ("partial-jwt",
     "truncated eyJhbGciOiJIUzI1NiJ9.eyJzdWIiO in log line",
     ["eyJhbGciOiJIUzI1NiJ9"]),
    ("authorization-header",
     "Authorization: Bearer abcDEF123456789xyzWvUt",
     ["abcDEF123456789xyzWvUt"]),
    ("x-api-key-header",
     "X-Api-Key: 9a8b7c6d5e4f3a2b1c0d and more text",
     ["9a8b7c6d5e4f3a2b1c0d"]),
    ("token-field",
     "https://t.local/cb?token=xK9mP2qL7vR4tW8yB3nF6jH1z",
     ["xK9mP2qL7vR4tW8yB3nF6jH1z"]),
    ("password-field",
     "login POST password=Sup3rS3cretPass!&user=bob",
     ["Sup3rS3cretPass!"]),
    ("api-key-json",
     '{"api_key": "ak9x8W7v6U5t4S3r2Q1p0Z", "user": "bob"}',
     ["ak9x8W7v6U5t4S3r2Q1p0Z"]),
    ("aws-akia",
     "found AKIAIOSFODNN7EXAMPLE in env dump",
     ["AKIAIOSFODNN7EXAMPLE"]),
    ("github-ghp",
     "config ghp_1234567890abcdefghijklmnopqrstuvwx here",
     ["ghp_1234567890abcdefghijklmnopqrstuvwx"]),
    ("openai-sk",
     "key sk-abcDEF123456789xyzWvUt leaked",
     ["sk-abcDEF123456789xyzWvUt"]),
    ("google-aiza",
     "maps key AIzaSyB0tJ8nKcVq2WmXpL7dR4fG1hZ5eY3xU6i inline",
     ["AIzaSyB0tJ8nKcVq2WmXpL7dR4fG1hZ5eY3xU6i"]),
    ("pem-block",
     "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj\nMZEfYyjiWA4R4M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSu\n-----END PRIVATE KEY-----",
     ["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj",
      "BEGIN PRIVATE KEY"]),
    ("reset-token-in-path",
     "GET /account/reset-password/8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh HTTP/1.1",
     ["8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh"]),
    ("opaque-query-value",
     "GET /search?ref=a8Xk29LmPq47ZwTvB3cR6yHn&q=shoes HTTP/1.1",
     ["a8Xk29LmPq47ZwTvB3cR6yHn"]),
    ("bearer-without-header",
     "retry with Bearer 1a2B3c4D5e6F7g8H9i0JkL now",
     ["1a2B3c4D5e6F7g8H9i0JkL"]),
]


class VectorSuiteTest(unittest.TestCase):
    def test_every_vector_scrubbed(self):
        failures = []
        for label, text, secrets in VECTORS:
            out = ra.redact_text(text)
            for s in secrets:
                if s in out:
                    failures.append((label, s[:20]))
        self.assertEqual(failures, [], f"unscrubbed secrets: {failures}")

    def test_scrubbed_vectors_carry_marker(self):
        for label, text, _ in VECTORS:
            out = ra.redact_text(text)
            self.assertTrue("<redacted>" in out or "<jwt>" in out,
                            f"{label}: no redaction marker in output")


class EntropyScrubTest(unittest.TestCase):
    def test_high_entropy_opaque_run_scrubbed(self):
        out = ra.entropy_scrub("id=8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh done")
        self.assertNotIn("8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh", out)
        self.assertIn("<redacted>", out)

    def test_ordinary_words_survive(self):
        text = ("The product allows remote attackers to execute arbitrary "
                "code via internationalization of the authentication component")
        self.assertEqual(ra.entropy_scrub(text), text)

    def test_vuln_ids_survive(self):
        # exact-id pin signal (design 5.3 item 5) MUST NOT be eaten
        text = "matching CVE-2024-50001 and CWE-79 plus CVE-2017-5638 in refs"
        self.assertEqual(ra.entropy_scrub(text), text)

    def test_short_runs_survive(self):
        self.assertEqual(ra.entropy_scrub("abc123 def456 x9Y8z7"), "abc123 def456 x9Y8z7")

    def test_threshold_and_minlen_constants(self):
        self.assertGreaterEqual(ra.ENTROPY_THRESHOLD, 3.5)
        self.assertLessEqual(ra.ENTROPY_THRESHOLD, 4.0)
        self.assertEqual(ra.ENTROPY_MIN_LEN, 16)


class RedactEventTest(unittest.TestCase):
    def event(self, **over):
        e = {
            "ts": "2026-10-15T12:00:00", "hunt_id": "task-1", "tap_class": "python",
            "url": "https://t.local/reset/8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh?token=xK9mP2qL7vR4tW8y",
            "method": "GET", "decision": "allowed", "status": 200,
            "denial_reason": "rate Authorization: Bearer abcDEF123456789xyzWvUt",
            "ua_present": True, "cookie_present": False,
            "content_type": "text/html",
            "body_redacted": "<html>session aB3dE5fG7hI9jK1lM3nO5p</html>",
            "provenance": "net_guarded_request",
        }
        e.update(over)
        return e

    def test_all_string_fields_scrubbed(self):
        out, dropped = ra.redact_event(self.event())
        self.assertFalse(dropped)
        self.assertNotIn("8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh", out["url"])
        self.assertNotIn("xK9mP2qL7vR4tW8y", out["url"])
        self.assertNotIn("abcDEF123456789xyzWvUt", out["denial_reason"])
        self.assertNotIn("aB3dE5fG7hI9jK1lM3nO5p", out["body_redacted"])

    def test_non_string_fields_untouched(self):
        out, _ = ra.redact_event(self.event())
        self.assertEqual(out["status"], 200)
        self.assertIs(out["ua_present"], True)
        self.assertEqual(out["method"], "GET")

    def test_pre_truncate_8kb_before_redaction(self):
        body = "x" * 100 + "SECRET1 aB3dE5fG7hI9jK1lM3nO5p\n" + "y" * 19000
        out, dropped = ra.redact_event(self.event(body_redacted=body))
        self.assertFalse(dropped)
        self.assertLessEqual(len(out["body_redacted"]), ra.PRE_TRUNCATE_BYTES)
        self.assertNotIn("aB3dE5fG7hI9jK1lM3nO5p", out["body_redacted"])

    def test_pre_truncate_drops_content_beyond_cap(self):
        body = "y" * 9000 + "TAILMARKER9fKx2QpLm"
        out, _ = ra.redact_event(self.event(body_redacted=body))
        self.assertNotIn("TAILMARKER9fKx2QpLm", out["body_redacted"])

    def test_persist_cap_4000_post_redaction(self):
        out, _ = ra.redact_event(self.event(body_redacted="z" * 8000))
        self.assertLessEqual(len(out["body_redacted"]), ra.PERSIST_CAP_CHARS)

    def test_fail_closed_drop_on_redactor_exception(self):
        def boom(text):
            raise RuntimeError("redactor exploded")
        out, dropped = ra.redact_event(self.event(), redactor=boom)
        self.assertIsNone(out)
        self.assertTrue(dropped)


if __name__ == "__main__":
    unittest.main()
