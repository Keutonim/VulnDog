"""Tests for vulndog.engine.api.analyze_run -- the pinned cross-half
facade (brief: Developer A step 4-6).

Offline + deterministic by construction: a tiny fixture store built
with the engine's OWN store/chunker code (StagedStore + chunk_record)
and a fixed-vector stub embedder injected via config["embedder"]. No
network, no Ollama, no 1.93 GiB store.

Engine law under test (verified in QA): the embedder runs BEFORE
exact-id pins (query.py:303 vs :319-322); on embed failure the engine
returns a skipped/embed-failed envelope with ZERO matches and the
matcher enters down-mode (matcher.py:112). The facade must surface
that honestly -- the negative control below fails if the facade ever
reports a silent success.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest

from vulndog.engine import api
from vulndog.engine import chunker
from vulndog.engine import embed_client as ec
from vulndog.engine import event_schema as es
from vulndog.engine import highlights as hl
from vulndog.engine import store as st

CORPUS_VERSION = "vkb1-fixture"

# Orthogonal unit vectors: cosine is 1.0 for the intended pair and 0.0
# for every other record (same pattern as test_query.StoreFixture).
E1 = [1.0, 0.0, 0.0, 0.0]
E2 = [0.0, 1.0, 0.0, 0.0]
E3 = [0.0, 0.0, 1.0, 0.0]
E4 = [0.0, 0.0, 0.0, 1.0]


class StubEmbedder:
    """embed_query protocol double: fixed vector, or raises (outage)."""

    def __init__(self, vector=None, fail=False):
        self.vector = list(vector) if vector is not None else list(E1)
        self.fail = fail
        self.calls = []

    def embed_query(self, text):
        self.calls.append(text)
        if self.fail:
            raise ec.EmbeddingError("ollama unreachable (test stub)")
        return list(self.vector)


def rec(rid, kind="cve", title=None, text="t", **over):
    r = {
        "id": rid, "kind": kind, "title": title or rid,
        "text_fields": [text], "cwe_ids": [], "cvss": None,
        "owasp_categories": [], "exploit_refs": [], "cve_refs": [],
        "dates": {}, "confidence": "documented", "source_path": "s",
        "corpus_version": CORPUS_VERSION,
        "evidence": {"src": "s.zip", "note": "n"},
        "excluded_from_index": False,
    }
    r.update(over)
    return r


#: fixture records -> chunk vector (excluded record gets NO chunks)
FIXTURE_RECORDS = [
    (rec("CVE-2024-1000", title="XSS in login",
         text="cross site scripting in login.php via the redirect parameter",
         cwe_ids=["cwe-79"], owasp_categories=["A03:2021-Injection"],
         cvss={"score": 9.8, "severity": "CRITICAL"},
         exploit_refs=["edb-1"]), E1),
    (rec("CVE-2024-2000", title="SQL injection in search",
         text="sql injection in the search query parameter",
         cwe_ids=["cwe-89"]), E2),
    (rec("CVE-2024-3000", title="Buffer overflow in parser",
         text="stack buffer overflow in the header parser",
         cwe_ids=["cwe-120"]), E3),
    (rec("cwe-79", kind="cwe", title="Cross-site Scripting",
         text="the product does not neutralize user-controllable input"), E4),
    (rec("edb-1", kind="exploit", title="Login XSS exploit",
         text="proof of concept for the login redirect xss"), E1),
    (rec("CVE-2024-9999", title="Excluded record",
         text="excluded from the index", excluded_from_index=True), None),
]


def build_fixture_store(path):
    """Tiny KB via the engine's OWN staged builder + chunker."""
    with st.StagedStore(path) as s:
        for record, vector in FIXTURE_RECORDS:
            s.add_record(record)
            if vector is None:
                continue
            for c in chunker.chunk_record(record):
                s.add_chunk(c["record_id"], c["chunk_index"],
                            c["parts_total"], c["text"], vector,
                            est_tokens=c["est_tokens"],
                            truncated=c["truncated"])
        s.finish({"manifest_version": 1, "corpus_version": CORPUS_VERSION,
                  "counts": {"records_total": len(FIXTURE_RECORDS)}})
        s.swap_into_dest()
    return path


def event(url="https://t.local/login.php?redirect=<len-4>",
          hunt_id="20261120-120000-apitest", body="login redirect xss",
          **over):
    kwargs = dict(tap_class="python", url=url, decision="allowed",
                  provenance="test.tap", hunt_id=hunt_id, method="GET",
                  status=200, content_type="text/html", body_redacted=body)
    kwargs.update(over)
    return es.make_event(**kwargs)


class ApiTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-api-")
        self.run_dir = os.path.join(self.tmp, "20261120-120000-apitest")
        os.makedirs(self.run_dir)
        self.events_path = os.path.join(self.run_dir, "events.jsonl")
        self.store_path = build_fixture_store(
            os.path.join(self.tmp, "vulnkb.sqlite"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_events(self, events):
        with open(self.events_path, "w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    def analyze(self, embedder=None, config=None, **kw):
        cfg = dict(config or {})
        if embedder is not None:
            cfg["embedder"] = embedder
        return api.analyze_run(events_path=self.events_path,
                               run_dir=self.run_dir,
                               store_path=self.store_path,
                               config=cfg, **kw)

    def read_highlights(self):
        p = os.path.join(self.run_dir, "highlights.jsonl")
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def read_md(self):
        p = os.path.join(self.run_dir, "highlights.md")
        if not os.path.exists(p):
            return ""
        with open(p, encoding="utf-8") as fh:
            return fh.read()


class AnalyzeRunTest(ApiTestBase):
    def test_semantic_match_writes_both_surfaces_in_engine_order(self):
        self.write_events([event()])
        summary = self.analyze(embedder=StubEmbedder(E1))
        self.assertEqual(summary["events_read"], 1)
        self.assertGreaterEqual(summary["highlights"], 1)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["corpus_version"], CORPUS_VERSION)
        self.assertEqual(summary["status"], "ok")
        hls = self.read_highlights()
        self.assertEqual(len(hls), summary["highlights"])
        for h in hls:
            self.assertEqual(list(h.keys()), list(hl.HIGHLIGHT_FIELDS))
        self.assertEqual(hls[0]["record_id"], "CVE-2024-1000")
        self.assertEqual(hls[0]["reason"], "semantic")
        self.assertEqual(hls[0]["hunt_id"], "20261120-120000-apitest")
        self.assertEqual(hls[0]["corpus_version"], CORPUS_VERSION)
        md = self.read_md()
        self.assertIn("## H-0001", md)
        self.assertIn("## Run summary", md)
        self.assertIn("ADVISORY CANDIDATES ONLY", md)

    def test_exact_id_pin_bypasses_floor_when_embed_ok(self):
        # query vector E1 is orthogonal to the CVE-2024-2000 chunk (E2):
        # semantic score 0.0 < floor -- only the exact-id pin can match.
        self.write_events([event(url="https://t.local/advisory/CVE-2024-2000",
                                 body="advisory text")])
        summary = self.analyze(embedder=StubEmbedder(E1))
        hls = self.read_highlights()
        pinned = [h for h in hls if h["record_id"] == "CVE-2024-2000"]
        self.assertEqual(len(pinned), 1)
        self.assertEqual(pinned[0]["reason"], "exact-id")
        self.assertEqual(summary["status"], "ok")

    def test_embed_failure_is_skipped_with_zero_highlights(self):
        # NEGATIVE CONTROL: pin bait in the text must NOT rescue the
        # match -- embed runs before pins (query.py:303 vs :319-322).
        self.write_events([
            event(url="https://t.local/advisory/CVE-2024-1000"),
            event(url="https://t.local/second"),
        ])
        summary = self.analyze(embedder=StubEmbedder(fail=True))
        self.assertEqual(summary["status"], "skipped")
        self.assertEqual(summary["highlights"], 0)
        self.assertEqual(self.read_highlights(), [])
        self.assertGreaterEqual(summary["errors"], 1)
        self.assertGreaterEqual(summary["embed_failures"], 1)
        self.assertEqual(summary["mode"], "ollama-down")
        self.assertNotIn("## H-", self.read_md())
        self.assertIn("## Run summary", self.read_md())

    def test_invalid_events_dropped_fail_closed_and_counted(self):
        # Layer order (matcher COND-7a): schema validation runs BEFORE
        # the F4 re-run. A forbidden "headers" key is an unknown_field
        # -> schema drop; a schema-valid lone-surrogate body passes the
        # schema but makes the redaction encode step raise -> F4
        # fail-closed drop. Both are counted, never matched.
        bad_schema = event()
        del bad_schema["decision"]
        forbidden = event()
        forbidden["headers"] = {"Authorization": "Bearer x"}
        surrogate = event(body_redacted="body\ud800tail")
        with open(self.events_path, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(event()) + "\n")
            fh.write(json.dumps(bad_schema) + "\n")
            fh.write(json.dumps(forbidden) + "\n")
            fh.write(json.dumps(surrogate) + "\n")
            fh.write("{not json\n")
        summary = self.analyze(embedder=StubEmbedder(E1))
        self.assertEqual(summary["events_read"], 5)
        self.assertEqual(summary["schema_invalid"], 2)
        self.assertEqual(summary["redaction_dropped"], 1)
        self.assertEqual(summary["json_errors"], 1)
        self.assertEqual(summary["errors"], 4)
        self.assertEqual(summary["highlights"], len(self.read_highlights()))
        self.assertGreaterEqual(summary["highlights"], 1)

    def test_missing_store_is_disabled_not_crash(self):
        self.write_events([event()])
        summary = api.analyze_run(
            events_path=self.events_path, run_dir=self.run_dir,
            store_path=os.path.join(self.tmp, "no-store.sqlite"),
            config={"embedder": StubEmbedder(E1)})
        self.assertEqual(summary["status"], "disabled")
        self.assertEqual(summary["highlights"], 0)
        self.assertGreaterEqual(summary["kb_disabled_events"], 1)

    def test_missing_events_file_is_zero_events_not_crash(self):
        summary = self.analyze(embedder=StubEmbedder(E1))
        self.assertEqual(summary["events_read"], 0)
        self.assertEqual(summary["highlights"], 0)
        self.assertEqual(summary["errors"], 0)
        self.assertEqual(summary["status"], "ok")

    def test_invalid_path_args_are_caller_errors(self):
        # H2/F1: store_path=None used to leak into QueryAPI, raise
        # TypeError per event and surface as status "ok" + api-exception
        # skips — an unconfigured store reported as a clean analysis.
        # Caller-side path errors are ValueError at the boundary (the
        # engine's own discipline: bad filters raise, store failures
        # map to the disabled envelope).
        self.write_events([event()])
        for bad in (None, "", 123):
            with self.assertRaises(ValueError):
                api.analyze_run(events_path=self.events_path,
                                run_dir=self.run_dir, store_path=bad,
                                config={"embedder": StubEmbedder(E1)})
        with self.assertRaises(ValueError):
            api.analyze_run(events_path=None, run_dir=self.run_dir,
                            store_path=self.store_path)
        with self.assertRaises(ValueError):
            api.analyze_run(events_path=self.events_path, run_dir="",
                            store_path=self.store_path)

    def test_mute_config_suppresses_record(self):
        self.write_events([event()])
        summary = self.analyze(embedder=StubEmbedder(E1),
                               config={"mute_record_ids": ["CVE-2024-1000",
                                                           "edb-1"]})
        self.assertEqual(summary["highlights"], 0)
        self.assertGreaterEqual(summary["matcher"]["muted_records"], 1)

    def test_rerun_is_idempotent(self):
        self.write_events([event()])
        s1 = self.analyze(embedder=StubEmbedder(E1))
        hls1 = self.read_highlights()
        md1 = self.read_md()
        s2 = self.analyze(embedder=StubEmbedder(E1))
        self.assertEqual(s1["highlights"], s2["highlights"])
        # matched_at is the one volatile field (wall-clock, documented
        # in api.py); every other field must be identical on re-run.
        def stable(rows):
            return [{k: v for k, v in h.items() if k != "matched_at"}
                    for h in rows]
        self.assertEqual(stable(self.read_highlights()), stable(hls1))
        self.assertEqual(self.read_md().count("## H-"),
                         md1.count("## H-"))

    def test_duplicate_url_record_pair_collapses(self):
        self.write_events([event(), event()])
        summary = self.analyze(embedder=StubEmbedder(E1))
        self.assertEqual(summary["matcher"]["suppressed_duplicates"],
                         summary["highlights"])
        self.assertEqual(summary["events_read"], 2)


if __name__ == "__main__":
    unittest.main()