"""Tests for vuln_watchdog.build (WD-E5 runner; design-spec 3.2, plan A5).

Contract under test:
- run_build(): one streaming pass extract -> join -> recipe -> chunk ->
  embed -> StagedStore -> atomic swap + manifest.json; exit codes
  0 ok / 2 input-config / 3 aborted / 4 embed-blocked / 5 store-error;
- dry-run: measured record/chunk counts with NO embedding and NO store
  write (the recipe-tightening decision instrument);
- DOC-prefix law (C16): every text sent to Ollama carries the document
  prefix EXACTLY once, never the query prefix;
- sha-cache resume (A5 DoD 2): an aborted pass re-run embeds ONLY the
  cache-missing chunks (kill-and-resume semantics, zero re-embedding);
- abort discipline: abort file -> graceful stop, staged temp cleaned,
  destination never touched, cache preserved;
- embed failure: transient transport failures ride the outer retry;
  permanent failure -> exit 4, NO store swap, staged cleaned, cache
  preserved for the resume;
- store vectors: 768-d f32 BLOBs, unit-normalized;
- manifest: counts reconcile with the built DB; corpus_version
  deterministic across identical rebuilds;
- --limit smoke, years filter passthrough, main() CLI dry-run.
"""
import json
import math
import os
import shutil
import sqlite3
import tempfile
import unittest

import hashlib

from vulndog.engine import build as bd
from vulndog.engine import corpus as cp
from vulndog.engine import embed_client as ec
from vulndog.engine import store as st
from vulndog.engine.tests.test_corpus import mini_archives

DOC_PREFIX = ec.DOC_PREFIX
QUERY_PREFIX = ec.QUERY_PREFIX


def text_vector(text, dims=768):
    seed = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16)
    return [(((seed + i) % 89) / 89.0) - 0.5 for i in range(dims)]


class FakeTransport:
    """Ollama /api/embed double: deterministic per-text vectors,
    injectable failures, payload capture."""

    def __init__(self, dims=768, fail_times=0, fail_forever=False):
        self.dims = dims
        self.fail_times = fail_times
        self.fail_forever = fail_forever
        self.calls = 0
        self.texts = 0
        self.payloads = []

    def __call__(self, url, payload, timeout):
        self.calls += 1
        inputs = payload["input"]
        self.texts += len(inputs)
        self.payloads.append(list(inputs))
        if self.fail_forever or self.calls <= self.fail_times:
            raise OSError("connection refused (test)")
        return {"embeddings": [text_vector(t, self.dims) for t in inputs]}


class BuildTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = tempfile.mkdtemp(prefix="wd-e5-raw-")
        cls.paths = mini_archives(cls.raw)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.raw, True)

    def setUp(self):
        self.store_dir = tempfile.mkdtemp(prefix="wd-e5-store-")
        self.cache_dir = os.path.join(self.store_dir, "embed_cache")
        self.dest = os.path.join(self.store_dir, "vulnkb.sqlite")
        self.manifest_path = os.path.join(self.store_dir, "manifest.json")
        self.logs = []

    def tearDown(self):
        shutil.rmtree(self.store_dir, True)

    def log(self, msg):
        self.logs.append(msg)

    def client(self, transport=None, **kw):
        t = transport if transport is not None else FakeTransport()
        kw.setdefault("max_retries", 0)
        kw.setdefault("retry_backoff_s", 0)
        return ec.EmbeddingClient(cache_dir=self.cache_dir, transport=t,
                                  **kw), t

    def do_run(self, stage="slice", embedder=None, **kw):
        kw.setdefault("embed_batch", 2)
        kw.setdefault("commit_every", 4)
        kw.setdefault("progress_every", 1000)
        kw.setdefault("embed_retry_backoff_s", 0)
        kw.setdefault("embed_max_retries", 3)
        kw.setdefault("log", self.log)
        raw_dir = kw.pop("raw_dir", self.raw)
        return bd.run_build(stage, raw_dir=raw_dir,
                            store_dir=self.store_dir,
                            cache_dir=self.cache_dir,
                            embedder=embedder, **kw)

    def staged_leftovers(self):
        return [n for n in os.listdir(self.store_dir)
                if n.startswith(st.STAGED_PREFIX)]


class DryRunTest(BuildTestBase):
    def test_dry_run_counts_without_store(self):
        s = self.do_run(dry_run=True)
        self.assertEqual(s["exit_code"], 0)
        self.assertTrue(s["dry_run"])
        # mini tightened slice: 8 records (traced in test_corpus)
        self.assertEqual(s["records_total"], 8)
        self.assertGreaterEqual(s["chunks_total"], 8)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.manifest_path))
        self.assertEqual(s["api_texts"], 0)  # nothing embedded
        self.assertTrue(s["corpus_version"].startswith("vkb1-"))

    def test_dry_run_full_recipe(self):
        s = self.do_run(stage="full", dry_run=True)
        self.assertEqual(s["records_total"], 14)
        self.assertEqual(s["records_excluded_store_only"], 2)  # 0005 + cat
        self.assertFalse(os.path.exists(self.dest))


class SliceBuildTest(BuildTestBase):
    def test_build_swap_manifest(self):
        emb, transport = self.client()
        s = self.do_run(embedder=emb)
        self.assertEqual(s["exit_code"], 0)
        self.assertTrue(os.path.exists(self.dest))
        self.assertTrue(os.path.exists(self.manifest_path))
        self.assertEqual(self.staged_leftovers(), [])
        # store counts == manifest counts (A4 DoD 3: no silent loss)
        with open(self.manifest_path, encoding="utf-8") as f:
            man = json.load(f)
        conn = st.open_store(self.dest)
        n_rec, = conn.execute("SELECT count(*) FROM records").fetchone()
        n_ch, = conn.execute("SELECT count(*) FROM chunks").fetchone()
        cv, = conn.execute("SELECT value FROM meta "
                           "WHERE key='corpus_version'").fetchone()
        conn.close()
        self.assertEqual(man["counts"]["records_total"], n_rec)
        self.assertEqual(man["counts"]["chunks_total"], n_ch)
        self.assertEqual(s["records_total"], n_rec)
        self.assertEqual(s["chunks_total"], n_ch)
        self.assertEqual(man["corpus_version"], cv)
        self.assertEqual(s["corpus_version"], cv)
        self.assertEqual(man["stage"], "slice")
        self.assertEqual(man["recipe"]["logic"], "tightened")
        # every embedded text carried the DOC prefix exactly once (C16)
        self.assertTrue(transport.payloads)
        for batch in transport.payloads:
            for t in batch:
                self.assertTrue(t.startswith(DOC_PREFIX), t[:60])
                self.assertFalse(t.startswith(DOC_PREFIX + DOC_PREFIX))
                self.assertNotIn(QUERY_PREFIX, t)
        self.assertEqual(transport.texts, n_ch)

    def test_store_vectors_are_unit_f32_768(self):
        emb, _ = self.client()
        self.do_run(embedder=emb)
        conn = st.open_store(self.dest)
        rows = conn.execute("SELECT vec FROM chunks LIMIT 5").fetchall()
        conn.close()
        for (blob,) in rows:
            self.assertEqual(len(blob), 768 * 4)
            v = st.unpack_vector(blob)
            self.assertEqual(len(v), 768)
            norm = math.sqrt(sum(x * x for x in v))
            self.assertAlmostEqual(norm, 1.0, places=4)

    def test_corpus_version_deterministic_across_rebuilds(self):
        emb1, _ = self.client()
        s1 = self.do_run(embedder=emb1)
        emb2, _ = self.client()
        s2 = self.do_run(embedder=emb2)
        self.assertEqual(s1["corpus_version"], s2["corpus_version"])
        # second build swapped atomically over the first
        self.assertTrue(os.path.exists(self.dest))

    def test_progress_logged(self):
        emb, _ = self.client()
        self.do_run(embedder=emb, progress_every=2)
        self.assertTrue(any("records=" in m for m in self.logs))

    def test_limit_smoke(self):
        emb, _ = self.client()
        s = self.do_run(embedder=emb, limit=2)
        self.assertEqual(s["exit_code"], 0)
        conn = st.open_store(self.dest)
        n, = conn.execute("SELECT count(*) FROM records").fetchone()
        conn.close()
        self.assertEqual(n, 2)

    def test_years_passthrough(self):
        emb, _ = self.client()
        s = self.do_run(embedder=emb, years=["2023"], stage="full")
        self.assertEqual(s["exit_code"], 0)
        conn = st.open_store(self.dest)
        n_cve, = conn.execute("SELECT count(*) FROM records "
                              "WHERE kind='cve'").fetchone()
        conn.close()
        self.assertEqual(n_cve, 0)

    def test_missing_archives_exit_2(self):
        s = self.do_run(raw_dir=os.path.join(self.raw, "nope"))
        self.assertEqual(s["exit_code"], 2)
        self.assertFalse(os.path.exists(self.dest))


class AbortResumeTest(BuildTestBase):
    """A5 DoD 2: sha-cache resume -- zero re-embedding of done chunks."""

    def test_abort_then_resume_embeds_only_missing(self):
        abort_file = os.path.join(self.store_dir, "build-slice.abort")
        # run 1: abort after the progress log shows >= 3 records
        seen = {"n": 0}

        def aborting_log(msg):
            self.logs.append(msg)
            if "records=" in msg:
                seen["n"] += 1
                if seen["n"] >= 3 and not os.path.exists(abort_file):
                    with open(abort_file, "w") as f:
                        f.write("stop")

        t1 = FakeTransport()
        emb1 = ec.EmbeddingClient(cache_dir=self.cache_dir, transport=t1,
                                  max_retries=0, retry_backoff_s=0)
        s1 = self.do_run(embedder=emb1, progress_every=1, embed_batch=1,
                      abort_file=abort_file, log=aborting_log)
        self.assertEqual(s1["exit_code"], 3)
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.staged_leftovers(), [])
        cached_after_run1 = len([n for n in os.listdir(self.cache_dir)
                                 if n.endswith(".json")])
        self.assertGreater(cached_after_run1, 0)   # partial progress kept
        self.assertGreater(t1.texts, 0)

        # run 2: resume -- only the cache-missing chunks hit the API
        os.unlink(abort_file)
        t2 = FakeTransport()
        emb2 = ec.EmbeddingClient(cache_dir=self.cache_dir, transport=t2,
                                  max_retries=0, retry_backoff_s=0)
        s2 = self.do_run(embedder=emb2, embed_batch=1, abort_file=abort_file)
        self.assertEqual(s2["exit_code"], 0)
        self.assertTrue(os.path.exists(self.dest))
        self.assertEqual(s2["chunks_total"], s2["chunks_total"])
        # run-2 API texts == total chunks - what run 1 already cached
        self.assertEqual(t2.texts, s2["chunks_total"] - cached_after_run1)
        self.assertEqual(t1.texts + t2.texts, s2["chunks_total"])

    def test_abort_before_start(self):
        abort_file = os.path.join(self.store_dir, "build-slice.abort")
        with open(abort_file, "w") as f:
            f.write("stop")
        emb, t = self.client()
        s = self.do_run(embedder=emb, abort_file=abort_file)
        self.assertEqual(s["exit_code"], 3)
        self.assertEqual(t.calls, 0)
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self.staged_leftovers(), [])

    def test_default_abort_file_path(self):
        p = bd.default_abort_file(self.store_dir, "full")
        self.assertEqual(p, os.path.join(self.store_dir, "build-full.abort"))


class EmbedFailureTest(BuildTestBase):
    def test_transient_failures_ride_outer_retry(self):
        t = FakeTransport(fail_times=2)
        emb = ec.EmbeddingClient(cache_dir=self.cache_dir, transport=t,
                                 max_retries=0, retry_backoff_s=0)
        s = self.do_run(embedder=emb, embed_batch=1)
        self.assertEqual(s["exit_code"], 0)
        self.assertTrue(os.path.exists(self.dest))

    def test_permanent_failure_exit_4_no_store(self):
        t = FakeTransport(fail_forever=True)
        emb = ec.EmbeddingClient(cache_dir=self.cache_dir, transport=t,
                                 max_retries=0, retry_backoff_s=0)
        s = self.do_run(embedder=emb, embed_batch=1, embed_max_retries=2)
        self.assertEqual(s["exit_code"], 4)
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(self.manifest_path))
        self.assertEqual(self.staged_leftovers(), [])
        self.assertTrue(s.get("embed_error"))

    def test_previous_store_survives_failed_rebuild(self):
        emb1, _ = self.client()
        self.do_run(embedder=emb1)
        before = open(self.dest, "rb").read()
        t = FakeTransport(fail_forever=True)
        emb2 = ec.EmbeddingClient(cache_dir=os.path.join(
            self.store_dir, "cache2"), transport=t,
            max_retries=0, retry_backoff_s=0)
        s = self.do_run(embedder=emb2, embed_max_retries=1)
        self.assertEqual(s["exit_code"], 4)
        self.assertEqual(open(self.dest, "rb").read(), before)


class FakeFunctionEmbedderTest(BuildTestBase):
    def test_plain_callable_embedder_supported(self):
        calls = []

        def embed(texts):
            calls.append(len(texts))
            return [text_vector(t) for t in texts]

        s = self.do_run(embedder=embed)
        self.assertEqual(s["exit_code"], 0)
        self.assertTrue(calls)
        self.assertTrue(os.path.exists(self.dest))


class MainCliTest(BuildTestBase):
    def test_main_dry_run_returns_zero(self):
        rc = bd.main(["--stage", "slice", "--raw-dir", self.raw,
                      "--store-dir", self.store_dir,
                      "--cache-dir", self.cache_dir, "--dry-run"])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(self.dest))

    def test_main_bad_stage_exits(self):
        with self.assertRaises(SystemExit):
            bd.main(["--stage", "nope", "--raw-dir", self.raw,
                     "--store-dir", self.store_dir])

    def test_main_prints_summary_json(self):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = bd.main(["--stage", "slice", "--raw-dir", self.raw,
                          "--store-dir", self.store_dir,
                          "--cache-dir", self.cache_dir, "--dry-run"])
        self.assertEqual(rc, 0)
        out = json.loads(buf.getvalue())
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["records_total"], 8)


class NoRawDirTest(BuildTestBase):
    """FINAL-01: an unconfigured raw dir must surface as a clean input
    error (exit 2, explicit message) on the engine build path -- never a
    raw traceback and never a silent developer-path reference. Mirrors
    the M3.4 fail-loud input law (GAP-5). The probes pass an explicit
    None / force the portable None default so they never touch a real
    archive directory, before or after the fix."""

    def test_run_build_unconfigured_raw_dir_is_input_error(self):
        s = bd.run_build("slice", raw_dir=None, store_dir=self.store_dir,
                         cache_dir=self.cache_dir, log=self.log)
        self.assertEqual(s["exit_code"], bd.EXIT_INPUT)
        self.assertIn("no archive directory configured", s["message"])
        self.assertFalse(os.path.exists(self.dest))

    def test_main_without_raw_dir_exits_input(self):
        import contextlib
        import io
        from unittest import mock
        buf = io.StringIO()
        # force the portable default (None) through the CLI arg surface
        with mock.patch.object(cp, "DEFAULT_RAW_DIR", None), \
                contextlib.redirect_stdout(buf):
            rc = bd.main(["--stage", "slice",
                          "--store-dir", self.store_dir,
                          "--cache-dir", self.cache_dir])
        self.assertEqual(rc, bd.EXIT_INPUT)
        out = json.loads(buf.getvalue())
        self.assertIn("no archive directory configured", out["message"])
        self.assertFalse(os.path.exists(self.dest))


if __name__ == "__main__":
    unittest.main()
