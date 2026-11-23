"""Tests for vuln_watchdog.embed_client (design-spec 5.1 / plan F2).

TDD: written BEFORE the implementation. Network is never touched here --
a fake transport is injected. Real Ollama loopback calls happen only in
the benchmark scripts.
"""
import hashlib
import json
import math
import os
import shutil
import tempfile
import unittest
import urllib.request

from vulndog.engine import embed_client as ec


DIM = 768


def vec(seed):
    """Deterministic pseudo-vector of exactly DIM floats."""
    out = []
    x = seed + 1
    for _ in range(DIM):
        x = (x * 1103515245 + 12345) % (2 ** 31)
        out.append((x / 2 ** 31) - 0.5)
    return out


class FakeTransport:
    """Records calls; returns canned embeddings for each input text."""

    def __init__(self, fail_times=0, exc=None, vectors=None):
        self.calls = []          # list of (url, payload, timeout)
        self.fail_times = fail_times
        self.exc = exc or TimeoutError("simulated hang")
        self.vectors = vectors   # optional dict prefixed_text -> vector
        self.n = 0

    def __call__(self, url, payload, timeout):
        self.calls.append((url, payload, timeout))
        if self.fail_times:
            self.fail_times -= 1
            raise self.exc
        inputs = payload["input"]
        embs = []
        for t in inputs:
            if self.vectors and t in self.vectors:
                embs.append(list(self.vectors[t]))
            else:
                self.n += 1
                embs.append(vec(hash(t) % 10000))
        return {"embeddings": embs}

    @property
    def inputs(self):
        out = []
        for _, payload, _ in self.calls:
            out.extend(payload["input"])
        return out


class PrefixDisciplineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-embed-test-")
        self.t = FakeTransport()
        self.c = ec.EmbeddingClient(cache_dir=self.tmp, transport=self.t)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_document_prefix_applied(self):
        self.c.embed_documents(["hello world"])
        self.assertEqual(self.t.inputs, ["title: none | text: hello world"])

    def test_query_prefix_applied(self):
        self.c.embed_query("hello world")
        self.assertEqual(self.t.inputs, ["task: search result | query: hello world"])

    def test_prefixes_never_mixed(self):
        self.c.embed_documents(["doc a", "doc b"])
        self.c.embed_query("q a")
        for t in self.t.inputs[:2]:
            self.assertTrue(t.startswith(ec.DOC_PREFIX))
            self.assertNotIn(ec.QUERY_PREFIX, t)
        self.assertTrue(self.t.inputs[2].startswith(ec.QUERY_PREFIX))
        self.assertNotIn(ec.DOC_PREFIX, self.t.inputs[2])

    def test_model_sent_in_payload(self):
        self.c.embed_query("x")
        _, payload, _ = self.t.calls[0]
        self.assertEqual(payload["model"], ec.DEFAULT_MODEL)


class LoopbackOnlyTest(unittest.TestCase):
    def test_single_constant_loopback_address(self):
        self.assertEqual(ec.OLLAMA_BASE_URL, "http://127.0.0.1:11434")

    def test_request_url_built_from_constant(self):
        req = ec.build_embed_request({"model": "m", "input": ["t"]})
        self.assertEqual(req.full_url, "http://127.0.0.1:11434/api/embed")

    def test_default_opener_ignores_proxy_env(self):
        # Behavioral invariant: with poisoned proxy env vars, the default
        # urllib opener WOULD carry them; ours must carry none.
        saved = {k: os.environ.get(k) for k in ("http_proxy", "HTTP_PROXY", "all_proxy")}
        os.environ["http_proxy"] = "http://127.0.0.1:9"
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:9"
        try:
            default_opener = urllib.request.build_opener()
            leaked = [h for h in default_opener.handlers
                      if getattr(h, "proxies", None)]
            self.assertTrue(leaked, "sanity: default opener must pick up env proxies")
            opener = ec.make_no_proxy_opener()
            carrying = [h for h in opener.handlers
                        if getattr(h, "proxies", None)]
            self.assertEqual(carrying, [], "no handler may carry proxy config")
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_constructor_exposes_no_host_parameter(self):
        import inspect
        params = inspect.signature(ec.EmbeddingClient.__init__).parameters
        for banned in ("host", "url", "base_url", "endpoint", "address"):
            self.assertNotIn(banned, params)


class ValidationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-embed-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def client_with(self, embeddings):
        def transport(url, payload, timeout):
            return {"embeddings": embeddings}
        return ec.EmbeddingClient(cache_dir=self.tmp, transport=transport)

    def test_accepts_768_finite_dims(self):
        c = self.client_with([vec(1)])
        v = c.embed_query("ok")
        self.assertEqual(len(v), DIM)
        self.assertTrue(all(math.isfinite(x) for x in v))

    def test_rejects_wrong_dim(self):
        c = self.client_with([[0.1] * (DIM - 1)])
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_query("bad dims")

    def test_rejects_non_finite(self):
        bad = vec(2)
        bad[10] = float("nan")
        bad[11] = float("inf")
        c = self.client_with([bad])
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_query("nan inf")

    def test_rejects_empty_vector_bug(self):
        c = self.client_with([[]])
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_query("empty")

    def test_rejects_missing_embeddings_key(self):
        def transport(url, payload, timeout):
            return {}
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=transport)
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_query("no key")

    def test_validation_failure_written_to_repair_log(self):
        c = self.client_with([[]])
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_query("empty")
        log = os.path.join(self.tmp, "repair_log.jsonl")
        self.assertTrue(os.path.exists(log))
        with open(log, encoding="utf-8") as f:
            entry = json.loads(f.read().strip())
        self.assertEqual(entry["kind"], "empty-or-invalid-embedding")


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-embed-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_cache_miss_then_hit_no_second_call(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t)
        v1 = c.embed_query("cache me")
        v2 = c.embed_query("cache me")
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(v1, v2)

    def test_cache_key_is_sha256_model_newline_prefixed_text(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t)
        c.embed_query("abc")
        prefixed = ec.QUERY_PREFIX + "abc"
        expected = hashlib.sha256(
            (ec.DEFAULT_MODEL + "\n" + prefixed).encode("utf-8")
        ).hexdigest()
        self.assertTrue(os.path.exists(os.path.join(self.tmp, expected + ".json")))

    def test_cache_resumable_across_instances(self):
        t1 = FakeTransport()
        ec.EmbeddingClient(cache_dir=self.tmp, transport=t1).embed_documents(["resume me"])
        t2 = FakeTransport()
        c2 = ec.EmbeddingClient(cache_dir=self.tmp, transport=t2)
        v = c2.embed_documents(["resume me"])
        self.assertEqual(t2.calls, [])
        self.assertEqual(len(v), 1)
        self.assertEqual(len(v[0]), DIM)

    def test_model_swap_invalidates_cache(self):
        t1 = FakeTransport()
        ec.EmbeddingClient(cache_dir=self.tmp, transport=t1,
                           model="embeddinggemma:300m").embed_query("swap")
        t2 = FakeTransport()
        c2 = ec.EmbeddingClient(cache_dir=self.tmp, transport=t2,
                                model="nomic-embed-text:latest")
        c2.embed_query("swap")
        self.assertEqual(len(t2.calls), 1, "model swap must re-embed")

    def test_doc_and_query_cache_separate(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t)
        c.embed_documents(["same text"])
        c.embed_query("same text")
        self.assertEqual(len(t.calls), 2, "different prefixes = different keys")

    def test_cache_disabled_bypasses_disk(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t, use_cache=False)
        v1 = c.embed_query("no cache")
        v2 = c.embed_query("no cache")
        self.assertEqual(len(t.calls), 2)
        self.assertEqual(v1, v2)
        files = [f for f in os.listdir(self.tmp) if f.endswith(".json")]
        self.assertEqual(files, [])

    def test_partial_cache_batch_only_fetches_missing(self):
        t1 = FakeTransport()
        ec.EmbeddingClient(cache_dir=self.tmp, transport=t1).embed_documents(["a", "b"])
        t2 = FakeTransport()
        c2 = ec.EmbeddingClient(cache_dir=self.tmp, transport=t2, batch_size=8)
        c2.embed_documents(["a", "b", "c"])
        self.assertEqual(t2.inputs, [ec.DOC_PREFIX + "c"])


class TimeoutRetryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-embed-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_timeout_propagates_as_embedding_error_after_retries(self):
        t = FakeTransport(fail_times=99)
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t,
                               max_retries=2, retry_backoff_s=0.0)
        with self.assertRaises(ec.EmbeddingError):
            c.embed_query("hang")
        self.assertEqual(len(t.calls), 3)  # 1 attempt + 2 retries

    def test_transient_failure_then_success(self):
        t = FakeTransport(fail_times=1)
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t,
                               max_retries=2, retry_backoff_s=0.0)
        v = c.embed_query("flaky")
        self.assertEqual(len(v), DIM)
        self.assertEqual(len(t.calls), 2)

    def test_timeout_value_passed_to_transport(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t, timeout_s=7.5)
        c.embed_query("t")
        self.assertEqual(t.calls[0][2], 7.5)

    def test_default_timeout_is_10s(self):
        import inspect
        sig = inspect.signature(ec.EmbeddingClient.__init__)
        self.assertEqual(sig.parameters["timeout_s"].default, 10.0)


class BatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-embed-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_batch_call_alignment(self):
        va, vb = vec(11), vec(22)
        t = FakeTransport(vectors={
            ec.DOC_PREFIX + "a": va,
            ec.DOC_PREFIX + "b": vb,
        })
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t, batch_size=8)
        out = c.embed_documents(["a", "b"])
        self.assertEqual(len(t.calls), 1)
        self.assertEqual(out[0], va)
        self.assertEqual(out[1], vb)

    def test_batch_size_splits_calls(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t, batch_size=2)
        c.embed_documents(["x1", "x2", "x3", "x4", "x5"])
        self.assertEqual(len(t.calls), 3)

    def test_token_budget_caps_batch(self):
        # 5 texts x ~56 est tokens (200 chars + prefix), budget 120 -> 2 per call
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t,
                               batch_size=64, batch_max_est_tokens=120)
        c.embed_documents(["x" * 200] * 5)
        self.assertEqual(len(t.calls), 3)
        self.assertEqual([len(p["input"]) for _, p, _ in t.calls], [2, 2, 1])

    def test_single_text_over_budget_sent_alone(self):
        t = FakeTransport()
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=t,
                               batch_size=64, batch_max_est_tokens=120)
        c.embed_documents(["y" * 8000, "z" * 40])
        self.assertEqual(len(t.calls), 2)
        self.assertEqual([len(p["input"]) for _, p, _ in t.calls], [1, 1])

    def test_batch_response_length_mismatch_raises(self):
        def transport(url, payload, timeout):
            return {"embeddings": [vec(1)]}  # asked N>1, got 1
        c = ec.EmbeddingClient(cache_dir=self.tmp, transport=transport,
                               batch_size=4, max_retries=0)
        with self.assertRaises(ec.EmbeddingValidationError):
            c.embed_documents(["p", "q"])


if __name__ == "__main__":
    unittest.main()
