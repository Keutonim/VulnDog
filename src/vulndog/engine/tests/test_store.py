"""Tests for vuln_watchdog.store (WD-E6; design-spec 3.6/6 SEC C-5, plan A6a/A7).

Contract under test:
- vector codec: f32 little-endian BLOB, round-trip stable, 768-d blob is
  exactly 3072 bytes;
- StagedStore: records table carries the F1 fields (JSON list columns,
  derived exploit_available, extras in props), chunks table carries
  (record_id, part, text, vec BLOB), chunks_fts is an FTS5 external-
  content table aligned by rowid, meta carries schema_version +
  corpus_version + manifest;
- ATOMIC build (SEC C-5, request_budget.py precedent): staged temp DB
  in the DEST dir + os.replace swap; a previous store survives until
  the swap; a failed build cleans the staged temp, never leaves a
  partial vulnkb.sqlite, never touches the previous store; failed
  integrity check -> no swap;
- open_store(): missing file / corrupt bytes / wrong schema ->
  StoreError with an explicit reason (query.py maps these to the
  DISABLED signal), never a raw sqlite crash;
- apply_delta(): id-upsert on a COPY + FTS rebuild + atomic swap +
  .prev backup (A7 skeleton: deltaLog-driven upsert; full refresh =
  rebuild via the build path);
- parse_deltalog_ids(): tolerant deltaLog walker -> sorted unique CVE
  ids; garbage -> StoreError, never a silent empty list.
"""
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

from vulndog.engine import store as st


def vec(dims=8, seed=1):
    return [((i + seed) % 7) * 0.125 - 0.25 for i in range(dims)]


def mkrec(**over):
    r = {
        "id": "CVE-2024-0001", "kind": "cve", "title": "Test vuln",
        "text_fields": ["desc"], "cwe_ids": ["cwe-79"],
        "cvss": {"score": 9.8, "severity": "CRITICAL",
                 "vector": "CVSS:3.1/AV:N"},
        "owasp_categories": ["A03:2021-Injection"],
        "exploit_refs": ["edb-1"], "dates": {"published": "2024-01-01"},
        "confidence": "documented", "source_path": "cves/2024/x.json",
        "corpus_version": "vkb1-test",
        "evidence": {"src": "s.zip", "note": "n"},
        "excluded_from_index": False, "html_entities": False,
        "refs": ["https://example.invalid"],
    }
    r.update(over)
    return r


def fake_embedder_factory(dims=8):
    calls = []

    def embed(texts):
        calls.append(list(texts))
        return [vec(dims, seed=len(t) % 5 + 1) for t in texts]
    embed.calls = calls
    return embed


MANIFEST = {"manifest_version": 1, "corpus_version": "vkb1-test",
            "counts": {"records_total": 1}}


class VectorCodecTest(unittest.TestCase):
    def test_roundtrip(self):
        from vulndog.engine import vecmath
        v = vec(768)
        blob = st.pack_vector(v)
        self.assertEqual(len(blob), 768 * 4)
        out = st.unpack_vector(blob)
        self.assertEqual(len(out), 768)
        # pack unit-normalizes by design (dot == cosine at query time)
        want = vecmath.normalize(v)
        for a, b in zip(want, out):
            self.assertAlmostEqual(a, b, places=6)

    def test_unpack_empty_blob(self):
        self.assertEqual(st.unpack_vector(b""), [])


class StagedStoreBasicsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e6-")
        self.dest = os.path.join(self.tmp, "sub", "vulnkb.sqlite")

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def build(self, records=None, manifest=None, dims=8):
        records = records if records is not None else [mkrec()]
        with st.StagedStore(self.dest) as s:
            for i, rec in enumerate(records):
                s.add_record(rec)
                s.add_chunk(rec["id"], 0, 1, rec["text_fields"][0]
                            if rec["text_fields"] else "",
                            vec(dims, i + 1), est_tokens=5)
            s.finish(manifest or MANIFEST)
            s.swap_into_dest()
        return self.dest

    def test_schema_tables_exist(self):
        self.build()
        conn = sqlite3.connect(self.dest)
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN "
            "('table','index') OR sql LIKE 'CREATE VIRTUAL%'")}
        conn.close()
        for t in ("records", "chunks", "chunks_fts", "meta"):
            self.assertIn(t, names)

    def test_chunks_fts_is_fts5(self):
        self.build()
        conn = sqlite3.connect(self.dest)
        sql = conn.execute("SELECT sql FROM sqlite_master "
                           "WHERE name='chunks_fts'").fetchone()[0]
        conn.close()
        self.assertIn("fts5", sql.lower())

    def test_record_row_roundtrip(self):
        rec = mkrec()
        self.build([rec])
        conn = st.open_store(self.dest)
        cur = conn.execute("SELECT * FROM records WHERE id=?",
                           (rec["id"],))
        row = cur.fetchone()
        cols = [d[0] for d in cur.description]
        d = dict(zip(cols, row))
        conn.close()
        self.assertEqual(d["kind"], "cve")
        self.assertEqual(d["title"], "Test vuln")
        self.assertEqual(json.loads(d["cwe_ids"]), ["cwe-79"])
        self.assertEqual(d["cvss_score"], 9.8)
        self.assertEqual(d["cvss_severity"], "CRITICAL")
        self.assertEqual(json.loads(d["owasp_categories"]),
                         ["A03:2021-Injection"])
        self.assertEqual(json.loads(d["exploit_refs"]), ["edb-1"])
        self.assertEqual(json.loads(d["dates"])["published"], "2024-01-01")
        self.assertEqual(json.loads(d["evidence"])["src"], "s.zip")
        self.assertEqual(d["excluded_from_index"], 0)
        self.assertEqual(d["exploit_available"], 1)  # cve with exploit_refs
        # extras land in props
        props = json.loads(d["props"])
        self.assertEqual(props["refs"], ["https://example.invalid"])
        # text_fields is NOT double-stored (chunks carry the text)
        self.assertNotIn("text_fields", props)

    def test_exploit_available_derivation(self):
        recs = [
            mkrec(id="CVE-2024-0001", exploit_refs=[]),
            mkrec(id="edb-5", kind="exploit", title="e", exploit_refs=[],
                  cve_refs=["CVE-2024-0001"]),
            mkrec(id="cwe-79", kind="cwe", title="c", cwe_ids=[],
                  exploit_refs=[]),
        ]
        self.build(recs)
        conn = st.open_store(self.dest)
        got = dict(conn.execute(
            "SELECT id, exploit_available FROM records").fetchall())
        conn.close()
        self.assertEqual(got, {"CVE-2024-0001": 0, "edb-5": 1, "cwe-79": 0})

    def test_excluded_record_kept_with_flag_and_no_chunks(self):
        rec = mkrec(id="CVE-2024-0002", text_fields=[],
                    excluded_from_index=True)
        with st.StagedStore(self.dest) as s:
            s.add_record(rec)
            s.finish(MANIFEST)
            s.swap_into_dest()
        conn = st.open_store(self.dest)
        flag, = conn.execute("SELECT excluded_from_index FROM records "
                             "WHERE id='CVE-2024-0002'").fetchone()
        n, = conn.execute("SELECT count(*) FROM chunks "
                          "WHERE record_id='CVE-2024-0002'").fetchone()
        conn.close()
        self.assertEqual(flag, 1)
        self.assertEqual(n, 0)

    def test_chunk_rows_and_fts_alignment(self):
        rec = mkrec(text_fields=["alpha beta gamma text"])
        self.build([rec])
        conn = st.open_store(self.dest)
        cid, part, text, blob = conn.execute(
            "SELECT id, part, text, vec FROM chunks").fetchone()
        hits = conn.execute(
            "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH "
            "\"gamma\"").fetchall()
        conn.close()
        self.assertEqual(part, 0)
        self.assertIn("gamma", text)
        self.assertEqual(len(blob), 8 * 4)
        self.assertEqual([h[0] for h in hits], [cid])  # rowid aligned

    def test_meta_manifest_and_version(self):
        self.build()
        conn = st.open_store(self.dest)
        m = st.read_manifest(conn)
        version, = conn.execute("SELECT value FROM meta "
                                "WHERE key='schema_version'").fetchone()
        cv, = conn.execute("SELECT value FROM meta "
                           "WHERE key='corpus_version'").fetchone()
        conn.close()
        self.assertEqual(m["corpus_version"], "vkb1-test")
        self.assertEqual(int(version), st.SCHEMA_VERSION)
        self.assertEqual(cv, "vkb1-test")

    def test_dest_dir_created(self):
        self.build()
        self.assertTrue(os.path.isdir(os.path.dirname(self.dest)))


class AtomicSwapTest(unittest.TestCase):
    """SEC C-5: staged temp + os.replace + cleanup-on-failure."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e6-atom-")
        self.dest = os.path.join(self.tmp, "vulnkb.sqlite")

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def _staged_leftovers(self):
        return [n for n in os.listdir(self.tmp)
                if n.startswith(st.STAGED_PREFIX)]

    def test_failure_inside_context_leaves_no_dest_no_temp(self):
        with self.assertRaises(RuntimeError):
            with st.StagedStore(self.dest) as s:
                s.add_record(mkrec())
                raise RuntimeError("simulated mid-build failure")
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self._staged_leftovers(), [])

    def test_previous_store_survives_failed_build(self):
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-7777", title="OLD"))
            s.finish(MANIFEST)
            s.swap_into_dest()
        before = open(self.dest, "rb").read()
        with self.assertRaises(RuntimeError):
            with st.StagedStore(self.dest) as s:
                s.add_record(mkrec(id="CVE-2024-8888", title="NEW"))
                raise RuntimeError("boom")
        self.assertEqual(open(self.dest, "rb").read(), before)
        conn = st.open_store(self.dest)
        n, = conn.execute("SELECT count(*) FROM records").fetchone()
        conn.close()
        self.assertEqual(n, 1)
        self.assertEqual(self._staged_leftovers(), [])

    def test_integrity_failure_blocks_swap(self):
        s = st.StagedStore(self.dest)
        with s:
            s.add_record(mkrec())
            s._integrity_check = lambda: "*** in database main ***: bad"
            with self.assertRaises(st.StoreError) as ctx:
                s.finish(MANIFEST)
            self.assertEqual(ctx.exception.reason, "integrity-check-failed")
        self.assertFalse(os.path.exists(self.dest))
        self.assertEqual(self._staged_leftovers(), [])

    def test_swap_replaces_previous_atomically(self):
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-7777", title="OLD"))
            s.finish(MANIFEST)
            s.swap_into_dest()
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-8888", title="NEW"))
            s.finish(MANIFEST)
            s.swap_into_dest()
        conn = st.open_store(self.dest)
        ids = [r[0] for r in conn.execute("SELECT id FROM records")]
        conn.close()
        self.assertEqual(ids, ["CVE-2024-8888"])
        self.assertEqual(self._staged_leftovers(), [])

    @unittest.skipUnless(sys.platform == "win32", "Windows file-locking semantics")
    def test_swap_while_reader_open_windows_semantics(self):
        """MEASURED Windows behavior: an open sqlite read connection
        BLOCKS os.replace (PermissionError) -- swap_into_dest retries
        then raises StoreError('swap-failed') and the DEST STORE STAYS
        INTACT (SEC C-5: the previous store survives a failed swap).
        Consequence (documented for query.py): readers must NOT hold
        connections across calls -- open per match(), close in finally.
        The stage-2 background build's final swap therefore requires no
        concurrent long-lived reader (none exists pre-P4)."""
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-7777"))
            s.finish(MANIFEST)
            s.swap_into_dest()
        before = open(self.dest, "rb").read()
        reader = st.open_store(self.dest)
        try:
            with self.assertRaises(st.StoreError) as ctx:
                with st.StagedStore(self.dest) as s:
                    s.add_record(mkrec(id="CVE-2024-9999"))
                    s.finish(MANIFEST)
                    s.swap_into_dest(retries=2, backoff_s=0.01)
            self.assertEqual(ctx.exception.reason, "swap-failed")
        finally:
            reader.close()
        # dest intact + staged temps cleaned even after the failed swap
        self.assertEqual(open(self.dest, "rb").read(), before)
        self.assertEqual(self._staged_leftovers(), [])
        # and once the reader is gone the swap succeeds
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-9999"))
            s.finish(MANIFEST)
            s.swap_into_dest()
        conn = st.open_store(self.dest)
        ids = [r[0] for r in conn.execute("SELECT id FROM records")]
        conn.close()
        self.assertEqual(ids, ["CVE-2024-9999"])

    def test_staged_file_lives_in_dest_dir(self):
        s = st.StagedStore(self.dest)
        try:
            self.assertEqual(os.path.dirname(s.staged_path),
                             os.path.dirname(os.path.abspath(self.dest)))
            self.assertTrue(os.path.exists(s.staged_path))
            self.assertFalse(os.path.exists(self.dest))
        finally:
            s.abort_cleanup()
        self.assertEqual(self._staged_leftovers(), [])


class OpenStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e6-open-")

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def test_missing_file(self):
        with self.assertRaises(st.StoreError) as ctx:
            st.open_store(os.path.join(self.tmp, "nope.sqlite"))
        self.assertEqual(ctx.exception.reason, "store-missing")

    def test_corrupt_bytes(self):
        p = os.path.join(self.tmp, "garbage.sqlite")
        with open(p, "wb") as f:
            f.write(b"this is definitely not a sqlite database " * 40)
        with self.assertRaises(st.StoreError) as ctx:
            st.open_store(p)
        self.assertEqual(ctx.exception.reason, "store-corrupt")

    def test_valid_sqlite_without_schema(self):
        p = os.path.join(self.tmp, "empty.sqlite")
        conn = sqlite3.connect(p)
        conn.execute("CREATE TABLE other (x)")
        conn.commit()
        conn.close()
        with self.assertRaises(st.StoreError) as ctx:
            st.open_store(p)
        self.assertEqual(ctx.exception.reason, "schema-mismatch")

    def test_wrong_schema_version(self):
        p = os.path.join(self.tmp, "v.sqlite")
        with st.StagedStore(p) as s:
            s.add_record(mkrec())
            s.finish(MANIFEST)
            s.swap_into_dest()
        conn = sqlite3.connect(p)
        conn.execute("UPDATE meta SET value=? WHERE key='schema_version'",
                     (str(st.SCHEMA_VERSION + 99),))
        conn.commit()
        conn.close()
        with self.assertRaises(st.StoreError) as ctx:
            st.open_store(p)
        self.assertEqual(ctx.exception.reason, "schema-mismatch")

    def test_open_store_is_query_only(self):
        p = os.path.join(self.tmp, "v.sqlite")
        with st.StagedStore(p) as s:
            s.add_record(mkrec())
            s.finish(MANIFEST)
            s.swap_into_dest()
        conn = st.open_store(p)
        with self.assertRaises(sqlite3.OperationalError):
            conn.execute("INSERT INTO records (id, kind) VALUES ('x','cve')")
        conn.close()


class ApplyDeltaTest(unittest.TestCase):
    """A7 skeleton: deltaLog-driven id-upsert; atomic; .prev backup."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-e6-delta-")
        self.dest = os.path.join(self.tmp, "vulnkb.sqlite")
        with st.StagedStore(self.dest) as s:
            s.add_record(mkrec(id="CVE-2024-0001",
                               text_fields=["alpha one"]))
            s.add_chunk("CVE-2024-0001", 0, 1, "alpha one", vec(8, 1))
            s.add_record(mkrec(id="CVE-2024-0002", title="keep me",
                               text_fields=["beta two"],
                               exploit_refs=[]))
            s.add_chunk("CVE-2024-0002", 0, 1, "beta two", vec(8, 2))
            s.finish(MANIFEST)
            s.swap_into_dest()

    def tearDown(self):
        shutil.rmtree(self.tmp, True)

    def test_upsert_replaces_and_inserts(self):
        changed = mkrec(id="CVE-2024-0001", title="CHANGED title",
                        text_fields=["gamma refreshed"])
        brand_new = mkrec(id="CVE-2024-0003", title="brand new",
                          text_fields=["delta new"], exploit_refs=[])
        emb = fake_embedder_factory(8)
        st.apply_delta(self.dest, [changed, brand_new], emb,
                       corpus_version="vkb1-delta")
        conn = st.open_store(self.dest)
        titles = dict(conn.execute("SELECT id, title FROM records"))
        texts = {r[0] for r in conn.execute("SELECT text FROM chunks")}
        cv, = conn.execute("SELECT value FROM meta "
                           "WHERE key='corpus_version'").fetchone()
        fts_new = conn.execute("SELECT count(*) FROM chunks_fts "
                               "WHERE chunks_fts MATCH '\"gamma\"'").fetchone()[0]
        fts_old = conn.execute("SELECT count(*) FROM chunks_fts "
                               "WHERE chunks_fts MATCH '\"alpha\"'").fetchone()[0]
        conn.close()
        self.assertEqual(titles["CVE-2024-0001"], "CHANGED title")
        self.assertIn("CVE-2024-0003", titles)
        self.assertEqual(titles["CVE-2024-0002"], "keep me")
        self.assertIn("gamma refreshed", texts)
        self.assertNotIn("alpha one", texts)
        self.assertIn("beta two", texts)
        self.assertEqual(cv, "vkb1-delta")
        self.assertEqual(fts_new, 1)   # fts rebuilt: new text findable
        self.assertEqual(fts_old, 0)   # old text gone from the index
        self.assertTrue(emb.calls)     # embedder was used

    def test_backup_prev_written(self):
        st.apply_delta(self.dest, [], fake_embedder_factory(8))
        self.assertTrue(os.path.exists(self.dest + ".prev"))

    def test_failed_delta_leaves_store_intact(self):
        before = open(self.dest, "rb").read()

        def bad_embedder(texts):
            raise RuntimeError("ollama down mid-delta")

        with self.assertRaises(RuntimeError):
            st.apply_delta(self.dest, [mkrec(id="CVE-2024-0009")],
                           bad_embedder)
        self.assertEqual(open(self.dest, "rb").read(), before)
        self.assertEqual([n for n in os.listdir(self.tmp)
                          if n.startswith(st.STAGED_PREFIX)], [])

    def test_missing_store_raises_store_error(self):
        with self.assertRaises(st.StoreError):
            st.apply_delta(os.path.join(self.tmp, "none.sqlite"), [],
                           fake_embedder_factory(8))


class ParseDeltaLogTest(unittest.TestCase):
    def test_delta_key_form(self):
        payload = {"type": "DELTA", "delta": [
            {"cveId": "CVE-2026-0002", "state": "PUBLISHED"},
            {"cveId": "CVE-2026-0001", "state": "UPDATED"},
            {"cveId": "CVE-2026-0001", "state": "UPDATED"},
        ]}
        self.assertEqual(st.parse_deltalog_ids(payload),
                         ["CVE-2026-0001", "CVE-2026-0002"])

    def test_bare_list_and_string_input(self):
        self.assertEqual(
            st.parse_deltalog_ids([{"cveId": "CVE-2025-1111"}]),
            ["CVE-2025-1111"])
        raw = json.dumps({"entries": [{"cveId": "CVE-2025-2222"}]})
        self.assertEqual(st.parse_deltalog_ids(raw), ["CVE-2025-2222"])

    def test_tolerates_junk_entries(self):
        payload = {"delta": [{"cveId": "not-a-cve"}, {"x": 1}, None,
                             {"cveId": "CVE-2025-3333"}]}
        self.assertEqual(st.parse_deltalog_ids(payload), ["CVE-2025-3333"])

    def test_garbage_raises(self):
        with self.assertRaises(st.StoreError):
            st.parse_deltalog_ids("{not json")
        with self.assertRaises(st.StoreError):
            st.parse_deltalog_ids(None)

    def test_no_ids_is_empty_list(self):
        self.assertEqual(st.parse_deltalog_ids({"delta": []}), [])


class DefaultsTest(unittest.TestCase):
    def test_default_paths_ascii_under_data(self):
        p = st.DEFAULT_STORE_PATH
        self.assertTrue(p.endswith(os.path.join("data", "vulnkb",
                                                "vulnkb.sqlite")))
        self.assertTrue(p.isascii())
        self.assertTrue(st.DEFAULT_EMBED_CACHE_DIR.isascii()
                        if isinstance(st.DEFAULT_EMBED_CACHE_DIR, str)
                        else True)
        self.assertTrue(st.DEFAULT_EMBED_CACHE_DIR.endswith(
            os.path.join("vulnkb", "embed_cache")))


if __name__ == "__main__":
    unittest.main()
