"""Walkthrough case 3 — custom records (docs/VULNERABILITY-DB.md Step 6).

The documented surface is library-level (v1 has no CLI ingestion flag;
`db build` reads exactly the four archives): custom records go through
record_schema.normalize_record (ids/kinds/patterns enforced), then the
SAME pipeline doors the build uses — joiner.attach_joins,
chunker.chunk_record, the embedder, store.StagedStore — and db verify
gates the result. This file pins that end-to-end on sample inputs.
"""
from __future__ import annotations

import pytest

from vulndog.engine import chunker, corpus, extractors, joiner
from vulndog.engine import owasp_map as om
from vulndog.engine import record_schema as rs
from vulndog.engine import store as st
from vulndog.engine import embed_client as ec
from vulndog.db import integrity
from tests.db_fixture import FakeTransport

CUSTOM = {
    "id": "CVE-2026-11111", "kind": "cve",
    "title": "Stranger custom XSS in widget",
    "text_fields": ["A custom record added by an operator: reflected "
                    "XSS in the widget parameter."],
    "cwe_ids": ["CWE-79"], "cvss": {"score": 8.2, "severity": "HIGH"},
    "evidence": {"src": "operator-note", "note": "custom record"},
    "confidence": "documented",
}


def test_valid_custom_record_normalized():
    rec, errors, anomalies = rs.normalize_record(CUSTOM)
    assert errors == [] and rec is not None
    assert rec["id"] == "CVE-2026-11111"
    assert rec["cwe_ids"] == ["cwe-79"]
    assert rec["excluded_from_index"] is False


@pytest.mark.parametrize("over,code", [
    ({"id": "CVE-26-1"}, "id_format"),
    ({"id": "not-a-cve"}, "id_format"),
    ({"kind": "malware"}, "unknown_kind"),
    ({"title": ""}, "missing:title"),
    ({"evidence": {"src": "cvejson.json", "note": "x"}}, "excluded_source"),
    ({"confidence": "guessed"}, "bad_confidence"),
], ids=["short-id", "non-canonical-id", "unknown-kind", "empty-title",
        "d6-excluded-source", "bad-confidence"])
def test_schema_enforced_on_custom_records(over, code):
    rec, errors, _ = rs.normalize_record({**CUSTOM, **over})
    assert rec is None
    assert any(code in e for e in errors), errors


def test_custom_record_end_to_end_identical_treatment(wt_raw, tmp_path):
    """One extracted record + one custom record through the SAME doors:
    join -> chunk -> embed -> StagedStore -> manifest -> db verify."""
    # an extracted record, straight from the engine's own extractor
    stats = extractors.ExtractStats("cvelistV5")
    extracted = next(extractors.iter_cve_records(
        str(wt_raw / "cvelistV5-main.zip"), stats))
    custom, errors, _ = rs.normalize_record(CUSTOM)
    assert errors == []

    index = joiner.JoinIndex()
    index.add_cwe({"id": "cwe-79", "kind": "cwe", "title": "XSS"})
    table = om.load_map()
    store_dir = tmp_path / "kb"
    store_dir.mkdir()
    dest = str(store_dir / st.STORE_FILENAME)
    embedder = ec.EmbeddingClient(cache_dir=str(store_dir / "embed_cache"),
                                  transport=FakeTransport(), max_retries=0,
                                  retry_backoff_s=0)
    cv = "vkb1-stranger-custom"
    n_chunks = 0
    with st.StagedStore(dest) as s:
        for rec in (extracted, custom):
            joined, _dangling = joiner.attach_joins(rec, index, table)
            joined["corpus_version"] = cv
            s.add_record(joined)
            chunks = chunker.chunk_record(joined, min_total_tokens=1)
            for c in chunks:
                vec = embedder.embed_documents([c["text"]])[0]
                s.add_chunk(joined["id"], c["chunk_index"],
                            c["parts_total"], c["text"], vec,
                            c["est_tokens"], c["truncated"])
                n_chunks += 1
        manifest = {
            "manifest_version": 1, "corpus_version": cv, "stage": "slice",
            "recipe": {"recipe_id": "stranger-custom",
                       "recipe_version": "1.0.0"},
            "inputs": {},
            "counts": {"records_total": 2, "chunks_total": n_chunks,
                       "records_by_kind": {"cve": 2},
                       "chunks_by_kind": {"cve": n_chunks}},
        }
        s.finish(manifest)
        s.swap_into_dest()
    corpus.write_manifest_atomic(str(store_dir / st.MANIFEST_FILENAME),
                                 manifest)
    integrity.stamp_store_digest(str(store_dir))

    result = integrity.verify_store(dest)
    assert result["ok"], result["checks"]
    info = integrity.store_info(dest)
    assert info["db_counts"]["records_total"] == 2
    assert info["db_counts"]["records_by_kind"] == {"cve": 2}
    # the custom record is a first-class store row
    conn = st.open_store(dest)
    try:
        row = conn.execute("SELECT title FROM records WHERE id=?",
                           ("CVE-2026-11111",)).fetchone()
    finally:
        conn.close()
    assert row is not None and "widget" in row[0]