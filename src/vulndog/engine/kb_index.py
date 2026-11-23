"""SQLite+FTS5 KB index for the P0 latency/recall benchmarks (design 5.3).

Retrieval mechanics implemented exactly as specified:
- FTS5 token prefilter, top-500 by BM25 (``ORDER BY rank``);
- cosine re-rank in pure Python over the prefiltered candidates only
  (stored vectors are unit-normalized float32, so dot == cosine);
- top-K with a score floor;
- FTS5 MATCH construction (Security C-4/SEC-12): the query text is
  tokenized to alphanumeric terms, each individually double-quoted and
  OR-joined -- untrusted text can never steer query shape (OR/NEAR/column
  filters) or raise malformed-query errors; a per-event query error is a
  per-event SKIP (``skipped: True``), never a global failure.

Benchmark-scoped: this is NOT the A6/A8 store (P3 work); it is the
measurement vehicle for prefilter+re-rank latency and recall@500.
"""
from __future__ import annotations

import re
import sqlite3
from array import array

from . import vecmath

PREFILTER_LIMIT = 500
TOP_K = 3
SCORE_FLOOR = 0.55
_TERM_RE = re.compile(r"[A-Za-z0-9]+")


def fts_match_query(text: str, max_terms: int = 64) -> str:
    """Build a SAFE FTS5 MATCH expression from untrusted text.

    Alphanumeric tokens only, each double-quoted, OR-joined, deduped
    (first occurrence wins), capped at max_terms. Empty string when the
    text carries no tokens (caller treats it as no-candidates, not error).
    """
    seen = set()
    terms = []
    for tok in _TERM_RE.findall(text):
        low = tok.lower()
        if low in seen:
            continue
        seen.add(low)
        terms.append('"%s"' % tok)
        if len(terms) >= max_terms:
            break
    return " OR ".join(terms)


def build_index(db_path: str, chunks, vectors, page_size_kb: int = 64) -> None:
    """Create (or overwrite) the benchmark KB at db_path.

    chunks: dicts with record_id/kind/chunk_index/text; vectors: same-length
    list of float sequences. Vectors are unit-normalized and stored as
    float32 blobs. Rowids are 1-based in chunk order.
    """
    import os
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA page_size = %d" % (page_size_kb * 1024))
        conn.execute("PRAGMA journal_mode = OFF")
        conn.execute("PRAGMA synchronous = OFF")
        conn.execute(
            "CREATE TABLE chunks (id INTEGER PRIMARY KEY, record_id TEXT,"
            " kind TEXT, chunk_index INTEGER, text TEXT, vec BLOB)")
        conn.execute("CREATE VIRTUAL TABLE chunks_fts USING fts5(text)")
        rows = []
        fts_rows = []
        for i, (c, v) in enumerate(zip(chunks, vectors), start=1):
            unit = vecmath.normalize(v)
            if unit is None:
                unit = [0.0] * len(v)
            blob = array("f", unit).tobytes()
            rows.append((i, c["record_id"], c.get("kind", ""),
                         c.get("chunk_index", 0), c["text"], blob))
            fts_rows.append((i, c["text"]))
        conn.executemany("INSERT INTO chunks VALUES (?,?,?,?,?,?)", rows)
        conn.executemany("INSERT INTO chunks_fts (rowid, text) VALUES (?,?)", fts_rows)
        conn.commit()
    finally:
        conn.close()


def open_index(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA query_only = ON")
    return conn


def index_size(conn) -> int:
    return conn.execute("SELECT count(*) FROM chunks").fetchone()[0]


def prefilter(conn, query_text: str, limit: int = PREFILTER_LIMIT):
    """FTS5 BM25 prefilter -> list of rowids (best first). [] on no tokens."""
    q = fts_match_query(query_text)
    if not q:
        return []
    cur = conn.execute(
        "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?"
        " ORDER BY rank LIMIT ?", (q, limit))
    return [r[0] for r in cur.fetchall()]


def load_vectors(conn, rowids):
    """rowids -> {rowid: unit vector list}. One indexed fetch."""
    out = {}
    if not rowids:
        return out
    qmarks = ",".join("?" * len(rowids))
    cur = conn.execute(
        "SELECT id, vec FROM chunks WHERE id IN (%s)" % qmarks, tuple(rowids))
    for rid, blob in cur.fetchall():
        a = array("f")
        a.frombytes(blob)
        out[rid] = a.tolist()
    return out


def load_all_vectors(conn):
    out = {}
    cur = conn.execute("SELECT id, vec FROM chunks")
    for rid, blob in cur.fetchall():
        a = array("f")
        a.frombytes(blob)
        out[rid] = a.tolist()
    return out


def rerank(conn, rowids, query_vec, top_k: int = TOP_K, floor: float = SCORE_FLOOR):
    """Pure-Python cosine re-rank over prefiltered rowids (vectors already
    unit-normalized at index time, so dot == cosine). Floor + top-K applied.
    """
    qn = vecmath.normalize(query_vec)
    if qn is None or not rowids:
        return []
    vecs = load_vectors(conn, rowids)
    meta = {}
    qmarks = ",".join("?" * len(rowids))
    cur = conn.execute(
        "SELECT id, record_id, kind, chunk_index FROM chunks WHERE id IN (%s)"
        % qmarks, tuple(rowids))
    for rid, record_id, kind, ci in cur.fetchall():
        meta[rid] = (record_id, kind, ci)
    scored = []
    for rid, v in vecs.items():
        s = vecmath.dot(qn, v)
        if s >= floor:
            record_id, kind, ci = meta[rid]
            scored.append({"rowid": rid, "record_id": record_id, "kind": kind,
                           "chunk_index": ci, "score": s})
    scored.sort(key=lambda d: d["score"], reverse=True)
    return scored[:top_k]


def match(conn, query_text: str, query_vec, top_k: int = TOP_K,
          floor: float = SCORE_FLOOR, limit: int = PREFILTER_LIMIT) -> dict:
    """Full retrieval step: FTS prefilter -> cosine re-rank -> top-K.

    Per-event query errors are SKIPS (skipped: True), never raised
    (Security C-4: a malformed per-event query must not disable the KB).
    """
    try:
        hits = prefilter(conn, query_text, limit=limit)
        cands = rerank(conn, hits, query_vec, top_k=top_k, floor=floor)
        return {"candidates": cands, "prefilter_hits": len(hits), "skipped": False}
    except sqlite3.Error:
        return {"candidates": [], "prefilter_hits": 0, "skipped": True}
