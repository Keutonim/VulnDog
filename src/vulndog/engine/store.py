"""WD-E6 -- the Vuln-KB SQLite store writer (design-spec 3.6, plan A6a/A7).

Store: ``data/vulnkb/vulnkb.sqlite`` (K2, standalone; ASCII path,
C9) + ``manifest.json`` beside it. Tables:
- ``records``  -- F1 fields as columns (JSON list columns for the ref
  arrays) + derived ``exploit_available`` + non-column extras in a
  ``props`` JSON blob. ``text_fields`` is NOT double-stored: chunks
  carry the embeddable text (excluded records have none by definition).
- ``chunks``   -- (record_id, part, parts_total, text, vec f32 BLOB
  768-d unit-normalized, est_tokens, truncated).
- ``chunks_fts`` -- FTS5 EXTERNAL-CONTENT table over chunks.text
  (content='chunks', rowid-aligned; saves the text duplication at
  456k-chunk scale).
- ``meta``     -- key/value: schema_version, corpus_version, manifest
  JSON, built_at.

ATOMIC build/refresh (Security C-5 / SEC-07; precedent
request_budget.py:406-432): everything is written into a STAGED temp DB
in the DEST directory (same volume), integrity-checked, then
``os.replace``-swapped in ONE step. A failed build never leaves a
partial vulnkb.sqlite; the previous store survives until the swap
completes; the staged temp is cleaned on any failure.

Refresh (plan A7 skeleton; procedure doc + drill land in P4):
``apply_delta`` upserts F1 records BY ID into a COPY of the current
store (staged temp), re-chunks + re-embeds only the changed records
(sha cache makes unchanged text free), rebuilds the FTS index from the
content table, keeps a ``.prev`` backup (K2 rollback = restore the
previous store file -- never unknown backups), then swaps atomically.
FULL refresh = a rebuild through the build path (vuln_watchdog.build),
which is idempotent given the same inputs (deterministic corpus).
``parse_deltalog_ids`` is the tolerant deltaLog.json walker feeding the
upsert (cvelistV5 ships deltaLog.json at the archive root; the owner
places new drops manually -- offline contract, C1).

Pure stdlib (sqlite3 + FTS5 verified live in the venv, C4). No rail
functions here: this module never gates, budgets or rate-limits (C2).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import time
import uuid
from array import array

from . import chunker
from . import vecmath

SCHEMA_VERSION = 1

STORE_FILENAME = "vulnkb.sqlite"
MANIFEST_FILENAME = "manifest.json"

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_STORE_DIR = os.path.join(_REPO_ROOT, "data", "vulnkb")
DEFAULT_STORE_PATH = os.path.join(DEFAULT_STORE_DIR, STORE_FILENAME)
DEFAULT_MANIFEST_PATH = os.path.join(DEFAULT_STORE_DIR, MANIFEST_FILENAME)
DEFAULT_EMBED_CACHE_DIR = os.path.join(DEFAULT_STORE_DIR, "embed_cache")

#: staged temp DB prefix (same-dir os.replace atomicity; cleanup target)
STAGED_PREFIX = ".vulnkb-staged-"

#: build pragmas: staging only -- a crash discards the temp DB, so the
#: durability knobs are performance-safe here (P0-proven settings).
BUILD_PAGE_SIZE = 65536

_CVE_ID_RE = re.compile(r"\ACVE-\d{4}-\d{4,}\Z")

# records-table columns <- F1 field mapping (single source of truth for
# add_record / apply_delta / tests)
_COLUMN_FIELDS = (
    "id", "kind", "title", "excluded_from_index", "exploit_available",
    "exploit_verified", "cvss_score", "cvss_severity", "cvss_vector",
    "platform", "type", "confidence", "cwe_ids", "owasp_categories",
    "exploit_refs", "cve_refs", "related_cwe_ids", "dates", "evidence",
    "source_path", "corpus_version", "props",
)
#: F1 keys that live in dedicated columns (everything else -> props)
_PROPIED_KEYS = frozenset({
    "id", "kind", "title", "excluded_from_index", "exploit_verified",
    "cvss", "platform", "type", "confidence", "cwe_ids",
    "owasp_categories", "exploit_refs", "cve_refs", "related_cwe_ids",
    "dates", "evidence", "source_path", "corpus_version",
    "text_fields",  # chunks carry the text -- never double-stored
})

_SCHEMA_SQL = """
CREATE TABLE records (
  id                  TEXT PRIMARY KEY,
  kind                TEXT NOT NULL,
  title               TEXT NOT NULL DEFAULT '',
  excluded_from_index INTEGER NOT NULL DEFAULT 0,
  exploit_available   INTEGER NOT NULL DEFAULT 0,
  exploit_verified    INTEGER,
  cvss_score          REAL,
  cvss_severity       TEXT,
  cvss_vector         TEXT,
  platform            TEXT,
  type                TEXT,
  confidence          TEXT,
  cwe_ids             TEXT NOT NULL DEFAULT '[]',
  owasp_categories    TEXT NOT NULL DEFAULT '[]',
  exploit_refs        TEXT NOT NULL DEFAULT '[]',
  cve_refs            TEXT NOT NULL DEFAULT '[]',
  related_cwe_ids     TEXT NOT NULL DEFAULT '[]',
  dates               TEXT NOT NULL DEFAULT '{}',
  evidence            TEXT NOT NULL DEFAULT '{}',
  source_path         TEXT,
  corpus_version      TEXT,
  props               TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX records_kind ON records(kind);
CREATE INDEX records_cvss_score ON records(cvss_score);
CREATE TABLE chunks (
  id          INTEGER PRIMARY KEY,
  record_id   TEXT NOT NULL,
  part        INTEGER NOT NULL,
  parts_total INTEGER NOT NULL DEFAULT 1,
  est_tokens  INTEGER NOT NULL DEFAULT 0,
  truncated   INTEGER NOT NULL DEFAULT 0,
  text        TEXT NOT NULL,
  vec         BLOB NOT NULL
);
CREATE INDEX chunks_record ON chunks(record_id);
CREATE VIRTUAL TABLE chunks_fts USING fts5(
  text, content='chunks', content_rowid='id'
);
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


class StoreError(RuntimeError):
    """Store-level failure with an explicit machine-readable reason
    (query.py maps these to the DISABLED signal -- never a raw crash)."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


# --------------------------------------------------------------------------
# vector codec (f32 little-endian BLOB)
# --------------------------------------------------------------------------

def pack_vector(vector) -> bytes:
    """Unit-normalize + pack to an f32 BLOB (dot == cosine downstream)."""
    unit = vecmath.normalize(vector)
    if unit is None:
        unit = [0.0] * len(vector)
    return array("f", unit).tobytes()


def unpack_vector(blob) -> list:
    a = array("f")
    a.frombytes(blob or b"")
    return a.tolist()


# --------------------------------------------------------------------------
# record row mapping
# --------------------------------------------------------------------------

def _jsonb(value, default):
    try:
        return json.dumps(value if value is not None else default,
                          ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError):
        return json.dumps(default, separators=(",", ":"))


def exploit_available_for(record: dict) -> int:
    kind = record.get("kind")
    if kind == "exploit":
        return 1
    if kind == "cve":
        return 1 if (record.get("exploit_refs") or []) else 0
    return 0


def record_row(record: dict) -> tuple:
    cvss = record.get("cvss")
    cvss = cvss if isinstance(cvss, dict) else {}
    props = {k: v for k, v in record.items() if k not in _PROPIED_KEYS}
    ev = record.get("exploit_verified")
    return (
        record.get("id", ""),
        record.get("kind", ""),
        record.get("title", "") or "",
        1 if record.get("excluded_from_index") else 0,
        exploit_available_for(record),
        (1 if ev else 0) if isinstance(ev, bool) else None,
        cvss.get("score"),
        cvss.get("severity"),
        cvss.get("vector"),
        record.get("platform"),
        record.get("type"),
        record.get("confidence"),
        _jsonb(record.get("cwe_ids"), []),
        _jsonb(record.get("owasp_categories"), []),
        _jsonb(record.get("exploit_refs"), []),
        _jsonb(record.get("cve_refs"), []),
        _jsonb(record.get("related_cwe_ids"), []),
        _jsonb(record.get("dates"), {}),
        _jsonb(record.get("evidence"), {}),
        record.get("source_path"),
        record.get("corpus_version"),
        _jsonb(props, {}),
    )


_INSERT_RECORD_SQL = (
    "INSERT OR REPLACE INTO records (" + ",".join(_COLUMN_FIELDS) + ")"
    " VALUES (" + ",".join("?" * len(_COLUMN_FIELDS)) + ")")


# --------------------------------------------------------------------------
# staged builder
# --------------------------------------------------------------------------

class StagedStore:
    """Write-once staged builder. Use as a context manager:

        with StagedStore(dest) as s:
            s.add_record(rec); s.add_chunk(...); ...
            s.finish(manifest)
            s.swap_into_dest()

    Any exception (or a forgotten swap) cleans the staged temp file;
    the destination is only ever touched by the final os.replace."""

    def __init__(self, dest_path: str = DEFAULT_STORE_PATH,
                 page_size: int = BUILD_PAGE_SIZE):
        self.dest_path = os.path.abspath(dest_path)
        self.dest_dir = os.path.dirname(self.dest_path)
        os.makedirs(self.dest_dir, exist_ok=True)
        self.staged_path = os.path.join(
            self.dest_dir,
            f"{STAGED_PREFIX}{os.getpid()}-{uuid.uuid4().hex[:8]}.sqlite")
        self.conn = sqlite3.connect(self.staged_path)
        self.conn.execute(f"PRAGMA page_size = {int(page_size)}")
        self.conn.execute("PRAGMA journal_mode = OFF")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.executescript(_SCHEMA_SQL)
        self._chunk_id = 0
        self._finished = False
        self._swapped = False
        self.counts = {"records": 0, "chunks": 0}

    # -- context manager (SEC C-5 cleanup-on-failure)
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.abort_cleanup()
        return False

    # -- writes
    def add_record(self, record: dict) -> None:
        self.conn.execute(_INSERT_RECORD_SQL, record_row(record))
        self.counts["records"] += 1

    def add_chunk(self, record_id: str, part: int, parts_total: int,
                  text: str, vector, est_tokens: int = 0,
                  truncated: bool = False) -> int:
        self._chunk_id += 1
        cid = self._chunk_id
        blob = pack_vector(vector)
        self.conn.execute(
            "INSERT INTO chunks (id, record_id, part, parts_total,"
            " est_tokens, truncated, text, vec)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (cid, record_id, int(part), int(parts_total), int(est_tokens),
             1 if truncated else 0, text, blob))
        # external-content FTS: index the row at its chunks.id rowid
        self.conn.execute(
            "INSERT INTO chunks_fts (rowid, text) VALUES (?,?)",
            (cid, text))
        self.counts["chunks"] += 1
        return cid

    def commit(self) -> None:
        self.conn.commit()

    # -- finalize
    def _integrity_check(self) -> str:
        row = self.conn.execute("PRAGMA integrity_check").fetchone()
        return str(row[0]) if row else "missing-result"

    def finish(self, manifest: dict) -> None:
        """meta rows + commit + integrity check + close. Raises
        StoreError BEFORE any swap when the staged DB is not sound."""
        cv = (manifest or {}).get("corpus_version", "")
        rows = [
            ("schema_version", str(SCHEMA_VERSION)),
            ("corpus_version", str(cv)),
            ("manifest", json.dumps(manifest or {}, ensure_ascii=True,
                                    sort_keys=True)),
            ("built_at", time.strftime("%Y-%m-%dT%H:%M:%S")),
            ("counts", json.dumps(self.counts)),
        ]
        self.conn.executemany(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)", rows)
        self.conn.commit()
        result = self._integrity_check()
        if result != "ok":
            raise StoreError("integrity-check-failed", str(result)[:500])
        self._finished = True
        self.conn.close()

    def swap_into_dest(self, retries: int = 3, backoff_s: float = 0.2) -> None:
        """The single atomic step: os.replace(staged, dest). The previous
        store (if any) survives until this call completes."""
        if not self._finished:
            raise StoreError("swap-before-finish",
                             "finish(manifest) must succeed first")
        last = None
        for attempt in range(max(1, retries)):
            try:
                os.replace(self.staged_path, self.dest_path)
                self._swapped = True
                self.staged_path = None
                return
            except OSError as exc:  # transient AV/indexer locks on win32
                last = exc
                time.sleep(backoff_s * (attempt + 1))
        raise StoreError("swap-failed", repr(last))

    # -- cleanup
    def abort_cleanup(self) -> None:
        """Close + unlink the staged temp (idempotent; post-swap no-op)."""
        try:
            if self.conn is not None:
                self.conn.close()
        except sqlite3.Error:
            pass
        self.conn = None
        if self.staged_path and os.path.exists(self.staged_path):
            try:
                os.unlink(self.staged_path)
            except OSError:
                pass


# --------------------------------------------------------------------------
# read side
# --------------------------------------------------------------------------

def open_store(path: str = DEFAULT_STORE_PATH) -> sqlite3.Connection:
    """Open the built store read-only + validate the schema. Raises
    StoreError with reason in {store-missing, store-corrupt,
    schema-mismatch} -- query.py turns these into the DISABLED signal."""
    if not os.path.exists(path):
        raise StoreError("store-missing", path)
    try:
        conn = sqlite3.connect(path)
        conn.execute("PRAGMA query_only = ON")
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    except sqlite3.DatabaseError as exc:
        raise StoreError("store-corrupt", f"{path}: {exc}") from exc
    if not {"records", "chunks", "meta"} <= tables:
        conn.close()
        raise StoreError("schema-mismatch",
                         f"missing tables in {path}: {sorted(tables)}")
    try:
        row = conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
    except sqlite3.DatabaseError as exc:
        conn.close()
        raise StoreError("store-corrupt", str(exc)) from exc
    if row is None or str(row[0]) != str(SCHEMA_VERSION):
        conn.close()
        raise StoreError(
            "schema-mismatch",
            f"store schema {row[0] if row else None!r} != "
            f"expected {SCHEMA_VERSION}")
    return conn


def read_manifest(conn: sqlite3.Connection):
    row = conn.execute(
        "SELECT value FROM meta WHERE key='manifest'").fetchone()
    if row is None:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return None


# --------------------------------------------------------------------------
# delta refresh (A7 skeleton)
# --------------------------------------------------------------------------

def parse_deltalog_ids(payload) -> list:
    """Tolerant deltaLog walker -> sorted unique CVE ids.

    Accepts the parsed JSON (dict/list) or raw text/bytes. Recognized
    shapes: any nesting level carrying ``cveId`` values that match the
    canonical CVE pattern (deltaLog.json ships {"delta": [{"cveId": ...}]}
    variants across cvelistV5 snapshots). Junk entries are skipped; an
    UNPARSEABLE payload raises StoreError (never a silent [])."""
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode("utf-8", "replace")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError as exc:
            raise StoreError("deltalog-parse", str(exc)) from exc
    if payload is None:
        raise StoreError("deltalog-parse", "payload is None")
    found = set()

    def walk(node, depth=0):
        if depth > 12:
            return
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "cveId" and isinstance(v, str) \
                        and _CVE_ID_RE.match(v.strip().upper()):
                    found.add(v.strip().upper())
                else:
                    walk(v, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    walk(payload)
    return sorted(found)


def apply_delta(dest_path: str, records, embedder,
                corpus_version: str = None, progress=None,
                min_total_tokens: int = 1, backup: bool = True) -> dict:
    """Id-upsert delta refresh (atomic, with a .prev backup).

    ``records``: iterable of F1-normalized records (re-extracted from the
    NEW archive drop for the deltaLog ids). ``embedder``: callable
    list[str] -> list[vector] (the sha-cached client wrapper: unchanged
    text costs zero API calls). Each record REPLACES its id entirely
    (records row + all chunks + FTS entries). The FTS index is rebuilt
    from the content table at the end (external-content tables cannot
    take plain row DELETEs; a full rebuild is the documented skeleton
    cost -- P4's refresh drill measures it). FULL refresh = rebuild via
    vuln_watchdog.build (never an unbounded delta chain)."""
    if not os.path.exists(dest_path):
        raise StoreError("store-missing", dest_path)
    dest_dir = os.path.dirname(os.path.abspath(dest_path))
    staged_path = os.path.join(
        dest_dir,
        f"{STAGED_PREFIX}{os.getpid()}-{uuid.uuid4().hex[:8]}.sqlite")
    conn = None
    try:
        shutil.copy2(dest_path, staged_path)
        conn = sqlite3.connect(staged_path)
        n_up = 0
        n_chunks = 0
        for rec in records:
            rid = rec.get("id", "")
            if not rid:
                continue
            conn.execute("DELETE FROM chunks WHERE record_id=?", (rid,))
            conn.execute("DELETE FROM records WHERE id=?", (rid,))
            conn.execute(_INSERT_RECORD_SQL, record_row(rec))
            chunks = chunker.chunk_record(
                rec, min_total_tokens=min_total_tokens)
            if chunks:
                vectors = embedder([c["text"] for c in chunks])
                if len(vectors) != len(chunks):
                    raise StoreError(
                        "delta-embed-mismatch",
                        f"{len(vectors)} vectors for {len(chunks)} chunks")
                for c, v in zip(chunks, vectors):
                    blob = pack_vector(v)
                    conn.execute(
                        "INSERT INTO chunks (record_id, part, parts_total,"
                        " est_tokens, truncated, text, vec)"
                        " VALUES (?,?,?,?,?,?,?)",
                        (c["record_id"], c["chunk_index"], c["parts_total"],
                         c["est_tokens"], 1 if c["truncated"] else 0,
                         c["text"], blob))
                    n_chunks += 1
            n_up += 1
            if progress and n_up % 100 == 0:
                progress(f"delta: {n_up} records upserted")
        # re-align the external-content FTS index with the chunks table
        conn.execute("INSERT INTO chunks_fts(chunks_fts) VALUES('rebuild')")
        cv = corpus_version
        if cv is None:
            row = conn.execute("SELECT value FROM meta "
                               "WHERE key='corpus_version'").fetchone()
            cv = row[0] if row else ""
        counts = {
            "records": conn.execute(
                "SELECT count(*) FROM records").fetchone()[0],
            "chunks": conn.execute(
                "SELECT count(*) FROM chunks").fetchone()[0],
        }
        conn.executemany(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?,?)",
            [("corpus_version", str(cv)),
             ("refreshed_at", time.strftime("%Y-%m-%dT%H:%M:%S")),
             ("counts", json.dumps(counts))])
        # keep the embedded manifest counts consistent
        row = conn.execute(
            "SELECT value FROM meta WHERE key='manifest'").fetchone()
        if row:
            try:
                man = json.loads(row[0])
                man.setdefault("counts", {})
                man["counts"]["records_total"] = counts["records"]
                man["counts"]["chunks_total"] = counts["chunks"]
                man["corpus_version"] = str(cv)
                man["last_delta"] = {
                    "records_upserted": n_up,
                    "chunks_reembedded": n_chunks,
                    "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES "
                    "('manifest', ?)",
                    (json.dumps(man, ensure_ascii=True, sort_keys=True),))
            except (ValueError, TypeError):
                pass
        conn.commit()
        result = conn.execute("PRAGMA integrity_check").fetchone()
        if not result or str(result[0]) != "ok":
            raise StoreError("integrity-check-failed", str(result)[:500])
        conn.close()
        conn = None
        if backup:
            shutil.copy2(dest_path, dest_path + ".prev")
        os.replace(staged_path, dest_path)
        staged_path = None
        return {"records_upserted": n_up, "chunks_reembedded": n_chunks,
                "corpus_version": cv, "counts": counts}
    finally:
        if conn is not None:
            try:
                conn.close()
            except sqlite3.Error:
                pass
        if staged_path and os.path.exists(staged_path):
            try:
                os.unlink(staged_path)
            except OSError:
                pass
