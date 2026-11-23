"""WD-E7 -- the KB query API (design-spec 5.3, plan A8).

The watchdog's ONLY KB door (K2 routing: in-repo SQLite; removes the
"stack down" live-matching failure mode). Contract:

    match(text, top_k=3, filters=None) ->
        {"status": "ok" | "skipped" | "disabled",
         "reason": None | str,
         "matches": [{record_id, kind, title, score, reason, cwe_ids,
                      owasp_categories, cvss, exploit_available,
                      matched_snippet(<=200 chars)}],
         "prefilter_hits": int, "pinned": int,
         "corpus_version": str | None}

Retrieval law (5.3.3, P0-measured path): FTS5 BM25 prefilter top-500
over chunk text -> pure-Python cosine re-rank (stored vectors are
unit-normalized f32, so dot == cosine) -> top-K (default 3) with score
floor (default 0.55 -- DEFAULT-TO-CALIBRATE, config; P0/B6 calibrates
before the number is trusted).

FTS5 MATCH construction (Security C-4/SEC-12): the UNTRUSTED text is
tokenized into individually double-quoted alphanumeric terms with all
FTS5 syntax stripped (reuses the P0-proven kb_index.fts_match_query
discipline) -- untrusted input can never steer query shape (OR/NEAR/
column filters) or raise malformed-query errors.

Exact-id pin law (5.3.5): verbatim CVE-\\d{4}-\\d{4,} / CWE-\\d+ tokens
in the text pin those records (reason="exact-id") IN ADDITION to the
semantic top-K; pins bypass the score floor and the filters (documented
A8 choice: a named id is the operator's explicit intent); unknown ids
are ignored; the pin count is bounded (MAX_PINS).

Failure semantics (C-4, section 7):
- STORE-level failure (missing/corrupt/schema-mismatch) -> status
  "disabled" with an explicit reason -- NEVER a crash, NEVER a raise;
- PER-EVENT errors (query embed failure, sqlite error mid-query) ->
  status "skipped" + ``skipped_events`` counter; the API stays usable
  for the next event (no global disable);
- Connections are opened PER CALL and closed in ``finally``: holding a
  connection would block the stage-2 atomic store swap on Windows
  (measured: test_store.py::test_swap_while_reader_open_windows_semantics)
  and per-call opening makes swaps visible immediately (auto-detect,
  section 7 "KB cold/missing" recovery row).

Prefix law (C16): the query text goes to Ollama with the QUERY prefix
only (the F2 client applies it inside embed_query); query vectors are
TRANSIENT -- the default embedder runs with use_cache=False and a temp
cache dir, so query vectors are never persisted (design section 6).

Pure stdlib. Loopback-only by construction (embedder is the F2 client).
"""
from __future__ import annotations

import json
import re
import sqlite3
import tempfile

from . import embed_client as _ec
from . import kb_index
from . import store as _store
from . import vecmath

DEFAULT_TOP_K = 3
#: DEFAULT-TO-CALIBRATE (design 5.3.4): 0.55 until P0/B6 positive+
#: negative control calibration says otherwise.
DEFAULT_SCORE_FLOOR = 0.55
PREFILTER_LIMIT = 500
MAX_PINS = 32
SNIPPET_CHARS = 200

CVE_PIN_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
CWE_PIN_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)

_ALLOWED_FILTERS = ("kind", "min_cvss", "exploit_available", "cwe_id")

_RECORD_COLS = ("r.id, r.kind, r.title, r.cvss_score, r.cvss_severity,"
                " r.cvss_vector, r.exploit_available, r.cwe_ids,"
                " r.owasp_categories")


def build_fts_query(text: str, max_terms: int = 64) -> str:
    """SAFE FTS5 MATCH expression from untrusted text (SEC C-4).

    Single implementation = the P0-recall-measured kb_index discipline:
    alphanumeric tokens only, each individually double-quoted,
    OR-joined, deduped, capped. "" when the text has no tokens."""
    return kb_index.fts_match_query(text, max_terms=max_terms)


def extract_pin_ids(text: str) -> list:
    """Verbatim exact-id tokens -> store ids (CVE upper, cwe lower).

    Order: CVE tokens first then CWE tokens, first-occurrence order,
    deduped, capped at MAX_PINS (a pathological event text can never
    blow the pin lookup up)."""
    if not isinstance(text, str) or not text:
        return []
    out = []
    for m in CVE_PIN_RE.finditer(text):
        v = m.group(0).upper()
        if v not in out:
            out.append(v)
    for m in CWE_PIN_RE.finditer(text):
        v = "cwe-" + m.group(0)[4:].lower()
        if v not in out:
            out.append(v)
    return out[:MAX_PINS]


def make_transient_embedder(cache_dir: str = None):
    """Default query-side F2 client: TRANSIENT query vectors
    (use_cache=False, temp cache dir), QUERY prefix applied internally
    by embed_query (C16), 10 s timeout + bounded retries (C-3)."""
    d = cache_dir or tempfile.mkdtemp(prefix="vkb-query-")
    return _ec.EmbeddingClient(cache_dir=d, use_cache=False)


def _json_list(value):
    try:
        out = json.loads(value) if value else []
        return out if isinstance(out, list) else []
    except (ValueError, TypeError):
        return []


def _cvss_out(score, severity, vector):
    if score is None and not severity and not vector:
        return None
    out = {}
    if score is not None:
        out["score"] = score
    if severity:
        out["severity"] = severity
    if vector:
        out["vector"] = vector
    return out or None


def _match_out(rid, kind, title, score, reason, cwe_ids, owasp,
               cvss, exploit_available, snippet):
    return {
        "record_id": rid,
        "kind": kind,
        "title": title or "",
        "score": round(float(score), 6),
        "reason": reason,
        "cwe_ids": cwe_ids,
        "owasp_categories": owasp,
        "cvss": cvss,
        "exploit_available": bool(exploit_available),
        "matched_snippet": (snippet or "")[:SNIPPET_CHARS],
    }


def _row_to_meta(row):
    (rid, kind, title, cvss_score, cvss_sev, cvss_vec,
     exploit_available, cwe_ids, owasp) = row
    return {
        "record_id": rid, "kind": kind, "title": title,
        "cvss": _cvss_out(cvss_score, cvss_sev, cvss_vec),
        "exploit_available": exploit_available,
        "cwe_ids": _json_list(cwe_ids),
        "owasp_categories": _json_list(owasp),
    }


def _filter_sql(filters):
    """filters dict -> (sql_fragment, params). ValueError on unknown keys
    (caller-side programming error, NOT untrusted input)."""
    if not filters:
        return "", ()
    bad = [k for k in filters if k not in _ALLOWED_FILTERS]
    if bad:
        raise ValueError(
            f"unknown filter keys: {bad} (allowed: {_ALLOWED_FILTERS})")
    clauses, params = [], []
    if "kind" in filters:
        kinds = filters["kind"]
        kinds = [kinds] if isinstance(kinds, str) else list(kinds)
        clauses.append("r.kind IN (%s)" % ",".join("?" * len(kinds)))
        params.extend(kinds)
    if "min_cvss" in filters:
        clauses.append("r.cvss_score IS NOT NULL AND r.cvss_score >= ?")
        params.append(float(filters["min_cvss"]))
    if "exploit_available" in filters:
        clauses.append("r.exploit_available = ?")
        params.append(1 if filters["exploit_available"] else 0)
    if "cwe_id" in filters:
        cwe = str(filters["cwe_id"]).strip().lower()
        if not re.fullmatch(r"cwe-\d+", cwe):
            raise ValueError(f"bad cwe_id filter: {cwe!r}")
        # compact sorted JSON storage makes the quoted-id LIKE reliable
        clauses.append("r.cwe_ids LIKE ?")
        params.append(f'%"{cwe}"%')
    return (" AND " + " AND ".join(clauses)) if clauses else "", tuple(params)


class QueryAPI:
    """The A8 contract holder. Thread-affinity note: one instance per
    process/thread; connections are per-call so instances are safe to
    keep across a store swap (the next match() sees the new store)."""

    def __init__(self, store_path: str = _store.DEFAULT_STORE_PATH,
                 embedder=None, top_k: int = DEFAULT_TOP_K,
                 floor: float = DEFAULT_SCORE_FLOOR,
                 prefilter_limit: int = PREFILTER_LIMIT):
        self.store_path = store_path
        self._embedder = embedder  # None -> transient client, lazily
        self.top_k = int(top_k)
        self.floor = float(floor)
        self.prefilter_limit = int(prefilter_limit)
        self.skipped_events = 0

    # -- embedder
    @property
    def embedder(self):
        if self._embedder is None:
            self._embedder = make_transient_embedder()
        return self._embedder

    # -- connection (per call; StoreError -> DISABLED mapping)
    def _open_conn(self):
        return _store.open_store(self.store_path)

    # -- the contract
    def match(self, text, top_k: int = None, filters=None,
              floor: float = None, prefilter_limit: int = None) -> dict:
        """Never raises for store/query/embed failures (see module
        docstring). ValueError only for bad caller-side filters."""
        top_k = self.top_k if top_k is None else int(top_k)
        floor = self.floor if floor is None else float(floor)
        limit = self.prefilter_limit if prefilter_limit is None \
            else int(prefilter_limit)
        text = text if isinstance(text, str) else str(text or "")

        # bad filters are a CALLER programming error, not a per-event
        # skip: validated outside the try so ValueError propagates
        filter_sql, filter_params = _filter_sql(filters)

        disabled = self._disabled_envelope(text)
        if disabled is not None:
            return disabled

        conn = None
        try:
            conn = self._open_conn()
            return self._match_conn(conn, text, top_k, floor, limit,
                                    filter_sql, filter_params)
        except _store.StoreError as exc:
            return self._envelope("disabled", exc.reason)
        except sqlite3.Error as exc:
            self.skipped_events += 1
            return self._envelope("skipped", "query-error",
                                  detail=str(exc)[:200])
        except Exception as exc:  # noqa: BLE001 -- never crash the caller
            self.skipped_events += 1
            return self._envelope("skipped", "internal-error",
                                  detail=repr(exc)[:200])
        finally:
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass

    def close(self) -> None:
        """No persistent resources (per-call connections); kept for
        interface symmetry with P4 lifecycle code."""
        return None

    # -- internals
    def _disabled_envelope(self, text):
        """Cheap pre-check so a missing store never even reaches the
        embedder (per-event cost discipline for P4 capture-only mode)."""
        import os
        if not os.path.exists(self.store_path):
            return self._envelope("disabled", "store-missing")
        return None

    def _envelope(self, status, reason, matches=None, prefilter_hits=0,
                  pinned=0, corpus_version=None, detail=None):
        env = {"status": status, "reason": reason,
               "matches": matches if matches is not None else [],
               "prefilter_hits": prefilter_hits, "pinned": pinned,
               "corpus_version": corpus_version}
        if detail:
            env["detail"] = detail
        return env

    def _match_conn(self, conn, text, top_k, floor, limit,
                    filter_sql="", filter_params=()):
        cv_row = conn.execute("SELECT value FROM meta "
                              "WHERE key='corpus_version'").fetchone()
        corpus_version = cv_row[0] if cv_row else None

        pins = extract_pin_ids(text)
        fts_q = build_fts_query(text)
        if not fts_q and not pins:
            return self._envelope("ok", None, corpus_version=corpus_version)

        # 1) query vector (per-event failure -> SKIP, not disable)
        try:
            qvec = self.embedder.embed_query(text)
        except Exception as exc:  # noqa: BLE001 (EmbeddingError et al.)
            self.skipped_events += 1
            return self._envelope("skipped", "embed-failed",
                                  corpus_version=corpus_version,
                                  detail=repr(exc)[:200])
        qn = vecmath.normalize(qvec)
        if qn is None:
            self.skipped_events += 1
            return self._envelope("skipped", "embed-invalid",
                                  corpus_version=corpus_version)

        # 2) FTS5 BM25 prefilter (top-500) + filters, then cosine re-rank
        semantic_best = {}
        prefilter_hits = 0
        if fts_q:
            rowids = [r[0] for r in conn.execute(
                "SELECT rowid FROM chunks_fts WHERE chunks_fts MATCH ?"
                " ORDER BY rank LIMIT ?", (fts_q, limit)).fetchall()]
            prefilter_hits = len(rowids)
            if rowids:
                qmarks = ",".join("?" * len(rowids))
                sql = (
                    "SELECT c.record_id, c.text, c.vec, " + _RECORD_COLS +
                    " FROM chunks c JOIN records r ON r.id = c.record_id"
                    " WHERE c.id IN (%s)%s" % (qmarks, filter_sql))
                for row in conn.execute(sql, tuple(rowids) + filter_params):
                    rid, ctext, cblob = row[0], row[1], row[2]
                    meta = _row_to_meta(row[3:])
                    score = vecmath.dot(qn, _store.unpack_vector(cblob))
                    prev = semantic_best.get(rid)
                    if prev is None or score > prev[0]:
                        semantic_best[rid] = (score, ctext, meta)

        # 3) exact-id pins (bypass floor AND filters -- pin law)
        pin_entries = []
        if pins:
            pin_entries = self._pin_entries(conn, pins, qn, semantic_best)

        # 4) semantic top-K with floor (pinned ids removed: one entry)
        pinned_ids = {e["record_id"] for e in pin_entries}
        sem = [(rid, s, snip, meta)
               for rid, (s, snip, meta) in semantic_best.items()
               if s >= floor and rid not in pinned_ids]
        sem.sort(key=lambda t: (-t[1], t[0]))
        sem_entries = [
            _match_out(rid, meta["kind"], meta["title"], s, "semantic",
                       meta["cwe_ids"], meta["owasp_categories"],
                       meta["cvss"], meta["exploit_available"], snip)
            for rid, s, snip, meta in sem[:max(0, top_k)]]

        matches = pin_entries + sem_entries
        return self._envelope("ok", None, matches=matches,
                              prefilter_hits=prefilter_hits,
                              pinned=len(pin_entries),
                              corpus_version=corpus_version)

    def _pin_entries(self, conn, pins, qn, semantic_best):
        qmarks = ",".join("?" * len(pins))
        metas = {}
        for row in conn.execute(
                "SELECT " + _RECORD_COLS + " FROM records r"
                " WHERE r.id IN (%s)" % qmarks, tuple(pins)):
            m = _row_to_meta(row)
            metas[m["record_id"]] = m
        # best chunk per pinned record (pins bypass the prefilter: a
        # pinned record is fetched WHATEVER the FTS overlap is)
        best_chunk = {}
        for rid in metas:
            for ctext, cblob in conn.execute(
                    "SELECT text, vec FROM chunks WHERE record_id=?"
                    " ORDER BY part LIMIT 64", (rid,)):
                score = vecmath.dot(qn, _store.unpack_vector(cblob))
                prev = best_chunk.get(rid)
                if prev is None or score > prev[0]:
                    best_chunk[rid] = (score, ctext)
        entries = []
        for rid in pins:  # preserve first-occurrence order pre-sort
            if rid not in metas:
                continue  # unknown id -> ignored (never an error)
            meta = metas[rid]
            sem_hit = semantic_best.get(rid)
            chunk_score, snippet = best_chunk.get(rid, (0.0, None))
            if sem_hit is not None and sem_hit[0] > chunk_score:
                chunk_score = sem_hit[0]
            if snippet is None:
                snippet = sem_hit[1] if sem_hit else meta["title"]
            entries.append((chunk_score, rid, meta, snippet))
        entries.sort(key=lambda t: (-t[0], t[1]))
        return [_match_out(rid, meta["kind"], meta["title"], score,
                           "exact-id", meta["cwe_ids"],
                           meta["owasp_categories"], meta["cvss"],
                           meta["exploit_available"], snippet)
                for score, rid, meta, snippet in entries]


# --------------------------------------------------------------------------
# module-level convenience (plan A8 interface draft)
# --------------------------------------------------------------------------

_DEFAULT_API = None


def get_default_api(store_path: str = _store.DEFAULT_STORE_PATH,
                    embedder=None, **kw) -> QueryAPI:
    """Process-wide lazy default API (the P4 matching loop's door)."""
    global _DEFAULT_API
    if _DEFAULT_API is None:
        _DEFAULT_API = QueryAPI(store_path=store_path, embedder=embedder,
                                **kw)
    return _DEFAULT_API


def reset_default_api() -> None:
    global _DEFAULT_API
    if _DEFAULT_API is not None:
        try:
            _DEFAULT_API.close()
        finally:
            _DEFAULT_API = None


def match(text, top_k: int = DEFAULT_TOP_K, filters=None,
          api: QueryAPI = None, **kw) -> dict:
    """One-shot convenience wrapper over the default (or given) API."""
    a = api if api is not None else get_default_api()
    return a.match(text, top_k=top_k, filters=filters, **kw)
