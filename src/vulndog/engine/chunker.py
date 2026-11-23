"""WD-E3 -- production chunker (design-spec 5.2, plan A3).

Rules (exactly as designed):
- NO tokenizer dependency (C4): conservative character-based estimate
  ~4 chars/token (ASCII-weighted), rounded up.
- Chunks are cut at FIELD boundaries (cve/cwe/cwe_category/exploit:
  text_fields entries) or HEADING boundaries (owasp_doc: markdown '#'
  lines), packed greedily BELOW SOFT_CAP_TOKENS=1800 estimated tokens.
- A lone unit above the soft cap rides alone; above HARD_CAP_TOKENS=2000
  it is hard-truncated (<= 2000*4 chars) and flagged ``truncated``.
- E3 cleanup lives HERE (design 4.1: HTML entities are FLAGGED in F1 and
  cleaned in E3): html.unescape + NBSP + whitespace normalization run
  BEFORE sizing, so caps are judged on cleaned text.
- Doc-prefix discipline hook: every chunk carries record_id + part
  index (``chunk_index``/``parts_total``); ``embed_text()`` applies the
  EmbeddingGemma DOCUMENT prefix -- the query prefix must NEVER touch
  corpus chunks (C16); the constant is exported only so tests/guards
  can assert its absence.
- ``poc_body`` is NEVER chunked in v1 (index-only per design 4.2).
- ``excluded_from_index`` records and empty-after-cleaning text yield
  ZERO chunks (the store keeps the record; the embedding index does
  not). A3 length floor: ``min_total_tokens`` (config, A4 carries it).

The P0 benchmark module ``chunking.py`` stays untouched; this is the
production module (adds cleanup, prefix hook, floor, poc law, parts
metadata). Pure stdlib.
"""
from __future__ import annotations

import html as _html
import re

CHARS_PER_TOKEN = 4
SOFT_CAP_TOKENS = 1800
HARD_CAP_TOKENS = 2000

#: A3 length floor (config): records whose TOTAL cleaned embeddable text
#: estimates below this produce no chunks (skipped, countable by callers).
MIN_TOTAL_TOKENS_DEFAULT = 1

#: EmbeddingGemma trained prefixes (design 5.1). Documents ONLY here;
#: QUERY_PREFIX is exported solely so guards/tests can assert it is
#: never applied to corpus chunks (C16).
DOC_PREFIX = "title: none | text: "
QUERY_PREFIX = "task: search result | query: "

_HEADING_KINDS = {"owasp_doc"}
_HWS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n{3,}")


def estimate_tokens(text: str) -> int:
    """Conservative ~4 chars/token estimate, rounded up."""
    return -(-len(text) // CHARS_PER_TOKEN)


def clean_text(text: str) -> str:
    """A3 cleanup: decode HTML entities, fold NBSP, normalize whitespace
    (horizontal runs -> single space; 3+ newlines -> blank line)."""
    if not text:
        return ""
    s = _html.unescape(text)
    s = s.replace("\xa0", " ")
    s = _HWS_RE.sub(" ", s)
    s = _NL_RE.sub("\n\n", s)
    return s.strip()


def split_heading_units(body: str):
    """Split markdown at heading ('#' line) boundaries; text before the
    first heading becomes its own unit. Runs on RAW text (structure
    first, cleanup per-unit afterwards)."""
    units = []
    current = []
    for line in body.split("\n"):
        if line.startswith("#") and current:
            units.append("\n".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        units.append("\n".join(current))
    return [u for u in units if u.strip()]


def units_for(record: dict):
    """Boundary units per kind: heading boundaries for owasp_doc, field
    boundaries otherwise. poc_body is NEVER a unit (v1 law)."""
    fields = [f for f in record.get("text_fields") or []
              if isinstance(f, str) and f.strip()]
    if record.get("kind") in _HEADING_KINDS:
        units = []
        for f in fields:
            units.extend(split_heading_units(f))
        return units
    return fields


def _pack(units, soft_cap: int, hard_cap: int):
    """Greedily pack whole units below the soft cap; oversize units ride
    alone; above the hard cap -> truncate + flag. (P0-proven algorithm.)"""
    chunks = []
    buf = ""
    for unit in units:
        candidate = unit if not buf else buf + "\n" + unit
        if estimate_tokens(candidate) <= soft_cap:
            buf = candidate
            continue
        if buf:
            chunks.append((buf, False))
            buf = ""
        if estimate_tokens(unit) <= soft_cap:
            buf = unit
        elif estimate_tokens(unit) <= hard_cap:
            chunks.append((unit, False))
        else:
            chunks.append((unit[:hard_cap * CHARS_PER_TOKEN], True))
    if buf:
        chunks.append((buf, False))
    return chunks


def chunk_record(record: dict, soft_cap: int = SOFT_CAP_TOKENS,
                 hard_cap: int = HARD_CAP_TOKENS,
                 min_total_tokens: int = MIN_TOTAL_TOKENS_DEFAULT) -> list:
    """Normalize one F1 record into embeddable chunks.

    Returns a list of dicts: record_id, kind, chunk_index (part index),
    parts_total, text (CLEANED), est_tokens, truncated. Zero chunks for
    excluded_from_index records, empty text, or text below the A3 floor.
    """
    if record.get("excluded_from_index"):
        return []
    cleaned = []
    for unit in units_for(record):
        c = clean_text(unit)
        if c:
            cleaned.append(c)
    if not cleaned:
        return []
    total = estimate_tokens("\n".join(cleaned))
    if total < min_total_tokens:
        return []
    packed = _pack(cleaned, soft_cap, hard_cap)
    out = []
    for text, truncated in packed:
        if not text.strip():
            continue
        out.append({
            "record_id": record.get("id", ""),
            "kind": record.get("kind", ""),
            "chunk_index": 0,  # re-indexed below
            "parts_total": 0,
            "text": text,
            "est_tokens": estimate_tokens(text),
            "truncated": truncated,
        })
    for i, c in enumerate(out):
        c["chunk_index"] = i
        c["parts_total"] = len(out)
    return out


def embed_text(chunk: dict) -> str:
    """Doc-prefix discipline hook (C16): the DOCUMENT prefix, and never
    the query prefix, is what reaches Ollama for corpus chunks. The F2
    client (P3) composes prefix+text via this hook."""
    return DOC_PREFIX + chunk["text"]
