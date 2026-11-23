"""Corpus chunking policy (design-spec 5.2 / plan A3).

Rules implemented exactly as specified:
- No tokenizer dependency (C4): conservative character-based token estimate
  at ~4 chars/token (ASCII-weighted).
- Chunks are cut at FIELD boundaries (cve/cwe/exploit: text_fields entries)
  or HEADING boundaries (owasp_doc: markdown '#' lines), packed greedily
  below SOFT_CAP_TOKENS = 1800 estimated tokens.
- A single unit above the soft cap becomes its own chunk; above
  HARD_CAP_TOKENS = 2000 it is hard-truncated and flagged ``truncated``.
- ``poc_body`` is NEVER embedded in v1 (index-only per design 4.2).
"""
from __future__ import annotations

CHARS_PER_TOKEN = 4
SOFT_CAP_TOKENS = 1800
HARD_CAP_TOKENS = 2000
_HEADING_KINDS = {"owasp_doc"}


def estimate_tokens(text: str) -> int:
    """Conservative ~4 chars/token estimate, rounded up."""
    return -(-len(text) // CHARS_PER_TOKEN)


def _split_heading_units(body: str):
    """Split markdown into sections at heading ('#' line) boundaries.

    Text before the first heading (if any) becomes its own unit.
    """
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
    return [u.strip() for u in units if u.strip()]


def _units_for(record: dict):
    kind = record.get("kind", "")
    fields = [f for f in record.get("text_fields") or [] if isinstance(f, str) and f.strip()]
    if kind in _HEADING_KINDS:
        units = []
        for f in fields:
            units.extend(_split_heading_units(f))
        return units
    return fields


def _pack(units):
    """Greedily pack whole units into chunks <= SOFT_CAP; oversize units go
    alone and are hard-truncated at HARD_CAP with the truncated flag."""
    chunks = []
    buf = ""
    for unit in units:
        candidate = unit if not buf else buf + "\n" + unit
        if estimate_tokens(candidate) <= SOFT_CAP_TOKENS:
            buf = candidate
            continue
        if buf:
            chunks.append((buf, False))
            buf = ""
        if estimate_tokens(unit) <= SOFT_CAP_TOKENS:
            buf = unit
        elif estimate_tokens(unit) <= HARD_CAP_TOKENS:
            chunks.append((unit, False))
        else:
            chunks.append((unit[:HARD_CAP_TOKENS * CHARS_PER_TOKEN], True))
    if buf:
        chunks.append((buf, False))
    return chunks


def chunk_record(record: dict):
    """Normalize one corpus record into embeddable chunks.

    Returns a list of dicts: record_id, kind, chunk_index, text, est_tokens,
    truncated. Empty/blank records yield no chunks (never embed empty text).
    """
    units = _units_for(record)
    packed = _pack(units)
    out = []
    for idx, (text, truncated) in enumerate(packed):
        if not text.strip():
            continue
        out.append({
            "record_id": record.get("id", ""),
            "kind": record.get("kind", ""),
            "chunk_index": idx,
            "text": text,
            "est_tokens": estimate_tokens(text),
            "truncated": truncated,
        })
    # re-index contiguously in case a blank chunk was dropped
    for i, c in enumerate(out):
        c["chunk_index"] = i
    return out
