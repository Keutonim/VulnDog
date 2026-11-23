"""F1 -- canonical vulnerability record schema (design-spec 4.1/4.2).

The contract between extraction (A1), joining (A2), chunking (A3), the
corpus assembler (A4) and the P3 store writer (A6/WD-E6). Pure stdlib,
pure functions, no I/O -- reusable by every pipeline stage.

Laws encoded here (design 4.1 "Validation (F1 DoD)"):
- reject: missing id / unknown kind / confidence outside
  {documented, verified, inferred} / id not matching its kind's canonical
  format / wrong top-level types on contract fields;
- EMPTY text_fields -> record KEPT with ``excluded_from_index=True``
  (NOT a rejection -- supersedes plan F1 DoD item 2 per QA-1 m-3:
  reference kinds without embeddable text, e.g. cwe_category, stay in
  the store);
- cvejson.json is excluded BY RULE (D6): a record whose source_path or
  evidence.src points at it can never enter the corpus;
- HTML entities (e.g. ``&nbsp;``) are FLAGGED (``html_entities=True``)
  for the E3 cleanup pass -- not rejected;
- cwe_ids normalize to ``cwe-<n>``; missing cweId on cve/exploit is a
  KNOWN anomaly (R8) -> empty list + anomaly, never an error.

Error vs anomaly: an ERROR rejects the record (broken contract); an
ANOMALY is a counted data-quality note (real-world feeds) -- the record
survives with the offending fragment dropped. Codes are stable strings
so extractors and the A2 coverage report can aggregate them.

API (consumed by A1-A4 and the P3 store writer):
- ``normalize_record(rec) -> (rec|None, errors, anomalies)`` (never raises)
- ``validate_record(rec) -> errors``   (``[]`` = valid)
- ``is_valid(rec) -> bool``
"""
from __future__ import annotations

import os
import re

KINDS = ("cve", "exploit", "cwe", "cwe_category", "owasp_doc")
CONFIDENCES = ("documented", "verified", "inferred")
DEFAULT_CONFIDENCE = "documented"

# D6: the invalid source (Cloudflare bot-challenge HTML, 0 records).
EXCLUDED_SOURCES = ("cvejson.json",)

# Canonical id formats per kind (design 4.1 field table).
_ID_PATTERNS = {
    "cve": re.compile(r"\ACVE-\d{4}-\d{4,}\Z"),
    "exploit": re.compile(r"\Aedb-\d+\Z"),
    "cwe": re.compile(r"\Acwe-\d+\Z"),
    "cwe_category": re.compile(r"\Acwe-\d+\Z"),
    "owasp_doc": re.compile(
        r"\Aowasp-[A-Za-z0-9][A-Za-z0-9.]*-[A-Za-z0-9][A-Za-z0-9._-]*\Z"),
}

_CWE_REF_RE = re.compile(r"\Acwe-(\d+)\Z")
_CVE_REF_RE = re.compile(r"\ACVE-\d{4}-\d{4,}\Z")
_EDB_REF_RE = re.compile(r"\Aedb-\d+\Z")
_HTML_ENTITY_RE = re.compile(
    r"&(?:[a-zA-Z][a-zA-Z0-9]{1,30}|#[0-9]{1,8}|#[xX][0-9a-fA-F]{1,6});")

# Fields this module validates explicitly; anything else passes through
# untouched (forward compat for the A1-A4 extractors).
_KNOWN_FIELDS = frozenset({
    "id", "kind", "title", "text_fields", "cwe_ids", "cvss", "affected",
    "exploit_refs", "cve_refs", "related_cwe_ids", "owasp_categories",
    "dates", "exploit_verified", "platform", "type", "poc_body",
    "source_path", "corpus_version", "evidence", "confidence",
})


class _RecordTypeError(ValueError):
    """Internal signal: a contract field has the wrong top-level type."""


def _norm_cwe_list(values, code: str, anomalies: list) -> list:
    out = []
    for v in values:
        if isinstance(v, str):
            m = _CWE_REF_RE.match(v.strip().lower())
            if m:
                cid = f"cwe-{m.group(1)}"
                if cid not in out:
                    out.append(cid)
                continue
        anomalies.append(f"{code}_dropped:{v!r}")
    return out


def _check_str_list(record, field, out, anomalies, code):
    """Shared shape check for list[str] reference fields."""
    values = record[field]
    if not isinstance(values, (list, tuple)):
        raise _RecordTypeError(f"type:{field}")
    return values


def _normalize_core(record, errors, anomalies):
    """Required-field validation. Returns (rid, kind, title, text_fields,
    evidence, confidence) or Nones; appends contract errors."""
    # ---- kind (first: id format + defaults are kind-specific)
    kind_raw = record.get("kind")
    kind = None
    if kind_raw is None:
        errors.append("missing:kind")
    elif not isinstance(kind_raw, str) or kind_raw not in KINDS:
        errors.append(f"unknown_kind:{kind_raw!r}")
    else:
        kind = kind_raw

    # ---- id
    rid_raw = record.get("id")
    rid = None
    if rid_raw is None or (isinstance(rid_raw, str) and not rid_raw.strip()):
        errors.append("missing:id")
    elif not isinstance(rid_raw, str):
        errors.append("type:id")
    else:
        rid = rid_raw.strip()
        if kind == "cve":
            rid = rid.upper()
        elif kind in ("exploit", "cwe", "cwe_category"):
            rid = rid.lower()
        if kind is not None and not _ID_PATTERNS[kind].match(rid):
            errors.append(f"id_format:{rid}")

    # ---- title
    title_raw = record.get("title")
    title = ""
    if title_raw is None:
        errors.append("missing:title")
    elif not isinstance(title_raw, str):
        errors.append("type:title")
    else:
        title = title_raw.strip()
        if not title:
            errors.append("missing:title")

    # ---- text_fields (empty -> kept + excluded_from_index, NOT rejected)
    raw_tf = record.get("text_fields")
    text_fields = None
    if raw_tf is None:
        errors.append("missing:text_fields")
    elif not isinstance(raw_tf, (list, tuple)):
        errors.append("type:text_fields")
    else:
        text_fields = []
        for item in raw_tf:
            if not isinstance(item, str):
                errors.append("type:text_fields")
                text_fields = None
                break
            stripped = item.strip()
            if stripped:
                text_fields.append(stripped)
            else:
                anomalies.append("empty_text_field")

    # ---- evidence {src, note} -- required (C11/K1-ready, design 4.1)
    evidence = None
    ev_raw = record.get("evidence")
    if ev_raw is None:
        errors.append("missing:evidence")
    elif not isinstance(ev_raw, dict):
        errors.append("type:evidence")
    else:
        src = ev_raw.get("src")
        note = ev_raw.get("note", "")
        if not isinstance(src, str) or not src.strip():
            errors.append("missing:evidence.src")
            src = ""
        if not isinstance(note, str):
            errors.append("type:evidence.note")
            note = ""
        evidence = {"src": src.strip(), "note": note}

    # ---- confidence
    confidence = record.get("confidence", DEFAULT_CONFIDENCE)
    if confidence not in CONFIDENCES:
        errors.append(f"bad_confidence:{confidence!r}")

    # ---- D6 exclusion rule: cvejson.json can never enter the corpus
    for probe in (record.get("source_path"),
                  ev_raw.get("src") if isinstance(ev_raw, dict) else None):
        if isinstance(probe, str) and probe.strip():
            base = os.path.basename(probe.strip().replace("\\", "/")).lower()
            if base in EXCLUDED_SOURCES:
                errors.append(f"excluded_source:{probe}")

    return rid, kind, title, text_fields, evidence, confidence


def _normalize_optional(record, kind, out, anomalies):
    """Typed optional fields; raises _RecordTypeError on top-level type
    violations (reject), drops bad list entries with anomalies (R8)."""
    # ---- cwe_ids (cve/exploit); missing cweId = known anomaly (R8)
    if "cwe_ids" in record:
        values = _check_str_list(record, "cwe_ids", out, anomalies, "cwe_id")
        out["cwe_ids"] = _norm_cwe_list(values, "cwe_id", anomalies)
    elif kind in ("cve", "exploit"):
        out["cwe_ids"] = []
        anomalies.append("missing_cwe_ids")

    # ---- cvss (partial allowed; absent/empty -> None)
    if "cvss" in record and record["cvss"] is not None:
        cvss = record["cvss"]
        if not isinstance(cvss, dict):
            raise _RecordTypeError("type:cvss")
        clean = {}
        if "score" in cvss:
            score = cvss["score"]
            if (isinstance(score, bool) or not isinstance(score, (int, float))
                    or not (0.0 <= float(score) <= 10.0)):
                anomalies.append(f"cvss_score_invalid:{score!r}")
            else:
                clean["score"] = float(score)
        if "severity" in cvss:
            sev = cvss["severity"]
            if not isinstance(sev, str):
                anomalies.append(f"cvss_severity_invalid:{sev!r}")
            else:
                clean["severity"] = sev.strip().upper()
        if "vector" in cvss:
            vec = cvss["vector"]
            if not isinstance(vec, str):
                anomalies.append(f"cvss_vector_invalid:{vec!r}")
            else:
                clean["vector"] = vec.strip()
        out["cvss"] = clean or None

    # ---- affected
    if "affected" in record:
        affected = record["affected"]
        if not isinstance(affected, (list, tuple)):
            raise _RecordTypeError("type:affected")
        kept = []
        for entry in affected:
            if isinstance(entry, dict):
                kept.append(dict(entry))
            else:
                anomalies.append(f"affected_entry_dropped:{entry!r}")
        out["affected"] = kept

    # ---- exploit_refs
    if "exploit_refs" in record:
        refs = _check_str_list(record, "exploit_refs", out, anomalies, None)
        kept = []
        for v in refs:
            if isinstance(v, str) and _EDB_REF_RE.match(v.strip().lower()):
                r = v.strip().lower()
                if r not in kept:
                    kept.append(r)
            else:
                anomalies.append(f"exploit_ref_dropped:{v!r}")
        out["exploit_refs"] = kept

    # ---- cve_refs
    if "cve_refs" in record:
        refs = _check_str_list(record, "cve_refs", out, anomalies, None)
        kept = []
        for v in refs:
            if isinstance(v, str) and _CVE_REF_RE.match(v.strip().upper()):
                r = v.strip().upper()
                if r not in kept:
                    kept.append(r)
            else:
                anomalies.append(f"cve_ref_dropped:{v!r}")
        out["cve_refs"] = kept

    # ---- related_cwe_ids
    if "related_cwe_ids" in record:
        rel = _check_str_list(record, "related_cwe_ids", out, anomalies, None)
        out["related_cwe_ids"] = _norm_cwe_list(rel, "related_cwe", anomalies)

    # ---- owasp_categories
    if "owasp_categories" in record:
        cats = _check_str_list(record, "owasp_categories", out, anomalies, None)
        kept = []
        for v in cats:
            if isinstance(v, str) and v.strip():
                kept.append(v.strip())
            else:
                anomalies.append(f"owasp_category_dropped:{v!r}")
        out["owasp_categories"] = kept

    # ---- dates {published?, updated?}
    if "dates" in record:
        dates = record["dates"]
        if not isinstance(dates, dict):
            raise _RecordTypeError("type:dates")
        clean = {}
        for key, value in dates.items():
            if isinstance(value, str) and value.strip():
                clean[str(key)] = value.strip()
            else:
                anomalies.append(f"dates_field_dropped:{key}")
        out["dates"] = clean

    # ---- scalar typed fields
    if "exploit_verified" in record:
        ev = record["exploit_verified"]
        if not isinstance(ev, bool):
            raise _RecordTypeError("type:exploit_verified")
        out["exploit_verified"] = ev
    for field in ("platform", "type", "poc_body", "source_path",
                  "corpus_version"):
        if field in record:
            value = record[field]
            if not isinstance(value, str):
                raise _RecordTypeError(f"type:{field}")
            out[field] = value


def normalize_record(record):
    """Validate + normalize one candidate record. NEVER raises.

    Returns ``(rec|None, errors, anomalies)``: on any error ``rec`` is
    None and the record is REJECTED; anomalies never reject. The input
    is never mutated; unknown fields pass through.
    """
    errors: list = []
    anomalies: list = []
    if not isinstance(record, dict):
        return None, ["type:record"], anomalies

    rid, kind, title, text_fields, evidence, confidence = _normalize_core(
        record, errors, anomalies)
    if errors:
        return None, errors, anomalies

    out: dict = {
        "id": rid,
        "kind": kind,
        "title": title,
        "text_fields": text_fields,
        "excluded_from_index": not text_fields,
        "html_entities": bool(
            _HTML_ENTITY_RE.search(title)
            or any(_HTML_ENTITY_RE.search(t) for t in text_fields)),
        "confidence": confidence,
        "evidence": evidence,
    }

    try:
        _normalize_optional(record, kind, out, anomalies)
    except _RecordTypeError as exc:
        return None, [str(exc)], anomalies

    # ---- unknown fields pass through untouched (forward compat)
    for key, value in record.items():
        if key not in _KNOWN_FIELDS and key not in out:
            out[key] = value

    return out, errors, anomalies


def validate_record(record) -> list:
    """Pure predicate: the error-code list (``[]`` = valid)."""
    _, errors, _ = normalize_record(record)
    return errors


def is_valid(record) -> bool:
    """True when the record satisfies the F1 contract."""
    return not validate_record(record)
