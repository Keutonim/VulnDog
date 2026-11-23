"""WD-E1 -- production extractors for the 4 valid vuln-db sources.

Streams the raw archives (design-spec 4.2, plan A1) into F1 canonical
records (``record_schema.normalize_record``). Laws encoded here:

- STREAMING: one zip member / CSV row / XML element at a time; archives
  are never extracted to disk and never loaded whole (only the zip
  central-directory name list is held, per zipfile stdlib behavior).
- D6: ``cvejson.json`` is refused by rule (``guard_excluded_source``);
  it can never enter the corpus through any extractor.
- UNTRUSTED DATA (C12): archive text is carried as strings only, never
  interpreted; stats aggregate error/anomaly CODES, never values, so no
  untrusted fragment reaches reports.
- HTML entities are FLAGGED by F1 (``html_entities=True``) and cleaned
  later in E3 (chunker) -- extractors do NOT rewrite source text beyond
  structural trimming (design 4.1; deviation from the pilot's extract-
  time cleanup, recorded in results/MaxQwenAgent-003.md).
- Count reconciliation vs artifacts/vulndb-inventory.json:
  408,310 CVE / 47,170 EDB rows -> 46,698 unique (472 duplicate-id rows
  dropped, first wins -- pilot convention) / 969 Weakness + 422 Category
  / Top10 EN measured (61 with the ``<edition>/(docs/)?en/*.md`` rule).
- ``files_shellcodes.csv`` is NOT exported in v1 (not web-hunt-relevant;
  plan A1 default) -- recorded as a documented not-pursued-because in
  the stats and the P2 coverage report.

Pure stdlib. Every ``iter_*`` is a generator yielding normalized
records; rejected units are counted, never raised over (one broken
record must not kill a 408k-record stream).
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter

from . import record_schema

# --------------------------------------------------------------------------
# constants / rules
# --------------------------------------------------------------------------

#: D6 -- the invalid source (Cloudflare bot-challenge HTML, 0 records).
EXCLUDED_SOURCES = record_schema.EXCLUDED_SOURCES  # ("cvejson.json",)

#: PoC body cap (design 4.2: index-only in v1; on-demand read, <= 8 KB).
POC_CAP_BYTES = 8192

#: EDB index CSVs (design 4.2).
EDB_EXPLOITS_CSV = "files_exploits.csv"
EDB_SHELLCODES_CSV = "files_shellcodes.csv"  # NEVER exported in v1 (rule)

#: Inventory reconciliation targets (artifacts/vulndb-inventory.json,
#: Dparser-001 exact counts + Dparser-003 pilot manifest dedup fact).
INVENTORY_COUNTS = {
    "cvelistV5_cve_records": 408310,
    "exploitdb_csv_rows": 47170,
    "exploitdb_unique_ids": 46698,
    "exploitdb_duplicate_id_rows": 472,
    "cwec_weaknesses": 969,
    "cwec_categories": 422,
    "top10_en_docs_measured_rule": 61,  # MEASURED, not an inventory estimate
}

_CVE_MEMBER_RE = re.compile(
    r"^(?P<root>[^/]+)/cves/(?P<year>\d{4})/\d+xxx/CVE-\d{4}-\d+\.json$")
_TOP10_EN_RE = re.compile(
    r"^(?P<root>[^/]+)/(?P<edition>\d{4})/(?:docs/)?en/(?P<file>[^/]+)\.md$")
_CVE_TOKEN_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MD_ATTR_RE = re.compile(r"\{:[^}]*\}")
_WS_RE = re.compile(r"\s+")

#: error/anomaly codes that embed a raw value after the first colon --
#: stats keep the code only (untrusted fragments never reach reports).
_VALUE_CODES = (
    "id_format", "unknown_kind", "bad_confidence", "excluded_source",
    "cwe_id_dropped", "related_cwe_dropped", "cvss_score_invalid",
    "cvss_severity_invalid", "cvss_vector_invalid", "affected_entry_dropped",
    "exploit_ref_dropped", "cve_ref_dropped", "owasp_category_dropped",
    "dates_field_dropped",
)

# metrics key preference order (design 4.2: cvssV3_1/cvssV4_0/other;
# 'other' carries no standardized score fields -> NOT carried, reason
# documented in the P2 coverage report).
_METRIC_KEYS = ("cvssV3_1", "cvssV4_0", "cvssV3_0", "cvssV2_0", "cvssV2")


class ExtractorError(RuntimeError):
    """Structural failure: archive/member missing or unreadable."""


class ExcludedSourceError(ExtractorError):
    """D6: the source is excluded by rule (cvejson.json)."""


def _code(msg: str) -> str:
    for c in _VALUE_CODES:
        if msg.startswith(c):
            return c
    return msg


def guard_excluded_source(path: str) -> None:
    """Refuse D6-excluded sources before any read (rule, not convention)."""
    base = os.path.basename(str(path).replace("\\", "/")).lower()
    if base in EXCLUDED_SOURCES:
        raise ExcludedSourceError(f"source excluded by rule (D6): {base}")


class ExtractStats:
    """Per-source counters. Values are CODES only -- never raw feed text."""

    def __init__(self, source: str):
        self.source = source
        self.seen = 0
        self.emitted = 0
        self.rejected: Counter = Counter()
        self.anomalies: Counter = Counter()
        self.extras: dict = {}

    # -- mutators
    def reject(self, errors) -> None:
        for e in errors:
            self.rejected[_code(str(e))] += 1

    def anomaly(self, anomalies) -> None:
        for a in anomalies:
            self.anomalies[_code(str(a))] += 1

    def note(self, code: str) -> None:
        self.anomalies[code] += 1

    def emitted_ok(self) -> None:
        self.emitted += 1

    # -- queries
    def rejected_total(self) -> int:
        return sum(self.rejected.values())

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "seen": self.seen,
            "emitted": self.emitted,
            "rejected_total": self.rejected_total(),
            "rejected": dict(sorted(self.rejected.items())),
            "anomalies": dict(sorted(self.anomalies.items())),
            "extras": dict(sorted(self.extras.items())),
        }


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _zip_basename(zip_path: str) -> str:
    return os.path.basename(str(zip_path).replace("\\", "/"))


def _finish(rec, errors, anomalies, stats: ExtractStats):
    """Normalize bookkeeping shared by every extractor. Yields rec|None."""
    if rec is None:
        stats.reject(errors)
        stats.anomaly(anomalies)
        return None
    stats.anomaly(anomalies)
    if rec.get("html_entities"):
        stats.note("html_entities_flagged")
    if rec.get("excluded_from_index"):
        stats.note("no_embeddable_text")
    stats.emitted_ok()
    return rec


def _first_en(seq, key="value"):
    """First EN entry's `key` (lang defaults to 'en'); fallback: any entry
    (pilot convention: a sole non-EN description is still carried)."""
    if not isinstance(seq, list):
        return None
    for item in seq:
        if isinstance(item, dict) and item.get("lang", "en") == "en":
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                return v
    for item in seq:
        if isinstance(item, dict):
            v = item.get(key)
            if isinstance(v, str) and v.strip():
                return v
    return None


def _norm_cwe_token(value):
    """'CWE-79' / '79' -> 'cwe-79'; anything else -> None."""
    if value is None:
        return None
    m = re.search(r"(\d+)", str(value))
    return "cwe-" + m.group(1) if m else None


def _s(value) -> str:
    """Structural trim only -- NO entity cleanup (E3 owns that)."""
    return value.strip() if isinstance(value, str) else ""


# --------------------------------------------------------------------------
# cvelistV5 (CVE JSON 5.x; 408,310 records)
# --------------------------------------------------------------------------

def _collect_cwes(container) -> list:
    out = []
    for pt in (container.get("problemTypes") or []):
        if not isinstance(pt, dict):
            continue
        for d in (pt.get("descriptions") or []):
            if isinstance(d, dict):
                cid = _norm_cwe_token(d.get("cweId"))
                if cid and cid not in out:
                    out.append(cid)
    return out


def _find_metrics(container):
    for m in (container.get("metrics") or []):
        if not isinstance(m, dict):
            continue
        for k in _METRIC_KEYS:
            v = m.get(k)
            if isinstance(v, dict):
                return v
    return None


def _cve_candidate(obj, source_path: str, zip_base: str):
    """Build the pre-normalization candidate dict per design 4.2."""
    if not isinstance(obj, dict):
        return {"kind": "cve"}, "non-object record"
    meta = obj.get("cveMetadata")
    meta = meta if isinstance(meta, dict) else {}
    cve_id = _s(meta.get("cveId")).upper()
    containers = obj.get("containers")
    containers = containers if isinstance(containers, dict) else {}
    cna = containers.get("cna")
    cna = cna if isinstance(cna, dict) else {}
    adp_list = [a for a in (containers.get("adp") or []) if isinstance(a, dict)]

    note_parts = ["CVE JSON 5.1 record"]

    # descriptions: EN-first from cna; adp fallback (provenance noted)
    desc = _first_en(cna.get("descriptions"))
    if desc is None:
        for a in adp_list:
            desc = _first_en(a.get("descriptions"))
            if desc is not None:
                note_parts.append("description from adp")
                break
    desc = _s(desc)

    # title: cna -> adp -> first description sentence -> cve id
    title = _s(cna.get("title"))
    if not title:
        for a in adp_list:
            title = _s(a.get("title"))
            if title:
                break
    if not title and desc:
        title = desc.split(". ")[0][:200]
    if not title:
        title = cve_id or "(missing id)"

    # solutions
    sol = _s(_first_en(cna.get("solutions")))

    # affected (cna only, design 4.2)
    aff_list, aff_lines = [], []
    for a in (cna.get("affected") or []):
        if not isinstance(a, dict):
            continue
        vendor = _s(a.get("vendor"))
        product = _s(a.get("product"))
        versions = []
        for v in (a.get("versions") or []):
            if isinstance(v, dict):
                vv = _s(v.get("version"))
                if vv and vv.lower() != "n/a":
                    versions.append(vv)
        aff_list.append({"vendor": vendor, "product": product,
                         "versions": versions})
        line = ("affected: " + vendor + " " + product).strip()
        if line != "affected:":
            aff_lines.append(line)

    # problemTypes: cna first; adp merged ONLY when cna lacks them
    cwe_ids = _collect_cwes(cna)
    if not cwe_ids:
        for a in adp_list:
            got = _collect_cwes(a)
            if got:
                cwe_ids = got
                note_parts.append("problemTypes from adp")
                break

    # metrics: cna first; adp fallback (design 4.2 merge rule)
    mm = _find_metrics(cna)
    if mm is None:
        for a in adp_list:
            mm = _find_metrics(a)
            if mm is not None:
                note_parts.append("metrics from adp")
                break
    cvss = None
    if mm:
        cvss = {}
        score = mm.get("baseScore")
        if score is not None:
            cvss["score"] = score
        sev = _s(mm.get("baseSeverity"))
        if sev:
            cvss["severity"] = sev
        vec = _s(mm.get("vectorString"))
        if vec:
            cvss["vector"] = vec
        cvss = cvss or None

    # references: carried, NOT embedded (design 4.2)
    refs = []
    for r in (cna.get("references") or []):
        if isinstance(r, dict):
            u = _s(r.get("url"))
            if u:
                refs.append(u)

    text_fields = []
    if desc:
        text_fields.append(desc)
    if title and title != cve_id:
        text_fields.append("title: " + title)
    if sol:
        text_fields.append("solution: " + sol)
    text_fields.extend(aff_lines)
    # NO fallback text injection (production rule; F1 excluded_from_index
    # carries empty-text records -- deviation from the pilot, documented).

    dates = {}
    for key, field in (("published", "datePublished"),
                       ("updated", "dateUpdated")):
        v = _s(meta.get(field))
        if v:
            dates[key] = v

    cand = {
        "id": cve_id,
        "kind": "cve",
        "title": title,
        "text_fields": text_fields,
        "cwe_ids": cwe_ids,
        "cvss": cvss,
        "affected": aff_list,
        "dates": dates,
        "refs": refs,
        "cve_state": _s(meta.get("state")),
        "source_path": source_path,
        "evidence": {"src": zip_base, "note": "; ".join(note_parts)},
        "confidence": "documented",
    }
    return cand, None


def iter_cve_records(zip_path, stats: ExtractStats, years=None):
    """Stream per-CVE JSON records from the cvelistV5 zip.

    ``years``: optional set of 4-char year strings (scale/smoke tests).
    deltaLog.json / delta.json are NOT records (A7 refresh inputs) and
    are skipped by the member regex.
    """
    guard_excluded_source(zip_path)
    zip_base = _zip_basename(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        members = []
        for name in zf.namelist():
            m = _CVE_MEMBER_RE.match(name)
            if not m:
                continue
            if years is not None and m.group("year") not in years:
                continue
            members.append(name)
        members.sort()
        for name in members:
            stats.seen += 1
            try:
                with zf.open(name) as fh:
                    raw = fh.read()
                obj = json.loads(raw.decode("utf-8", "replace"))
            except (OSError, ValueError, zipfile.BadZipFile):
                stats.reject(["parse_error"])
                continue
            root_prefix = name.split("/", 1)[0] + "/"
            source_path = name[len(root_prefix):]
            cand, _err = _cve_candidate(obj, source_path, zip_base)
            rec, errors, anomalies = record_schema.normalize_record(cand)
            out = _finish(rec, errors, anomalies, stats)
            if out is not None:
                yield out


# --------------------------------------------------------------------------
# exploitdb (47,170 CSV rows -> 46,698 unique)
# --------------------------------------------------------------------------

def _codes_split(raw: str):
    """codes column -> (cve_tokens_upper, other_tokens)."""
    cves, others = [], []
    for tok in str(raw or "").split(";"):
        tok = tok.strip()
        if not tok:
            continue
        up = tok.upper()
        if _CVE_TOKEN_RE.fullmatch(up):
            if up not in cves:
                cves.append(up)
        elif up.startswith("CVE-"):
            # malformed CVE token: keep verbatim-uppercase in others so it
            # stays visible but never joins (F1 would drop it from cve_refs)
            others.append(tok)
        else:
            others.append(tok)
    return cves, others


def _edb_candidate(row, zip_base: str, poc_body=None):
    rid = _s(row.get("id"))
    desc = _s(row.get("description"))
    tags = _s(row.get("tags"))
    cve_refs, other_codes = _codes_split(row.get("codes"))

    # design 4.1: cve_refs from codes "(and aliases)" -- aliases scanned for
    # CVE-shaped tokens, counted separately by the caller (data shows they
    # are usually file monikers, not CVE lists).
    alias_tokens = [t for t in _CVE_TOKEN_RE.findall(_s(row.get("aliases")))
                    if t not in cve_refs]

    text_fields = []
    if desc:
        text_fields.append(desc)
    if tags:
        text_fields.append("tags: " + tags)

    dates = {}
    for key, col in (("published", "date_published"), ("updated", "date_updated")):
        v = _s(row.get(col))
        if v:
            dates[key] = v

    verified = _s(row.get("verified")) == "1"
    cand = {
        "id": "edb-" + rid,
        "kind": "exploit",
        "title": desc or ("EDB-" + rid),
        "text_fields": text_fields,
        "cwe_ids": [],
        "cve_refs": cve_refs + alias_tokens,
        "other_codes": other_codes,
        "platform": _s(row.get("platform")),
        "type": _s(row.get("type")),
        "exploit_verified": verified,
        # design 4.1: confidence "verified" for EDB verified=1 records
        "confidence": "verified" if verified else "documented",
        "dates": dates,
        "source_path": _s(row.get("file")),  # design 4.2: source_path=row.file
        "evidence": {"src": zip_base, "note": "Exploit-DB index row"},
    }
    if poc_body is not None:
        cand["poc_body"] = poc_body
    return cand, len(alias_tokens)


def iter_edb_records(zip_path, stats: ExtractStats, read_poc: bool = False,
                     poc_cap: int = POC_CAP_BYTES):
    """Stream files_exploits.csv rows into F1 exploit records.

    - id dedup: first occurrence wins (pilot convention; 472 duplicate
      rows in the frozen drop), counted in extras;
    - ``files_shellcodes.csv`` is NEVER opened (v1 exclusion rule); its
      presence is recorded for the coverage report;
    - ``read_poc=True`` reads ``exploits/<file>`` bodies capped at
      ``poc_cap`` bytes (on-demand only; index-only in v1 per design 4.2).
    """
    guard_excluded_source(zip_path)
    zip_base = _zip_basename(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        csv_members = [n for n in names
                       if n.rsplit("/", 1)[-1] == EDB_EXPLOITS_CSV]
        if not csv_members:
            raise ExtractorError(f"{EDB_EXPLOITS_CSV} not found in {zip_base}")
        csv_member = sorted(csv_members)[0]
        root = csv_member.rsplit("/", 1)[0] + "/" if "/" in csv_member else ""
        stats.extras["shellcodes_csv_present"] = any(
            n.rsplit("/", 1)[-1] == EDB_SHELLCODES_CSV for n in names)
        stats.extras["shellcodes_exported"] = False  # v1 rule: never exported
        stats.extras.setdefault("rows_dropped_duplicate_id", 0)
        stats.extras.setdefault("cve_tokens_from_aliases", 0)
        stats.extras.setdefault("poc_bodies_read", 0)

        seen_ids = set()
        with zf.open(csv_member) as fh:
            text = io.TextIOWrapper(fh, encoding="utf-8", errors="replace",
                                    newline="")
            for row in csv.DictReader(text):
                stats.seen += 1
                rid = _s(row.get("id"))
                if not rid.isdigit():
                    stats.reject(["id_format"])
                    continue
                if rid in seen_ids:
                    stats.extras["rows_dropped_duplicate_id"] += 1
                    continue
                seen_ids.add(rid)

                poc_body = None
                if read_poc:
                    file_rel = _s(row.get("file"))
                    if file_rel:
                        try:
                            with zf.open(root + file_rel) as pfh:
                                poc_body = pfh.read(poc_cap).decode(
                                    "utf-8", "replace")
                            stats.extras["poc_bodies_read"] += 1
                        except (KeyError, OSError, zipfile.BadZipFile):
                            stats.note("poc_read_error")

                cand, n_alias = _edb_candidate(row, zip_base, poc_body)
                stats.extras["cve_tokens_from_aliases"] += n_alias
                rec, errors, anomalies = record_schema.normalize_record(cand)
                out = _finish(rec, errors, anomalies, stats)
                if out is not None:
                    yield out


# --------------------------------------------------------------------------
# cwec (MITRE CWE v4.20 XML; 969 Weakness + 422 Category)
# --------------------------------------------------------------------------

def _local(tag) -> str:
    return str(tag).rsplit("}", 1)[-1]


def _children(elem, local):
    for ch in elem:
        if _local(ch.tag) == local:
            yield ch


def _findtext(elem, local) -> str:
    for ch in _children(elem, local):
        return _s(ch.text)
    return ""


def _weakness_candidate(w, xml_member: str, zip_base: str):
    wid = _s(w.get("ID"))
    name = _s(w.get("Name"))
    desc = _findtext(w, "Description")
    ext = _findtext(w, "Extended_Description")

    text_fields = []
    if desc:
        text_fields.append(desc)
    if ext:
        text_fields.append(ext)
    for cc in _children(w, "Common_Consequences"):
        for cons in _children(cc, "Consequence"):
            note = _findtext(cons, "Note")
            if note:
                text_fields.append(note)
    for de in _children(w, "Demonstrative_Examples"):
        for ex in _children(de, "Demonstrative_Example"):
            body = _findtext(ex, "Body_Text")
            if body:
                text_fields.append(body[:2000])  # pilot cap convention

    related = []
    for rw_group in _children(w, "Related_Weaknesses"):
        for rw in _children(rw_group, "Related_Weakness"):
            cid = _norm_cwe_token(rw.get("CWE_ID"))
            if cid and cid not in related:
                related.append(cid)

    cand = {
        "id": ("cwe-" + wid) if wid else "",
        "kind": "cwe",
        "title": (name or ("CWE-" + wid)) if wid else "",
        "text_fields": text_fields,
        # production rule: NO self cwe_ids on cwe-kind records (design 4.1
        # carries cwe_ids for cve/exploit only; pilot deviation documented)
        "related_cwe_ids": sorted(related),
        "abstraction": _s(w.get("Abstraction")),
        "status": _s(w.get("Status")),
        "source_path": xml_member,
        "evidence": {"src": zip_base, "note": "MITRE CWE v4.20 Weakness"},
        "confidence": "documented",
    }
    return cand


def _category_candidate(c, xml_member: str, zip_base: str):
    cid = _s(c.get("ID"))
    name = _s(c.get("Name"))
    return {
        "id": ("cwe-" + cid) if cid else "",
        "kind": "cwe_category",
        "title": (name or ("CWE-" + cid)) if cid else "",
        # reference-only, NOT embedded by default (design 4.2) -> empty
        # text_fields -> F1 keeps it with excluded_from_index=True
        "text_fields": [],
        "status": _s(c.get("Status")),
        "source_path": xml_member,
        "evidence": {"src": zip_base,
                     "note": "MITRE CWE v4.20 Category (reference-only)"},
        "confidence": "documented",
    }


def iter_cwe_records(zip_path, stats: ExtractStats,
                     include_categories: bool = True):
    """Pull-parse the CWE catalog XML (bounded memory: handled elements
    are cleared as the stream advances). Weaknesses -> kind=cwe;
    Categories -> kind=cwe_category reference-only.
    """
    guard_excluded_source(zip_path)
    zip_base = _zip_basename(zip_path)
    stats.extras.setdefault("weaknesses", 0)
    stats.extras.setdefault("categories", 0)
    with zipfile.ZipFile(zip_path) as zf:
        xml_members = sorted(n for n in zf.namelist() if n.endswith(".xml"))
        if not xml_members:
            raise ExtractorError(f"no XML member in {zip_base}")
        xml_member = xml_members[0]
        with zf.open(xml_member) as fh:
            try:
                for _event, elem in ET.iterparse(fh, events=("end",)):
                    local = _local(elem.tag)
                    if local == "Weakness":
                        stats.seen += 1
                        stats.extras["weaknesses"] += 1
                        cand = _weakness_candidate(elem, xml_member, zip_base)
                        rec, errors, anomalies = \
                            record_schema.normalize_record(cand)
                        out = _finish(rec, errors, anomalies, stats)
                        if out is not None:
                            yield out
                        elem.clear()
                    elif local == "Category":
                        if include_categories:
                            stats.seen += 1
                            stats.extras["categories"] += 1
                            cand = _category_candidate(elem, xml_member,
                                                       zip_base)
                            rec, errors, anomalies = \
                                record_schema.normalize_record(cand)
                            out = _finish(rec, errors, anomalies, stats)
                            if out is not None:
                                yield out
                        elem.clear()
                    elif local == "View":
                        elem.clear()  # Views are huge and not records
            except ET.ParseError as exc:
                raise ExtractorError(f"CWE XML parse error: {exc}") from exc


# --------------------------------------------------------------------------
# Top10 (OWASP; EN markdown docs only)
# --------------------------------------------------------------------------

def slugify(stem: str) -> str:
    """Filename stem -> F1-valid owasp_doc slug.

    The F1 id pattern allows [A-Za-z0-9._-] after an alphanumeric first
    char; real filenames carry spaces/parens (e.g. the 2021 SSRF doc --
    the pilot's raw-slug id FAILS F1). Rule: replace every disallowed
    run with '-', collapse repeats, trim, force an alphanumeric start.
    """
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", str(stem))
    s = re.sub(r"-{2,}", "-", s).strip("-._")
    s = re.sub(r"\A[^A-Za-z0-9]+", "", s)
    return s or "doc"


def _md_title(body: str, fallback: str) -> str:
    for line in body.splitlines():
        if line.startswith("# "):
            t = line[2:]
            t = _MD_IMAGE_RE.sub(" ", t)
            t = _MD_ATTR_RE.sub(" ", t)
            t = _WS_RE.sub(" ", t).strip()
            if t:
                return t
            break
    return fallback


def _top10_candidate(body: str, edition: str, slug: str, source_path: str,
                     zip_base: str):
    rid = f"owasp-{edition}-{slug}"
    text = body.strip()
    return {
        "id": rid,
        "kind": "owasp_doc",
        "title": _md_title(body, rid),
        "text_fields": [text] if text else [],
        "edition": edition,
        "source_path": source_path,
        "evidence": {"src": zip_base, "note": "OWASP Top 10 EN markdown"},
        "confidence": "documented",
    }


def iter_top10_records(zip_path, stats: ExtractStats):
    """Stream EN markdown docs: ``<edition>/(docs/)?en/*.md`` (MEASURED
    selection rule; translations, Data/, assets/ and binaries skipped --
    the regex only matches direct children of an ``en`` dir)."""
    guard_excluded_source(zip_path)
    zip_base = _zip_basename(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        members = []
        for name in zf.namelist():
            m = _TOP10_EN_RE.match(name)
            if m:
                members.append((m.group("edition"), m.group("file"), name))
        members.sort()
        for edition, filename, name in members:
            stats.seen += 1
            try:
                with zf.open(name) as fh:
                    body = fh.read().decode("utf-8", "replace")
            except (OSError, zipfile.BadZipFile):
                stats.reject(["parse_error"])
                continue
            slug = slugify(filename[:-3] if filename.endswith(".md")
                           else filename)
            source_path = name.split("/", 1)[1] if "/" in name else name
            cand = _top10_candidate(body, edition, slug, source_path,
                                    zip_base)
            rec, errors, anomalies = record_schema.normalize_record(cand)
            out = _finish(rec, errors, anomalies, stats)
            if out is not None:
                yield out
