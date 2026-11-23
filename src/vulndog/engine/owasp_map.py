"""WD-E2 part 1 -- the static CWE -> OWASP Top 10 mapping table.

Checked-in, versioned, ASCII: ``vuln_watchdog/data/cwe_owasp_map.json``
with a PER-ROW rationale note (plan A2 DoD 4). Seed source (offline,
C1): the OWASP-published ``## List of Mapped CWEs`` sections shipped in
the LOCAL Top10 archive's EN category docs (editions 2021 + 2025,
A01..A10). The CWE catalog's own ``Taxonomy_Mapping`` elements only
cover OWASP Top Ten 2004/2007 (probed in cwec_v4.20.xml, 2026-10-15),
so the Top10 docs are the authoritative local seed for the current
editions.

Labels are edition-disambiguated -- ``<code>:<edition>-<Title-Slug>``
(e.g. ``A03:2021-Injection`` vs ``A05:2025-Injection``): the 2025
renumbering makes bare ``A03-injection``-style labels ambiguous.

Honest limitation (design 4.3): this table maps CWE ids to taxonomy
LABELS only -- no record-level foreign key exists between CVE/EDB
records and the OWASP docs; coverage is reported by the joiner.

Regeneration (A7 refresh): ``build_seed_from_top10(zip_path)`` rebuilds
the table from a new archive drop and FAILS LOUD when an expected
edition does not yield exactly 10 category docs.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile

from . import extractors

MAP_VERSION = "1.0.0"
DEFAULT_MAP_PATH = os.path.join(os.path.dirname(__file__), "data",
                                "cwe_owasp_map.json")

#: editions the checked-in table covers (v1 seed; refresh = code change).
EXPECTED_EDITIONS = ("2021", "2025")

_CATEGORY_CODES = tuple(f"A{i:02d}" for i in range(1, 11))

_CAT_DOC_RE = re.compile(
    r"^(?P<root>[^/]+)/(?P<edition>\d{4})/(?:docs/)?en/(?P<file>[^/]+)\.md$")
_CAT_FILE_RE = re.compile(r"^(?P<code>A\d{2})_(?P<edition>\d{4})-(?P<rest>.+)$")
_HEADING_RE = re.compile(r"^#{1,6}\s*List of(?:\s+Mapped)?\s+CWEs\s*$",
                         re.MULTILINE)
_NEXT_HEADING_RE = re.compile(r"^#{1,6}\s", re.MULTILINE)
_CWE_LINK_RE = re.compile(r"\[CWE-(\d+)\b")
_CWE_ID_RE = re.compile(r"\Acwe-(\d+)\Z")


class OwaspMapError(ValueError):
    """Table shape invalid, seed source unusable, or layout changed."""


# --------------------------------------------------------------------------
# seed builder (offline; from the local Top10 archive)
# --------------------------------------------------------------------------

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _mapped_cwes(body: str):
    """CWE ids inside the 'List of (Mapped) CWEs' section only (the
    section ends at the next markdown heading or EOF)."""
    m = _HEADING_RE.search(body)
    if m is None:
        return None
    rest = body[m.end():]
    nxt = _NEXT_HEADING_RE.search(rest)
    section = rest[:nxt.start()] if nxt else rest
    out = []
    for cid in _CWE_LINK_RE.findall(section):
        key = "cwe-" + cid
        if key not in out:
            out.append(key)
    return out


def build_seed_from_top10(zip_path: str) -> dict:
    """Regenerate the table from a Top10 archive. Fails loud on layout
    drift (an expected edition without exactly 10 mapped category docs).
    UNTRUSTED DATA: doc bodies are parsed as data only (C12)."""
    extractors.guard_excluded_source(zip_path)
    docs = {}       # (edition, code) -> {title, doc, label, cwes}
    unexpected = set()
    with zipfile.ZipFile(zip_path) as zf:
        for name in sorted(zf.namelist()):
            m = _CAT_DOC_RE.match(name)
            if not m:
                continue
            # NOTE: _CAT_DOC_RE already consumed the ".md" suffix -- the
            # file group is the bare stem (a second [:-3] would eat real
            # characters: "Injection" -> "Inject").
            fm = _CAT_FILE_RE.match(m.group("file"))
            if not fm or fm.group("code") not in _CATEGORY_CODES:
                continue
            if fm.group("edition") != m.group("edition"):
                continue
            edition = m.group("edition")
            if edition not in EXPECTED_EDITIONS:
                unexpected.add(edition)
                continue
            with zf.open(name) as fh:
                body = fh.read().decode("utf-8", "replace")
            cwes = _mapped_cwes(body)
            if cwes is None:
                raise OwaspMapError(
                    f"no 'List of Mapped CWEs' section in {name}")
            title = fm.group("rest").replace("_", " ")
            slug = extractors.slugify(title)
            docs[(edition, fm.group("code"))] = {
                "label": f"{fm.group('code')}:{edition}-{slug}",
                "edition": edition,
                "code": fm.group("code"),
                "title": title,
                "doc": name.split("/", 1)[1] if "/" in name else name,
                "cwes": cwes,
            }

    for edition in EXPECTED_EDITIONS:
        got = sorted(c for (e, c) in docs if e == edition)
        if got != list(_CATEGORY_CODES):
            missing = [c for c in _CATEGORY_CODES if c not in got]
            raise OwaspMapError(
                f"edition {edition}: expected 10 category docs, missing "
                f"{missing or 'none'} (got {len(got)}) -- layout drift?")

    categories = []
    rows_by_cwe = {}
    for (edition, code) in sorted(docs, key=lambda k: (k[0], k[1])):
        d = docs[(edition, code)]
        categories.append({
            "label": d["label"], "edition": edition, "code": code,
            "title": d["title"], "doc": d["doc"],
            "cwe_count": len(d["cwes"]),
        })
        for cwe in d["cwes"]:
            rows_by_cwe.setdefault(cwe, []).append(
                (d["label"], d["edition"], d["code"], d["doc"]))

    rows = []
    for cwe in sorted(rows_by_cwe, key=lambda c: int(c.split("-")[1])):
        entries = sorted(rows_by_cwe[cwe], key=lambda e: (e[1], e[2]))
        rationale = "OWASP-published 'List of Mapped CWEs': " + "; ".join(
            f"{label} ({doc})" for label, _ed, _code, doc in entries)
        rows.append({
            "cwe": cwe,
            "categories": [label for label, _ed, _code, _doc in entries],
            "rationale": rationale,
        })

    return {
        "map_version": MAP_VERSION,
        "generated_at": "2026-10-15",
        "generated_by": "vuln_watchdog.owasp_map.build_seed_from_top10",
        "source": {
            "archive": os.path.basename(zip_path),
            "archive_sha256": _sha256_file(zip_path),
            "editions": list(EXPECTED_EDITIONS),
            "selection": "EN category docs <edition>/(docs/)?en/A01..A10_*.md,"
                         " section '## List of Mapped CWEs' (link-text parse)",
            "unexpected_editions_ignored": sorted(unexpected),
            "note": "Offline seed (C1). cwec_v4.20.xml Taxonomy_Mappings "
                    "cover only OWASP Top Ten 2004/2007; the Top10 archive "
                    "carries the published 2021/2025 per-category CWE lists.",
        },
        "categories": categories,
        "rows": rows,
    }


# --------------------------------------------------------------------------
# load / validate / lookup
# --------------------------------------------------------------------------

def validate_table(table) -> list:
    """Shape errors ([] = valid). Used by load_map and the tests."""
    errs = []
    if not isinstance(table, dict):
        return ["table:not-a-dict"]
    if not isinstance(table.get("map_version"), str) \
            or not table["map_version"].strip():
        errs.append("map_version:missing")
    cats = table.get("categories")
    if not isinstance(cats, list) or not cats:
        errs.append("categories:missing-or-empty")
        cats = []
    labels = set()
    for c in cats:
        if not isinstance(c, dict):
            errs.append("category:not-a-dict")
            continue
        for field in ("label", "edition", "code", "title", "doc"):
            if not isinstance(c.get(field), str) or not c[field].strip():
                errs.append(f"category_field:{field}")
        if c.get("label") in labels:
            errs.append(f"duplicate_label:{c.get('label')}")
        labels.add(c.get("label"))
    rows = table.get("rows")
    if not isinstance(rows, list) or not rows:
        errs.append("rows:missing-or-empty")
        rows = []
    for r in rows:
        if not isinstance(r, dict):
            errs.append("row:not-a-dict")
            continue
        if not isinstance(r.get("cwe"), str) or not _CWE_ID_RE.match(r["cwe"]):
            errs.append(f"row_cwe_not_normalized:{r.get('cwe')!r}")
        if not isinstance(r.get("rationale"), str) or not r["rationale"].strip():
            errs.append("row_rationale:missing")
        rc = r.get("categories")
        if not isinstance(rc, list) or not rc:
            errs.append("row_categories:missing-or-empty")
        else:
            for label in rc:
                if labels and label not in labels:
                    errs.append(f"dangling_category:{label}")
    return errs


_INDEX_CACHE = {}


def cwe_to_categories(table: dict) -> dict:
    """{cwe-<n>: [category labels]} index (cached per table object)."""
    key = id(table)
    hit = _INDEX_CACHE.get(key)
    if hit is not None and hit[0] is table:
        return hit[1]
    idx = {}
    for r in table.get("rows", []):
        idx[r["cwe"]] = list(r["categories"])
    _INDEX_CACHE[key] = (table, idx)  # hold the table: id() stability
    return idx


def load_map(path: str = None) -> dict:
    """Load + validate the checked-in table (default: package data file)."""
    p = path or DEFAULT_MAP_PATH
    try:
        with open(p, "rb") as f:
            table = json.loads(f.read().decode("ascii"))
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        raise OwaspMapError(f"cannot load OWASP map {p}: {exc}") from exc
    errs = validate_table(table)
    if errs:
        raise OwaspMapError(f"invalid OWASP map {p}: {errs[:5]}")
    return table


def _norm_cwe(cwe_id) -> str:
    if cwe_id is None:
        return ""
    m = re.search(r"(\d+)", str(cwe_id))
    return "cwe-" + m.group(1) if m else ""


def categories_for_cwe(cwe_id, table: dict = None) -> list:
    """Category labels for a CWE id ('cwe-79'/'CWE-79'/'79'); [] when
    unmapped. Loads the checked-in table when none is given."""
    key = _norm_cwe(cwe_id)
    if not key:
        return []
    if table is None:
        table = load_map()
    return list(cwe_to_categories(table).get(key, []))
