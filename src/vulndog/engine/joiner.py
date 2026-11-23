"""WD-E2 part 2 -- cross-source joins + JOIN COVERAGE REPORT (plan A2).

Joins on the inventory keys (design 4.3):
- ``cvelistV5.cveId <-> exploitdb codes`` CVE-* tokens -> exploit_refs /
  cve_refs;
- ``problemTypes[].cweId <-> cwec Weakness/@ID`` (Category ids count as
  RESOLVED -- categories are corpus records too; anything else is
  dangling and LISTED, never silently dropped -- A2 DoD 2);
- CWE/CVE -> OWASP via the static table (owasp_map) -- taxonomy LABELS
  only, no record-level foreign key exists (honest limitation carried
  in the coverage report).

Dedup: record id is primary everywhere; duplicate texts collapse by
(id, sha1(text)); join results dedup id pairs by construction (sets).

Stage-1 slice ESTIMATE (design 2.3 recipe): a record is included when
(a) its effective CWE set intersects WEB_RELEVANT_CWES (checked-in
seed, versioned; A4 re-carries it in the P3 manifest) OR (b)
cvss.score >= 7.0 OR (c) has-public-exploit -- for CVEs the join flag,
for exploit records the MIRROR (>= 1 resolved cve_ref; an EDB row IS
the public exploit). excluded_from_index records are never in the
slice (nothing to embed); reference kinds (cwe_category, owasp_doc)
are outside the strict recipe and counted separately.

``run_coverage_pass`` streams all 4 archives ONCE, retains only join
indexes/counters (never the corpus), and returns the JSON-serializable
stats dict persisted as artifacts/p2-join-stats.json.

Pure stdlib. Archive text is UNTRUSTED DATA (C12): carried/counted,
never interpreted.
"""
from __future__ import annotations

import hashlib
import time

from . import extractors
from . import owasp_map
from . import record_schema  # noqa: F401  (contract import for callers)

# --------------------------------------------------------------------------
# stage-1 recipe config (design 2.3; seeded from AGENTS.md step-3 triage
# priorities P1/P2 -- versioned, A4 carries it in the corpus manifest)
# --------------------------------------------------------------------------

WEB_RELEVANT_CWES_VERSION = "1.0.0"
WEB_RELEVANT_CWES = {
    # P1 injections
    "cwe-79": "xss", "cwe-80": "xss", "cwe-83": "xss", "cwe-87": "xss",
    "cwe-89": "sqli", "cwe-564": "sqli",
    "cwe-94": "ssti_code_injection", "cwe-95": "ssti_code_injection",
    "cwe-96": "ssti_code_injection", "cwe-917": "ssti_code_injection",
    "cwe-1336": "ssti_code_injection",
    "cwe-77": "command_injection", "cwe-78": "command_injection",
    "cwe-88": "command_injection",
    # P1 access control
    "cwe-284": "idor_access_control", "cwe-285": "idor_access_control",
    "cwe-425": "idor_access_control", "cwe-639": "idor_access_control",
    "cwe-862": "idor_access_control", "cwe-863": "idor_access_control",
    "cwe-287": "auth_bypass", "cwe-288": "auth_bypass",
    "cwe-290": "auth_bypass", "cwe-306": "auth_bypass",
    "cwe-384": "auth_bypass",
    "cwe-345": "jwt", "cwe-347": "jwt",
    # P2 classes
    "cwe-918": "ssrf",
    "cwe-362": "race", "cwe-367": "race",
    "cwe-915": "mass_assignment",
    "cwe-434": "upload",
    # GraphQL: no dedicated CWE family exists in the catalog -- documented
    # not-mappable in the coverage report.
}

CVSS_HIGH_THRESHOLD = 7.0

#: dangling-uniques lists longer than this are capped in the stats JSON
#: (count + head sample stay exact); the full list is re-derivable by a
#: re-run -- keeps p2-join-stats.json bounded at 408k scale.
DANGLING_LIST_CAP = 100000

_REASONS = ("a-web-cwe", "b-cvss-high", "c-public-exploit")


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def text_sha1(record: dict) -> str:
    joined = "\n".join(record.get("text_fields") or [])
    return hashlib.sha1(joined.encode("utf-8", "replace")).hexdigest()


def dedup_key(record: dict):
    """(id, sha1(text)) -- the design 4.3 dedup key."""
    return (record.get("id", ""), text_sha1(record))


def effective_cwe_ids(record: dict) -> list:
    """CWE set a record contributes to the recipe/joins: cve/exploit ->
    cwe_ids; cwe -> its own id; reference kinds -> none."""
    kind = record.get("kind")
    if kind in ("cve", "exploit"):
        return list(record.get("cwe_ids") or [])
    if kind == "cwe":
        rid = record.get("id", "")
        return [rid] if rid.startswith("cwe-") else []
    return []


class JoinIndex:
    """In-memory join structure. Holds ids/refs/shas only -- NEVER
    record text (the corpus itself is never retained)."""

    def __init__(self):
        self.cve_to_edb = {}        # CVE id -> set(edb ids)
        self.edb_rows = {}          # edb id -> {"cve_refs": tuple, "sha1": str}
        self.known_cve_ids = set()  # populated by the CVE phase
        self.cwe_weakness_ids = set()
        self.cwe_category_ids = set()
        self.dedup = {
            "cve": {"id_duplicates": 0, "text_duplicates": 0},
            "exploit": {"id_duplicates": 0, "text_duplicates": 0},
            "cwe": {"id_duplicates": 0, "text_duplicates": 0},
            "owasp_doc": {"id_duplicates": 0, "text_duplicates": 0},
        }
        self._dup_sha = {}  # id -> first sha1, for dup ids only

    # -- population
    def add_edb(self, record: dict) -> None:
        eid = record["id"]
        sha = text_sha1(record)
        if eid in self.edb_rows:
            self.dedup["exploit"]["id_duplicates"] += 1
            if self.edb_rows[eid]["sha1"] == sha:
                self.dedup["exploit"]["text_duplicates"] += 1
            return
        self.edb_rows[eid] = {"cve_refs": tuple(record.get("cve_refs") or ()),
                              "sha1": sha}
        for cve in record.get("cve_refs") or ():
            self.cve_to_edb.setdefault(cve, set()).add(eid)

    def add_cwe(self, record: dict) -> None:
        rid = record["id"]
        target = (self.cwe_weakness_ids if record.get("kind") == "cwe"
                  else self.cwe_category_ids)
        if rid in target:
            self.dedup["cwe"]["id_duplicates"] += 1
            return
        target.add(rid)

    def add_known_cve(self, cve_id: str) -> bool:
        """Returns False when the id was already known (duplicate)."""
        if cve_id in self.known_cve_ids:
            return False
        self.known_cve_ids.add(cve_id)
        return True

    def add_doc(self, record: dict) -> None:
        key = dedup_key(record)
        slot = self.dedup.setdefault(
            "owasp_doc", {"id_duplicates": 0, "text_duplicates": 0})
        if record["id"] in self._doc_ids():
            slot["id_duplicates"] += 1
            if self._dup_sha.get(record["id"]) == key[1]:
                slot["text_duplicates"] += 1
        else:
            self._doc_ids().add(record["id"])
            self._dup_sha.setdefault(record["id"], key[1])

    def _doc_ids(self):
        if not hasattr(self, "_doc_id_set"):
            self._doc_id_set = set()
        return self._doc_id_set

    # -- queries
    def exploit_refs_for(self, cve_id: str) -> list:
        return sorted(self.cve_to_edb.get(cve_id, ()))

    def has_exploit(self, cve_id: str) -> bool:
        return cve_id in self.cve_to_edb

    def resolve_cve(self, cve_id: str) -> bool:
        return cve_id in self.known_cve_ids

    def resolve_cwe(self, cwe_id: str) -> bool:
        return cwe_id in self.cwe_weakness_ids

    def resolve_cwe_category(self, cwe_id: str) -> bool:
        return cwe_id in self.cwe_category_ids

    def resolve_cwe_any(self, cwe_id: str) -> bool:
        return cwe_id in self.cwe_weakness_ids \
            or cwe_id in self.cwe_category_ids


# --------------------------------------------------------------------------
# record-level join (reused by the P3 store writer)
# --------------------------------------------------------------------------

_DOC_LABEL_CACHE = {}


def _doc_id_labels(table: dict) -> dict:
    """{owasp_doc record id: category label} for category docs."""
    hit = _DOC_LABEL_CACHE.get(id(table))
    if hit is not None and hit[0] is table:
        return hit[1]
    out = {}
    for c in table.get("categories", []):
        stem = c["doc"].rsplit("/", 1)[-1]
        if stem.endswith(".md"):
            stem = stem[:-3]
        rid = f"owasp-{c['edition']}-{extractors.slugify(stem)}"
        out[rid] = c["label"]
    _DOC_LABEL_CACHE[id(table)] = (table, out)
    return out


def owasp_categories_for(record: dict, table: dict) -> list:
    """Static-table attach: labels for the record's effective CWE set;
    owasp_doc records additionally carry their OWN category label."""
    idx = owasp_map.cwe_to_categories(table)
    labels = set()
    for cwe in effective_cwe_ids(record):
        for label in idx.get(cwe, ()):
            labels.add(label)
    if record.get("kind") == "owasp_doc":
        own = _doc_id_labels(table).get(record.get("id", ""))
        if own:
            labels.add(own)
    return sorted(labels)


def attach_joins(record: dict, index: JoinIndex, table: dict = None):
    """Return (joined_copy, dangling) -- the input is NEVER mutated.

    dangling entries: {"from": id, "ref": ref, "type": cve|cwe}; every
    unresolvable exploit_refs/cve_refs/cwe_ids/related_cwe_ids target is
    listed (A2 DoD 2). The CVE-existence check only runs once the CVE
    phase populated known_cve_ids (an empty set means 'not run', not
    'everything dangling').
    """
    out = dict(record)
    dangling = []
    kind = record.get("kind")
    rid = record.get("id", "")

    if kind == "cve":
        out["exploit_refs"] = index.exploit_refs_for(rid)
        for cwe in record.get("cwe_ids") or ():
            if not index.resolve_cwe_any(cwe):
                dangling.append({"from": rid, "ref": cwe, "type": "cwe"})
    elif kind == "exploit":
        if index.known_cve_ids:
            for cve in record.get("cve_refs") or ():
                if not index.resolve_cve(cve):
                    dangling.append({"from": rid, "ref": cve, "type": "cve"})
    elif kind == "cwe":
        for rel in record.get("related_cwe_ids") or ():
            if not index.resolve_cwe_any(rel):
                dangling.append({"from": rid, "ref": rel, "type": "cwe"})

    if table is not None:
        out["owasp_categories"] = owasp_categories_for(record, table)
    return out, dangling


def slice_included(record: dict, index: JoinIndex):
    """Stage-1 recipe predicate (design 2.3). Returns (bool, reasons)."""
    if record.get("excluded_from_index"):
        return False, []
    kind = record.get("kind")
    reasons = []
    if kind in ("cve", "exploit", "cwe"):
        if any(c in WEB_RELEVANT_CWES for c in effective_cwe_ids(record)):
            reasons.append("a-web-cwe")
        cvss = record.get("cvss")
        score = cvss.get("score") if isinstance(cvss, dict) else None
        if (isinstance(score, (int, float))
                and not isinstance(score, bool)
                and score >= CVSS_HIGH_THRESHOLD):
            reasons.append("b-cvss-high")
        if kind == "cve":
            if index.has_exploit(record.get("id", "")):
                reasons.append("c-public-exploit")
        elif kind == "exploit":
            refs = record.get("cve_refs") or ()
            if index.known_cve_ids and any(index.resolve_cve(c) for c in refs):
                reasons.append("c-public-exploit")
    return (True, reasons) if reasons else (False, [])


# --------------------------------------------------------------------------
# full streaming coverage pass
# --------------------------------------------------------------------------

def _pct(part, whole) -> float:
    return round(100.0 * part / whole, 2) if whole else 0.0


def peak_rss_mb():
    """Peak working set in MB; None when unavailable (non-win32).

    Uses kernel32!K32GetProcessMemoryInfo with explicit argtypes --
    the legacy psapi!GetProcessMemoryInfo entry point returns FALSE on
    this host (observed 2026-10-15, measured live probe)."""
    try:
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        pmc = PROCESS_MEMORY_COUNTERS()
        pmc.cb = ctypes.sizeof(pmc)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        fn = k32.K32GetProcessMemoryInfo
        fn.argtypes = [wintypes.HANDLE,
                       ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
                       wintypes.DWORD]
        fn.restype = wintypes.BOOL
        if fn(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb):
            return round(pmc.PeakWorkingSetSize / (1024.0 * 1024.0), 1)
    except Exception:
        pass
    return None


def _bounded_unique(uniques: set) -> dict:
    ordered = sorted(uniques)
    if len(ordered) > DANGLING_LIST_CAP:
        return {"count": len(ordered), "truncated": True,
                "unique": ordered[:1000]}
    return {"count": len(ordered), "truncated": False, "unique": ordered}


def run_coverage_pass(paths: dict, map_table: dict = None,
                      expected: dict = None, progress=None,
                      years=None) -> dict:
    """Stream all 4 archives once; return the measured coverage stats.

    ``paths``: {cvelistV5, exploitdb, cwec, top10} -> zip paths.
    ``expected``: optional {source: int} reconciliation targets (the
    real run passes extractors.INVENTORY_COUNTS values); None ->
    internal-consistency reconciliation only (emitted+rejected==seen).
    ``years``: optional CVE year filter (smoke runs).
    Only indexes/counters are retained -- the corpus is never held.
    """
    t0 = time.monotonic()
    table = map_table if map_table is not None else owasp_map.load_map()
    map_idx = owasp_map.cwe_to_categories(table)
    expected = dict(expected or {})

    def say(msg):
        if progress:
            progress(msg)

    index = JoinIndex()
    src_stats = {}

    # ---- phase 1: cwec catalog (small; ids only)
    say("phase 1/5: cwec catalog")
    st = extractors.ExtractStats("cwec")
    weaknesses_with_owasp = 0
    for rec in extractors.iter_cwe_records(paths["cwec"], st):
        index.add_cwe(rec)
        if rec["kind"] == "cwe" and rec["id"] in map_idx:
            weaknesses_with_owasp += 1
    src_stats["cwec"] = st

    # ---- phase 2: Top10 EN docs (counts only)
    say("phase 2/5: top10 EN docs")
    st = extractors.ExtractStats("top10")
    t10_editions = {}
    for rec in extractors.iter_top10_records(paths["top10"], st):
        index.add_doc(rec)
        t10_editions[rec.get("edition", "?")] = \
            t10_editions.get(rec.get("edition", "?"), 0) + 1
    st.extras["editions"] = dict(sorted(t10_editions.items()))
    src_stats["top10"] = st

    # ---- phase 3: exploitdb (index build)
    say("phase 3/5: exploitdb index")
    st = extractors.ExtractStats("exploitdb")
    edb_with_token = 0
    edb_cve_token_occurrences = 0
    for rec in extractors.iter_edb_records(paths["exploitdb"], st):
        index.add_edb(rec)
        refs = rec.get("cve_refs") or []
        if refs:
            edb_with_token += 1
            edb_cve_token_occurrences += len(refs)
    src_stats["exploitdb"] = st

    # ---- phase 4: cvelistV5 (the big stream; counters only)
    say("phase 4/5: cvelistV5 stream")
    st = extractors.ExtractStats("cvelistV5")
    cve_total = 0
    cve_with_cwe = 0
    cve_cwe_refs_total = 0
    cve_cwe_dangling_occ = 0
    cve_cwe_dangling_uni = set()
    cve_cwe_to_category = 0
    cve_with_owasp = 0
    cve_cvss_high = 0
    cve_with_exploit = 0
    cve_excluded = 0
    slice_cve = 0
    by_reason = {r: 0 for r in _REASONS}
    first_dup_sha = {}
    n = 0
    for rec in extractors.iter_cve_records(paths["cvelistV5"], st,
                                           years=years):
        n += 1
        if progress and n % 50000 == 0:
            say(f"  ... {n} CVE records streamed")
        rid = rec["id"]
        cve_total += 1
        if not index.add_known_cve(rid):
            index.dedup["cve"]["id_duplicates"] += 1
            sha = text_sha1(rec)
            if first_dup_sha.get(rid) == sha:
                index.dedup["cve"]["text_duplicates"] += 1
            first_dup_sha.setdefault(rid, sha)

        cwes = rec.get("cwe_ids") or []
        if cwes:
            cve_with_cwe += 1
        cve_cwe_refs_total += len(cwes)
        mapped = False
        for c in cwes:
            if index.resolve_cwe(c):
                pass
            elif index.resolve_cwe_category(c):
                cve_cwe_to_category += 1
            else:
                cve_cwe_dangling_occ += 1
                cve_cwe_dangling_uni.add(c)
            if c in map_idx:
                mapped = True
        if mapped:
            cve_with_owasp += 1

        cvss = rec.get("cvss")
        score = cvss.get("score") if isinstance(cvss, dict) else None
        if (isinstance(score, (int, float)) and not isinstance(score, bool)
                and score >= CVSS_HIGH_THRESHOLD):
            cve_cvss_high += 1
        if index.has_exploit(rid):
            cve_with_exploit += 1
        if rec.get("excluded_from_index"):
            cve_excluded += 1

        ok, reasons = slice_included(rec, index)
        if ok:
            slice_cve += 1
            for r in reasons:
                by_reason[r] += 1
    src_stats["cvelistV5"] = st
    say(f"  cvelistV5 done: {cve_total} records")

    # ---- phase 5: post-resolve EDB refs + slice tails
    say("phase 5/5: EDB dangling resolution + slice tails")
    edb_resolved_rows = 0
    edb_dangling_occ = 0
    edb_dangling_uni = set()
    slice_edb = 0
    for eid, row in index.edb_rows.items():
        refs = row["cve_refs"]
        resolved_any = False
        for c in refs:
            if index.resolve_cve(c):
                resolved_any = True
            else:
                edb_dangling_occ += 1
                edb_dangling_uni.add(c)
        if resolved_any:
            edb_resolved_rows += 1
            slice_edb += 1
            by_reason["c-public-exploit"] += 1
    slice_cwe = 0
    for cid in sorted(index.cwe_weakness_ids):
        if cid in WEB_RELEVANT_CWES:
            slice_cwe += 1
            by_reason["a-web-cwe"] += 1

    edb_rows_total = len(index.edb_rows)
    weaknesses_total = len(index.cwe_weakness_ids)
    map_cwes_total = len(map_idx)
    map_resolved = sum(1 for c in map_idx if index.resolve_cwe_any(c))

    # ---- reconciliation
    def recon(key, st, expected_count, actual, note=""):
        exp = expected.get(key)
        consistent = (st.emitted + st.rejected_total() == st.seen)
        if expected_count is not None:
            exp = expected_count
        match = consistent and (exp is None or actual == exp)
        return {"expected": exp, "actual": actual,
                "internal_consistent": consistent, "match": match,
                "note": note}

    edb_expected_rows = expected.get("exploitdb_rows")
    edb_expected_unique = expected.get("exploitdb_unique")
    edb_st = src_stats["exploitdb"]
    # duplicate-id collapses count in `seen` but are neither emitted nor
    # rejected -- they are the pilot dedup convention (first wins)
    st_ok = (edb_st.emitted + edb_st.rejected_total()
             + edb_st.extras.get("rows_dropped_duplicate_id", 0)
             == edb_st.seen)
    edb_match = st_ok and \
        (edb_expected_rows is None or edb_st.seen == edb_expected_rows) and \
        (edb_expected_unique is None or edb_rows_total == edb_expected_unique)
    cwe_expected = expected.get("cwec")
    cwe_actual = (len(index.cwe_weakness_ids) + len(index.cwe_category_ids))
    reconciliation = {
        "cvelistV5": recon("cvelistV5", src_stats["cvelistV5"],
                           expected.get("cvelistV5"),
                           src_stats["cvelistV5"].seen,
                           "CVE-regex members streamed"),
        "exploitdb": {"expected_rows": edb_expected_rows,
                      "actual_rows": src_stats["exploitdb"].seen,
                      "expected_unique": edb_expected_unique,
                      "actual_unique": edb_rows_total,
                      "internal_consistent": st_ok,
                      "match": edb_match,
                      "note": "rows incl. duplicate-id collapses (first wins)"},
        "cwec": {"expected": cwe_expected, "actual": cwe_actual,
                 "weaknesses": len(index.cwe_weakness_ids),
                 "categories": len(index.cwe_category_ids),
                 "internal_consistent":
                     src_stats["cwec"].emitted
                     + src_stats["cwec"].rejected_total()
                     == src_stats["cwec"].seen,
                 "match": (src_stats["cwec"].emitted
                           + src_stats["cwec"].rejected_total()
                           == src_stats["cwec"].seen)
                 and (cwe_expected is None or cwe_actual == cwe_expected),
                 "note": "969 Weakness + 422 Category expected (inventory)"},
        "top10": {"expected": expected.get("top10"),
                  "actual": src_stats["top10"].emitted,
                  "internal_consistent":
                      src_stats["top10"].emitted
                      + src_stats["top10"].rejected_total()
                      == src_stats["top10"].seen,
                  "match": (src_stats["top10"].emitted
                            + src_stats["top10"].rejected_total()
                            == src_stats["top10"].seen)
                  and (expected.get("top10") is None
                       or src_stats["top10"].emitted == expected["top10"]),
                  "note": "EN measured rule <edition>/(docs/)?en/*.md"},
    }

    stats = {
        "generated_by": "vuln_watchdog.joiner.run_coverage_pass",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "wall_time_seconds": round(time.monotonic() - t0, 1),
        "peak_rss_mb": peak_rss_mb(),
        "inputs": {k: {"path": v, "sha256": owasp_map._sha256_file(v)}
                   for k, v in sorted(paths.items())},
        "counts": {k: s.as_dict() for k, s in sorted(src_stats.items())},
        "reconciliation": reconciliation,
        "join_coverage": {
            "edb_rows_total": edb_rows_total,
            "edb_rows_with_cve_token": edb_with_token,
            "edb_rows_with_cve_token_pct":
                _pct(edb_with_token, edb_rows_total),
            "edb_cve_token_occurrences": edb_cve_token_occurrences,
            "edb_rows_with_resolved_cve": edb_resolved_rows,
            "edb_rows_with_resolved_cve_pct":
                _pct(edb_resolved_rows, edb_rows_total),
            "edb_cve_tokens_dangling_occurrences": edb_dangling_occ,
            "edb_cve_tokens_dangling_unique": len(edb_dangling_uni),
            "cve_total": cve_total,
            "cve_with_cwe": cve_with_cwe,
            "cve_with_cwe_pct": _pct(cve_with_cwe, cve_total),
            "cve_cwe_refs_total": cve_cwe_refs_total,
            "cve_cwe_refs_dangling_occurrences": cve_cwe_dangling_occ,
            "cve_cwe_refs_dangling_unique": len(cve_cwe_dangling_uni),
            "cve_cwe_refs_resolved_to_category": cve_cwe_to_category,
            "cve_with_public_exploit": cve_with_exploit,
            "cve_with_public_exploit_pct": _pct(cve_with_exploit, cve_total),
            "cve_with_owasp_mapping": cve_with_owasp,
            "cve_with_owasp_mapping_pct_of_with_cwe":
                _pct(cve_with_owasp, cve_with_cwe),
            "cve_cvss_high_count": cve_cvss_high,
            "cve_cvss_high_pct": _pct(cve_cvss_high, cve_total),
            "cve_excluded_from_index": cve_excluded,
            "cwe_weaknesses_total": weaknesses_total,
            "cwe_weaknesses_with_owasp": weaknesses_with_owasp,
            "cwe_owasp_coverage_pct":
                _pct(weaknesses_with_owasp, weaknesses_total),
            "map_cwes_total": map_cwes_total,
            "map_cwes_resolved_in_catalog": map_resolved,
            "map_version": table.get("map_version"),
            "web_relevant_cwes_version": WEB_RELEVANT_CWES_VERSION,
            "web_relevant_cwes_count": len(WEB_RELEVANT_CWES),
        },
        "dedup": index.dedup,
        "dangling_refs": {
            "cve_from_edb": _bounded_unique(edb_dangling_uni),
            "cwe_from_cve": _bounded_unique(cve_cwe_dangling_uni),
            "cwe_from_map": _bounded_unique(
                {c for c in map_idx if not index.resolve_cwe_any(c)}),
        },
        "slice_estimate": {
            "recipe": "stage-1 (design 2.3): web-relevant CWE OR cvss>=7.0 "
                      "OR has-public-exploit (exploit kind: resolved-cve "
                      "mirror); excluded_from_index vetoed",
            "web_relevant_cwes_version": WEB_RELEVANT_CWES_VERSION,
            "included": {
                "cve": slice_cve,
                "exploit": slice_edb,
                "cwe": slice_cwe,
                "cwe_category": 0,
                "owasp_doc": 0,
                "total": slice_cve + slice_edb + slice_cwe,
            },
            "by_reason": dict(by_reason),
            "taxonomy_docs_available": src_stats["top10"].emitted,
            "note": "owasp_doc/cwe_category are OUTSIDE the strict recipe "
                    "(reference kinds); A4 (P3) decides their inclusion as "
                    "a manifest config choice.",
        },
    }
    say("coverage pass complete")
    return stats
