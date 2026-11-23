"""WD-E4 -- corpus assembler (design-spec 2.3/3.2, plan A4).

Recipe config (checked-in JSON, versioned) -> deterministic manifest
(record/chunk counts, input archive sha256s, corpus_version, recipe).
Selects records per the recipe and STREAMS them (never a full
in-memory corpus; only join indexes, the 1,391-record CWE catalog and
the 61 OWASP docs are retained -- bounded reference data, not corpus).

Recipes (data, not code paths -- plan A4 DoD 1):
- ``logic: "tightened"`` -- director ruling D3/A4 2026-10-15: a AND
  (b OR c): web-relevant CWE (a) AND (cvss >= cvss_min (b) OR
  has-public-exploit (c));
- ``logic: "union"`` -- design-2.3 original: a OR b OR c (kept for
  parity tests vs ``joiner.slice_included``);
- ``logic: "full"`` -- stage 2: every record; excluded_from_index
  records ride along STORE-ONLY (F1 law, zero chunks downstream).

Exploit records carry no cwe_ids, so branch (a) is unsatisfiable for
them; their inclusion is the configurable ``exploit_mirror``
(A4 composition sub-choice, design 2.3 / p2-join-stats
slice_estimate.note): "sliced-cve" (>= 1 resolved CVE ref that is
itself in the slice), "resolved-cve" (union-era mirror), "all",
"none". Reference kinds (web-relevant CWE catalog rows, cwe_category,
owasp_doc) are an ``include_reference`` config choice.

Determinism: same recipe + same input sha256s -> same corpus_version
and same record sequence (extractors sort members; phases are fixed).
``created_at`` in the manifest is the ONLY non-deterministic field and
is labeled as such.

Pure stdlib; archive text is UNTRUSTED DATA (C12) -- carried, counted,
never interpreted.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from collections import Counter

from . import extractors
from . import joiner
from . import owasp_map

MANIFEST_VERSION = 1

RECIPE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
STAGE_RECIPES = {"slice": "recipe_stage1.json", "full": "recipe_full.json"}
RECIPE_NAMES = {"stage1": "recipe_stage1.json", "full": "recipe_full.json",
                "slice": "recipe_stage1.json"}

#: raw archive folder -- UNCONFIGURED by default (FINAL-01). No absolute
#: developer path ships in the wheel; the build CLI requires an explicit
#: --raw-dir, and an unconfigured value is a loud input error (see
#: default_archive_paths). The directory is given -- never created.
DEFAULT_RAW_DIR = None
ARCHIVE_FILENAMES = {
    "cvelistV5": "cvelistV5-main.zip",
    "exploitdb": "exploitdb-main.zip",
    "cwec": "cwec_latest.xml.zip",
    "top10": "Top10-master.zip",
}

LOGICS = ("tightened", "union", "full")
MIRRORS = ("sliced-cve", "resolved-cve", "all", "none")
_REFERENCE_KEYS = ("cwe_web_relevant", "cwe_category", "owasp_doc")
_BRANCH_REASONS = ("a-web-cwe", "b-cvss-high", "c-public-exploit")

_REQUIRED_FIELDS = ("recipe_id", "recipe_version", "stage", "logic",
                    "exploit_mirror", "include_reference",
                    "excluded_from_index_veto", "min_total_tokens")


class CorpusError(RuntimeError):
    """Recipe/config/input failure -- never a partial corpus."""


# --------------------------------------------------------------------------
# recipe config
# --------------------------------------------------------------------------

def validate_recipe(recipe) -> list:
    """Shape errors ([] = valid). Config is data: bad shapes are reported
    as error codes, never KeyErrors mid-stream."""
    errs = []
    if not isinstance(recipe, dict):
        return ["recipe:not-a-dict"]
    for field in _REQUIRED_FIELDS:
        if field not in recipe:
            errs.append(f"missing:{field}")
    for field in ("recipe_id", "recipe_version", "stage"):
        v = recipe.get(field)
        if not isinstance(v, str) or not v.strip():
            errs.append(f"bad_{field}:{v!r}")
    if recipe.get("logic") not in LOGICS:
        errs.append(f"bad_logic:{recipe.get('logic')!r}")
    if recipe.get("exploit_mirror") not in MIRRORS:
        errs.append(f"bad_exploit_mirror:{recipe.get('exploit_mirror')!r}")
    cvss_min = recipe.get("cvss_min")
    if cvss_min is not None and (
            isinstance(cvss_min, bool)
            or not isinstance(cvss_min, (int, float))
            or not (0.0 <= float(cvss_min) <= 10.0)):
        errs.append(f"bad_cvss_min:{cvss_min!r}")
    inc = recipe.get("include_reference")
    if not isinstance(inc, dict) or any(k not in inc for k in _REFERENCE_KEYS):
        errs.append(f"bad_include_reference:{inc!r}")
    else:
        for k in _REFERENCE_KEYS:
            if not isinstance(inc[k], bool):
                errs.append(f"bad_include_reference:{k}={inc[k]!r}")
    if not isinstance(recipe.get("excluded_from_index_veto"), bool):
        errs.append("bad_excluded_from_index_veto")
    mtt = recipe.get("min_total_tokens")
    if isinstance(mtt, bool) or not isinstance(mtt, int) or mtt < 0:
        errs.append(f"bad_min_total_tokens:{mtt!r}")
    years = recipe.get("years")
    if years is not None and (
            not isinstance(years, (list, tuple, set))
            or not all(isinstance(y, str) and len(y) == 4 and y.isdigit()
                       for y in years)):
        errs.append(f"bad_years:{years!r}")
    return errs


def load_recipe(name_or_path=None, stage: str = None) -> dict:
    """Load a checked-in recipe by stage ('slice'/'full'), short name
    ('stage1'/'full'), or explicit file path. Validates shape."""
    if name_or_path is not None:
        p = name_or_path
        if not os.path.isabs(p) and not os.path.exists(p):
            cand = os.path.join(RECIPE_DIR, p)
            p = cand if os.path.exists(cand) else p
        if not os.path.exists(p) and p in RECIPE_NAMES:
            p = os.path.join(RECIPE_DIR, RECIPE_NAMES[p])
    elif stage is not None:
        if stage not in STAGE_RECIPES:
            raise CorpusError(f"unknown stage recipe: {stage!r} "
                              f"(known: {sorted(STAGE_RECIPES)})")
        p = os.path.join(RECIPE_DIR, STAGE_RECIPES[stage])
    else:
        p = os.path.join(RECIPE_DIR, STAGE_RECIPES["slice"])
    try:
        with open(p, encoding="utf-8") as f:
            recipe = json.load(f)
    except (OSError, ValueError) as exc:
        raise CorpusError(f"cannot load recipe {p}: {exc}") from exc
    errs = validate_recipe(recipe)
    if errs:
        raise CorpusError(f"invalid recipe {p}: {errs}")
    return recipe


def default_archive_paths(raw_dir: str = DEFAULT_RAW_DIR) -> dict:
    """Paths of the 4 raw archives under ``raw_dir``. An unconfigured
    raw dir (the portable None default, or an empty string) is an
    explicit input error -- never a silent join onto a developer path
    (FINAL-01). The caller supplies the directory (--raw-dir)."""
    if not raw_dir:
        raise CorpusError(
            "no archive directory configured -- pass --raw-dir "
            "<dir-with-4-archives> (e.g. vulndog db build --raw-dir ...)")
    return {name: os.path.join(raw_dir, fn)
            for name, fn in ARCHIVE_FILENAMES.items()}


# --------------------------------------------------------------------------
# recipe predicate
# --------------------------------------------------------------------------

def recipe_branches(record: dict, index: joiner.JoinIndex,
                    recipe: dict) -> dict:
    """Boolean branch flags {a, b, c} (design 2.3 names):
    a = effective CWE set intersects the web-relevant list;
    b = cvss.score >= recipe cvss_min (null cvss = below threshold);
    c = has-public-exploit (cve: join flag; exploit: >= 1 resolved
        cve_ref -- the design-2.3 mirror branch)."""
    a = any(c in joiner.WEB_RELEVANT_CWES
            for c in joiner.effective_cwe_ids(record))
    cvss = record.get("cvss")
    score = cvss.get("score") if isinstance(cvss, dict) else None
    cvss_min = recipe.get("cvss_min")
    b = (isinstance(score, (int, float)) and not isinstance(score, bool)
         and cvss_min is not None and score >= cvss_min)
    c = False
    kind = record.get("kind")
    if kind == "cve":
        c = index.has_exploit(record.get("id", ""))
    elif kind == "exploit":
        refs = record.get("cve_refs") or ()
        c = bool(index.known_cve_ids) and any(index.resolve_cve(r)
                                              for r in refs)
    return {"a": a, "b": b, "c": c}


def record_included(record: dict, index: joiner.JoinIndex, recipe: dict,
                    sliced_cve_ids: set = None):
    """Recipe predicate -> (included, reasons). Pure (no mutation).

    ``sliced_cve_ids``: the set of CVE ids already accepted into the
    slice (exploit_mirror="sliced-cve" consumes it; None = empty)."""
    logic = recipe.get("logic")
    if logic == "full":
        return True, ["full"]
    if recipe.get("excluded_from_index_veto", True) \
            and record.get("excluded_from_index"):
        return False, []
    kind = record.get("kind")
    inc_ref = recipe.get("include_reference") or {}

    if kind == "cwe_category":
        if inc_ref.get("cwe_category"):
            return True, ["ref-cwe-category"]
        return False, []
    if kind == "owasp_doc":
        if inc_ref.get("owasp_doc"):
            return True, ["ref-owasp-doc"]
        return False, []
    if kind == "cwe":
        if inc_ref.get("cwe_web_relevant") \
                and record.get("id") in joiner.WEB_RELEVANT_CWES:
            return True, ["ref-web-cwe"]
        if logic == "union":
            # parity with joiner.slice_included: a-branch for cwe kind
            br = recipe_branches(record, index, recipe)
            if br["a"]:
                return True, ["a-web-cwe"]
        return False, []
    if kind == "exploit":
        mirror = recipe.get("exploit_mirror", "none")
        refs = record.get("cve_refs") or ()
        if mirror == "all":
            return True, ["mirror-all"]
        if mirror == "sliced-cve":
            if sliced_cve_ids and any(r in sliced_cve_ids for r in refs):
                return True, ["mirror-sliced-cve"]
            return False, []
        if mirror == "resolved-cve":
            if index.known_cve_ids and any(index.resolve_cve(r)
                                           for r in refs):
                return True, ["c-public-exploit"]
            return False, []
        return False, []
    if kind == "cve":
        br = recipe_branches(record, index, recipe)
        if logic == "tightened":
            ok = br["a"] and (br["b"] or br["c"])
        elif logic == "union":
            ok = br["a"] or br["b"] or br["c"]
        else:
            ok = False
        reasons = [name for name, flag in zip(_BRANCH_REASONS,
                                              (br["a"], br["b"], br["c"]))
                   if flag]
        return ok, reasons
    return False, []


# --------------------------------------------------------------------------
# streaming assembler
# --------------------------------------------------------------------------

class CorpusAssembler:
    """Single streaming pass: extract -> join-attach -> recipe filter.

    Yields F1-normalized, join-attached records (never mutates inputs,
    never holds the corpus). ``stats`` is filled AS the stream advances
    (final when the generator is exhausted)."""

    def __init__(self, paths: dict, recipe: dict, map_table: dict = None,
                 progress=None, years=None):
        errs = validate_recipe(recipe)
        if errs:
            raise CorpusError(f"invalid recipe: {errs}")
        missing = [k for k in ("cvelistV5", "exploitdb", "cwec", "top10")
                   if k not in paths]
        if missing:
            raise CorpusError(f"missing archive paths: {missing}")
        self.paths = dict(paths)
        self.recipe = recipe
        self.table = map_table if map_table is not None \
            else owasp_map.load_map()
        self.progress = progress
        self.years = years  # smoke override; recipe years is the default
        if self.years is None:
            ry = recipe.get("years")
            self.years = set(ry) if ry else None
        self.stats = {
            "kinds": {k: {"seen": 0, "included": 0}
                      for k in extractors.record_schema.KINDS},
            "by_reason": Counter(),
            "excluded_vetoed": 0,
            "dangling": {"cve_occ": 0, "cwe_occ": 0},
            "included_total": 0,
            "phase_seconds": {},
        }
        self.extract_stats = {}

    # -- helpers
    def _say(self, msg):
        if self.progress:
            self.progress(msg)

    def _count_dangling(self, dangling):
        for d in dangling:
            if d.get("type") == "cve":
                self.stats["dangling"]["cve_occ"] += 1
            else:
                self.stats["dangling"]["cwe_occ"] += 1

    def _emit(self, record, reasons):
        kind = record.get("kind")
        self.stats["kinds"].setdefault(
            kind, {"seen": 0, "included": 0})["included"] += 1
        self.stats["included_total"] += 1
        for r in reasons:
            self.stats["by_reason"][r] += 1
        return record

    # -- the pass
    def iter_records(self):
        t_start = time.monotonic()
        index = joiner.JoinIndex()
        st = self.stats

        # phase 1: CWE catalog (ids for the join + retained records:
        # 1,391 bounded reference rows, NOT corpus)
        self._say("corpus phase 1/6: cwec catalog")
        ex_st = extractors.ExtractStats("cwec")
        self.extract_stats["cwec"] = ex_st
        cwe_records = []
        for rec in extractors.iter_cwe_records(self.paths["cwec"], ex_st):
            index.add_cwe(rec)
            st["kinds"][rec["kind"]]["seen"] += 1
            cwe_records.append(rec)
        st["phase_seconds"]["cwec"] = round(time.monotonic() - t_start, 2)

        # phase 2: Top10 EN docs (bounded: ~61)
        self._say("corpus phase 2/6: top10 docs")
        t = time.monotonic()
        ex_st = extractors.ExtractStats("top10")
        self.extract_stats["top10"] = ex_st
        docs = []
        for rec in extractors.iter_top10_records(self.paths["top10"], ex_st):
            index.add_doc(rec)
            st["kinds"]["owasp_doc"]["seen"] += 1
            docs.append(rec)
        st["phase_seconds"]["top10"] = round(time.monotonic() - t, 2)
        # Fail-loud edition law (docs/VULNERABILITY-DB.md Step 1; the
        # same expected editions the map regen enforces): a missing
        # expected edition aborts the build -- never a silent partial
        # store. Presence (>= 1 EN doc), not the map's exactly-10 rule:
        # the build streams ALL EN docs of an edition, not only A01..A10.
        editions_seen = {r.get("edition") for r in docs}
        missing_editions = [e for e in owasp_map.EXPECTED_EDITIONS
                            if e not in editions_seen]
        if missing_editions:
            raise CorpusError(
                f"OWASP archive missing expected edition(s) "
                f"{missing_editions}: {self.paths['top10']} -- layout "
                "drift? (fail-loud: never a silent partial store)")

        # phase 3: exploitdb index (ids + cve_refs + sha only)
        self._say("corpus phase 3/6: exploitdb index")
        t = time.monotonic()
        ex_st = extractors.ExtractStats("exploitdb")
        self.extract_stats["exploitdb_index"] = ex_st
        for rec in extractors.iter_edb_records(self.paths["exploitdb"],
                                               ex_st):
            index.add_edb(rec)
            st["kinds"]["exploit"]["seen"] += 1
        st["phase_seconds"]["exploitdb_index"] = \
            round(time.monotonic() - t, 2)

        # phase 4: the big CVE stream (yield-and-forget)
        self._say("corpus phase 4/6: cvelistV5 stream")
        t = time.monotonic()
        ex_st = extractors.ExtractStats("cvelistV5")
        self.extract_stats["cvelistV5"] = ex_st
        need_sliced = self.recipe.get("exploit_mirror") == "sliced-cve"
        sliced_cve_ids = set() if need_sliced else None
        n = 0
        for rec in extractors.iter_cve_records(self.paths["cvelistV5"],
                                               ex_st, years=self.years):
            n += 1
            if n % 50000 == 0:
                self._say(f"  ... {n} CVE records streamed")
            st["kinds"]["cve"]["seen"] += 1
            index.add_known_cve(rec.get("id", ""))
            joined, dangling = joiner.attach_joins(rec, index, self.table)
            self._count_dangling(dangling)
            ok, reasons = record_included(joined, index, self.recipe,
                                          sliced_cve_ids=sliced_cve_ids)
            if not ok:
                if joined.get("excluded_from_index") \
                        and self.recipe.get("excluded_from_index_veto",
                                            True):
                    st["excluded_vetoed"] += 1
                continue
            if need_sliced:
                sliced_cve_ids.add(joined["id"])
            yield self._emit(joined, reasons)
        st["phase_seconds"]["cvelistV5"] = round(time.monotonic() - t, 2)

        # phase 5: exploitdb emit pass (mirror needs the finished CVE
        # phase; CSV re-stream is cheap, records are NOT retained)
        self._say("corpus phase 5/6: exploitdb emit")
        t = time.monotonic()
        ex_st = extractors.ExtractStats("exploitdb-emit")
        self.extract_stats["exploitdb_emit"] = ex_st
        for rec in extractors.iter_edb_records(self.paths["exploitdb"],
                                               ex_st):
            joined, dangling = joiner.attach_joins(rec, index, self.table)
            self._count_dangling(dangling)
            ok, reasons = record_included(joined, index, self.recipe,
                                          sliced_cve_ids=sliced_cve_ids)
            if ok:
                yield self._emit(joined, reasons)
        st["phase_seconds"]["exploitdb_emit"] = round(time.monotonic() - t, 2)

        # phase 6: retained reference records (cwe, categories, docs)
        self._say("corpus phase 6/6: reference records")
        t = time.monotonic()
        for rec in cwe_records:
            joined, dangling = joiner.attach_joins(rec, index, self.table)
            self._count_dangling(dangling)
            ok, reasons = record_included(joined, index, self.recipe,
                                          sliced_cve_ids=sliced_cve_ids)
            if ok:
                yield self._emit(joined, reasons)
        for rec in docs:
            joined, dangling = joiner.attach_joins(rec, index, self.table)
            self._count_dangling(dangling)
            ok, reasons = record_included(joined, index, self.recipe,
                                          sliced_cve_ids=sliced_cve_ids)
            if ok:
                yield self._emit(joined, reasons)
        st["phase_seconds"]["reference"] = round(time.monotonic() - t, 2)
        st["by_reason"] = dict(st["by_reason"])
        self._say(f"corpus assembly complete: "
                  f"{st['included_total']} records included")


# --------------------------------------------------------------------------
# fingerprint / version / manifest
# --------------------------------------------------------------------------

def input_fingerprint(paths: dict) -> dict:
    """{name: {path, sha256, size_bytes}} -- streams each archive once."""
    out = {}
    for name in sorted(paths):
        p = paths[name]
        if not os.path.exists(p):
            raise CorpusError(f"input archive missing: {name} -> {p}")
        out[name] = {
            "path": p,
            "sha256": owasp_map._sha256_file(p),
            "size_bytes": os.path.getsize(p),
        }
    return out


def corpus_version(recipe: dict, fingerprint: dict) -> str:
    """Deterministic corpus id: a pure function of the recipe JSON and
    the input sha256s (any change -> new version; R10)."""
    payload = json.dumps(recipe, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True)
    payload += "\n" + json.dumps(
        sorted((name, fp.get("sha256", ""))
               for name, fp in fingerprint.items()),
        separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return "vkb1-" + digest[:16]


def build_manifest(recipe: dict, inputs: dict, assembler_stats: dict,
                   chunk_counts: dict, stage: str = None,
                   builder: str = "vuln_watchdog.build",
                   extra: dict = None) -> dict:
    """The deterministic corpus manifest (plan A4 DoD 2). ``created_at``
    is the ONLY non-deterministic field (labeled in the manifest)."""
    kinds_seen = {k: v.get("seen", 0)
                  for k, v in (assembler_stats.get("kinds") or {}).items()}
    kinds_inc = {k: v.get("included", 0)
                 for k, v in (assembler_stats.get("kinds") or {}).items()}
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "corpus_version": corpus_version(recipe, inputs),
        "stage": stage or recipe.get("stage"),
        "recipe": recipe,
        "inputs": inputs,
        "counts": {
            "records_total": assembler_stats.get("included_total", 0),
            "records_by_kind": kinds_inc,
            "records_seen_by_kind": kinds_seen,
            "records_excluded_store_only":
                chunk_counts.get("records_excluded_store_only", 0),
            "excluded_vetoed": assembler_stats.get("excluded_vetoed", 0),
            "chunks_total": chunk_counts.get("chunks_total", 0),
            "chunks_by_kind": chunk_counts.get("chunks_by_kind", {}),
            "chunks_truncated": chunk_counts.get("chunks_truncated", 0),
            "by_reason": assembler_stats.get("by_reason", {}),
            "dangling_ref_occurrences":
                assembler_stats.get("dangling", {}),
        },
        "chunker": {
            "soft_cap_tokens": chunk_counts.get("soft_cap_tokens"),
            "hard_cap_tokens": chunk_counts.get("hard_cap_tokens"),
            "min_total_tokens": recipe.get("min_total_tokens", 1),
        },
        "builder": builder,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "determinism_note": "corpus_version and all counts are a "
                            "deterministic function of (recipe, input "
                            "sha256s); created_at is the only "
                            "non-deterministic field.",
    }
    if extra:
        manifest["extra"] = extra
    return manifest


def write_manifest_atomic(path: str, manifest: dict) -> None:
    """tmp + os.replace (SEC C-5 pattern): a failure never leaves a
    partial manifest and never touches a previous one."""
    tmp = f"{path}.tmp-{os.getpid()}"
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            json.dump(manifest, f, indent=1, ensure_ascii=True,
                      sort_keys=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
