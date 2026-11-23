"""WD-E5 runner -- the corpus embedding pass + store build CLI.

One streaming pass (design-spec 3.2 D-1): extract -> join -> recipe
filter (corpus.CorpusAssembler) -> chunk (chunker) -> embed (F2 client,
sha cache) -> StagedStore -> ATOMIC swap (store.StagedStore, SEC C-5)
-> manifest.json (atomic write).

Stages: ``slice`` (stage-1 tightened recipe, data/recipe_stage1.json)
and ``full`` (stage-2 full corpus, data/recipe_full.json -- owner D3
sign-off 2026-10-15, task.md ADDENDUM 2).

Kill-and-resume semantics (plan A5 DoD 2):
- the sha-keyed embed cache (``data/vulnkb/embed_cache/``) is
  the resume state: an interrupted pass re-run embeds ONLY the
  cache-missing chunks (zero re-embedding of completed work);
- the STAGED store DB is deliberately NOT resumed -- it is rebuilt
  from the stream (cheap relative to embedding) and swapped in one
  atomic os.replace at the very end;
- abort paths: (1) graceful -- create the abort file
  (``<store_dir>/build-<stage>.abort``); the loop exits at the next
  flush/commit boundary with code 3; (2) hard -- kill the process
  (taskkill): the staged temp is garbage (dot-prefixed in the store
  dir), the cache survives, re-launch resumes; (3) Ctrl-C /
  KeyboardInterrupt -> same graceful path (code 3).
- embed outage: transient Ollama failures ride the outer retry
  (default 30 x 60 s ~= 30 min of outage tolerance); a permanent
  failure exits 4 with NO store swap and the cache preserved.

Destination note: ``vulnkb.sqlite`` is a SINGLE destination -- the
stage-2 pass swaps its full store over the stage-1 slice store when it
finishes (atomic; readers with per-call connections pick it up; see
query.py Windows swap semantics).

Progress logs go to the ``log`` callback (default: stderr with
timestamps) so a detached run's stdout stays a clean JSON summary.

Pure stdlib. Loopback-only embedding (F2 client contract, C7).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import zipfile

from . import chunker
from . import corpus
from . import embed_client as ec
from . import extractors
from . import joiner
from . import store

EXIT_OK = 0
EXIT_INPUT = 2
EXIT_ABORTED = 3
EXIT_EMBED_BLOCKED = 4
EXIT_STORE = 5

#: Structural input failures surfaced by the streaming pass (corrupt /
#: truncated archives, missing expected editions, excluded sources).
#: The documented exit law (docs/VULNERABILITY-DB.md): these are INPUT
#: errors -- exit 2 with the engine's clear message, never a traceback.
_INPUT_ERRORS = (corpus.CorpusError, extractors.ExtractorError,
                 zipfile.BadZipFile)

DEFAULT_EMBED_BATCH = 64
DEFAULT_COMMIT_EVERY = 2000
DEFAULT_PROGRESS_EVERY = 2000
DEFAULT_EMBED_MAX_RETRIES = 30
DEFAULT_EMBED_RETRY_BACKOFF_S = 60.0


class BuildAbort(Exception):
    """Graceful abort requested (abort file / interrupt)."""


class EmbedBlocked(Exception):
    """Ollama stayed unreachable past the outer retry budget."""


class BuildInputError(Exception):
    """Bad stage/recipe/archives -- nothing was written."""


def default_abort_file(store_dir: str, stage: str) -> str:
    return os.path.join(store_dir, f"build-{stage}.abort")


def _stderr_log(msg: str) -> None:
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}",
          file=sys.stderr, flush=True)


class _EmbedAdapter:
    """Normalizes the embedder injection point: an EmbeddingClient (real
    runs: sha cache + validation + prefix law) or a plain callable
    list[str] -> list[vec] (tests / exotic reruns)."""

    def __init__(self, embedder, cache_dir, model=None, log=_stderr_log):
        self.stats_source = None
        self.api_texts = 0
        self.model = model or ec.DEFAULT_MODEL
        if embedder is None:
            self.client = ec.EmbeddingClient(
                cache_dir=cache_dir, model=self.model)
            self.stats_source = self.client
        elif isinstance(embedder, ec.EmbeddingClient):
            self.client = embedder
            self.model = embedder.model
            self.stats_source = embedder
        elif callable(embedder):
            self.client = None
            self._fn = embedder
        else:
            raise BuildInputError(
                "embedder must be an EmbeddingClient or a callable")

    def embed_documents(self, texts):
        if self.client is not None:
            return self.client.embed_documents(texts)
        out = self._fn(texts)
        self.api_texts += len(texts)
        if len(out) != len(texts):
            raise ec.EmbeddingValidationError(
                f"embedder returned {len(out)} vectors "
                f"for {len(texts)} texts")
        return out

    def stats(self):
        if self.stats_source is not None:
            s = dict(self.stats_source.stats)
        else:
            s = {"cache_hits": 0, "api_texts": self.api_texts,
                 "api_calls": 0, "retries": 0, "validation_failures": 0}
        return s


def run_build(stage: str,
              raw_dir: str = corpus.DEFAULT_RAW_DIR,
              store_dir: str = store.DEFAULT_STORE_DIR,
              recipe_path: str = None,
              cache_dir: str = None,
              dry_run: bool = False,
              limit: int = None,
              years=None,
              embed_batch: int = DEFAULT_EMBED_BATCH,
              commit_every: int = DEFAULT_COMMIT_EVERY,
              progress_every: int = DEFAULT_PROGRESS_EVERY,
              abort_file: str = None,
              embedder=None,
              embed_max_retries: int = DEFAULT_EMBED_MAX_RETRIES,
              embed_retry_backoff_s: float = DEFAULT_EMBED_RETRY_BACKOFF_S,
              log=None,
              model: str = None,
              eta_hint_chunks: int = None) -> dict:
    """Run one build stage; returns the summary dict (exit_code field).

    NEVER raises for the handled failure classes (abort / embed-blocked
    / store / input) -- the summary carries the exit code. (A5: the
    launcher script and tests read exit_code; main() maps it to the
    process exit status.)"""
    log = log or _stderr_log
    t0 = time.monotonic()
    summary = {
        "exit_code": EXIT_OK, "stage": stage, "dry_run": bool(dry_run),
        "recipe_id": None, "corpus_version": None,
        "records_total": 0, "records_by_kind": {},
        "records_seen_total": 0,
        "records_excluded_store_only": 0, "excluded_vetoed": 0,
        "chunks_total": 0, "chunks_by_kind": {}, "chunks_truncated": 0,
        "api_texts": 0, "api_calls": 0, "cache_hits": 0,
        "wall_seconds": 0.0, "chunks_per_s": None,
        "store_path": None, "store_bytes": None, "manifest_path": None,
        "message": "",
    }

    def finish(code, message, **extra):
        summary["exit_code"] = code
        summary["message"] = message
        summary["wall_seconds"] = round(time.monotonic() - t0, 2)
        summary.update(extra)
        return summary

    # ---- inputs / recipe (exit 2 on any config problem)
    try:
        recipe = corpus.load_recipe(recipe_path, stage=stage) \
            if recipe_path else corpus.load_recipe(stage=stage)
    except corpus.CorpusError as exc:
        return finish(EXIT_INPUT, f"recipe error: {exc}")
    summary["recipe_id"] = recipe["recipe_id"]
    try:
        paths = corpus.default_archive_paths(raw_dir)
    except corpus.CorpusError as exc:
        # FINAL-01: an unconfigured raw dir is an input error (exit 2
        # with the engine's clear message), never a raw traceback --
        # the same fail-loud input law as M3.4 (GAP-5).
        return finish(EXIT_INPUT, str(exc))
    missing = [f"{k}:{v}" for k, v in paths.items()
               if not os.path.exists(v)]
    if missing:
        return finish(EXIT_INPUT, f"missing archives: {missing}")
    try:
        inputs = corpus.input_fingerprint(paths)
    except corpus.CorpusError as exc:
        return finish(EXIT_INPUT, f"fingerprint error: {exc}")
    cv = corpus.corpus_version(recipe, inputs)
    summary["corpus_version"] = cv
    log(f"stage={stage} recipe={recipe['recipe_id']} "
        f"corpus_version={cv} dry_run={dry_run}")

    dest = os.path.join(store_dir, store.STORE_FILENAME)
    manifest_path = os.path.join(store_dir, store.MANIFEST_FILENAME)
    cache_dir = cache_dir or os.path.join(store_dir, "embed_cache")
    abort_file = abort_file or default_abort_file(store_dir, stage)
    summary["store_path"] = dest
    summary["manifest_path"] = manifest_path
    summary["abort_file"] = abort_file

    years_set = set(years) if years else None
    assembler = corpus.CorpusAssembler(paths, recipe,
                                       progress=log, years=years_set)

    # ---- streaming chunk counters
    chunks_total = 0
    chunks_by_kind = {}
    chunks_truncated = 0
    records_excluded_store_only = 0
    records_total = 0

    def count_chunks(rec, chunks):
        nonlocal chunks_total, chunks_truncated, records_excluded_store_only
        kind = rec.get("kind", "?")
        for c in chunks:
            chunks_total += 1
            chunks_by_kind[kind] = chunks_by_kind.get(kind, 0) + 1
            if c.get("truncated"):
                chunks_truncated += 1
        if rec.get("excluded_from_index"):
            records_excluded_store_only += 1

    def chunk_counts_block():
        return {"chunks_total": chunks_total,
                "chunks_by_kind": dict(sorted(chunks_by_kind.items())),
                "chunks_truncated": chunks_truncated,
                "records_excluded_store_only": records_excluded_store_only}

    # ---- dry run: measured counts, no embedder, no store writes
    if dry_run:
        try:
            for rec in assembler.iter_records():
                records_total += 1
                if os.path.exists(abort_file):
                    raise BuildAbort()
                count_chunks(rec, chunker.chunk_record(
                    rec, min_total_tokens=recipe.get("min_total_tokens", 1)))
                if limit is not None and records_total >= limit:
                    break
        except BuildAbort:
            return finish(EXIT_ABORTED, "dry run aborted",
                          records_total=records_total)
        except _INPUT_ERRORS as exc:
            return finish(EXIT_INPUT, f"input error: {exc}",
                          records_total=records_total)
        summary.update(
            records_total=assembler.stats["included_total"],
            records_by_kind={
                k: v["included"]
                for k, v in sorted(assembler.stats["kinds"].items())},
            records_seen_total=sum(
                v["seen"] for v in assembler.stats["kinds"].values()),
            excluded_vetoed=assembler.stats["excluded_vetoed"],
            by_reason=assembler.stats["by_reason"],
            phase_seconds=assembler.stats["phase_seconds"],
            **chunk_counts_block())
        return finish(EXIT_OK, "dry run complete (no store written)")

    # ---- real build
    if os.path.exists(abort_file):
        return finish(EXIT_ABORTED,
                      f"abort file present before start: {abort_file}")
    try:
        adapter = _EmbedAdapter(embedder, cache_dir, model=model, log=log)
    except BuildInputError as exc:
        return finish(EXIT_INPUT, str(exc))
    summary["model"] = adapter.model

    def check_abort():
        if os.path.exists(abort_file):
            raise BuildAbort()

    def embed_with_retry(texts):
        attempt = 0
        while True:
            try:
                return adapter.embed_documents(texts)
            except ec.EmbeddingError as exc:
                if attempt >= embed_max_retries:
                    raise EmbedBlocked(
                        f"ollama unreachable after {attempt + 1} outer "
                        f"attempts: {exc}") from exc
                attempt += 1
                log(f"embed retry {attempt}/{embed_max_retries} after: "
                    f"{exc!r}; backoff {embed_retry_backoff_s}s "
                    f"(cache preserved -- resume-safe)")
                if embed_retry_backoff_s:
                    time.sleep(embed_retry_backoff_s)

    staged = store.StagedStore(dest)
    pending = []
    embedded = 0

    def flush():
        nonlocal pending, embedded
        if not pending:
            return
        texts = [c["text"] for _, c in pending]
        vectors = embed_with_retry(texts)
        if len(vectors) != len(pending):
            raise store.StoreError(
                "embed-count-mismatch",
                f"{len(vectors)} vectors for {len(pending)} chunks")
        for (rid, c), v in zip(pending, vectors):
            staged.add_chunk(rid, c["chunk_index"], c["parts_total"],
                             c["text"], v, c["est_tokens"],
                             c["truncated"])
        embedded += len(pending)
        pending = []

    try:
        with staged:
            for rec in assembler.iter_records():
                rec["corpus_version"] = cv
                staged.add_record(rec)
                records_total += 1
                chunks = chunker.chunk_record(
                    rec, min_total_tokens=recipe.get("min_total_tokens", 1))
                count_chunks(rec, chunks)
                for c in chunks:
                    pending.append((rec["id"], c))
                if len(pending) >= embed_batch:
                    flush()
                    check_abort()
                if records_total % commit_every == 0:
                    staged.commit()
                    check_abort()
                if progress_every and records_total % progress_every == 0:
                    s = adapter.stats()
                    elapsed = time.monotonic() - t0
                    rate = (s["cache_hits"] + s["api_texts"]) / elapsed \
                        if elapsed > 0 else 0.0
                    eta = ""
                    if eta_hint_chunks and rate > 0:
                        left = max(0, eta_hint_chunks - chunks_total)
                        eta = f" eta~{left / rate / 3600.0:.2f}h"
                    log(f"records={records_total} chunks={chunks_total} "
                        f"embedded={embedded} "
                        f"cache_hits={s['cache_hits']} "
                        f"api_texts={s['api_texts']} "
                        f"api_calls={s['api_calls']} "
                        f"rate={rate:.1f}/s elapsed={elapsed:.0f}s{eta} "
                        f"rss={joiner.peak_rss_mb()}MB")
                if limit is not None and records_total >= limit:
                    log(f"limit {limit} reached -- stopping stream")
                    break
            flush()
            staged.commit()

            # finish + swap INSIDE the context guard: any failure here
            # still triggers the staged-temp cleanup (SEC C-5), and the
            # destination is only touched by the single os.replace.
            st_stats = adapter.stats()
            manifest = corpus.build_manifest(
                recipe, inputs, assembler.stats, chunk_counts_block(),
                stage=stage, builder="vuln_watchdog.build",
                extra={
                    "embed": {"model": adapter.model,
                              "cache_dir": cache_dir,
                              "cache_hits": st_stats["cache_hits"],
                              "api_texts": st_stats["api_texts"],
                              "api_calls": st_stats["api_calls"],
                              "validation_failures":
                                  st_stats["validation_failures"]},
                    "phase_seconds": assembler.stats["phase_seconds"],
                    "by_reason": assembler.stats["by_reason"],
                    "wall_seconds": round(time.monotonic() - t0, 2),
                    "limit": limit,
                })
            staged.finish(manifest)
            staged.swap_into_dest()
            # the store's own meta table already carries the manifest
            # (authoritative); manifest.json is the convenience artifact
            corpus.write_manifest_atomic(manifest_path, manifest)
    except BuildAbort:
        return finish(EXIT_ABORTED,
                      f"aborted (cache preserved; re-run to resume): "
                      f"{abort_file}",
                      records_total=records_total,
                      chunks_total=chunks_total)
    except EmbedBlocked as exc:
        return finish(EXIT_EMBED_BLOCKED, str(exc),
                      records_total=records_total,
                      chunks_total=chunks_total,
                      embed_error=str(exc))
    except _INPUT_ERRORS as exc:
        # the staged temp is already cleaned by the context guard; the
        # destination store is untouched (no swap on an input failure)
        return finish(EXIT_INPUT, f"input error: {exc}",
                      records_total=records_total,
                      chunks_total=chunks_total)
    except store.StoreError as exc:
        return finish(EXIT_STORE, f"store error: {exc}",
                      store_error=exc.reason)
    except OSError as exc:
        return finish(EXIT_STORE, f"I/O error: {exc!r}")

    elapsed = time.monotonic() - t0
    st_stats = adapter.stats()
    summary.update(
        records_total=assembler.stats["included_total"],
        records_by_kind={
            k: v["included"]
            for k, v in sorted(assembler.stats["kinds"].items())},
        records_seen_total=sum(
            v["seen"] for v in assembler.stats["kinds"].values()),
        excluded_vetoed=assembler.stats["excluded_vetoed"],
        by_reason=assembler.stats["by_reason"],
        phase_seconds=assembler.stats["phase_seconds"],
        **chunk_counts_block())
    summary["api_texts"] = st_stats["api_texts"]
    summary["api_calls"] = st_stats["api_calls"]
    summary["cache_hits"] = st_stats["cache_hits"]
    summary["chunks_per_s"] = round(
        (st_stats["cache_hits"] + st_stats["api_texts"]) / elapsed, 3) \
        if elapsed > 0 else None
    summary["embed_only_chunks_per_s"] = round(
        st_stats["api_texts"] / elapsed, 3) if elapsed > 0 else None
    try:
        summary["store_bytes"] = os.path.getsize(dest)
    except OSError:
        pass
    return finish(EXIT_OK, "build complete; store swapped atomically")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m vuln_watchdog.build",
        description="Vuln-KB corpus build (WD-E5): extract -> join -> "
                    "recipe -> chunk -> embed (loopback Ollama, sha "
                    "cache) -> atomic SQLite store swap.")
    p.add_argument("--stage", choices=("slice", "full"), required=True)
    p.add_argument("--raw-dir", default=corpus.DEFAULT_RAW_DIR,
                   help="folder with the 4 raw archives")
    p.add_argument("--store-dir", default=store.DEFAULT_STORE_DIR)
    p.add_argument("--recipe", default=None,
                   help="explicit recipe JSON path (overrides the stage "
                        "default)")
    p.add_argument("--cache-dir", default=None,
                   help="embed sha cache (default <store-dir>/embed_cache)")
    p.add_argument("--dry-run", action="store_true",
                   help="measured counts only; no embedding, no store")
    p.add_argument("--limit", type=int, default=None,
                   help="stop after N records (smoke runs)")
    p.add_argument("--years", default=None,
                   help="comma-separated CVE year filter (smoke runs)")
    p.add_argument("--embed-batch", type=int, default=DEFAULT_EMBED_BATCH)
    p.add_argument("--commit-every", type=int, default=DEFAULT_COMMIT_EVERY)
    p.add_argument("--progress-every", type=int,
                   default=DEFAULT_PROGRESS_EVERY)
    p.add_argument("--abort-file", default=None,
                   help="graceful-abort trigger file (default "
                        "<store-dir>/build-<stage>.abort)")
    p.add_argument("--embed-max-retries", type=int,
                   default=DEFAULT_EMBED_MAX_RETRIES)
    p.add_argument("--embed-retry-backoff", type=float,
                   default=DEFAULT_EMBED_RETRY_BACKOFF_S)
    p.add_argument("--model", default=None,
                   help=f"Ollama model (default {ec.DEFAULT_MODEL}; a "
                        "swap auto-invalidates the sha cache)")
    p.add_argument("--eta-hint-chunks", type=int, default=None,
                   help="projected total chunks for ETA lines (stage-2: "
                        "456123 per the P0 projection)")
    args = p.parse_args(argv)
    years = set(y.strip() for y in args.years.split(",")) \
        if args.years else None
    try:
        summary = run_build(
            args.stage, raw_dir=args.raw_dir, store_dir=args.store_dir,
            recipe_path=args.recipe, cache_dir=args.cache_dir,
            dry_run=args.dry_run, limit=args.limit, years=years,
            embed_batch=args.embed_batch, commit_every=args.commit_every,
            progress_every=args.progress_every,
            abort_file=args.abort_file,
            embed_max_retries=args.embed_max_retries,
            embed_retry_backoff_s=args.embed_retry_backoff,
            model=args.model, eta_hint_chunks=args.eta_hint_chunks)
    except KeyboardInterrupt:
        print(json.dumps({
            "exit_code": EXIT_ABORTED,
            "message": "interrupted -- kill-and-resume safe: the sha "
                       "cache is preserved; re-run the same command to "
                       "resume; the staged temp DB is garbage-"
                       "collectable (dot-prefixed in the store dir)"}))
        return EXIT_ABORTED
    print(json.dumps(summary, indent=1, default=str))
    return summary["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
