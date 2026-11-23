"""Cross-half analysis facade (pinned contract, brief Developer A).

``analyze_run`` is the ONE door the CLI half calls after a run: it
consumes the run's ``events.jsonl``, re-runs the engine's own matching
path on every event and writes the two flagged-request surfaces into
the run dir. Every event is F4-redacted BEFORE matching (one door,
fix-round-1 B2): the highlight surfaces derive from redacted data,
never from a raw spool row. Nothing here re-implements engine logic --
schema validation, the F4 redaction RE-RUN (COND-7a), the embed -> FTS5
prefilter -> pins -> cosine re-rank -> floor retrieval, mute/dedup and
the 19-field highlight records all come from the vendored modules
unchanged (``matcher.Matcher`` + ``query.QueryAPI`` +
``highlights.HighlightsWriter``).

Engine law surfaced honestly (docs/AI-INTEGRATION.md): the embedder
runs BEFORE exact-id pins; on embed failure the query API returns a
``skipped``/``embed-failed`` envelope with ZERO matches and the matcher
enters down-mode. The summary reports that as ``status="skipped"``
with the failure counters -- never a silent success. A missing/corrupt
store maps to ``status="disabled"`` (capture-only), likewise counted.

Idempotence: each call REWRITES highlights.jsonl + highlights.md from
the full events file (the two output files are removed first; no other
run-dir file is ever touched). Re-running the same analysis yields the
same surfaces; ``matched_at`` timestamps are the only volatile field.

Offline testing: ``config["embedder"]`` injects any object with
``embed_query(text)`` (the query-side protocol); absent, the real
transient Ollama client is used (``query.make_transient_embedder``,
loopback ``/api/embed``, embeddinggemma:300m). The injection key is an
internal seam -- producers never write it into the engine config file.
"""
from __future__ import annotations

import json
import os

from . import highlights as hl
from . import matcher as mt
from . import query as qy
from . import redaction_adapter as ra
from . import run as rn

#: Config keys the facade consumes from the engine config shape
#: (run.load_config). "embedder" is the test-injection seam (module
#: docstring); every other key keeps its engine meaning.
_ENGINE_KEYS = ("top_k", "floor", "filters", "mute_record_ids",
                "mute_url_prefixes", "per_event_deadline_s", "backoff_s")

#: Tap meta lines (M4): the bounded queue / spool cap report drops as
#: spool meta lines, NOT events. They are counted separately and never
#: reach the matcher (counting them as schema_invalid would pollute the
#: error accounting with the tap's own visibility mechanism).
_TAP_META_TYPES = frozenset({"drop_counter", "spool_cap"})


class _RecordingAPI:
    """QueryAPI wrapper that remembers the last non-null corpus_version
    from a match envelope (the matcher stamps it at match time; the
    summary needs it even when zero highlights were produced)."""

    def __init__(self, inner: qy.QueryAPI):
        self._inner = inner
        self.corpus_version: str | None = None

    def match(self, text, **kw) -> dict:
        env = self._inner.match(text, **kw)
        cv = env.get("corpus_version")
        if cv:
            self.corpus_version = cv
        return env


def _read_events(events_path: str):
    """Yield (event_or_None, json_error) per non-blank line. A missing
    file yields nothing (zero events is a legal quiet run)."""
    if not os.path.exists(events_path):
        return
    with open(events_path, encoding="utf-8") as fh:
        for line in fh:
            if not line.strip():
                continue
            try:
                yield json.loads(line), False
            except ValueError:
                yield None, True


def _status_for_mode(mode: str) -> str:
    if mode in (mt.MODE_OLLAMA_DOWN, mt.MODE_OLLAMA_HUNG):
        return "skipped"
    if mode == mt.MODE_KB_MISSING:
        return "disabled"
    return "ok"


def _require_path(name: str, value) -> str:
    """Boundary validation for caller-supplied paths (H2/F1).

    A None/empty/non-path store_path used to leak into QueryAPI and
    raise TypeError per event — surfaced as api-exception skips under
    status "ok", i.e. an unconfigured store reported as a clean
    analysis. Caller-side input errors raise ValueError (the engine's
    own discipline, cf. query._filter_sql); STORE-level failures still
    map to the never-raise "disabled" envelope inside QueryAPI.
    """
    if not isinstance(value, (str, os.PathLike)) or not os.fspath(value):
        raise ValueError(f"{name} must be a non-empty path, got {value!r}")
    return os.fspath(value)


def _effective_config(config: dict | None) -> dict:
    """Engine config layering (builtin <- checked-in file) with the
    caller's engine-key overrides on top. The merge itself stays in
    run.load_config — one decision in one place."""
    cfg = rn.load_config()
    for key in _ENGINE_KEYS:
        if config and key in config:
            cfg[key] = config[key]
    # normalize the mute lists once (Matcher accepts any iterable; the
    # facade passes them straight through)
    cfg["mute_record_ids"] = cfg.get("mute_record_ids") or ()
    cfg["mute_url_prefixes"] = cfg.get("mute_url_prefixes") or ()
    return cfg


def _prepare_outputs(run_dir: str) -> tuple[str, str, str]:
    """(hunt_id, jsonl_path, md_path). Idempotent rewrite: only the two
    owned output files are removed; no other run-dir file is touched."""
    os.makedirs(run_dir, exist_ok=True)
    hunt_id = os.path.basename(os.path.normpath(run_dir))
    jsonl_path = os.path.join(run_dir, "highlights.jsonl")
    md_path = os.path.join(run_dir, "highlights.md")
    for path in (jsonl_path, md_path):
        try:
            os.remove(path)
        except OSError:
            pass
    return hunt_id, jsonl_path, md_path


def _consume_events(matcher, writer, events_path: str) -> tuple[int, int, int]:
    """Drive the engine's per-event path over the spool; returns
    (events_read, json_errors, meta_lines). Schema/redaction drops are
    counted by the matcher (COND-7a); unparseable lines are counted
    here; tap meta lines (drop_counter / spool_cap, M4) are counted
    separately and skipped — they are visibility records, not events.
    Every event passes _pre_redact (the ONE door, B2) before matching;
    the matcher's own F4 re-run stays as defense in depth."""
    events_read = 0
    json_errors = 0
    meta_lines = 0
    for event, json_error in _read_events(events_path):
        events_read += 1
        if json_error:
            json_errors += 1
            continue
        if isinstance(event, dict) and event.get("type") in _TAP_META_TYPES:
            meta_lines += 1
            continue
        for highlight in matcher.process_event(_pre_redact(event)):
            writer.emit(highlight)
    return events_read, json_errors, meta_lines


def _pre_redact(event):
    """ONE door (B2): the F4-redacted copy feeds the matcher, so the
    highlight surfaces derive from redacted data even for a legacy raw
    spool. On a fail-closed drop the ORIGINAL is returned: the matcher's
    own COND-7a layers (schema first, then the F4 re-run) attribute the
    drop exactly as before, and the deterministic F4 verdict guarantees
    the raw event can never be matched."""
    if isinstance(event, dict):
        redacted, dropped = ra.redact_event(dict(event))
        if not dropped:
            return redacted
    return event


def analyze_run(*, events_path: str, run_dir: str, store_path: str,
                config: dict | None = None) -> dict:
    """Analyze one run's events and write its highlight surfaces.

    Args:
        events_path: the run's events.jsonl (F3 events, one JSON per
            line, as persisted by the tap).
        run_dir: the run folder; highlights.jsonl + highlights.md are
            (re)written here. hunt_id = the folder name (RUNS-AND-LOGS).
        store_path: the vulnkb.sqlite to match against (read-only).
        config: engine config dict (run.load_config shape). Optional
            "embedder" key injects a query-side embedder for offline
            tests; absent -> the real transient Ollama client.

    Returns:
        Summary dict with at least events_read, highlights, errors,
        corpus_version; plus status ("ok" | "skipped" | "disabled"),
        mode, meta_lines (tap drop_counter/spool_cap visibility records
        skipped, M4), the fail-closed counters (json_errors, schema_invalid,
        redaction_dropped, embed_failures, skipped_events, hangs,
        kb_disabled_events, buffered_while_down, pending), write_errors,
        the full matcher stats under "matcher", and the output paths.
        ``errors`` = every consumed line that did not reach a match
        (parse/schema/redaction drops + embed/store failures + skips).

    Raises:
        ValueError: a path argument is None/empty/not a path (caller
            error — distinct from a missing store, which is reported
            as status "disabled", never raised).
    """
    events_path = _require_path("events_path", events_path)
    run_dir = _require_path("run_dir", run_dir)
    store_path = _require_path("store_path", store_path)
    cfg = _effective_config(config)
    embedder = (config or {}).get("embedder")
    hunt_id, jsonl_path, md_path = _prepare_outputs(run_dir)

    api = _RecordingAPI(qy.QueryAPI(
        store_path=store_path, embedder=embedder,
        top_k=cfg.get("top_k", qy.DEFAULT_TOP_K),
        floor=cfg.get("floor", rn.BUILTIN_DEFAULTS["floor"])))
    matcher = mt.Matcher(
        api,
        floor=cfg.get("floor"),
        top_k=cfg.get("top_k"),
        filters=cfg.get("filters"),
        mute_record_ids=cfg["mute_record_ids"],
        mute_url_prefixes=cfg["mute_url_prefixes"],
        per_event_deadline_s=cfg.get("per_event_deadline_s"),
        backoff_s=cfg.get("backoff_s", mt.DEFAULT_BACKOFF_S))
    writer = hl.HighlightsWriter(run_dir, hunt_id)

    events_read, json_errors, meta_lines = _consume_events(
        matcher, writer, events_path)
    stats = matcher.stats()
    writer.write_summary(stats, matcher.burst_counts)

    errors = (json_errors + stats["schema_invalid"]
              + stats["redaction_dropped"] + stats["embed_failures"]
              + stats["hangs"] + stats["skipped_events"]
              + stats["kb_disabled_events"])
    return {
        "events_read": events_read,
        "highlights": writer.stats()["emitted"],
        "errors": errors,
        "corpus_version": api.corpus_version,
        "status": _status_for_mode(stats["mode"]),
        "mode": stats["mode"],
        "json_errors": json_errors,
        "meta_lines": meta_lines,
        "schema_invalid": stats["schema_invalid"],
        "redaction_dropped": stats["redaction_dropped"],
        "embed_failures": stats["embed_failures"],
        "skipped_events": stats["skipped_events"],
        "hangs": stats["hangs"],
        "kb_disabled_events": stats["kb_disabled_events"],
        "buffered_while_down": stats["buffered_while_down"],
        "pending": stats["pending"],
        "write_errors": writer.stats()["write_errors"],
        "matcher": stats,
        "highlights_jsonl": jsonl_path,
        "highlights_md": md_path,
    }