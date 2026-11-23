# Engine vendoring record (ADR-1 / ADR-1d)

## Upstream source

- Engine: the upstream project's `vuln_watchdog` package in the original
  development environment (the owner's own tool; 22 root modules, ~7.9k LOC).
- Redaction dependency: the upstream runtime redaction module
  (162 lines) — the engine's ONLY hard cross-tree import
  (`redaction_adapter.py:63-64`, upstream finding D-I).
- Vendored copy date: **2026-11-20**. The upstream project tree is not a
  git repository, so there is no upstream commit sha; provenance is the
  per-file sha256 manifest below + the copy date. Upstream test baseline
  at copy time: **690 tests** (upstream README, 2026-10-28 state).
- License/provenance: both upstream trees are the project owner's own
  code, vendored into VulnDog with the owner's authorization. A
  PROVISIONAL MIT `LICENSE` now ships at the repo root (fix-round-1 B3;
  the owner's GAP-1 decision is still open — see the provenance
  manifest below for the per-file sha256 record and the swap rule).

## What was copied (pure copy, no behavior edits)

- All 22 root modules into `src/vulndog/engine/`, module names unchanged:
  `benchutil, build, chunker, chunking, corpus, embed_client,
  event_schema, extractors, highlights, joiner, kb_index, matcher,
  owasp_map, query, record_schema, redaction_adapter, run, store,
  tailers, tap_sim, vecmath, __init__`.
- `data/` (4 files, byte-identical): `watchdog_config.json`,
  `cwe_owasp_map.json`, `recipe_stage1.json`, `recipe_full.json`.
- `tests/` → `src/vulndog/engine/tests/` (see porting policy below).
- NOT vendored: `benchmarks/` (measurement harnesses, not engine code;
  the benchmark helper modules `benchutil.py` / `tap_sim.py` ARE kept),
  `README.md` (upstream readme; VulnDog ships its own), `__pycache__`,
  `.pytest_cache`.

## What was changed vs copied (the complete minimal-touch list)

1. **`_redaction_core.py` (NEW)** — byte-for-byte copy of
   the upstream runtime redaction module (verified `cmp` identical).
   Original Russian docstrings/comments kept as-is (pure-copy law).
   Note: its `redact_key()` helper lazily does `from ..config import
   mask_secret`; under the new package path that resolves to
   `vulndog.config` (CLI half) instead of the upstream config module. The engine
   never calls `redact_key` (only `sanitize_snapshot` / `scrub` are
   used), and the helper's try/except fallback (`<redacted>`) is
   unchanged, so behavior is preserved either way.
2. **`redaction_adapter.py:62-64`** — the two
   upstream redaction import lines replumbed to
   `from ._redaction_core import ...` (ADR-1d). Comment updated.
   Nothing else in the module touched; F4 stays the single enforcement
   point, used as-is.
3. **`engine/__init__.py`** — docstring only: describes the vendored
   package instead of the upstream project location (no code change).
4. **`tests/conftest.py` (NEW)** — puts `<repo>/src` on `sys.path` so the
   suite collects standalone without an install; no-op after
   `pip install -e . --no-deps`.
5. **Test import rewrite (mechanical, all ported test modules)** —
   `from vuln_watchdog import X` → `from vulndog.engine import X`;
   `from vuln_watchdog.tests import X` → `from vulndog.engine.tests
   import X`. Verified import-only diffs (spot-checked `test_chunker`,
   `test_corpus`).

Deferred to later milestones (NOT phase-1 scope, per PLAN.md ADR-1
minimal-touch list): default path functions `run.py:129-138` /
`store.py:58-62` (D-C), timestamp run-dir naming (ADR-4).
`corpus.py` `DEFAULT_RAW_DIR` was deliberately NOT touched at phase-1
(archives pass via the build-CLI arg surface); it has since been made
portable (None + explicit input error) — see "Post-vendoring delta:
M3.4/final (FINAL-01)". The new config keys (M2.1) were deferred
at phase-1 and have since landed — see "Post-vendoring delta: M2.1".

## Test porting policy and results

Vendored suite: **606 tests, all passing** under pytest 9.1.1 /
Python 3.14.7, fully offline (no network, no Ollama, no upstream runtime):

```
python -m pytest src/vulndog/engine/tests -q   # 606 passed
```

Accounting: 690 upstream − 84 excluded (below) = 606 ported.

Six upstream test modules import the upstream runtime package at module
level (the brief estimated 12; the empirical count at copy time is 6).
Two were adapted, four excluded:

### Adapted (kept, upstream coupling removed)

- **`test_run.py`** — only `TaskIdParityTest` used the upstream runtime
  (`wt._valid_task_id`). Upstream asserted parity between
  `run.validate_task_id` and the upstream tap's validator; VulnDog does
  not vendor that producer, so the same 24-value battery now asserts
  the documented COND-6 rule directly (explicit expected table;
  `run.py:99-120`). Class renamed `TaskIdLawTest`; test count unchanged.
  All other 30+ tests are injectable (FakeAPI/FakeClock/tmp dirs) and
  ported unchanged.
- **`test_fuzz_fail_closed.py`** — `AdapterFuzzTest` (3 tests, pure
  engine F4 fuzz) kept unchanged. `TapFuzzTest` (1 test) EXCLUDED: it
  fuzzes the upstream `watchdog_tap` flusher (publish/flush/conservation
  counters), which is not vendored. Unused imports removed.

### Excluded modules (explicit list, with reasons and counts)

| Module | Tests | Reason |
|---|---|---|
| `test_watchdog_tap.py` | 45 | Tests the upstream `watchdog_tap` producer itself (queue/flusher/kill-switch/lazy-import laws). VulnDog replaces it with its own tap (ADR-3, CLI half); the module under test is not vendored. |
| `test_p2_hooks.py` | 28 | Tests upstream producer hooks (`net_gate`, `tool_proxy`, `playwright_backend`, `watchdog_tap`). None of these producers is vendored; engine-side redaction/schema halves are covered by `test_redaction_adapter*`, `test_event_schema`, `test_tailers`. |
| `test_p2_drill.py` | 2 | Integration drill driving real `net_gate.guarded_request` + `RequestMeter` ledger writes into the engine's `LedgerTailer`. Stubbing the producers would change what the drill measures; the engine-side consumption half is covered by `test_tailers.py` (incl. hunt-id restamp). |
| `test_p4_drills.py` | 8 | Full-lifecycle drill wired to real upstream producers (`net_gate` + `watchdog_tap` + `RequestMeter`) over loopback HTTP. Same reasoning; the engine matching/lifecycle halves are covered by `test_matcher.py`, `test_query.py`, `test_run.py`, `test_highlights.py` and the new `test_api.py` facade tests. |
| `test_fuzz_fail_closed.py::TapFuzzTest` | 1 | Upstream tap flusher fuzz (see adapted list above). |
| **Total excluded** | **84** | Never silently skipped — this table is the record. |

## Facade (`engine/api.py`) — new code, not vendored

`analyze_run(*, events_path, run_dir, store_path, config=None)` is the
pinned cross-half API (brief). It reuses the engine's own path:
`event_schema.validate_event` + `redaction_adapter.redact_event` re-run
(via `matcher.Matcher`, COND-7a) → `query.QueryAPI.match` (embed →
FTS5 prefilter → pins → cosine re-rank → floor) → mute/dedup →
`highlights.HighlightsWriter` (19 `HIGHLIGHT_FIELDS`, engine order).
Embedder injection for offline tests: `config["embedder"]` (an object
with `embed_query(text)`); absent → the real transient Ollama client
(`query.make_transient_embedder`). The embed-before-pins law and the
down-mode envelope are surfaced honestly in the returned summary
(`status`, `mode`, `errors`, full matcher counters) — never a silent
success. Path arguments are validated at the boundary (`_require_path`,
phase-2 H2/F1): None/empty/non-path is a caller-side ValueError —
distinct from a missing STORE, which keeps the engine's never-raise
`disabled` envelope. Phase-2 refactors split the facade into
`_effective_config` / `_prepare_outputs` / `_consume_events` helpers
(behaviour unchanged, suite-proved); the pinned signature, side effects
and summary shape are untouched.

## Python floor

`requires-python = ">=3.11"` (pinned contract; PLAN.md M2.5 CI matrix
3.11/3.12/3.13). The vendored code itself uses no syntax newer than 3.8
(every module has `from __future__ import annotations`; no match
statements, walrus, runtime PEP-604 unions, `zip(strict=)`, `tomllib`
or 3.12+-only constructs — grep-verified), so nothing in the engine
requires more than the contract floor. Verified live on 3.14.7.

## Acceptance evidence (2026-11-20)

- The upstream runtime package NOT importable in the interpreter
  (`importlib.util.find_spec` returns None for it) and
  `import vulndog.engine` (+ redaction_adapter/run/matcher/query)
  succeeds with zero upstream-package entries in `sys.modules`.
- `python -m pytest src/vulndog/engine/tests -q` → **606 passed**,
  zero collection errors, zero failures, ~8 s, offline.
- `python -m pip install -e . --no-deps` → success (stdlib-only
  runtime; `vulndog = "vulndog.cli:main"` entry string pinned, `main()`
  provided by the CLI half).
- `diff -rq` upstream-vs-vendored: engine changes ONLY in
  `__init__.py` (docstring), `redaction_adapter.py` (import replumb),
  plus the NEW byte-identical `_redaction_core.py`; `data/`
  byte-identical; test diffs import-only except the two documented
  adaptations.
- Facade TDD: `test_api.py` written first, observed RED
  (`ImportError: cannot import name 'api'`), then GREEN (9 tests).
  The embed-failure negative control was mutation-proved: forcing
  `_status_for_mode` to report "ok" on down-mode makes the test FAIL
  (rc 1); restored, it passes. Full suite: **615 passed**
  (606 ported + 9 facade).
- Optional LIVE smoke (non-mutating, real 1.93 GiB store + live
  Ollama embeddinggemma:300m): 3 events -> 9 highlights, 0 errors,
  `corpus_version=vkb1-20746897a071179b`, store mtime+size unchanged;
  the openid-configuration event matched CVE-2021-32786 at 0.552157 —
  the exact score documented in docs/RUNS-AND-LOGS.md, confirming the
  vendored path reproduces upstream behavior. Smoke scratch removed.

## Phase-2 hardening update (2026-11-20, candidate branch)

The counts above are the phase-1 vendoring record. Current state after
the hardening round (briefs/hardening.md):

- Engine suite: **616 passed** (606 ported + 10 facade — the facade
  gained `test_invalid_path_args_are_caller_errors`, H2/F1).
- Whole candidate tree: **750 passed** (`python -m pytest -q`), incl.
  the persistent M1.4 drill (`tests/test_drill.py`, 3 legs: in-process
  product path, `python -m vulndog run` subprocess, embedder-outage
  negative control) — all offline, stub embedder.
- Vendored modules: still byte-identical to upstream except the two
  documented phase-1 touches; NO phase-2 edit touched vendored code
  (the facade `api.py` is new code, not vendored).
- Gates (CRAP/dryer/mutator) computed MANUALLY — tools absent on this
  machine; full tables, rubrics and the 18/18 mutant→killer battery:
  the internal gates-phase2 artifact (not shipped; every gate marked
  `GATE: heuristic`).
- Doc divergences introduced by hardening (run-tag trailing rule,
  exit-4 semantics, denial_reason vocabulary) are reported in the
  gates file for the owner; approved docs were NOT edited.

## Post-vendoring delta: M2.1 (config system v2, F-1) — 2026-11-23

ADR-1 delta bookkeeping for the first behavior edit to a vendored runtime
module after the phase-1 pure copy. Milestone PLAN.md §6 M2.1; routed here
by QA round 1 finding **F-1**.

**Defect (F-1).** `run.py` derived `_KNOWN_KEYS = frozenset(BUILTIN_DEFAULTS)`,
which holds only engine keys. The merge closure (`load_config`, upstream
`run.py:166-173`) therefore quarantined every product namespace
(`proxy`, `scope`, `runs`, `db`, `ai`) from a `--config` file's `defaults`
and `tasks` sections into `_unknown_keys` and NEVER applied it — a config
file could not even restrict scope. The P1 acceptance "new keys round-trip
through the same merge function" was false.

**Change (one line of logic + comment).** `run.py:97` area:

```python
_PRODUCT_KEYS = frozenset({"proxy", "scope", "runs", "db", "ai"})
_KNOWN_KEYS = frozenset(BUILTIN_DEFAULTS) | _PRODUCT_KEYS
```

That is the ENTIRE engine-source delta. `BUILTIN_DEFAULTS` is unchanged
(the product built-in defaults live in `vulndog.config.VULNDOG_DEFAULTS` —
one decision in one place). The `load_config` merge closure, the
never-crash law (`_config_errors`), the unknown-key isolation law
(`_unknown_keys`), and the builtin < file < task precedence are all
byte-identical to upstream. Genuinely unknown keys (e.g. `flor`,
`totally_bogus_key`) are still isolated and never applied.

**Why this shape (not a fork).** The brief requires the merge to stay in
ONE function (one door) and forbids forking the merge logic. Teaching the
existing known-key set the five product names is the smallest edit that
makes file/task product values flow through the SAME proven merge; the
VulnDog layer (`config.py`) only supplies defaults underneath and the CLI
layer on top, plus config discovery (cwd -> home -> builtins). No second
merge path was added.

**Proof.** TDD: `tests/test_config_v2.py` written first, observed RED
(24 failed — file product values quarantined: `scope.in == []`,
`proxy.port == 8080` builtin), then GREEN after this delta. Covers: F-1
full-config application of every product key; per-key precedence
(builtin < file defaults < per-run override < CLI) for every new key
(13 precedence cases, incl. `ai.timeout_s`);
corrupt-JSON never-crash + `_config_errors` + builtins; genuinely-unknown
isolation; one-door round-trip through `engine.run.load_config` itself;
discovery order; CLI end-to-end (config-file port binds, store reaches the
analyzer). Whole tree: **885 passed** (`python -m pytest -q`), zero
regressions vs the 857 candidate baseline. The provenance manifest row for
`run.py` is updated to the new vendored sha256 (status: documented touch
M2.1); upstream sha preserved.

## Post-vendoring delta: M2.4 (AI provider abstraction, R9) — 2026-11-23

**Engine-source delta: NONE.** ADR-6 ("provider config extends, never
replaces") is implemented entirely OUTSIDE the vendored package, in the
new product package `src/vulndog/aihook/`:

- `aihook/provider.py` — pure `ai.*` boundary (parse/validate) plus the
  banner/run-meta disclosure of a non-loopback or `file://` `base_url`.
  No engine import, so config validation keeps working when the engine
  half is absent.
- `aihook/embedder.py` — `ProviderEmbedder`, a SUBCLASS of the vendored
  `embed_client.EmbeddingClient`, and `build_embedder(ai.*)`. It extends
  the engine through its published seams only: the injectable
  `transport` (`embed_client.py:83-91`) re-targets the request URL,
  `embed_documents`/`embed_query` apply the configured prefixes, and
  `_embed_many`/`_cache_get` are mirrored with the configured `dims`
  passed to the engine's OWN `validate_vector`. Retry/backoff, batching,
  `cache_key`/`_cache_path`/`_cache_put`, the repair log and the stats
  counters remain the inherited engine implementations — no cache or
  retrieval logic is reimplemented, and no engine file is edited.
- For the STOCK default provider the factory delegates to
  `query.make_transient_embedder()`, so the engine's transient-query law
  and its offline stub seam (the M1.4 drill subprocess) stay in charge.
- The CLI hands the result to the facade through the facade's own
  `config["embedder"]` injection key (`engine/api.py`, new code, not
  vendored). An already-injected embedder always wins.
- The MCP query door (`mcp/tools.py::_default_query_api`, product code)
  consumes the SAME `ai.*` decision through the same factory, so one
  config cannot mean two providers; its never-crash law now also maps an
  invalid `ai` section (AiConfigError, a ValueError) to the honest
  `disabled` envelope. Both product doors were edited; no engine module.
- The mirrored `_embed_many` / `_cache_get` bodies were diffed against the
  vendored originals (normalized for the `ec.` qualification and the dims
  seam): FAITHFUL — the only behavioural difference is the expected-dims
  argument passed to the engine's own `validate_vector`.

**Outage law unchanged (D-H / GAP-4 D15).** Provider choice only: the
embedder stays mandatory in the match path. `query.py` still embeds
before pin resolution, `matcher.py` still enters down-mode once, buffers
and replays in order via `retry_pending`. No fts-only / no-AI mode was
added, claimed, or documented.

**Proof.** `git diff --name-only <internal candidate branch> HEAD --
src/vulndog/engine` lists ONLY this record file (`VENDORING.md`); every
engine runtime module and data file is byte-untouched (0 code files).
The provenance manifest hashes still match the committed LF bytes —
verified with `git show HEAD:<path> | sha256sum`:

- `embed_client.py` `e1a464f9335076be3669f42d0cae0b3d6352bbc56c8712424711339cc40988a3`
- `query.py` `a40f8a491b41cdcc950abf681c6640bd5b1978ffd42e1a2ab2f3654915f8e6a6`
- `matcher.py` `c17b679cd80c779c7d5e8b8b562e7037911de5595c985c81b20c56b197c6aefd`
- `run.py` `b537b5b53e903102c0c78cba6d88dfc95ff258d4cbca6e046788e9c6edd5f5ec`

No manifest row changes. Whole tree: **1105 passed** (`python -m pytest -q`),
zero regressions vs the 1024 candidate baseline (81 new tests:
`tests/test_aihook.py`, `tests/test_aihook_outage.py`,
`tests/test_aihook_cli.py`, `tests/test_aihook_mcp.py`).

## Post-vendoring delta: M3.4 (independent-extension validation, W10) — 2026-11-23

ADR-1 delta bookkeeping for the first behavior edits to `corpus.py` and
`build.py` after the phase-1 pure copy. Milestone PLAN.md §6 M3.4
acceptance item (2): "tampered archive (missing edition) → build FAILS
LOUD with nonzero exit". Routed here by the W10 tech-lead merge review:
the dev-j wave made the two forced engine repairs but did not update
this record; the merge fix adds the record and the manifest rows.

**Defect 1 (GAP-4, silent partial build).** `corpus.CorpusAssembler`
phase 2 streamed whatever EN Top10 docs the archive yielded; an OWASP
zip missing an expected edition (2021/2025) built a partial store with
exit 0 — violating the docs' fail-loud promise ("never a silent partial
store", docs/VULNERABILITY-DB.md Step 1) and the map-regen law's spirit
(`owasp_map.py:20-23`).

**Change 1 (`corpus.py`, +13 lines, phase-2 tail).** After the Top10
stream, check each `owasp_map.EXPECTED_EDITIONS` edition yielded ≥1 EN
doc; raise `CorpusError` naming the missing edition(s) + archive.
Presence (≥1), NOT the map's exactly-10 rule: the build streams ALL EN
docs of an edition (61 in the reference build), not only A01..A10. One
decision in one place: the expected-edition list stays owned by
`owasp_map` (reused, not duplicated). No signature change; the check
runs pre-recipe-filter, so no recipe can mask a missing edition.

**Defect 2 (GAP-5, raw traceback on corrupt input).** Structural input
failures (`zipfile.BadZipFile`, `extractors.ExtractorError`,
`corpus.CorpusError`) escaped `run_build` as raw tracebacks (exit 1),
violating the documented exit law (input = exit 2 with the engine's
clear message, docs/VULNERABILITY-DB.md).

**Change 2 (`build.py`, +18 lines).** `_INPUT_ERRORS =
(corpus.CorpusError, extractors.ExtractorError, zipfile.BadZipFile)`
caught at BOTH stream-consumption sites (dry-run pass and real build)
→ `finish(EXIT_INPUT, "input error: …")`. `ExcludedSourceError` (D6)
rides the same law via its `ExtractorError` base. Real build: the
staged temp is cleaned by the `StagedStore` context guard (SEC C-5);
the destination store is untouched (no swap on an input failure).
Catch ordering: disjoint from `BuildAbort` / `EmbedBlocked` /
`StoreError` / `OSError` handlers — no shadowing. No signature change;
no new CLI surface.

**Why this shape (not a fork).** Both repairs enforce law the docs
already promised; the alternative (implementing the overclaimed
validator gates GAP-1 found) would be new features, out of the wave's
scope. The docs were corrected to the verified surface instead
(GAP-1/2/3/6, docs/VULNERABILITY-DB.md).

**Proof.** TDD: `tests/walkthroughs/test_wt_tampered.py` written first,
RED on unfixed code (9 failed / 4 passed: missing-edition `assert 0 == 2`
silent partial; structural tamper raw `ExtractorError`/`BadZipFile`
propagation), GREEN after the two deltas (13 passed). 71 permanent
walkthrough tests pin all six M3.4 stranger paths. W10 merge fix:
`tests/test_package_root.py::test_vendoring_provenance_manifest_complete`
extended to hash-check EVERY manifest row (was: one file) — observed
RED on the stale `build.py`/`corpus.py` rows, GREEN after this record +
the row updates. Whole tree: see `artifacts/verification.log` (W10).
The provenance manifest rows for `corpus.py` and `build.py` are updated
to the new vendored sha256 (status: documented touch M3.4); upstream
shas preserved.

## Post-vendoring delta: M3.4/final (portable raw-dir default, FINAL-01) — 2026-11-23

ADR-1 delta bookkeeping for the final-wave OSS-release-hygiene fix to
`corpus.py` and `build.py`. Routed here by the security FINAL verdict
(`results/security-final.md`, **FINAL-01**) and QA round-2 final
(`results/qa-2-final.md`, **D2**): an absolute developer path shipped in
the built wheel.

**Defect (FINAL-01).** `corpus.py:54`
`DEFAULT_RAW_DIR = "[removed — personal path]"` — the
upstream personal archive folder — was the default for
`corpus.default_archive_paths`, `build.run_build` and the engine build
CLI's `--raw-dir`. Confirmed present in the built wheel: it leaks the
developer username + local layout and is non-portable. Not a security
vulnerability (no exploit; info disclosure + portability), but an
OSS-release blocker. The product `vulndog db build` already requires
`--raw-dir` (`db/cli.py:59`), so the product surface never used the
default; the engine-side CLI and `run_build` API did.

**Change 1 (`corpus.py`).** `DEFAULT_RAW_DIR = None` (unconfigured — no
absolute path ships). `default_archive_paths` now guards an unconfigured
raw dir (the None default or an empty string) and raises
`CorpusError("no archive directory configured -- pass --raw-dir …")`
before any path join — never a silent reference to a developer machine.
An explicit `raw_dir` argument behaves exactly as before (same four
fixed filenames joined under it). No signature change.

**Change 2 (`build.py`, +6 lines).** The `default_archive_paths` call in
`run_build` is wrapped to catch `corpus.CorpusError` →
`finish(EXIT_INPUT, …)` (exit 2 with the engine's clear message). This
keeps the M3.4 fail-loud input law (GAP-5): an unconfigured raw dir on
the engine build path is a clean exit-2 input error, never a raw
traceback and never a real-path build. No signature change; no new CLI
surface; the product CLI path is unchanged (it always passes
`--raw-dir`).

**Why this shape (not a fork).** One decision in one place: the
"unconfigured is an input error" rule lives in `default_archive_paths`
(the single path door); `build.py` only surfaces it through the existing
exit-2 input law. The alternative (a repo-relative `data/raw` default)
would still ship a concrete path and silently point at a non-existent
folder; None + explicit error is the portable, fail-loud choice the
finding asks for. The product CLI's required `--raw-dir` is unchanged.

**Proof.** TDD: `test_corpus.py::DefaultPathsTest` rewritten first
(`test_default_raw_dir_is_portable`,
`test_default_archive_paths_unconfigured_is_input_error`) and
`test_build.py::NoRawDirTest` added (run_build + main without a
configured raw dir → exit 2 + "no archive directory configured");
observed RED on unfixed code (4 failed: dev-string constant, no guard,
`TypeError` on None), GREEN after the two deltas (5 passed). The build
probes force the portable None default so they never touch a real
archive directory. Wheel built in a temp dir → grep for personal
absolute paths → **0 hits**; `vulndog db build` without `--raw-dir` → explicit usage error,
nonzero exit. Whole tree: **1251 passed** (`python -m pytest -q`), zero
regressions vs the 1248 candidate baseline (+3 new tests). The
provenance manifest rows for `corpus.py` and `build.py` are updated to
the new vendored sha256 (status: documented touch M3.4 + FINAL-01);
upstream shas preserved.

## Post-vendoring delta: UX-1 (wrong-shape config warning) — 2026-11-23

ADR-1 delta bookkeeping for the independent-local-test finding **UX-1**
(medium UX): a config file with product keys (`proxy`/`scope`/`runs`/`db`/
`ai`) at the JSON TOP level instead of inside the `defaults` wrapper was
accepted with no warning, no `_config_errors`, no `_unknown_keys` entry —
the run silently proceeded on builtins, so a user could believe a custom
AI endpoint was in force when it was not.

**Root cause.** `load_config` merges only `data.get("defaults")` and
`data.get("tasks")`; the top-level dict is never iterated for known keys,
so a misplaced top-level product key vanishes without a trace (it is not
even quarantined into `_unknown_keys`, which only collects unknown keys
INSIDE a merged section).

**Change (one detection block in `load_config`).** Before the merge, the
top-level keys that belong to `_KNOWN_KEYS` are collected and a stable
note is appended to `_config_errors`:

```python
misplaced = sorted(k for k in data if k in _KNOWN_KEYS)
if misplaced:
    cfg["_config_errors"].append(
        "keys found outside 'defaults' (%s) — ignored; move them "
        "under 'defaults' to apply" % ", ".join(misplaced))
```

The CLI's existing `_warn_config_errors` door prints it as
`WARNING: config: <note> (builtin defaults in force)` on stderr — no new
warning path, no second merge. The never-crash law holds (builtins
proceed); legitimately-shaped files stay silent (`config_version`,
`defaults`, `tasks`, `floor_note`, `_readme` are not in `_KNOWN_KEYS`).
The merge closure, precedence, and unknown-key isolation are otherwise
byte-identical to the M2.1 state.

**Why an engine touch (not the VulnDog layer).** The file shape is known
only where the file is parsed — the engine merge door. Detecting it in
`config.py` would re-read and re-parse the file, forking the shape
knowledge against the "one decision in one place" law. This is the
smallest single-place edit, consistent with the M2.1 delta to the same
function.

**Proof.** TDD: `tests/test_config_v2.py::test_ux1_*` and
`tests/test_cli.py::test_ux1_*` written first, observed RED (no warning
note / no stderr WARNING for a wrong-shape file), then GREEN. Covers:
wrong-shape -> note names the misplaced keys + builtins in force;
correct-shape -> keys apply, no warning (config-level and CLI stderr
level). The provenance manifest row for `run.py` is updated to the new
vendored sha256 (status: documented touch M2.1 + UX-1).

## Post-vendoring delta: UX-2 (no insider refs in product output) — 2026-11-23

ADR-1 delta bookkeeping for the independent-local-test finding **UX-2**
(medium polish): user-facing output cited unshipped insider artifacts —
the `highlights.md` header named the internal router doc, the internal
design-spec sections, the internal PoC verifier and the upstream watchdog
producer; the engine config `floor_note` carried internal workspace
calibration paths that surfaced verbatim in every run's
`watchdog-run.json` config snapshot and MCP `run_status`.

**Two surfaces, two fixes (one engine touch, one product-layer touch).**

1. `highlights.py` `_MD_HEADER` (the ONLY engine-source delta): the
   insider sentence "Promotion to a lead requires PROOF-before-FLAG +
   [internal PoC verifier] confirmation ([internal router doc];
   [internal design-spec])" becomes "Promotion to a lead requires proof
   before flagging", and
   "Generated incrementally by vuln_watchdog (WD-R2)" becomes "Generated
   incrementally by VulnDog". The locked advisory law (C8) is preserved
   byte-for-byte: "ADVISORY CANDIDATES ONLY", "candidate / possible
   direction", "never a finding", the resume title "# Watchdog
   highlights", and the COND-7c fence label are unchanged. No rendering
   logic, field order, or fence escaping touched.

2. `floor_note` is sanitized in the PRODUCT layer (`cli.py`
   `_meta_payload`), NOT by editing the vendored `data/watchdog_config.json`
   (ADR-1 minimal touch — the data file stayed byte-identical at that
   point; the later anonymization delta edited it, see below). The
   run-state config snapshot replaces `floor_note` with the constant
   `cli._PRODUCT_FLOOR_NOTE` ("0.49 = full-store calibrated default").
   `_json_safe` returns a fresh copy, so the caller's resolved cfg is
   never mutated. MCP `run_status` reads `watchdog-run.json`, so it
   inherits the sanitized value with no MCP change.

**Why this shape.** The header text lives only in the vendored formatter;
a presentational constant edit is the smallest single-place fix (the
brief sanctions an engine touch recorded here). The `floor_note` is
sanitized at the product meta writer so the vendored data file — and its
upstream sha — stays untouched.

**Proof.** TDD: `tests/test_cli.py::test_ux2_meta_floor_note_is_product_appropriate`,
`tests/test_drill.py::test_ux2_highlights_header_has_no_insider_refs`,
and `tests/test_drill.py::test_drill_output_has_no_insider_references`
written first, observed RED (insider calibration paths in the meta
snapshot; insider pointers in the header; insider refs in the drill
output), then GREEN. The drill grep test runs the REAL engine config
(floor_note from the shipped data file) and asserts 0 hits for the
insider tokens (the internal router doc, the internal PoC verifier,
internal workspace paths, the internal project name) in BOTH
highlights.md and watchdog-run.json.
The engine advisory pins (`test_highlights.py`) stay green. The
provenance manifest row for `highlights.py` is updated to the new
vendored sha256 (status: documented touch UX-2); upstream sha preserved.

## Post-vendoring delta: Anonymization (public OSS release) — 2026-11-23

ADR-1 delta bookkeeping for the public-release anonymization pass. No
behavior change to the matching/redaction/lifecycle laws; the edits are
names, comments, docstrings, default path segments and provenance text.

**Scope.**

1. **Module rename.** The vendored redaction copy was renamed to
   `_redaction_core.py` (`git mv`, history preserved; the old name carried
   the internal project name). The two `redaction_adapter.py` imports
   replumbed; the private import aliases renamed `_upstream_sanitize` /
   `_upstream_scrub`. Inside the vendored copy the ONLY edits: the default
   logger name of `install_redacting_filter` (now "vulndog") and its
   docstring — the helper is never called by the engine, and no test pins
   the old logger name. All redaction patterns/laws byte-unchanged.
2. **Neutral default paths.** `store.py` `DEFAULT_STORE_DIR` drops the
   internal project segment (`data/vulnkb` under the package root);
   `run.py` default spool/ledger/evidence paths drop it likewise
   (`evidence/...`). The product CLI already resolves user-facing paths
   (UX-3); these engine defaults are the phantom fallbacks. The pinning
   test (`test_store.py::DefaultsTest`) updated to the new segments.
3. **Comments/docstrings/provenance text.** Internal project names and
   personal paths replaced with "the upstream project" / "the upstream
   runtime" / "the upstream redaction module" phrasing across the engine
   docstrings, `VENDORING.md`, `PLAN.md`, `docs/RUNS-AND-LOGS.md` and the
   ported tests. `data/watchdog_config.json` `floor_note` / `_readme`
   calibration provenance generalized (all calibration numbers kept);
   the UX-2 product-layer sanitization stays as defense in depth.
4. **Leak-check tests keep their teeth.** The UX-2 acceptance tests
   assemble the internal project name at runtime ("bug" + "hunt") so the
   shipped source carries no insider literal while the assertions check
   the same runtime string. Optional real-corpus tests are now
   env-driven (`VULNDOG_RAW_DIR`, `VULNDOG_PILOT_CORPUS`) instead of
   hard-coded personal paths; absent → skipped, as on any public machine.

**Proof.** Full suite green after the pass (1262 passed with the local
corpus env vars set; the corpus tests skip cleanly without them).
`git grep` for the internal project names, personal paths and the owner
identity → 0 hits in tracked files. The provenance manifest rows for
every touched file are updated to the new vendored sha256 (status:
documented touch anonymization); upstream shas preserved.

## Provenance manifest (fix-round-1 B3, 2026-11-21)

Per-file sha256 of every vendored RUNTIME file, vendored copy vs upstream
source. This completes the provenance record required for a public
release (security B3 / QA F-15): source path (see "Upstream source"
above), per-file sha256 (this table), extraction date (**2026-11-20**),
and the authorship statement (both upstream trees are the project
owner's own code, vendored into VulnDog with the owner's authorization).

**Hash basis.** Hashes are of the COMMITTED LF bytes (git index). This
repository checks out with `core.autocrlf=true`, so worktree files may
materialize CRLF; normalize CRLF->LF before hashing (the regression test
`tests/test_package_root.py::test_vendoring_provenance_manifest_complete`
does exactly this). Upstream project files are LF as stored.

**Result.** 15 of 27 runtime files are byte-identical to upstream. The
twelve differences are documented minimal touches: `__init__.py`
(docstring, phase-1 + anonymization), `_redaction_core.py` (renamed from
the upstream redaction copy; default logger name anonymized),
`redaction_adapter.py` (the two import lines replumbed to the vendored
copy, ADR-1d, phase-1; comments/aliases anonymized), `run.py` (the M2.1
known-keys extension + the UX-1 wrong-shape warning + anonymized
docstrings/default paths — see "Post-vendoring delta: M2.1", "UX-1" and
"Anonymization"), `highlights.py` (the UX-2 product header — see
"Post-vendoring delta: UX-2"), `store.py` (anonymized docstring + neutral
default store dir), `event_schema.py` / `tailers.py` / `tap_sim.py`
(anonymized docstrings), and `corpus.py` + `build.py` (the M3.4 fail-loud
input law + the FINAL-01 portable raw-dir default + anonymized
docstrings — see "Post-vendoring delta: M3.4" and "M3.4/final"), and
`data/watchdog_config.json` (anonymized calibration provenance). `api.py`
is the VulnDog facade — NEW code, not vendored,
excluded from this manifest.
Vendored TEST files carry import-only rewrites plus the two documented
adaptations (see the porting policy above); they are not runtime files.

**License — PROVISIONAL.** `LICENSE` (repo root) ships the **MIT** license
as the provisional default recommended in the approved docs
(docs/VULNERABILITY-DB.md, GAP-1). The owner's GAP-1 decision is still
OPEN: when the owner resolves it, LICENSE, the `pyproject.toml` license
field and this section must be updated together. The vendored upstream
code is the owner's own code and carries the same provisional grant
pending that decision; the KB data sources keep their own per-source
terms (docs/VULNERABILITY-DB.md attribution table).

| file | sha256 (vendored, committed LF bytes) | sha256 (upstream) | status |
|---|---|---|---|
| `__init__.py` | `86c03582f87486da1ea3fd2c5a1cddd75748216ee832be1f1e7b1bf9627df44e` | `edadcff4f4a860de262ed55ed6165b466632bebd05a8d79ce34518a633a3a982` | documented touch (phase-1 + anonymization) |
| `_redaction_core.py` | `a16103b3c92911dd82958b111ed41b5c9d75ddf70a17e77ae27a9ee63577d745` | `ad44e25af6ef2858f1ab19983acff5b1f3c73fcece65720d208a731d13a1e696` | documented touch (anonymization: rename + logger name) |
| `benchutil.py` | `bd14b1448723cbbf55b3c808b6a6495038ceb9ab9fc2dd3388d02cd336eed4e2` | `bd14b1448723cbbf55b3c808b6a6495038ceb9ab9fc2dd3388d02cd336eed4e2` | identical |
| `build.py` | `a01d8d9444af0cfa202bdf0829374748a398cf5bd1e61dcbcdfbaad9ef670163` | `03a270b0a7344439939372595635c6bcb03821ea7a5a535b93ec36681ae95ebc` | documented touch (M3.4 + FINAL-01 + anonymization) |
| `chunker.py` | `8bde8ccd02b70cf31e64f6f9ffb8ae6e9980cd458908101c25f92b9e7b68eb26` | `8bde8ccd02b70cf31e64f6f9ffb8ae6e9980cd458908101c25f92b9e7b68eb26` | identical |
| `chunking.py` | `2d36a4a5a15616128556e10bab0e0d8d3994d991fa6dfd36e980cad58de2a7d1` | `2d36a4a5a15616128556e10bab0e0d8d3994d991fa6dfd36e980cad58de2a7d1` | identical |
| `corpus.py` | `204991731d6f438a798a87c7b6d72c82310bf7c05d7c9b8abc86747cf9736826` | `223710d5b98064e7b3f35d8a298c9a05fbaa103fa811d128d98f446e773415c6` | documented touch (M3.4 + FINAL-01) |
| `embed_client.py` | `e1a464f9335076be3669f42d0cae0b3d6352bbc56c8712424711339cc40988a3` | `e1a464f9335076be3669f42d0cae0b3d6352bbc56c8712424711339cc40988a3` | identical |
| `event_schema.py` | `05feadf31a32f65ba6fbb69d29a12f0869bfe051e443e4142b5c2bddb0d79b0c` | `c97dd8f78b35cd510388575a0eec51c08add59abf0cb4854a848a19fb9c40a99` | documented touch (anonymization) |
| `extractors.py` | `303e560f447febfbc0ef2310aa996ffd1ce4ff616a5fef371269d4242b05e26a` | `303e560f447febfbc0ef2310aa996ffd1ce4ff616a5fef371269d4242b05e26a` | identical |
| `highlights.py` | `06210d0dbb95370a2e3941cdf63bbbd60cf0a5cc6e5cbfb16dab0cbb4feb8edc` | `4d9260b52ff74b5501a83d27e7d015ea8ff942cafbcafd59b2caabf3dbdf63c8` | documented touch (UX-2) |
| `joiner.py` | `ae29447a3d6f29dc26904f32450825c7ddf1474971b2964104bc80730214c6b5` | `ae29447a3d6f29dc26904f32450825c7ddf1474971b2964104bc80730214c6b5` | identical |
| `kb_index.py` | `6f7de435d7c7aa2e1154030c4a7d9c214215a36b4bb6ac43d1e33e73ac48f72b` | `6f7de435d7c7aa2e1154030c4a7d9c214215a36b4bb6ac43d1e33e73ac48f72b` | identical |
| `matcher.py` | `c17b679cd80c779c7d5e8b8b562e7037911de5595c985c81b20c56b197c6aefd` | `c17b679cd80c779c7d5e8b8b562e7037911de5595c985c81b20c56b197c6aefd` | identical |
| `owasp_map.py` | `1ca2e9d075d1adda9f24b296b762923ed72db70564653551c8ea6588cdcade62` | `1ca2e9d075d1adda9f24b296b762923ed72db70564653551c8ea6588cdcade62` | identical |
| `query.py` | `a40f8a491b41cdcc950abf681c6640bd5b1978ffd42e1a2ab2f3654915f8e6a6` | `a40f8a491b41cdcc950abf681c6640bd5b1978ffd42e1a2ab2f3654915f8e6a6` | identical |
| `record_schema.py` | `f99f3b4a655668cced7301287b7b5d7b0644c3e48bdb7f3ee2a441fe0b721383` | `f99f3b4a655668cced7301287b7b5d7b0644c3e48bdb7f3ee2a441fe0b721383` | identical |
| `redaction_adapter.py` | `b23683d00d9aa83ecee1baf7787956a9a418cab947267c2025e6366ca3193aa0` | `a4142135193cb1d0278fb2f993a1ac2c70c9f4faf8c26f3ed3ba6d84242aaa93` | documented touch (phase-1 + anonymization) |
| `run.py` | `4886c43d2d885ed66b70fa1adfc51f0ecbdc374638c16d3b5c6d31bf07add552` | `630467bf9ecb86583bad110bd19fc291a651af542a40a7a7ebe80a6ae9cea891` | documented touch (M2.1 + UX-1 + anonymization) |
| `store.py` | `a663510290ea905c5df76f683f23c432f45b4c7174a4b9d912f88357a1022a24` | `54bba595b0237473d03111aaea527629986a3f70437a65cc53eb196c073a8e1e` | documented touch (anonymization: neutral default dir) |
| `tailers.py` | `c2b0da1f2e4154f98274637d5473db01ce0495ac1512892f7b0f479da8598e45` | `e511a86624197da8b27daca2f1d541fe60d780ede7464781b85e9be03c8e5d2e` | documented touch (anonymization) |
| `tap_sim.py` | `99ec2870702bb5bbbb92be62a2a152f284ce781f62413be9d3811c2c65860599` | `0844213ea31b32f7751eb84908ccd3ac53010eb2d5add5b95f3c10272db41d87` | documented touch (anonymization) |
| `vecmath.py` | `5de9733a4ffdd0e0e3ca83e3a351d0ba57b48f8b985d0b8908a9fb60a8e94f84` | `5de9733a4ffdd0e0e3ca83e3a351d0ba57b48f8b985d0b8908a9fb60a8e94f84` | identical |
| `data/cwe_owasp_map.json` | `4dcc18d76b1b841a6137722caf71d1d180cc037be12e0e545a9c35ec0962ab23` | `4dcc18d76b1b841a6137722caf71d1d180cc037be12e0e545a9c35ec0962ab23` | identical |
| `data/recipe_full.json` | `24a063a10a81424c3d99cfbe319744ac71bbeda7d623eeb6a2ea10b23d478520` | `24a063a10a81424c3d99cfbe319744ac71bbeda7d623eeb6a2ea10b23d478520` | identical |
| `data/recipe_stage1.json` | `5e316cf828ab7bdf0792cfdbc5ee35ea935d62120f2fb83f3f7bfeb9d16e00fc` | `5e316cf828ab7bdf0792cfdbc5ee35ea935d62120f2fb83f3f7bfeb9d16e00fc` | identical |
| `data/watchdog_config.json` | `a1cc7620e0764ba1e58d591fa37846883f58fcbe27197dfd1c54213d26880ff0` | `4ea176ad8ef525b0aaff4c4d17804481bdd67ce7769d9b28bace46cad64db592` | documented touch (anonymization) |