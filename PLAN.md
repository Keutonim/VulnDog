# VulnDog — Implementation Plan

Condensed, human-readable implementation plan for **VulnDog**, a standalone open-source
CLI proxy monitor that highlights potentially vulnerable requests for AI agents. This
file consolidates the approved internal planner report (rev 2,
QA-verified 2026-11-12); it is the single source for phased scope. Milestone IDs
and acceptance-criteria references are preserved verbatim from that report.

**Status: pre-implementation.** Nothing here has been built yet; implementation is
gated on owner approval of this plan. Citation shorthand: IW = `artifacts/inventory-watchdog.md`,
IC = `artifacts/inventory-context.md`; `file:line` refs are against the verbatim source
copies in the plan workspace. Note: the streamdog fts-only degrade is evidenced at
**IW:554** (planner rev 1 mis-cited it as IC:554; corrected per QA round 1).

---

## 1. Executive summary

VulnDog re-packages the proven upstream `vuln_watchdog` engine (pure-stdlib Python,
690 tests green 2026-10-28, IW:44) as a standalone OSS tool. The matching core —
redaction → event text → query embedding → FTS5 BM25 prefilter → cosine re-rank →
score floor + pins → highlights — is reused **fully** (owner law: "do not redesign
what already works"). Everything the owner requires that the engine already has
(KB store + build pipeline, matching, redaction, highlight log, config merge law,
Ollama-outage buffering) maps to existing modules; everything it lacks is a **thin,
new perimeter**: a proxy listener (the engine today only *consumes* an upstream spool,
IW:59-61), timestamped run dirs, scope config, an MCP server, an AI-provider config
abstraction, and OSS packaging.

**Load-bearing engine law (QA-verified):** the embedding call is **mandatory in the
match path**. `query.py:_match_conn` runs `embedder.embed_query(text)` at
`query.py:303-309` BEFORE pin resolution; on embed failure it returns a
`"skipped"/"embed-failed"` envelope with **zero matches**, and `matcher.py:112`
(`_EMBED_DOWN_REASONS = {"embed-failed","embed-invalid"}`) puts the matcher into
down-mode: events are buffered, the runner backs off 60 s, and nothing is highlighted
until the embedder recovers (`matcher.py:32-36, 393-399`). Pins bypass the score floor
AND the filters (`query.py:28-31` docstring law) — **but not the embedder**. There is
NO fts-only matching mode in this engine (that mode exists only in the sibling copy
streamdog, IW:554). Consequence: any run, drill, or test that expects highlights —
including exact-id pins — needs a working embedder (local Ollama or an injected stub
transport). See D-H, M1.4, M2.4, ADR-6/7, GAP-4.

**Owner-decision law inherited from project memory (outranks fresh guesses):**

- **MITM / Mode B stays REJECTED** (`OWNER-DECISIONS.md:204`, 2026-10-22, "not
  re-asked"); the proxy is a CONNECT-tunnel Mode A observer only.
- **Custom run identifiers for parallel instances** already ordered 2026-11-06
  (`OWNER-DECISIONS.md:406`); timestamp dirs carry an optional custom tag.
- **Advisory-only forever** — highlights are "candidate / never a finding"
  (`highlights.py:18-20`); no auto-promotion anywhere.
- **No-new-deps law (C4)** — the engine is pure stdlib by design
  (`embed_client.py:18`, IC:292); the MCP transport choice respects it (ADR-5).

Resolved input (owner's open question): request analysis in the current watchdog is
**HYBRID — a deterministic script pipeline plus a local Ollama embedding model, zero
cloud LLM calls** (IW §3: 14 AI call sites, all `/api/embed` + `/api/tags` probes;
25 rule/pattern sites; no chat/completion endpoint anywhere). The embedding step sits
in the **mandatory** match path — with Ollama down the engine produces no highlights
at all (D-H). The owner's "optional AI hook" is therefore a **provider configuration**
problem (D-G), not a new-LLM problem; whether "optional" may also mean "runs with no
AI service at all" is owner-gated (GAP-4).

---

## 2. Verified deltas (watchdog → VulnDog)

Every delta below was re-verified first-hand against the verbatim source copies
(`artifacts/scout-1/raw/`), not copied blindly.

| # | Delta | Verdict | Primary evidence |
|---|---|---|---|
| D-A | Run dirs are **task-id-named**, not timestamp-named | CONFIRMED | `run.py:327` `self.task_dir = os.path.join(self.spool_root, self.task_id)`; id law `run.py:102-120` (`_TASK_ID_RE`, Windows reserved stems); 9 on-disk dirs all task-named (IW:285-288) |
| D-B | Scope lives in the upstream runtime, absent from watchdog | CONFIRMED | `grep scope` in package → 1 unrelated hit (`kb_index.py:14`, IW:250-252); scope canon in the upstream runtime profiles module + `runtime/scope_canon.py`; enforcement in upstream `tool_proxy.py` (allowlist → 403) |
| D-C | Watchdog hard-couples to the upstream project tree | CONFIRMED (extends to D-I) | `run.py:129-138` defaults pointed into the upstream project's `evidence/...`; `store.py:58-62` `DEFAULT_STORE_DIR` pointed into the upstream project's `data/vulnkb`; traffic enters only via the upstream tap (`watchdog_tap.py`, PURE OBSERVER) |
| D-D | No dependency manifest | CONFIRMED | 0 matches for requirements/pyproject/setup in raw copies; "Pure stdlib … No new deps (C4)" `embed_client.py:18` (IC:292) |
| D-E | No MCP anywhere in the engine | CONFIRMED | grep over all 19 raw copies → NONE; local precedents: raw JSON-RPC client `browser_mcp.py:16,221`, stdio server fork `browsermcp-fork/server/index.mjs:6,193`, FastMCP server `files-mcp/.../server.py:10-33` (IC:497-539) |
| D-F | 2 GB store vs OSS distribution | CONFIRMED | `vulnkb.sqlite` 2,066,808,832 B ≈ 1.93 GiB (IC:319); build wall 23,570 s ≈ 6.5 h, 16,310 Ollama calls (manifest.extra, IW:489-491); inputs ≈ 965 MB of zips (IW:482-486); GitHub release asset cap ≈ 2 GiB/file — fits *barely* |
| D-G | AI address is hard-coded loopback | CONFIRMED | `embed_client.py:30-45`: single constant `OLLAMA_BASE_URL`, "loopback only, by construction", no constructor host/url param, `ProxyHandler({})` ignores env proxies |
| D-H | **Embedder is mandatory for ALL matching incl. pins; no fts-only mode** | CONFIRMED | `query.py:297-309`: pins extracted at `:297`, then `try: qvec = self.embedder.embed_query(text)` `:303-304`; any exception → `return self._envelope("skipped", "embed-failed", …)` `:307-309` with NO matches — pin lookup (`:338-341`) unreachable; `_pin_entries(conn, pins, qn, …)` `:361` even consumes the normalized query vector; `matcher.py:110-112` maps `embed-failed` → down-mode (buffer + 60 s backoff, `matcher.py:32-36, 393-399`); recovery replays the buffer (`matcher.py:362-368` announce + `recovered` counter; ordered replay via `retry_pending` `:375-390`; counters IW:347-352). fts-only degrade is a **streamdog** feature (IW:554), not engine behavior |
| D-I | **`redaction_adapter.py:63-64` is the ONLY hard cross-tree import** | CONFIRMED | raw `redaction_adapter.py:62-64`: comment "Read-only import of the upstream redaction (C2: used as-is)" + the two upstream redaction import lines (`sanitize_snapshot` `:63`, `scrub` `:64`); grep over all 19 raw `.py` for upstream-runtime imports → exactly these 2 hits. The upstream runtime redaction module must be vendored/ported at M1.1 |

---

## 3. Engine module map (watchdog → VulnDog disposition)

Every `vuln_watchdog` module and its disposition in the vendored repo
(`src/vulndog/engine/`; module names kept identical to keep ADR-1 diffs minimal).

| Upstream module | Role | Disposition |
|---|---|---|
| `run.py` | watchdog lifecycle CLI (start/stop/status) | VENDOR + adapt: run-dir naming (ADR-4), default paths (D-C), config keys (M2.1) |
| `query.py` | KB query API (library-only door) | REUSE as-is (`match()` at `:227` is the only KB door; MCP wraps it) |
| `matcher.py` | per-event matching loop | REUSE as-is (outage law D-H preserved verbatim) |
| `highlights.py` | highlight surfaces (console/jsonl/md/summary) | REUSE as-is (writer surfaces unchanged) |
| `tailers.py` | resume-safe event tailers | REUSE (`SpoolTailer` consumes the new tap's spool unchanged) |
| `redaction_adapter.py` | F4 redaction — single enforcement point | VENDOR + replumb the only cross-tree import (`:63-64`) to the vendored `_redaction_core.py` (D-I, ADR-1d) |
| `event_schema.py` | one event schema for every tap | REUSE as-is |
| `record_schema.py` | canonical vulnerability record schema | REUSE as-is |
| `store.py` | SQLite store writer | REUSE (default path moves to `data/vulnkb`, D-C) |
| `build.py` | store build CLI | REUSE (wrapped by `vulndog db`, M3.1; `DEFAULT_RAW_DIR` untouched — archives pass via CLI args) |
| `corpus.py` | corpus assembler + recipe predicate | REUSE as-is |
| `extractors.py` | production extractors for the 4 sources | REUSE as-is |
| `joiner.py` | CWE/exploit/OWASP joins + web-relevant CWE list | REUSE as-is |
| `chunker.py` / `chunking.py` | record → chunk packing | REUSE as-is |
| `owasp_map.py` | static CWE→OWASP mapping table | REUSE as-is (regen stays fail-loud) |
| `embed_client.py` | loopback-only Ollama embed client | REUSE (transport seam `:83-91` carries provider config + test stubs) |
| `kb_index.py` | benchmark-scoped indexer + `fts_match_query` | REUSE (FTS5-injection discipline lives here; benchmark-scoped, not the production indexer) |
| `vecmath.py` | pure-Python dot/normalize | REUSE as-is |
| `benchutil.py` | benchmark helpers | VENDOR (kept for calibration work) |
| `tap_sim.py` | tap mechanics simulator | VENDOR (benchmarks; drift-prone by design) |
| `__init__.py` | package marker | absorbed into `src/vulndog/engine/` |

Adjacent (not imported by the engine, dispositioned for VulnDog):
`watchdog_tap.py` (upstream runtime) → **REPLACED** by VulnDog's own in-repo tap inside
`vulndog/proxy/` (ADR-3; mechanics reused: queue cap 1000 drop-oldest, flusher
0.25 s / batch 500 — raw copy `watchdog_tap.py:50-53`); the upstream runtime redaction module
→ **VENDORED** as `engine/_redaction_core.py` (D-I); upstream `tool_proxy.py` (CountingProxy)
→ **PRECEDENT** for `vulndog/proxy/` (not imported); `runtime/scope_canon.py` →
semantics **REUSED** by `vulndog/scope/` (ADR-8). NEW components (outside `engine/`):
`cli.py`, `proxy/`, `rundirs/`, `scope/`, `mcp/`, `aihook/`, `pyproject.toml`.

---

## 4. Requirement → component mapping (R1-R10)

| Req | Constraint (task NARROWING / deliverable) | Mapping | Evidence / delta scope |
|---|---|---|---|
| R1 | NO implementation now; plan+docs only | this plan + the 7 docs | milestones are post-approval work items |
| R2 | Open source, all product content EN | N1 OSS packaging set | NEW: LICENSE, CONTRIBUTING, SECURITY, EN CLI help (M2.5, M3.2, M3.3) |
| R3 | CLI-only interface | E1 `run.py` CLI + E2 `build.py` CLI | exist; NEW: single `vulndog` console entry unifying run/build/db/mcp (M2.5) |
| R4 | Per-run **timestamp-named folder in-project** + flagged-request log | E3 highlight surfaces (`highlights.py:211-258`, canonical field order `:48-53`) · N2 run-dir naming policy | NEW: `runs/YYYYMMDD-HHMMSS[_tag]/` + optional custom tag (M1.3, ADR-4) |
| R5 | MCP server mandatory (AI agents primary consumers) | N3 `vulndog/mcp/` stdio JSON-RPC server | 0 MCP in engine (D-E); tools `vuln_query`, `highlights`, `run_status` (M2.3) |
| R6 | Configurable scope / out-of-scope | N4 `vulndog/scope/` config + enforcement | absent from engine (D-B); semantics reuse the upstream `scope_canon`, enforcement reuses the upstream tool_proxy 403-cut pattern (M2.2) |
| R7 | Configurable proxy listen address/port | N5 `vulndog/proxy/` forward proxy listener | engine has NO listener (D-C); precedent `tool_proxy.py:519,528-540,636` (ThreadingTCPServer, `start(host,port)`); loopback default; Mode A only — MITM banned (M1.2) |
| R8 | Built-in vuln DB + independent population docs | E4 store/build/corpus/extractors/joiner + E5 recipes/CWE-OWASP map in `data/` | exists, proven (456,460-record store); NEW: bundled seed-store resolution + `docs/VULNERABILITY-DB.md` + distribution strategy (D-F) (M3.1, M3.4) |
| R9 | Optional AI hook via ollama or custom provider | E6 `embed_client.py` (transport-injectable `:83-91`) + E7 outage mode (down-mode buffering + recovery replay) · N6 provider config section | NEW: `ai` config keys defaulting byte-for-byte to current constants; loopback default preserved; NOTE (D-H): no fts-only mode — a working embedder is required for any matching; "no-AI operation" is owner-gated (GAP-4) (M2.4) |
| R10 | Reuse the upstream `vuln_watchdog` fully | E8 whole package vendored | N7 repo restructure: `src/vulndog/engine/` with minimal-touch list incl. the one cross-tree import (D-I, ADR-1) (M1.1) |

---

## 5. Architecture decisions (ADR-1..ADR-9)

Each decision is LOCKED for all milestones unless the owner flips it.

- **ADR-1 Vendor, don't import — with the one cross-tree import vendored too.**
  Copy the package as `src/vulndog/engine/`, module names identical; adaptation only
  through the named minimal-touch list: (a) default path functions `run.py:129-138`,
  `store.py:58-62`; (b) run-dir naming; (c) config keys; (d) `redaction_adapter.py:63-64`
  — vendor the upstream runtime redaction module (sanitize_snapshot/scrub) into the engine dir
  (e.g. `engine/_redaction_core.py`, used as-is) or replumb those 2 import lines —
  without this the vendored engine and its tests cannot even import. Rejected:
  runtime import of the upstream project (couples an OSS tool to a private repo) and
  pip-install-from-git (provenance + offline breaks). `corpus.py:54` DEFAULT_RAW_DIR
  (hardcoded non-ASCII owner path) is deliberately NOT touched — archives pass via
  the existing build-CLI arg surface.
- **ADR-2 Proxy = observing forward proxy, Mode A only.** Absolute-form HTTP +
  CONNECT tunnel; no MITM, no TLS termination, no certificates (mirrors
  `tool_proxy.py:30-45`; MITM REJECTED by owner). Default bind 127.0.0.1, port from
  config/CLI; 0.0.0.0 possible only by explicit flag (loopback law,
  `streamdog/config.py:38`). Out-of-scope host:port → 403, request never leaves the
  machine. Docs carry the honest visibility matrix: HTTP legs fully inspectable,
  HTTPS legs = CONNECT-level metadata only.
- **ADR-3 One tap, owned in-repo.** VulnDog ships its own tap (queue cap 1000
  drop-oldest, flusher 0.25 s / batch 500 — raw copy `watchdog_tap.py:50-53`) writing
  `events.jsonl` inside the run dir; the engine's `SpoolTailer` (`tailers.py:202-249`)
  consumes it unchanged. No upstream-runtime dependency remains at runtime. F4 redaction
  before persist stays the single enforcement point.
- **ADR-4 Timestamp run dirs + custom tag.** `runs/<YYYYMMDD-HHMMSS>[-<tag>]/` inside
  the project; collision-safe (suffix `-1`, `-2`… within the same second); tag
  satisfies the parallel-instances directive (`OWNER-DECISIONS.md:406`). Dir contents
  mirror today's task dir (events.jsonl, highlights.md/jsonl, state.json, pid/stop,
  run-state json — IW:276-283).
- **ADR-5 MCP transport = raw JSON-RPC over stdio, stdlib only; stdio-only is the
  shipped v1 surface.** Keeps C4 no-new-deps; precedent `browser_mcp.py:16,221` +
  `browsermcp-fork/server/index.mjs:6` (initialize → initialized → tools/list →
  tools/call, `content [{type:"text"}]`, isError). FastMCP REJECTED as a runtime dep
  (acceptable later as an optional extra if community demands). Recorded risk
  boundary: v1 ships NO HTTP/SSE listener; any future HTTP/SSE transport = new
  security review (auth + loopback-only law) and is out of scope until then.
- **ADR-6 Provider config extends, never replaces; embedder stays mandatory.** New
  `ai` config section: `{provider: "ollama"|"custom", base_url, model, dims,
  doc_prefix, query_prefix, timeout_s}`. Defaults reproduce the current constants
  exactly (`embed_client.py:31-45`); model change auto-invalidates the embed cache
  (sha-keyed, `embed_client.py:35`). Custom base_url = explicit opt-in with a
  documented rebuild warning. Secrets via env vars only — never in config files.
  Per D-H the outage law is preserved verbatim; NO fts-only mode is invented (a true
  no-AI mode is GAP-4 and would be an explicit, owner-approved engine amendment).
- **ADR-7 Store distribution = seed + asset + build-it-yourself (recommendation,
  owner decides — GAP-1).** (a) mini seed store for first-run UX (stage-1 slice
  precedent: 39,473 records / 186.7 MB, memory `vuln-watchdog-001/state.md:93-96`);
  (b) prebuilt full store (1.93 GiB) as a GitHub release asset with published sha256
  + manifest (fits the ~2 GiB asset cap barely — verify at release time); (c) fully
  documented self-build from the 4 archives. Honest prerequisite (D-H): build-time
  doc-side embedding is mandatory (`build.py:274-290` EmbedBlocked after retries),
  and runtime matching of any kind needs a working embedder.
- **ADR-8 Scope semantics = proxy-enforced host allow/deny + event annotation.**
  In/out host patterns (exact + wildcard/suffix, per `scope_canon` boundary rules);
  enforcement at the proxy (403 + `denial_reason` event, vocabulary reused from
  `tool_proxy.py:38`); matching-side filtering stays OUT of v1 scope semantics (mute
  lists already exist: `mute_record_ids`/`mute_url_prefixes`,
  `watchdog_config.json:13-14`). Unconfigured-scope default: GAP-2 (recommend
  allow-all + loud banner — VulnDog is a passive monitor, not an attacker rail).
- **ADR-9 Advisory-only forever.** No verdict language beyond "candidate", no
  auto-promotion, no target-bound requests from the engine (the upstream
  zero-power law). Console lines never carry snippets (`highlights.py:111-113`).

---

## 6. Phased plan

### Phase 1 — "Make it Work" (walking skeleton; smallest end-to-end cut)

| ID | Milestone | Goal → tasks | Depends on | Acceptance criteria (mechanically verifiable) | Size | Wave |
|---|---|---|---|---|---|---|
| M1.1 | Engine vendoring + repo bootstrap (incl. the D-I import fix) | Vendor `vuln_watchdog` → `src/vulndog/engine/` (module names unchanged); port `tests/` + `data/`; **vendor the upstream runtime redaction module and replumb `redaction_adapter.py:63-64` to it (ADR-1d — without this nothing imports)**; root scaffold (README stub, LICENSE placeholder pending GAP-1, `.gitignore` for `runs/`) | — | (1) `python -m pytest src/vulndog/engine/tests -q` → ≥690 passed (baseline `README.md:69-76`) **with no upstream-project entry on sys.path**; (2) `diff -r` upstream-vs-vendored shows changes ONLY inside the ADR-1 minimal-touch list, which explicitly includes RA:63-64 + the new vendored redaction module; (3) `python -m vulndog.engine.run status --json` exits 0 against a copied store | M | W1 |
| M1.2 | Proxy listener + owned tap (R7) | New `vulndog/proxy/`: observing forward proxy (ADR-2/3) — absolute-form HTTP forward + CONNECT tunnel; **fixed hardcoded safety denylist for the drill** (user-configurable scope patterns are M2.2) → 403 + denial event; in-repo tap writes redacted `events.jsonl` into the run dir (queue cap 1000 drop-oldest, flusher 0.25 s/500 — `watchdog_tap.py:50-53` semantics) | M1.1 | (1) canned absolute-form GET through proxy → forwarded, 1 valid event row (`event_schema.validate_event` true); (2) CONNECT to test host → tunnel opens, tunnel-level event, **no path captured** (Mode A law); (3) denylisted host → 403 + event `denial_reason:"proxy_oos"`, socket to target never opened (loopback test double); (4) `grep -riE "mitm\|wrap_socket\|ssl\.wrap" src/vulndog/proxy` → 0 hits; (5) tap queue overflow → drop_counter meta line, no crash | L | W2 |
| M1.3 | Timestamped run dirs + flagged log (R4) | New run-dir policy (ADR-4) wired into the vendored runner: `runs/YYYYMMDD-HHMMSS[-tag]/`; HighlightsWriter reused unchanged; pid/stop/state files as today | M1.1 | (1) run → dir matches `^\d{8}-\d{6}(-[A-Za-z0-9._-]{0,64})?$` under `<project>/runs/`; (2) dir contains highlights.jsonl + highlights.md + run-state json; (3) two runs inside one second → collision suffix, both intact; (4) `-tag` honored (parallel-instances directive); (5) highlights.jsonl row 1 field order == `HIGHLIGHT_FIELDS` (`highlights.py:48-53`) | S | W2 |
| M1.4 | End-to-end walking-skeleton drill (re-specced per QA blockers) | Scripted drill: start proxy+run → replay canned request set (incl. one URL containing a literal `CVE-\d{4}-\d{4,}` token) → stop → assert artifacts. **Prerequisite (D-H): a working embedder — EITHER local Ollama with the embed model pulled, OR an in-process stub embed transport injected through `embed_client`'s transport seam (`embed_client.py:83-91`), returning valid 768-d unit vectors. Pin law: pins bypass floor AND filters but NOT the embedder (`query.py:28-31`).** | M1.2, M1.3 | (1) drill exits 0 with the embedder prerequisite declared and satisfied (real Ollama or stub — both acceptable); (2) run-dir highlights.jsonl ≥1 line with `"reason":"exact-id"` (requires the successful-embed path, D-H); (3) run summary counters `events_in>0`, `highlights>0`, `embed_failures=0`, `mode:"enabled"`; (4) negative control: same drill with the embedder transport raising → zero highlights, counters `embed_failures>0`, `buffered_while_down>0`, mode leaves `"enabled"` (documents the outage law, `matcher.py:110-112, 393-399`); (5) full suite green after drill | M | W3 |

**Phase 1 exit:** a stranger can run the skeleton via `python -m vulndog …` (the
unified `vulndog` console entry lands at M2.5, Phase 2): proxy listening, requests
flowing, flagged requests readable in a timestamped folder — nothing else.

### Phase 2 — "Make it Right" (correct structure, boundary discipline, behavior-tested)

| ID | Milestone | Goal → tasks | Depends on | Acceptance criteria (mechanically verifiable) | Size | Wave |
|---|---|---|---|---|---|---|
| M2.1 | Config system v2 (R6/R7/R9 substrate) | Extend the proven 3-layer merge (`run.py:143-183`) with new keys: `proxy.host/port`, `scope.in/out`, `ai.*` (ADR-6), `runs.dir`, `db.store_path`; config discovery (cwd → home → builtins); preserve never-crash + `_unknown_keys` isolation laws verbatim | M1.4 | (1) precedence tests: builtin < file defaults < per-run override < CLI for every new key; (2) corrupt JSON → exit 0 with `_config_errors` populated; (3) unknown key → `_unknown_keys`, never applied; (4) new keys round-trip through the same merge function (one door) | M | W4 |
| M2.2 | Scope module (R6) | `vulndog/scope/`: in/out pattern compile (exact + wildcard/suffix), match function (pure), proxy enforcement hook replacing M1.2's hardcoded denylist (403 + denial event), banner at start; ADR-8 semantics | M2.1, M1.2 | (1) pure-function match table tests (exact/wildcard/suffix/overlap in-vs-out — out wins); (2) e2e: in-scope host forwarded, out-of-scope → 403 + `denial_reason:"proxy_oos"` event; (3) unconfigured-scope behavior == GAP-2 decision outcome, banner line present; (4) scope parse errors → fail-fast at startup with nonzero exit | M | W5 |
| M2.3 | MCP server (R5) | `vulndog/mcp/`: stdio JSON-RPC server (ADR-5). Tools: `vuln_query(text, top_k?, floor?, filters?)` → KB matches (wraps `query.py:227 match()`, library-only door); `highlights(run_id?, last_n?)` → flagged requests from run dir; `run_status()` → live state. Resources: run-dir listings. EN tool descriptions | M1.4 | (1) conformance script: initialize → notifications/initialized → tools/list → tools/call each tool → valid `content [{type:"text"}]` JSON, isError=false; (2) unknown method → JSON-RPC error envelope; (3) tools/list contains exactly the documented tool set; (4) KB-down → `vuln_query` returns the store-failure status envelope (never a crash, `query.py:229-230` never-raises law); (5) MCP smoke against a scripted agent transcript recorded as test fixture | L | W4 |
| M2.4 | AI provider abstraction (R9) — outage semantics per D-H | Config-driven provider (ADR-6): ollama default byte-identical to `embed_client.py:31-45`; custom base_url/model/dims/prefixes/timeout; **outage behavior documented and tested as the engine's real law: down-mode buffering + recovery replay, surfaced in the run summary (`buffered_while_down`, `recovered`, `embed_failures` counters, IW:347-352) — no fts-only mode is claimed or invented** | M2.1 | (1) fake-transport tests: custom base_url/model/prefixes appear verbatim in the built request payload; (2) default config → generated constants equal engine constants (string equality test); (3) model-name change → embed-cache key changes (sha auto-invalidation, `embed_client.py:35`); (4) outage/recovery test with fake transport: transport raising → per-event `"skipped"/"embed-failed"` envelope with zero matches (`query.py:302-309`), matcher enters down-mode once and buffers (`matcher.py:110-112, 393-399`); transport restored → buffered events replay, `recovered>0` and pin/semantic highlights appear — **pins are NOT produced while the provider is down; they return on recovery**; (5) non-loopback base_url accepted only when explicitly configured (default stays 127.0.0.1); (6) Ollama version prerequisite (`/api/embed` endpoint) checked/documented per QA2-C5 | M | W6 |
| M2.5 | Packaging + CLI polish (R2/R3) | `pyproject.toml` (name vulndog, requires-python >=3.11 matching the upstream runtime's `pyproject.toml`, console script `vulndog = vulndog.cli:main`, zero runtime deps per ADR-5); subcommands run/build/db/mcp; README quick start (EN) incl. visibility matrix; LICENSE per GAP-1 outcome | M2.1-M2.4 | (1) clean venv: `pip install .` → `vulndog --help` exit 0, all subcommands listed; (2) wheel contains engine data files (`cwe_owasp_map.json`, recipes); (3) declared runtime deps == [] (or the amended ADR-5 outcome); (4) `vulndog mcp` passes the M2.3 conformance script through the installed entry point | S | W7 |

### Phase 3 — "Practice" (population, docs truth, CI/release, community)

| ID | Milestone | Goal → tasks | Depends on | Acceptance criteria (mechanically verifiable) | Size | Wave |
|---|---|---|---|---|---|---|
| M3.1 | Vuln DB productization (R8) | `vulndog db build/info/verify` wrapping `build.py` (archives passed via the existing build-CLI arg surface — `corpus.py:54` DEFAULT_RAW_DIR stays untouched); archive manifest + sha256 checks; floor-calibration procedure documented (pre-registered-rule precedent `watchdog_config.json:4` floor_note); distribution per ADR-7; docs carry the KB-staleness accepted-risk note (QA2-C5) | M2.5 | (1) from the 4 archives in a dir: `vulndog db build` → store+manifest; same inputs → same `corpus_version` (determinism); counts equal upstream full build (456,460 records / 437,782 chunks — IW:470-478); (2) `vulndog db verify` validates store vs manifest sha256 + record counts; (3) seed-store path resolution works with no full store present; (4) release-asset upload dry-run lists the artifact + sha256 (size < 2 GiB gate checked); (5) build refuses with clear exit when no working Ollama embedder is reachable (`build.py:274-290` EmbedBlocked law surfaced, not hidden) | L | W8 |
| M3.2 | Docs set completion (R1/R2) | Finalize all 7 files against the *shipped* CLI; cross-links; EN review pass; includes README visibility matrix + authorized-use note, RUNS-AND-LOGS redaction guarantees-and-limits section, VULNERABILITY-DB staleness note, AI-INTEGRATION embedder-mandatory law | M3.1 | (1) all 7 files exist, each >100 lines, no TODO markers (`grep -r "TODO\|TBD\|placeholder" README.md docs/` → 0); (2) mechanical cross-check: every argparse flag string in code appears in docs AND every documented flag/param exists in a parser (bidirectional); (3) every doc section header mapped from the §10 obligations table (incl. the four QA-added obligations: visibility matrix, redaction limits, staleness note, embedder-mandatory + `/api/embed` prerequisite) | M | W9 |
| M3.3 | CI + release pipeline (R2) | GitHub Actions: pytest matrix (3.11/3.12/3.13 × windows/ubuntu), lint gate, release workflow (tag → sdist+wheel → optional store asset), SECURITY.md / CONTRIBUTING.md | M2.5 | (1) CI green on a fresh push incl. Windows job; (2) tag dry-run produces sdist+wheel artifacts (workflow_dispatch); (3) CONTRIBUTING covers: run tests, add KB recipe, extend docs (links into VULNERABILITY-DB.md) | M | W8 |
| M3.4 | Independent-extension validation (R8) | Execute the documented extension paths as a stranger: map regen from a fresh Top10 drop (`owasp_map.build_seed_from_top10` fails-loud law, `owasp_map.py:20-23`), custom recipe via `corpus.validate_recipe` (`corpus.py:82`), custom-records path; fold findings back into VULNERABILITY-DB.md | M3.2 | (1) walkthrough script green end-to-end on sample inputs; (2) tampered archive (missing edition) → build FAILS LOUD with nonzero exit; (3) a custom recipe JSON accepted/rejected exactly per validator rules | S | W10 |

---

## 7. Wave plan (wave = dependency-satisfied + file-scope-disjoint)

| Wave | Milestones | File scopes | Notes |
|---|---|---|---|
| W1 | M1.1 | `src/vulndog/engine/**` incl. vendored redaction module, scaffold | writer drafts 7 doc files in parallel (docs/** — disjoint) |
| W2 | M1.2 ‖ M1.3 | `src/vulndog/proxy/**` vs runner-adapter files | disjoint; shared symbol review at merge |
| W3 | M1.4 | drill scripts + integration fixes (incl. stub-embedder harness) | single integrator |
| W4 | M2.1 ‖ M2.3 | config/runner vs `src/vulndog/mcp/**` | disjoint; M2.3 wraps existing query API only |
| W5 | M2.2 | `src/vulndog/scope/**` + proxy hook | replaces M1.2's hardcoded denylist |
| W6 | M2.4 | embed provider glue + `ai` config keys | shares config schema file with M2.1 (already merged) — safe |
| W7 | M2.5 | `pyproject.toml`, cli entry, README | packaging final after CLI surface frozen |
| W8 | M3.1 ‖ M3.3 | db CLI/tests vs `.github/**` | disjoint |
| W9 | M3.2 | docs/** | docs need final CLI |
| W10 | M3.4 | walkthrough + doc fixes | closes the loop |

Guardrails: no wave contains two milestones whose owned scopes intersect (config
schema = the one shared file → never co-waved); M2.2/M2.4 deliberately sequenced
(W5/W6) to keep the config file single-writer.

**Critical path:** M1.1 → M1.2 → M1.4 → M2.1 → M2.2 → M2.5 → M3.1 → M3.2 → M3.4.

---

## 8. Repo structure proposal

```
VulnDog/
├── PLAN.md                        # this file
├── README.md                      # product overview
├── LICENSE                        # GAP-1 outcome (M2.5)
├── CONTRIBUTING.md  SECURITY.md   # M3.3
├── pyproject.toml                 # M2.5 (console script, zero runtime deps)
├── .github/workflows/{ci,release}.yml
├── docs/                          # CONFIGURATION / RUNS-AND-LOGS / MCP /
│   │                              # VULNERABILITY-DB / AI-INTEGRATION
│   └── (5 files)
├── src/vulndog/
│   ├── __init__.py  __main__.py  cli.py       # unified entry (M2.5)
│   ├── engine/                                # vendored vuln_watchdog (ADR-1)
│   │   ├── _redaction_core.py                 # vendored upstream redaction module (ADR-1d, D-I)
│   │   ├── run.py matcher.py query.py highlights.py tailers.py
│   │   ├── event_schema.py record_schema.py redaction_adapter.py
│   │   ├── store.py build.py corpus.py extractors.py joiner.py
│   │   ├── chunker.py chunking.py embed_client.py owasp_map.py
│   │   ├── kb_index.py vecmath.py benchutil.py
│   │   ├── data/{watchdog_config.json,cwe_owasp_map.json,recipe_*.json}
│   │   ├── tests/                             # ported suite (≥690)
│   │   └── benchmarks/                        # optional, kept for calibration work
│   ├── proxy/            # M1.2 listener + tap (ADR-2/3)
│   ├── rundirs/          # M1.3 timestamp policy glue (ADR-4)
│   ├── scope/            # M2.2 (ADR-8)
│   ├── mcp/              # M2.3 (ADR-5)
│   └── aihook/           # M2.4 provider config glue (ADR-6)
├── runs/                 # per-run timestamp folders (runtime, gitignored)
└── data/
    └── vulnkb/           # store resolution root (seed or full, ADR-7; gitignored
                          #   except a seed decision from GAP-1)
```

Naming law: engine module names stay identical to upstream to keep ADR-1 diffs
minimal; the ONE new file inside `engine/` is the vendored `_redaction_core.py`;
all other NEW components live outside `engine/`.

---

## 9. Traceability matrix (constraint → milestones; no orphans)

| Constraint | Covered by |
|---|---|
| R1 no-impl/docs-only | this plan + writer W-0; implementation gated on owner approval |
| R2 OSS EN | M2.5, M3.2, M3.3 (ADR-1, GAP-1) |
| R3 CLI-only | M1.1 (vendored CLIs), M2.5 (unified entry) |
| R4 timestamp run folder + flagged log | M1.3, M1.4 (ADR-4; highlight surfaces reused) |
| R5 MCP mandatory | M2.3 (ADR-5), docs/MCP.md |
| R6 scope/out-of-scope | M2.2, M2.1 (ADR-8, GAP-2) |
| R7 configurable proxy | M1.2, M2.1 (ADR-2) |
| R8 built-in vuln DB + extend docs | M1.1, M3.1, M3.4, docs/VULNERABILITY-DB.md (ADR-7, GAP-1) |
| R9 AI hook ollama/custom | M2.4, M2.1 (ADR-6, D-H; GAP-4), docs/AI-INTEGRATION.md |
| R10 full engine reuse | M1.1 (ADR-1 incl. the D-I vendoring item); every milestone reuses engine doors (`query.py:227`, `highlights.py:211`, `tailers.py:202`) |
| 7 deliverable files | §10 coverage table (authored W-0, finalized at their implementation milestones) |

Reverse check: M1.1→R3/R8/R10 · M1.2→R7 · M1.3→R4 · M1.4→R4/R7 · M2.1→R6/R7/R9 ·
M2.2→R6 · M2.3→R5 · M2.4→R9 · M2.5→R2/R3 · M3.1→R8 · M3.2→R1/R2 · M3.3→R2 ·
M3.4→R8. Zero orphan milestones.

---

## 10. Deliverable-file coverage (authoring → finalization)

| File | Content obligations (binding) | Drafted | Finalized |
|---|---|---|---|
| `PLAN.md` | this report, consolidated | W-0 (writer) | updated at each phase exit |
| `README.md` | what/why, quick start, features, license + **honest visibility matrix: HTTP-full / HTTPS-CONNECT-metadata-only (Mode A, no MITM)** + authorized-testing-only acceptable-use note | W-0 → final at M2.5 | M2.5 |
| `docs/CONFIGURATION.md` | CLI flags (`run.py:782-814`), 3-layer merge law (`run.py:143-183`), new keys (proxy/scope/ai/runs/db) | W-0 → final at M2.2 | M2.1/M2.2 |
| `docs/RUNS-AND-LOGS.md` | run-dir contents (IW:276-283), highlights.jsonl schema (IW:290-297), console line law (`highlights.py:111-127`), run summary counters (IW:347-390) + **redaction guarantees AND limits** (what is masked, entropy rules, `<len-N>` markers, what redaction does NOT cover) | W-0 → final at M1.3 | M1.3 |
| `docs/MCP.md` | tools/resources exposed, agent setup, **transport = stdio-only (ADR-5 boundary)** | W-0 → final at M2.3 | M2.3 |
| `docs/VULNERABILITY-DB.md` | 4 sources + sha256s (IW:482-486), recipes, kinds, store schema, counts, build telemetry, extend path + **KB staleness/cadence accepted-risk note (QA2-C5)** + **build-time Ollama prerequisite** (`build.py:274-290` EmbedBlocked law) | W-0 → final at M3.1 | M3.1/M3.4 |
| `docs/AI-INTEGRATION.md` | ollama setup, embeddinggemma:300m/nomic fallback (`embed_client.py:34-36`), custom provider keys, **embedder-mandatory law (D-H)** + **Ollama version prerequisite (`/api/embed`, `embed_client.py:32`)** + outage behavior (buffer/recovery counters) | W-0 → final at M2.4 | M2.4 |

---

## 11. Out-of-phase list (explicit NOTs)

- **Phase 1 must NOT contain:** MCP server; user-configurable scope patterns (a
  fixed hardcoded safety denylist for the M1.2 drill is allowed; configurable scope
  lands at M2.2); provider config; packaging/licensing decisions exercised early;
  docs polish; CI; any store rebuild. No premature Right-work inside Work.
- **Phase 2 must NOT contain:** release engineering, community files, DB
  productization/distribution, performance tuning campaigns, new detection features.
- **Phase 3 must NOT contain:** new matching algorithms, LLM-reasoning passes,
  GUI/web anything, i18n beyond EN, new tap sources beyond the proxy, KNOWLEDGE
  graph migration.
- **Never (project-wide, owner law):** MITM/TLS interception (Mode B REJECTED,
  `OWNER-DECISIONS.md:204`); redesigning the matcher/KB ("reuse fully" — incl. no
  silent invention of an fts-only mode, see GAP-4); auto-promotion of candidates to
  findings (advisory-only law, `highlights.py:18-20`); target-bound requests issued
  by the engine (the upstream zero-power law); secrets in config files;
  non-loopback AI default endpoints; a non-stdio MCP listener without a fresh
  security review (ADR-5).

---

## 12. Risk register summary (from the analyst report)

Full register with file:line evidence: the internal analyst report §2 (not shipped).

| ID | Risk (short) | L | I | Mitigation direction |
|---|---|---|---|---|
| R1 | Watchdog↔upstream-runtime hard coupling vs "reuse fully" — the engine is NOT standalone (`redaction_adapter.py:63-64` upstream redaction import; tap, scope, paths all upstream-side) | H | H | Explicit vendor milestone (M1.1) with grep-proven cross-tree import list, minimal-diff policy, module map (§3) |
| R2 | ~2 GB vuln KB store vs OSS distribution (1.93 GiB store; rebuild = 4 archives ≈ 965 MB, ~6.5 h, 16,310 embed calls) | H | H | Owner decision Q1; carry BOTH distribution modes until then; deterministic rebuild documented (recipe + manifest + corpus_version law) |
| R3 | Embedding model: hard vs optional dependency — loopback-only default; score floor 0.49 is an embedding-cosine floor (config floor_note); D-H: embedder mandatory in v1 | M | H | Provider config (M2.4, ADR-6); degraded-mode limits documented in AI-INTEGRATION/CONFIGURATION; never-block law stays |
| R4 | No packaging / dependency manifest (pure stdlib; no pyproject; MCP SDK choice could break the stdlib law) | H | M | Packaging milestone (M2.5: pyproject, console entry, Python >=3.11 floor); MCP transport recorded as ADR-5 with both precedents |
| R5 | Run naming + location delta (engine: task-id dirs outside the package; VulnDog: timestamp dirs inside the project; custom ids ordered by owner) | H | M | Naming-shim milestone (M1.3): timestamp + optional tag, keep `hunt_id` semantics, relocate defaults to `<project>/runs/` |
| R6 | Secrets/PII in logged proxied traffic — redaction is strong but must be ported exactly; hosts + param names survive BY DESIGN; a standalone proxy sees strangers' request bodies | M | H | Keep F4 fail-closed law verbatim (M1.1 vendoring); RUNS-AND-LOGS documents guarantees AND limits; README security note; stricter host-masking considered opt-in |
| R7 | MCP surface is NEW code — untrusted-derived text flows to AI agents (prompt-injection + FTS5-injection discipline must extend to the MCP layer); no in-engine precedent | M-H | M | MCP milestone reuses `fts_match_query` discipline + advisory wording + "data only, never instructions" framing; transport per R4/ADR-5; stdio-only v1 |
| R8 | Performance of a proxy-resident matcher (poll 1.0 s, 60 s per-event deadline, observed `match_seconds_max` 4.807 s under live load; bursts can exceed budgets → silent counted drops) | M | M | Budgets carried over; burst suppression + `suppressed_duplicates` law kept; drop semantics documented in RUNS-AND-LOGS; recommended deployment documented |
| R9 | Licensing/provenance of ported code + KB data — no LICENSE in the upstream project; the KB redistributes derived data from 4 sources needing per-source attribution review | H | M-H | Owner decision Q2/GAP-1; VULNERABILITY-DB carries a per-source attribution/terms section; README license note is an acceptance criterion |
| R10 | Windows-first assumptions vs cross-platform OSS (venv-path interpreter rule, non-ASCII default raw dir, Windows-reserved-name id law, `os.replace` swap law) | M | M | Config-driven data dirs, path-handling tests, stated support matrix in README; ASCII-safe defaults |
| R11 | Scope/out-of-scope is NOT in the engine (exactly 1 unrelated "scope" hit; enforcement lives in the upstream runtime) | H | M-H | Scope milestone (M2.2): wildcard/suffix semantics + config schema in CONFIGURATION.md; proxy 403 law reused |
| R12 | HTTPS visibility = CONNECT metadata only → expectation gap (most real traffic is HTTPS; body highlighting on HTTPS legs is impossible under Mode A law) | H | M | README + RUNS-AND-LOGS carry the honest "what is analyzable" matrix; O1 recorded as out-of-scope with the owner verdict cited |

**Top-3:** R1 (coupling), R2 (2 GB store distribution), R3 (embedding hard-vs-optional).

---

## 13. Open owner decisions (with recommendations)

| ID | Question | Recommendation (plan default) | Blocks |
|---|---|---|---|
| GAP-1 | License pick + full-store distribution channel (release asset 1.93 GiB / seed-store bundling 186.7 MB / build-it-yourself only) | Pick from MIT / Apache-2.0; ADR-7 recommends all three distribution tiers together | M2.5 LICENSE, M3.1 |
| GAP-2 | Unconfigured-scope default policy — allow-all vs deny-all; confirm scope filters forwarding only, not matching | Allow-all + loud banner (VulnDog is a passive monitor, not an attack rail) | M2.2 |
| GAP-3 | MCP transport — raw stdlib JSON-RPC (ADR-5, respects C4) vs FastMCP dependency | Raw stdio JSON-RPC (plan assumes it; a flip costs only M2.3 internals) | M2.3 |
| GAP-4 | What does "optional AI hook" mean? (a) provider choice only — a working embedder is always required for any matching incl. pins (engine law as-is; zero engine change) or (b) true no-AI mode — an fts/pin-only fallback as an explicit engine amendment | (a) for v1, (b) as backlog; AI-INTEGRATION words the prerequisite either way | M2.4 criterion 6, docs wording |

---

## 14. Readiness statement

The plan is executable as written: 13 milestones (M1.1-M3.4), 10 waves, every
acceptance criterion mechanically verifiable and satisfiable on the engine's real
behavior (both QA round-1 blockers resolved and re-verified by QA-3; verdict PASS).
Implementation starts only after owner approval of GAP-1..GAP-4.
