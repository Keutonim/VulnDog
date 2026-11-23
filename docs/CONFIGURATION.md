# Configuration

How VulnDog is configured: CLI flags, the JSON config file and its merge law,
proxy listener settings, scope / out-of-scope target selection, matching
thresholds, and mute lists.

Every key is marked with its **status**: **[engine]** — an engine-carried key
that behaves today exactly as documented; **[NEW, Mx.y]** — a VulnDog key
introduced by that milestone. Since **M2.1** a config file's product keys
(`proxy.*`, `scope.*`, `runs.*`, `db.*`, `ai.*`) are applied by the config merge
(F-1 closed), and since **M2.4** all five namespaces are also **consumed** by
the shipped product (`ai.*` by the provider factory, `src/vulndog/aihook/`).
Where a key is resolved but not yet consumed by a component, the section says
so plainly — see the layer-status table under the merge law.

## How configuration resolves (merge law)

Configuration resolves through **four** layers, lowest priority first:

1. **Built-in defaults** (compiled into the engine).
2. **Config file `defaults`** — a JSON file merged over the builtins.
3. **Per-run overrides** — a task/run entry in the config file's `tasks` section.
4. **CLI flags** — override everything.

Layers 1-3 are the engine's proven merge law (`run.py:143-183`: builtin ← file
`defaults` ← `tasks` entry), with CLI flags applied on top. **Since M2.1 the
product namespaces (`proxy`, `scope`, `runs`, `db`, `ai`) are known to that same
merge**, so a config file's values for them apply through the one door (F-1
closed) — see the layer-status table below for which component consumes each
key today. Two laws that come with it:

- **Never crash on bad config.** A missing or corrupt config file degrades to
  built-in defaults and records the problem in a `_config_errors` note; the CLI
  prints each note as a `WARNING: config: … (builtin defaults in force)` line to
  stderr at startup (P2-05), and the run still starts (exit 0).
- **Unknown keys are isolated, never applied.** A genuinely unrecognized key
  lands in `_unknown_keys` in the resolved state instead of being silently used
  or crashing. (Isolation is at the engine's top-level key granularity: a known
  namespace applies as a whole.)

Config file discovery (M2.1): current directory → home directory → built-in
defaults — the first existing `vulndog.json` wins (home is `$HOME` /
`%USERPROFILE%`); an explicit `--config` path bypasses discovery. A
discovered-but-corrupt file is reported in `_config_errors` and degrades to
builtins (it is not silently skipped). The file is plain JSON with the shape
below; the engine's shipped example is `engine/data/watchdog_config.json`.

### Layer status (M2.1 merge applies product keys; M2.4 completes consumption)

| Layer / key family | Applies today? | Notes |
|---|---|---|
| Built-in defaults | **yes** | the effective defaults listed per section below |
| Engine-known keys from the file (`top_k`, `floor`, `filters`, `mute_record_ids`, `mute_url_prefixes`, `store_path`, `poll_interval_s`, `state_interval_s`, `backoff_s`, `per_event_deadline_s`) | **yes** | merged by the engine's known-key law |
| **Product keys from the file** (`proxy.*`, `scope.*`, `runs.*`, `db.*`, `ai.*`) | **yes (M2.1)** | known to the engine's single-door merge, so file/task values apply (builtin < file defaults < per-run override < CLI); missing sub-keys are gap-filled from builtins. **Consumption:** `proxy.*`, `runs.dir`, `db.store_path` and `scope.*` are consumed by the shipped proxy/runs path; **`ai.*` is consumed since M2.4** — the provider factory (`vulndog.aihook`) builds the match-path embedder from it (ollama default = the engine's own loopback client, byte-identical; custom = the configured endpoint). The provider choice is disclosed in the run banner and in `watchdog-run.json`'s `ai` section |
| CLI flags | **yes** | applied last; they always win (`--host`, `--port`, `--store`) |

Wrong-typed product config fails fast at startup with a usage error (exit 2)
**before any capture**: `proxy` must be an object (`host` a string, `port` an
int in 0..65535), `scope` an object whose `in`/`out` are lists of strings,
`runs.dir` a path string, `db.store_path` a path string or null, and (M2.4)
`ai` an object with `provider` in {`ollama`, `custom`}, non-empty string
`base_url`/`model`, a positive int `dims`, string `doc_prefix`/`query_prefix`
(empty allowed), and `timeout_s` a positive number or null. The `ai` shape law
lives in `vulndog.aihook.provider.parse_ai` (one decision in one place, the same
pattern as `scope`). Engine keys keep the engine's own never-crash merge law.

## Config file example

Values shown for `[engine]` keys are the shipped defaults, verbatim.
`[NEW]` product-key values in the file are applied by the config merge since
M2.1 (see the sections below for each key's consuming component and the
layer-status table above).

```json
{
  "config_version": 1,
  "floor_note": "0.49 = full-store recalibrated default 2026-10-16 (see docs/VULNERABILITY-DB.md)",
  "defaults": {
    "top_k": 3,
    "floor": 0.49,
    "poll_interval_s": 1.0,
    "state_interval_s": 5.0,
    "backoff_s": 60.0,
    "per_event_deadline_s": 60.0,
    "console": true,
    "mute_record_ids": [],
    "mute_url_prefixes": [],
    "filters": null,
    "store_path": null,
    "proxy": { "host": "127.0.0.1", "port": 8080 },
    "scope": { "in": [], "out": [] },
    "runs": { "dir": "runs" },
    "db": { "store_path": null },
    "ai": {
      "provider": "ollama",
      "base_url": "http://127.0.0.1:11434",
      "model": "embeddinggemma:300m",
      "dims": 768,
      "doc_prefix": "title: none | text: ",
      "query_prefix": "task: search result | query: "
    }
  },
  "tasks": {}
}
```

Per-run overrides go under `"tasks"` keyed by run id; they merge over `defaults`
the same way, and CLI flags still win.

## Matching and thresholds

| Key | Default | Meaning |
|---|---|---|
| `top_k` [engine] | `3` | max KB matches reported per event (semantic candidates) |
| `floor` [engine] | `0.49` | score floor: semantic candidates below it are dropped. Calibrated as an **embedding-cosine** floor; see `floor_note` in the config file and the recalibration procedure in docs/VULNERABILITY-DB.md |
| `poll_interval_s` [engine] | `1.0` | how often the runner polls the spool for new events |
| `state_interval_s` [engine] | `5.0` | how often the run-state file is persisted |
| `backoff_s` [engine] | `60.0` | retry backoff while the embedder is down (see docs/AI-INTEGRATION.md) |
| `per_event_deadline_s` [engine] | `60.0` | hard deadline for matching one event; over-deadline events are counted (`hangs`), not stuck on |
| `console` [engine] | `true` | print highlight candidate lines to the console (lines never carry snippets). The key is accepted by the merge; in the shipped VulnDog run path the analysis facade wires no console sink, so candidates land in `highlights.jsonl` / `highlights.md` (see docs/RUNS-AND-LOGS.md) |

Burst behavior (engine law, not configurable): identical `(url, record_id)` pairs
are deduplicated per run (`suppressed_duplicates` counter); repeated hits raise a
burst notice at the 10th / 100th / 1000th / 10000th repeat. See
docs/RUNS-AND-LOGS.md.

## Filters

`filters` [engine] (default `null` = no filtering): an optional dict restricting
which KB records can match. Allowed keys only — anything else is rejected by the
query API:

| Key | Meaning |
|---|---|
| `kind` | record kind: `cve`, `exploit`, `cwe`, `cwe_category`, `owasp_doc` |
| `min_cvss` | minimum CVSS score of the record |
| `exploit_available` | boolean — only records with a known public exploit |
| `cwe_id` | restrict to a CWE id |

## Mutes

| Key | Default | Meaning |
|---|---|---|
| `mute_record_ids` [engine] | `[]` | KB record ids to suppress entirely (counted in `muted_records`) |
| `mute_url_prefixes` [engine] | `[]` | URL prefixes to suppress entirely (counted in `muted_urls`) |

Mutes are the matching-side knob: they silence *reporting* of known-noise pairs
without touching the proxy. To keep requests from even being forwarded, use
`scope` below instead.

## Proxy settings

VulnDog is an **observing forward proxy** (Mode A): it forwards absolute-form HTTP
requests and relays CONNECT tunnels opaquely. It never terminates TLS and never
modifies traffic.

| Key | Default | Meaning |
|---|---|---|
| `proxy.host` [NEW, M1.2/M2.1] | `127.0.0.1` | listen address. Loopback is the default and the safe choice; a non-loopback bind requires `--allow-remote-bind` **and** a client credential — see the safety behavior below. Set via the config file (applied since M2.1) or `--host` (CLI wins) |
| `proxy.port` [NEW, M1.2/M2.1] | `8080` (designed default — the engine has no listener, so no precedent value) | listen port; set via the config file (applied since M2.1) or `--port` (CLI wins) |

Safety behavior (shipped, applies under any scope):

- **SSRF rail (default-deny).** The proxy refuses to forward to loopback,
  RFC1918, link-local (including the cloud-metadata address
  `169.254.169.254`), CGNAT `100.64.0.0/10`, IPv6 ULA/link-local, and internal
  names (`localhost`, `*.internal`): both legs answer **403** with
  `denial_reason:"proxy_private"` before any upstream socket. Numeric IP
  spellings (decimal/hex/octal `inet_aton` shorthand) are normalized before
  classification. Other names are classified at **connect time against their
  resolved address**: the proxy resolves once, denies the name when **any**
  resolved address is non-global (fail-closed on unclassifiable answers), and
  connects to that classified address — a public name that resolves to a
  private address (DNS rebinding, e.g. `*.nip.io` services) is refused, and the
  checked address IS the connected address (no second resolution).
  **Residual limitation, stated honestly:** the rebinding TOCTOU on
  re-resolution — a DNS record flipping between separate resolutions across
  requests — is a narrow known race (one resolution per request, the socket
  never re-resolves the name, but stdlib offers no resolver-level pinning);
  treat the rail as a floor, not a full SSRF defense. `--allow-private` is the
  explicit opt-in (it skips the rail but keeps the single-resolution pinning;
  out-of-scope still wins over it).
- **Remote bind credential law.** `--allow-remote-bind` alone is not enough:
  without `--client-token <secret>` or `--client-allow <cidr>` the proxy
  **refuses to start** (usage error) rather than becoming an unauthenticated
  network-wide relay. With a credential, every request (both legs) is gated:
  a token check accepts `Proxy-Authorization: Bearer <token>` (constant-time
  compare, answered 407 `proxy_auth` on failure), a CIDR check admits matching
  client IPs (403 `proxy_client_denied` otherwise); either credential passing
  suffices. The credential is hop-by-hop — never forwarded to the origin,
  never persisted.
- **Connection cap.** 64 concurrent connections by default; excess connections
  are answered `503` before a handler thread spawns and counted
  (`connections_refused`).
- **Banner.** Every run prints its effective posture at start. With no scope
  configured the banner warns: "no scope configured — all PUBLIC hosts are
  forwarded (allow-all passive-monitor default)" and states the rail state.

Behavior notes:

- Out-of-scope requests are answered with **HTTP 403** at the proxy; the request
  never leaves your machine (no upstream socket is opened).
- HTTPS legs are visible as **CONNECT metadata only** (host:port, timing — no
  path, no body). Plain HTTP legs are inspectable in full. See the visibility
  matrix in README.md and docs/RUNS-AND-LOGS.md.
- Point a client at the proxy the way that client accepts proxies (e.g. an
  `HTTP_PROXY`-style environment variable or the client tool's own proxy
  option); VulnDog only listens — it never launches or configures clients.

## Scope / out-of-scope

| Key | Default | Meaning |
|---|---|---|
| `scope.in` [NEW, M2.2] | `[]` | in-scope host patterns (an exact hostname, or `*.suffix` — which covers the domain itself and its subdomains) |
| `scope.out` [NEW, M2.2] | `[]` | out-of-scope host patterns; **out wins** when a host matches both lists |

**Status (M2.2):** the scope check is implemented and enforced at the proxy
(403 + a `denial_reason:"proxy_oos"` event, no upstream socket, both legs), and
**a scope configured in the config file is applied since M2.1** (F-1 closed — a
config file can now restrict scope). There is still no CLI scope flag (set
scope via the config file). The dedicated scope module (`vulndog.scope`, M2.2)
owns pattern compile and the pure match function; the proxy compiles the scope
once at startup and matches via it. With no scope configured the default is the
empty scope: all **public** hosts forwarded, private targets denied by the SSRF
rail.

Semantics (ADR-8):

- Enforcement happens **at the proxy**: an out-of-scope host:port gets 403 plus a
  `denial_reason:"proxy_oos"` event in the run's `events.jsonl`; the scope check
  runs before the SSRF rail (the `proxy_oos` vocabulary is preserved for
  out-of-scope hosts).
- Scope controls **forwarding only** — it does not filter KB matching. For that,
  use `filters` and the mute lists.
- Wrong-typed scope config fails fast at startup with a nonzero exit (exit 2 —
  no half-configured proxy). Patterns are matched literally: an exact hostname
  or a `*.suffix` wildcard only. A pattern carrying a scheme, path, port,
  userinfo, query, fragment, interior whitespace, or a misplaced wildcard is
  **rejected** at compile time (exit 2, message names the key and pattern) —
  never silently normalized into a different target. Case and a trailing root
  dot are normalized (lowercased / stripped); a `www.` prefix is an ordinary
  exact pattern, not a special rule.
- Every run prints a banner at start showing the effective scope.
- With no scope configured, VulnDog allows all **public** hosts **and prints a
  loud banner** saying so; private/metadata targets stay denied by the SSRF rail
  (see Proxy settings) unless `--allow-private` is passed. This default is an
  open owner decision (PLAN.md GAP-2).

> Decision pending: unconfigured-scope default — recommended **allow-all for
> public hosts with a loud banner** (the SSRF rail is a hard floor under it);
> deny-all is the safe alternative and remains a one-flag flip.

## Run folders and store paths

| Key | Default | Meaning |
|---|---|---|
| `runs.dir` [NEW, M1.3/M2.1] | `runs` | root directory for timestamped run folders, created inside the project (`--project` chooses the project root; the config-file value is applied since M2.1) |
| `store_path` / `db.store_path` [engine key; `db.*` namespace NEW, M2.1] | `null` → engine default store path | path to `vulnkb.sqlite`. A configured path wins (`--store` overrides everything); `null` resolves to the engine's built-in default store path (`store.DEFAULT_STORE_PATH`, a path inside the installed `vulndog` package). **No store ships in the tree yet**: with no store at the resolved path, a run still captures every event; a run with captured events then fails with exit 4 (analysis skipped — never "no vulnerabilities found") and an actionable message ("build one … or pass --store"), while a run that captured zero events exits 0 (empty-spool semantics). The `vulndog db` commands (shipped, M3.1) resolve the tiered order: explicit store, then `db.store_path`, then the project `data/vulnkb/` store root (seed or full), then the engine default; the `run` path keeps the order described here — see docs/VULNERABILITY-DB.md |

Engine-carried path keys retained for advanced use [engine]: `spool_root`,
`ledger_path`, `evidence_dir`. In the default VulnDog flow the **proxy tap** writes
the spool (`events.jsonl`) directly into the run folder, so you normally never set
these; they remain supported for pointing the engine at other event sources.

Run folder layout and file formats: see docs/RUNS-AND-LOGS.md.

## AI provider settings

| Key | Default | Meaning |
|---|---|---|
| `ai.provider` [NEW, M2.4] | `ollama` | `ollama` or `custom`. Selects the provider, never "no provider": the embedder stays mandatory in the match path (GAP-4/D15) |
| `ai.base_url` [NEW, M2.4] | `http://127.0.0.1:11434` | embedding service base URL — **applied since M2.4**, verbatim (`base_url + /api/embed`). The default is loopback and the engine's client ignores proxy environment variables. A non-loopback or `file://` value is **accepted only because you explicitly configured it** (your own box) and is disclosed with a `WARNING` banner line plus the `ai` section of `watchdog-run.json` — never silent. Think before pointing it at a remote host: `base_url` receives the **text of your proxied traffic** (redacted event text), so a remote address sends that text off-machine |
| `ai.model` [NEW, M2.4] | `embeddinggemma:300m` | embedding model, sent verbatim in the request. Changing it auto-invalidates the embed cache (the engine's sha256 of model+prefixed text) and **requires rebuilding the KB vectors** |
| `ai.dims` [NEW, M2.4] | `768` | expected embedding dimensionality — the validation law for answers and cached vectors. A wrong-dims answer is an embed failure (`skipped`/`embed-failed`), never a silent match |
| `ai.doc_prefix` / `ai.query_prefix` [NEW, M2.4] | engine constants | model prefixes for documents vs queries; applied verbatim, never mixed, never replaced by the engine's constants. `""` is legal for a model that needs no prefix |
| `ai.timeout_s` [NEW, M2.4] | engine default (10 s) | per-request embedding timeout; `null` keeps the engine default |

**Status (M2.4 — wired):** the `ai` keys are applied by the config merge
(builtin < file defaults < per-run override < CLI, M2.1/F-1) **and consumed** by
the provider factory `src/vulndog/aihook/`. With every value at its default the
factory returns the engine's own transient loopback client, so the default
request is byte-identical to `engine/embed_client.py`'s constants (pinned by
string-equality and request-equality tests). Any deviating value builds a
configured client through the engine's published seams; no engine module is
edited (ADR-1). Query vectors stay transient on the match path
(`use_cache=False`), per the engine's design law.

**Offline test seam (unchanged):** an injected `config["embedder"]` object wins
over the factory — that is how the P1 suite and the M1.4 drill stay
deterministic without Ollama. Producers never write that key into a config file.

Full semantics, the embedder-mandatory law, and outage behavior: see
docs/AI-INTEGRATION.md.

## CLI flags

Shipped entry points (M2.5): the `vulndog` console script (after
`pip install .`) and its module form `python -m vulndog <subcommand>`, with
subcommands `run`, `status`, `version`, `mcp`, `db`. `mcp` runs the shipped
M2.3 stdio server (docs/MCP.md); `db` is the shipped M3.1 store-management
surface (`db build / info / verify`, plus `--release-asset-dry-run`) — its
full flag tables and exit law live in docs/VULNERABILITY-DB.md.

### `run` — capture traffic through the proxy, then analyze the run

| Flag | Default | Meaning |
|---|---|---|
| `--project` | `.` | project root; run folders land under its `runs.dir` |
| `--config` | none | config JSON path (engine and product keys apply since M2.1; when omitted, discovery is cwd → home → builtins) |
| `--task` | none | per-run task entry key for the config file's `tasks` section |
| `--tag` | none | custom run tag `[A-Za-z0-9._-]{1,64}` (no trailing `.` or `-`) to tell parallel instances apart |
| `--host` | `127.0.0.1` | proxy listen host |
| `--port` | `8080` | proxy listen port |
| `--allow-remote-bind` | off | explicitly allow a non-loopback listen address |
| `--client-token` | none | client credential required **with** `--allow-remote-bind`: requests must carry `Proxy-Authorization: Bearer <token>` (constant-time compared; hop-by-hop, never forwarded upstream) |
| `--client-allow` | none | client CIDR allowed **with** `--allow-remote-bind` (alternative to `--client-token`; either credential passing suffices). A malformed CIDR is a usage error |
| `--allow-private` | off | explicitly allow forwarding to private targets (loopback, RFC1918, link-local/cloud metadata, internal names) — default-**denied** by the SSRF rail |
| `--store` | none | `vulnkb.sqlite` path (overrides `db.store_path`) |
| `--duration` | none | auto-stop after N seconds (bounded capture) |

Stop paths: Ctrl-C (SIGINT), a `stop-request` file in the run folder, or
`--duration`. On a clean stop the captured spool is handed to the analysis
facade, which writes the flagged-request log (docs/RUNS-AND-LOGS.md).

### `status` — show the latest run

| Flag | Meaning |
|---|---|
| `--project` | project root (default `.`) |
| `--config` / `--task` | as for `run` |
| `--json` | machine-readable output: `hunt_id`, `run_dir`, `pid`, `alive`, `mode`, `counters`, `stop_requested` |

### `version`, `mcp`, and `db`

- `vulndog version` — prints the package version (`vulndog 0.1.0`).
- `vulndog mcp` — runs the MCP server over stdio (M2.3; docs/MCP.md). Flags
  (owned by the server entry, identical for `python -m vulndog mcp` and
  `python -m vulndog.mcp`):

  | Flag | Default | Meaning |
  |---|---|---|
  | `--project` | `.` | project root; run folders live under its `runs.dir` |
  | `--config` | none | config JSON path (discovery cwd → home → builtins when omitted) |
  | `--task` | none | per-run task entry key |
  | `--store` | none | `vulnkb.sqlite` path (overrides `db.store_path`) |

- `vulndog db` — shipped store management (M3.1). Subcommands `build`,
  `info`, `verify`, plus a top-level `--release-asset-dry-run [STORE]`. The
  flag surface is owned by `vulndog.db.cli` and passes through untouched
  (the same pattern as `mcp`); `vulndog db --help` shows the real flags.
  Global flags `--project` / `--config` / `--task` resolve the store the same
  way as `run`; `build` takes `--raw-dir` (required), `--output`, `--stage`,
  `--recipe`, `--dry-run`, `--limit`, `--embed-max-retries`,
  `--embed-retry-backoff`; `info` / `verify` take an optional `store`
  positional (`info` also `--json`). Full tables, the tiered store-resolution
  order, and the exit law: docs/VULNERABILITY-DB.md.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | ok |
| `1` | runtime error (e.g. cannot bind the listen address) |
| `2` | usage error (bad flag values, invalid tag, non-loopback bind without the required flag/credential, wrong-typed product config) |
| `3` | engine unavailable — capture preserved, analysis NOT performed (never a fake "no vulnerabilities" claim) |
| `4` | analysis failed or not performed — `skipped` (embedder outage) / `disabled` (KB store unavailable) / missing store; zero highlights from an outage is never reported as success |

`vulndog db` has its own exit law (docs/VULNERABILITY-DB.md): `0` ok, `1`
store/manifest error or `verify` FAIL, `2` usage; `db build` surfaces the
engine build exit codes verbatim (`0` ok / `2` input / `3` aborted /
`4` embed-blocked / `5` store). `vulndog mcp` exits `0` on clean EOF, `1` when
the engine half is unavailable, `2` on a config usage error.

### Advanced engine runner (vendored, engine-side — not the product surface)

The vendored engine keeps its own upstream runner CLI (`vulndog.engine.run`,
argument surface `run.py:782-814`) for engine-side and diagnostic work. These
flags are **not** part of the `vulndog` product CLI:

| Flag | Meaning |
|---|---|
| `command` | `start` \| `stop` \| `status` \| `<run-id>` (bare id = start) |
| `--task` | run id |
| `--config` | config JSON path (default: the engine data config; discovery per above) |
| `--spool-root` | spool root dir (advanced; the default flow uses the proxy tap — see Run folders above) |
| `--ledger` | guard-ledger path (advanced, engine-carried) |
| `--evidence-dir` | evidence dir (advanced, engine-carried) |
| `--store` | `vulnkb.sqlite` path (overrides `store_path`) |
| `--floor` | score floor float |
| `--top-k` | top_k int |
| `--poll` | poll interval seconds |
| `--backoff` | embedder-down retry backoff seconds |
| `--max-cycles` | bounded drain mode (run N cycles then stop) |
| `--once` | alias for `--max-cycles 1` |
| `--json` | machine-readable `status` output |
| `--timeout` | `stop`: wait seconds for clean exit (default 30.0) |
| `--force` | `stop`: hard-kill after timeout, explicit only |

Proxy listen address/port are set with `--host` / `--port` on `run` or via the
config file; scope via `scope.in` / `scope.out` in the config file (applied since
M2.1). Config precedence is always: CLI > tasks entry > file defaults > builtins
— config-file **product keys** apply through the same merge since M2.1 (F-1
closed; see the layer-status table for which component consumes each key today).
