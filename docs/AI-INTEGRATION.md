# AI Integration

VulnDog's "AI hook" is the semantic-matching layer: a local embedding model that
reacts to every proxied request and searches the vulnerability knowledge base for
matches. This page explains exactly what the AI component does (and does not do),
how to set it up with Ollama, how to point it at a custom provider, and what
happens when it is unavailable.

## What the AI component does — embeddings only

The AI in VulnDog is **an embedding model, not a chat LLM**. For every event, the
engine embeds the request text and compares it by cosine similarity against the
pre-embedded vulnerability KB chunks:

```
event text ("GET /login.php params=redirect,status ct=text/html snippet=…")
  → query embedding        (local Ollama /api/embed, 768-d vector)
  → cosine similarity vs stored KB chunk vectors   (pure Python, dot == cosine)
  → top_k above the score floor → semantic candidates
```

In the current engine there is **no LLM anywhere**: no chat-completion endpoint, no
prompt, no per-request model verdict, no cloud calls. An exhaustive survey of the
engine (plus its sibling copies) found 14 AI-related call sites, all of them
`/api/embed` embedding calls or `/api/tags` liveness probes — and zero hits for any
chat/completions/OpenAI/Anthropic surface. The "intelligence" comes from the KB
itself: the embedding model
places the request and the vulnerability descriptions in the same vector space;
ranking, floors, pins, and verdict wording are all deterministic code.

This makes the AI hook "optional" in a **provider** sense — Ollama is the default,
a custom embedding provider can be configured — and it is the same mechanism the
product requirement describes: "AI that reacts to requests and searches for
vulnerability matches".

**Important, stated honestly (engine law):** the embedding step is **mandatory in
the match path** — it runs before pin resolution, and pins bypass the score floor
and filters but **not** the embedder. With no working embedder configured, VulnDog
produces **no highlights at all**; there is no deterministic-only fallback mode in
v1. See "When the embedder is down" below.

## Setup with Ollama (default provider)

Requirements:

1. **Ollama installed and running**, loopback `http://127.0.0.1:11434`.
2. **The embed model pulled:**

   ```text
   ollama pull embeddinggemma:300m
   ```

   Default model `embeddinggemma:300m` (768-dim vectors). The engine also knows a
   built-in fallback model name (`nomic-embed-text:latest`) — if you override
   `ai.model`, the store vectors and the query embedder must be the same model.
3. **An Ollama version with the `/api/embed` endpoint.** The client calls
   `POST /api/embed`; older Ollama releases only expose the legacy
   `/api/embeddings` route and will fail every call — check your version if
   embedding fails with a 404-style error at startup.
4. **A matching KB.** Store vectors were embedded with the same model recorded in
   the store's `manifest.json` (`extra.embed.model`). Mixing models/dims breaks
   cosine comparability — rebuild the store if you change the model (see
   docs/VULNERABILITY-DB.md).

How it connects (engine behavior, unchanged): the client posts to
`base_url + /api/embed` with `{"model": …, "input": [prefixed texts]}`, using
plain HTTP (no proxy environment variables are honored — the embed path is
loopback by construction). Liveness is probed with `GET /api/tags`; the run status
surfaces `reachable` and whether the embed model is present.

Mandatory prefixes (never mixed): documents are embedded with the
`doc_prefix` (`"title: none | text: "`), queries with the `query_prefix`
(`"task: search result | query: "`). The custom provider config carries both so a
replacement provider reproduces the model's expected inputs exactly.

## Custom provider configuration

**Status (M2.4): the `ai` keys below are APPLIED — the provider factory builds
the embedder the match path uses.** Since M2.1 (config system v2, F-1) the `ai`
namespace is known to the engine's single-door merge, so a config file's `ai.*`
values reach the resolved config (builtin < file defaults < per-run override <
CLI). Since M2.4 the product's provider factory (`src/vulndog/aihook/`) consumes
them:

- **Default (`provider: "ollama"`, every value at its built-in default):** the
  factory hands back the engine's own transient loopback client
  (`query.make_transient_embedder`) — one constant address
  (`http://127.0.0.1:11434`, `/api/embed`), proxy environment variables ignored
  by construction. The default request is **byte-identical** to the engine's
  built-in constants (pinned by a string-equality test against
  `engine/embed_client.py`, and by comparing the two outgoing requests field for
  field).
- **Custom (any deviating value, or `provider: "custom"`):** the factory builds a
  configured client — a subclass of the engine's `EmbeddingClient` that extends
  it through its published seams only. `base_url`, `model`, `doc_prefix`,
  `query_prefix`, `dims` and `timeout_s` appear **verbatim** in the outgoing
  request (`base_url + /api/embed`, `{"model": …, "input": [prefix + text]}`);
  nothing is normalized or rewritten. The engine's retry/backoff, batching, sha
  cache, vector validation and repair log stay the single implementation. The
  custom provider's response read is **capped at the aihook transport seam**
  (P2-07): the ceiling is derived from the engine's request caps (at most
  `DEFAULT_BATCH_SIZE` vectors of `dims` floats), and an over-cap body fails
  closed as `embed-failed` — never an unbounded allocation. No engine module is
  edited (ADR-1; see `engine/VENDORING.md`, M2.4 delta: none).

The provider choice is **disclosed, never silent**: the startup banner prints
the provider/model/address, and `watchdog-run.json` carries an `ai` section
(`provider`, `base_url`, `model`, `dims`, `loopback`, `warning`). A wrong-typed
`ai` value fails fast at startup with exit 2, before any capture.

**Privacy posture (read this before pointing `base_url` at a remote host):** the
default is loopback and keeps everything on your machine. A non-loopback — or
`file://` — `base_url` is **accepted when you explicitly configure it** (it is
your own box; GAP-4 scope), but that address then receives the **text of your
proxied traffic** (redacted event text). Such a configuration is reported with a
loud `WARNING` line in the run banner and a `warning` field in the run meta; it
is never refused silently and never applied silently.

**Disclosure is scheme AND authority (P2-03, shipped):** only an `http`/`https`
URL whose host is a literal loopback IP or `localhost` counts as loopback.
**Any other scheme is non-loopback whatever its authority** — so every
`file://` form (including `file://127.0.0.1/…` and `file://localhost/…`, which
urllib serves from a local file) carries the disclosure warning; a loopback
hostname can never make a `file://` address silent. The predicate
(`aihook/provider.py is_loopback_url`) is pinned to agree with the proxy rail's
loopback notion for real http hosts.

**Which doors consume it (honest boundary).** M2.4 wires the **query side**: the
match path used by `vulndog run` analysis and by the MCP `vuln_query` tool — one
`ai.*` decision, both doors. The **doc side** (embedding KB chunks when you build
a store) is the engine's build door (`engine/build.py`), wrapped by the shipped
product subcommand `vulndog db build` (M3.1; docs/VULNERABILITY-DB.md). The build
requires a working **loopback Ollama** embedder and refuses loudly without one
(the EmbedBlocked law); it does not read a custom `ai.base_url` for the doc side.
So when you change `ai.model`, `ai.dims` or the prefixes for a custom provider,
the store must be rebuilt with the **same** provider settings — query and
document vectors have to live in the same space, or cosine comparability breaks
(see docs/VULNERABILITY-DB.md).

The `ai` config section (docs/CONFIGURATION.md) configures the provider; defaults
reproduce the engine constants byte-for-byte:

```json
{
  "ai": {
    "provider": "ollama",
    "base_url": "http://127.0.0.1:11434",
    "model": "embeddinggemma:300m",
    "dims": 768,
    "doc_prefix": "title: none | text: ",
    "query_prefix": "task: search result | query: ",
    "timeout_s": null
  }
}
```

| Key | Notes |
|---|---|
| `provider` | `ollama` (default) or `custom` |
| `base_url` | **applied (M2.4)**, verbatim: the request goes to `base_url + /api/embed`. The loopback default stays the design law. A non-loopback or `file://` value is accepted only because you explicitly configured it, and is disclosed in the banner + run meta — `base_url` receives the **text of your proxied traffic** (redacted event text), so a remote address sends that text off-machine and changes the product's privacy posture |
| `model` | changing it **auto-invalidates the embed cache** (cache keys are the engine's sha256 of model+prefixed text) and requires a KB rebuild to match (see docs/VULNERABILITY-DB.md) |
| `dims` | must equal the model's true dimensionality (768 for the default); it is the validation law for every answer AND every cached vector. A wrong-dims answer raises inside the client, so the event is reported `skipped` / `embed-failed` (a vector that passes dims but cannot be normalized is `embed-invalid`) — never a silent match |
| `doc_prefix` / `query_prefix` | model-specific input prefixes; keep them exactly as the model expects |
| `timeout_s` | per-request timeout; the engine default is kept unless you set it |

Secrets (if a provider needs auth) go in **environment variables, never in config
files**. The engine's outage semantics (below) apply to any provider, custom
included: what matters is that the endpoint speaks the same request/response shape
(`{"model", "input"}` in → `{"embeddings": [[…]]}` out) and returns correct,
unit-consistent vectors.

## When the embedder is down (outage law)

This behavior is the engine's real, tested law — not a new design:

1. **Embed call fails** (unreachable, hung, wrong dims) → the event gets a
   `"skipped"` status with reason `"embed-failed"` (or `"embed-invalid"` for bad
   vectors) and **zero matches** — including exact-id pins, which never execute
   their lookup on a failed embed.
2. **The matcher enters down-mode.** The run's `mode` leaves `"enabled"`; incoming
   events are **buffered** (`buffered_while_down` counter grows) instead of being
   dropped; the runner retries with a **60 s backoff** (`backoff_s`).
3. **Nothing is highlighted while down.** There is no fts-only degrade in this
   engine — a text-only fallback exists only in a sibling project, never in this
   codebase, and none is invented for v1.
4. **Recovery replays in order.** When the embedder responds again, buffered
   events are matched in order (`recovered` counter), and highlights — semantic
   and exact-id alike — appear again.
5. **Everything is visible in the run summary:** `embed_failures`,
   `buffered_while_down`, `recovered`, `mode` (see docs/RUNS-AND-LOGS.md), and in
   `run_status()` over MCP (see docs/MCP.md).

The matching loop never blocks or crashes the run on an outage: the worst case is
a delayed, buffered candidate list.

### What an outage looks like in the shipped Phase-1 flow

Analysis runs at the clean stop of a run: the CLI hands the spool
(`events.jsonl`) to the engine facade, which re-runs the match path over every
captured event. If the embedding provider is unreachable at that moment:

- **The capture is unaffected.** The proxy keeps observing and persisting
  redacted events; the outage only affects the matching pass.
- **The request is reported as `skipped` / `embed-failed` with ZERO matches.**
  Every event gets that envelope; **pins are NOT produced while the provider is
  down** — the embed call runs before exact-id pin resolution, so a pin still
  needs the embedder to have succeeded first (engine law, not an optimization
  choice).
- **The matcher buffers; replay is the runner's door.** While down, events are
  buffered (`buffered_while_down` grows, `pending` stays nonzero) instead of
  being dropped. In-order replay with `recovered>0` is
  `matcher.retry_pending()` — the door the engine's live matching loop drives
  on its 60 s backoff clock (`engine/run.py:459-462`). The Phase-1 facade
  (`analyze_run`) drives ONE pass over the spool and does not replay mid-pass:
  if the provider recovers halfway through, the remaining events stay buffered
  and the summary still reports the outage honestly (never a fake success).
  The practical Phase-1 recovery is to **re-run the analysis once the provider
  is back**: the facade is idempotent, re-matches the whole preserved spool,
  and the highlights (semantic and exact-id) appear then.
- **The run fails honestly, never fakes success.** The facade reports status
  `skipped` (embedder down/hung, or an over-cap provider response — P2-07) or
  `disabled` (KB store missing/corrupt) and the CLI exits **4** with a loud
  stderr line: "zero highlights here is NOT a clean bill of health". The
  captured events are preserved in `events.jsonl`.
- **The counters land in the run summary** (`highlights.md`) and in the
  analysis summary: `embed_failures`, `buffered_while_down`, `recovered`,
  `mode` — `enabled` when healthy, `ollama-down` / `ollama-hung` during the
  outage, `kb-missing` for the store case. (The `run_status()` MCP view of the
  same counters is the Phase-2 surface, docs/MCP.md.)

The matcher's mode vocabulary is therefore: `enabled`, `ollama-down`,
`ollama-hung`, `kb-missing`. There is no degraded "matches-without-embeddings"
mode in any state.

## "Optional" — what it means for v1

The engine as shipped requires a working embedder for any matching, pins included.
So "optional AI hook" in v1 means **provider choice** (Ollama default vs custom
endpoint), not "runs with no AI service". A true no-AI mode (a text-only fallback
when no embedder is configured) would be an explicit engine amendment — owner
decision **D15** keeps it in the backlog; it is not silently built.

> **Decision taken (GAP-4 / D15, shipped in M2.4): provider choice only for v1.**
> The embedder is always required for any matching, pins included; `ai.provider`
> selects ollama (default) or a custom endpoint. A true no-AI mode (a text-only
> fallback when no embedder is configured) stays **backlog** and would be an
> explicit, owner-approved engine amendment — it is not built, not claimed, and
> not reachable through any config value in this release.
