# Contributing to VulnDog

Thanks for considering a contribution. VulnDog is a CLI traffic-listening
vulnerability highlighter: an observing forward proxy plus an offline
vulnerability-KB matching engine. Every highlight is an advisory *candidate*,
never a finding — contributions must preserve that semantics.

Product content (CLI help, docs, comments in product surfaces) is **English**.

## Dev setup

Prerequisites: Python **>= 3.11** and git. A local Ollama with the embed model
(`ollama pull embeddinggemma:300m`) is needed for **live capture/analysis and
KB builds** — not for the test suite, which runs offline with injected fake
transports and a stub embedder.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/macOS: source .venv/bin/activate
python -m pip install -e ".[dev]"
```

The editable install gives you the `vulndog` console entry (equivalent module
form: `python -m vulndog …`). Runtime dependencies are **zero** — the dev
extra carries `pytest` (tests) and `build` (release packaging) only. Do not
add runtime dependencies without an owner decision.

## Run the tests

```bash
python -m pytest -q
```

This runs the **full in-tree suite**: the top-level `tests/` tree plus the
vendored engine tests (`src/vulndog/engine/tests`) and the MCP tests
(`src/vulndog/mcp/tests`). Keep it green — a change that breaks the suite is
not ready. The suite is offline by design (no network egress, stub embedder);
if a test of yours needs a live service, inject a fake instead.

The project defines **no linter** (stdlib-only codebase). CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs a
`python -m compileall` + import/CLI smoke step in place of a lint gate, then
the full suite on ubuntu + windows × Python 3.11/3.12/3.13. Quick local smoke:

```bash
vulndog version
vulndog --help
```

## Add a KB recipe (extend the vulnerability database)

The knowledge base is built from four source archives by a deterministic,
recipe-driven pipeline. The canonical guide is
[docs/VULNERABILITY-DB.md](docs/VULNERABILITY-DB.md) — read its
[Recipes](docs/VULNERABILITY-DB.md#recipes) section and the
[Populating / extending the DB independently](docs/VULNERABILITY-DB.md#populating--extending-the-db-independently)
walkthrough (Steps 1–7), in particular **Step 4 — add a custom recipe**.

The short version:

1. Start from a shipped recipe:
   [`src/vulndog/engine/data/recipe_full.json`](src/vulndog/engine/data/recipe_full.json)
   (full corpus) or
   [`src/vulndog/engine/data/recipe_stage1.json`](src/vulndog/engine/data/recipe_stage1.json)
   (tightened slice). Change one knob at a time.
2. Recipes are JSON, validated strictly by the engine's recipe validator
   (`corpus.validate_recipe`) before anything runs: it checks the required
   fields, their types, and the `logic` / `exploit_mirror` / `cvss_min` /
   `years` rules — on any violation the build refuses with the validator's
   reason (input exit `2`). Extra fields are **carried, not rejected**; the
   recipe's `stage` field is metadata carried into the manifest (the `--stage`
   CLI flag owns the stage choice, constrained to `slice` / `full`);
   `expected_records` is an **advisory size window for the operator, not a
   build gate** — check the measured counts with `--dry-run`. The full rule
   list lives in Step 4 of the guide.
3. Build and verify per the walkthrough (a working Ollama embedder is
   mandatory for builds — the build fails loud without it). Same recipe +
   same archive bytes → same `corpus_version` (the determinism law).

The `vulndog db` store-management surface (`build` / `info` / `verify`) is
specified in [docs/VULNERABILITY-DB.md](docs/VULNERABILITY-DB.md); its
milestone status (M3.1) lives in [PLAN.md](PLAN.md). No prebuilt store ships
in the tree yet — the distribution decision (GAP-1) is open.

## Extend the docs

Docs live in [`docs/`](docs/) and are indexed from the
[README.md](README.md) documentation table. When you change behavior, change
its doc in the same PR:

- [docs/CONFIGURATION.md](docs/CONFIGURATION.md) — CLI flags, config merge, scope
- [docs/RUNS-AND-LOGS.md](docs/RUNS-AND-LOGS.md) — run folders, log formats, redaction limits
- [docs/MCP.md](docs/MCP.md) — the MCP server for AI agents
- [docs/VULNERABILITY-DB.md](docs/VULNERABILITY-DB.md) — the KB and its extension paths
- [docs/AI-INTEGRATION.md](docs/AI-INTEGRATION.md) — Ollama/custom provider, outage behavior

Write limits honestly: what the tool cannot see (HTTPS bodies), what redaction
does not cover, what the rails do not defend. Never describe a candidate as a
finding, and never document a feature that does not ship.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/), English:

```text
feat(proxy): add per-request denial reason to the tap event
fix(redaction): drop events that fail scrubbing instead of persisting raw
docs(vulndb): document the custom-recipe validator rules
ci: add the release dry-run path
```

Work on a branch (`feat/…`, `fix/…`, `docs/…`), keep commits small and ordered,
and open a PR. CI must be green before merge. Do not commit run artifacts or
stores (`runs/`, `*.sqlite` are gitignored) — they contain sensitive traffic.

## Releases

[.github/workflows/release.yml](.github/workflows/release.yml) builds the
sdist + wheel (`python -m build`) on `v*` tags and on a manual
`workflow_dispatch` dry run (artifacts only, no release published). You can
reproduce the build locally: `python -m build` (the `build` package comes with
the dev extra). The full-store release asset upload is **disabled** pending
the owner's GAP-1 decision — see the marked step in the workflow.

Security issues: see [SECURITY.md](SECURITY.md) — report privately, not as a
public issue.