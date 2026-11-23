"""`vulndog db` command surface (M3.1) — parser, dispatch, build wrap.

One decision in one place: the engine's build CLI (engine/build.py
main) owns the build flag semantics and exit codes; this module only
TRANSLATES the product flags into that arg surface and surfaces the
result. The EmbedBlocked law (build.py:274-290) is never hidden: an
unreachable embedder exits nonzero with the engine's explicit message
and no store swap.

Exit codes: 0 ok; 1 store/manifest error or verify FAIL; 2 usage;
build passthrough: 2 input / 3 aborted / 4 embed-blocked / 5 store
(the engine's own build exit law, surfaced verbatim).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from vulndog import config
from vulndog.db import integrity
from vulndog.engine import build as bd
from vulndog.engine import store as st

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

_BUILD_HELP = (
    "Build the vulnerability store from the 4 raw archives "
    "(cvelistV5-main.zip, exploitdb-main.zip, cwec_latest.xml.zip, "
    "Top10-master.zip). Requires a working loopback Ollama embedder "
    "(docs/AI-INTEGRATION.md); without one the build refuses with a "
    "clear nonzero exit (EmbedBlocked law) — never a partial store."
)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulndog db",
        description="Vulnerability-store management: build, inspect, "
                    "verify. Wraps the engine's proven build machinery "
                    "(docs/VULNERABILITY-DB.md).")
    p.add_argument("--project", default=".",
                   help="project root for store resolution "
                        "(default: current directory)")
    p.add_argument("--config", default=None, help="config JSON path")
    p.add_argument("--task", default=None, help="per-run task entry key")
    p.add_argument("--release-asset-dry-run", nargs="?", const=True,
                   default=False, metavar="STORE",
                   help="list the release artifact + sha256 + the "
                        "<2 GiB asset gate result (no upload); optional "
                        "STORE path, otherwise the resolved store")
    sub = p.add_subparsers(dest="db_command")

    pb = sub.add_parser("build", help=_BUILD_HELP)
    pb.add_argument("--raw-dir", required=True,
                    help="directory holding the 4 raw archives")
    pb.add_argument("--output", default=None,
                    help="destination store DIRECTORY (default: the "
                         "resolved store directory; the store file is "
                         "vulnkb.sqlite + manifest.json beside it)")
    pb.add_argument("--stage", choices=("slice", "full"), default="slice",
                    help="recipe stage (default: slice — the seed-tier "
                         "recipe; full = the whole corpus)")
    pb.add_argument("--recipe", default=None,
                    help="explicit recipe JSON path (overrides the "
                         "stage default)")
    pb.add_argument("--dry-run", action="store_true",
                    help="measured counts only; no embedding, no store")
    pb.add_argument("--limit", type=int, default=None,
                    help="stop after N records (smoke runs)")
    pb.add_argument("--embed-max-retries", type=int, default=None,
                    help="outer embed retry budget (engine default: 30)")
    pb.add_argument("--embed-retry-backoff", type=float, default=None,
                    help="seconds between outer embed retries "
                         "(engine default: 60)")

    pi = sub.add_parser("info", help="manifest / record breakdown of a "
                                     "built store")
    pi.add_argument("store", nargs="?", default=None,
                    help="vulnkb.sqlite path (default: resolved store)")
    pi.add_argument("--store", dest="store_opt", default=None,
                    help="vulnkb.sqlite path (alias for the positional "
                         "store; consistent with run/mcp --store)")
    pi.add_argument("--json", action="store_true",
                    help="machine-readable output")

    pv = sub.add_parser("verify", help="manifest sha256 + counts vs the "
                                       "store (tamper gate)")
    pv.add_argument("store", nargs="?", default=None,
                    help="vulnkb.sqlite path (default: resolved store)")
    pv.add_argument("--store", dest="store_opt", default=None,
                    help="vulnkb.sqlite path (alias for the positional "
                         "store; consistent with run/mcp --store)")
    return p


def _resolve_cfg(args, config_loader) -> dict:
    """The product config merge (same door as run/status); honest
    degradation to builtins when the engine half is absent."""
    try:
        return config.load_config(path=args.config, task_id=args.task,
                                  overrides={}, loader=config_loader)
    except config.EngineUnavailableError:
        print("WARNING: vulndog.engine unavailable — config file "
              "ignored; using built-in defaults.", file=sys.stderr)
        return config.builtin_defaults()


def _explicit_or_resolved(args, cfg, project_root) -> tuple[str, str]:
    """The explicit store argument always wins; otherwise the tiered
    resolution (config -> project data/vulnkb -> engine default). UX-3:
    the positional store and the --store alias are the same explicit
    surface (positional wins if both are given; --store matches run/mcp)."""
    explicit = getattr(args, "store", None) or getattr(args, "store_opt", None)
    dry_run = getattr(args, "release_asset_dry_run", False)
    if isinstance(dry_run, str):
        explicit = dry_run
    if explicit:
        return explicit, "explicit"
    return integrity.resolve_store_path(cfg, project_root)


def _missing_store_help(path: str) -> None:
    print(f"error: no vulnerability store found at {path} — build one "
          "with: vulndog db build --raw-dir <dir-with-4-archives> "
          f"--output {os.path.dirname(path) or '.'} "
          "(requires a working Ollama embedder; see "
          "docs/VULNERABILITY-DB.md and docs/AI-INTEGRATION.md), or "
          "pass an existing store path / set db.store_path.",
          file=sys.stderr)


def _cmd_build(args, cfg, project_root) -> int:
    """Translate product flags into the engine build CLI arg surface
    and run it. The engine owns build semantics + exit codes; on
    success the db layer stamps the store-file sha256 into the
    manifest (the tamper gate verify checks)."""
    if args.output:
        store_dir = args.output
    else:
        resolved, source = integrity.resolve_store_path(cfg, project_root)
        if source == "default-missing":
            store_dir = os.path.join(str(project_root), "data", "vulnkb")
        else:
            store_dir = os.path.dirname(resolved)
    argv = ["--stage", args.stage, "--raw-dir", args.raw_dir,
            "--store-dir", store_dir]
    if args.recipe:
        argv += ["--recipe", args.recipe]
    if args.dry_run:
        argv.append("--dry-run")
    if args.limit is not None:
        argv += ["--limit", str(args.limit)]
    if args.embed_max_retries is not None:
        argv += ["--embed-max-retries", str(args.embed_max_retries)]
    if args.embed_retry_backoff is not None:
        argv += ["--embed-retry-backoff", str(args.embed_retry_backoff)]
    code = bd.main(argv)
    if code == bd.EXIT_OK and not args.dry_run:
        try:
            integrity.stamp_store_digest(store_dir)
        except (OSError, integrity.DbError) as exc:
            print(f"error: store built but the manifest digest stamp "
                  f"failed: {exc}", file=sys.stderr)
            return bd.EXIT_STORE
    return code


def _cmd_info(args, cfg, project_root) -> int:
    path, source = _explicit_or_resolved(args, cfg, project_root)
    if source == "default-missing":
        _missing_store_help(path)
        return EXIT_ERROR
    try:
        info = integrity.store_info(path)
    except (st.StoreError, integrity.DbError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=1))
        return EXIT_OK
    print(f"store:          {info['store_path']}")
    print(f"corpus_version: {info['corpus_version']}")
    print(f"stage:          {info['stage']}")
    print(f"recipe:         {info['recipe_id']} v{info['recipe_version']}")
    print(f"created_at:     {info['created_at']}")
    counts = info["counts"]
    print(f"records:        {counts.get('records_total')} "
          f"(store rows: {info['db_counts']['records_total']})")
    for kind, n in sorted(info["db_counts"]["records_by_kind"].items()):
        print(f"  {kind}: {n}")
    print(f"chunks:         {counts.get('chunks_total')} "
          f"(store rows: {info['db_counts']['chunks_total']})")
    print(f"store sha256:   {info['store_sha256'] or '(not stamped)'}")
    print("inputs:")
    for name, fp in sorted(info["inputs"].items()):
        print(f"  {name}: {fp['sha256']} ({fp['size_bytes']} bytes)")
    return EXIT_OK


def _cmd_verify(args, cfg, project_root) -> int:
    path, source = _explicit_or_resolved(args, cfg, project_root)
    if source == "default-missing":
        _missing_store_help(path)
        return EXIT_ERROR
    result = integrity.verify_store(path)
    for check in result["checks"]:
        state = "ok" if check["ok"] else "FAIL"
        line = f"  [{state}] {check['name']}"
        if check["detail"] and not check["ok"]:
            line += f": {check['detail']}"
        print(line)
    if result["ok"]:
        print(f"PASS: {path} matches its manifest "
              f"(corpus_version {result.get('corpus_version')})")
        return EXIT_OK
    print(f"FAIL: {path} does NOT match its manifest — do not match "
          "against this store; rebuild it (vulndog db build) or "
          "restore the published artifact.", file=sys.stderr)
    return EXIT_ERROR


def _cmd_release_dry_run(args, cfg, project_root) -> int:
    path, source = _explicit_or_resolved(args, cfg, project_root)
    if source == "default-missing":
        _missing_store_help(path)
        return EXIT_ERROR
    try:
        report = integrity.release_asset_report(path)
    except (integrity.DbError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    gate = "PASS" if report["gate_ok"] else "FAIL"
    print("release-asset dry-run (no upload):")
    print(f"  artifact: {report['artifact']}")
    print(f"  sha256:   {report['sha256']}")
    print(f"  size:     {report['size_bytes']} bytes "
          f"({report['size_gib']} GiB)")
    print(f"  gate:     {gate} — size < 2 GiB release-asset cap "
          f"({report['gate_max_bytes']} bytes)")
    return EXIT_OK if report["gate_ok"] else EXIT_ERROR


def main(argv: list[str] | None = None, *, config_loader=None,
         project_root=None) -> int:
    """Entry for the `vulndog db` slot (cli.py delegates here, the same
    pattern as the mcp slot). project_root is the test seam; production
    resolves it from --project."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    root = (Path(project_root) if project_root is not None
            else Path(args.project).resolve())
    try:
        cfg = _resolve_cfg(args, config_loader)
    except ValueError as exc:
        # product-config shape law (same as run/status): fail fast with
        # a usage exit, never a raw traceback
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.release_asset_dry_run is not False:
        return _cmd_release_dry_run(args, cfg, root)
    if args.db_command is None:
        parser.error("a subcommand is required: build, info, verify "
                     "(or --release-asset-dry-run)")
    if args.db_command == "build":
        return _cmd_build(args, cfg, root)
    if args.db_command == "info":
        return _cmd_info(args, cfg, root)
    return _cmd_verify(args, cfg, root)