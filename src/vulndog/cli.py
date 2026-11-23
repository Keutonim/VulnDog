"""VulnDog CLI — Phase-1 entry: python -m vulndog <subcommand>.

Subcommands:
  run      create a timestamped run folder, listen as an observing proxy,
           and on clean stop hand events.jsonl to the engine analyzer so the
           run folder ends up with the flagged-request log (highlights.*).
  status   show the latest run (metadata, pid liveness, counters).
  version  print the package version.
  mcp      run the MCP server (raw JSON-RPC 2.0 over stdio, M2.3);
           flags are owned by vulndog.mcp.server.main and pass through.
  db       vulnerability-store management (M3.1): build / info / verify
           + release-asset dry-run; flags are owned by vulndog.db.main
           and pass through (the engine build exit law is surfaced).

Exit codes: 0 ok; 1 runtime error; 2 usage error;
3 engine unavailable (capture preserved, analysis NOT performed — never a
fake "no vulnerabilities" claim); 4 analysis failed OR not performed
(facade status "skipped"/"disabled": embedder outage / KB unavailable —
zero highlights from an outage is never reported as success).

Injection seams (tests run without the engine half): main(argv, analyzer=,
config_loader=). Defaults resolve lazily to vulndog.engine.api.analyze_run
and vulndog.engine.run.load_config.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

from vulndog import config, runs
from vulndog.aihook.provider import ai_banner_lines, provider_meta
from vulndog.proxy import ProxyServer

_FALLBACK_VERSION = "0.1.0"

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_USAGE = 2
EXIT_ENGINE_ABSENT = 3
EXIT_ANALYSIS_FAILED = 4

#: UX-2: an engine config's floor_note may carry internal calibration
#: provenance meaningless to a product user. The run-state snapshot
#: replaces it with this product-appropriate string (defense in depth --
#: the shipped data file is anonymized too). MCP run_status reads
#: watchdog-run.json, so it inherits the sanitized value too.
_PRODUCT_FLOOR_NOTE = "0.49 = full-store calibrated default"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_safe(value):
    """Recursively coerce a config snapshot to JSON-serializable data.

    The effective config can carry non-JSON values through the documented
    injection seams (e.g. config["embedder"], an object). watchdog-run.json
    is a JSON surface: a raw object there crashed the run mid-capture
    (TypeError out of write_meta). Non-JSON leaves become their repr —
    visible in the state file, never a crash, never a silent drop.
    """
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return repr(value)


def _package_version() -> str:
    try:
        import vulndog

        return str(getattr(vulndog, "__version__", _FALLBACK_VERSION))
    except ImportError:
        return _FALLBACK_VERSION


def _resolve_analyzer(analyzer):
    """Injected analyzer wins; otherwise lazy-import the engine API."""
    if analyzer is not None:
        return analyzer
    try:
        from vulndog.engine.api import analyze_run

        return analyze_run
    except ImportError:
        return None


def _warn_config_errors(cfg: dict) -> None:
    """P2-05: surface the config layer's degradation notes at startup.

    The never-crash law keeps the run on builtins when a config file is
    missing/corrupt; the operator must SEE why (a discovered-but-corrupt
    file is never silently ignored). One stable WARNING line per note on
    stderr; the run proceeds unchanged. Empty/absent notes stay silent.
    """
    for note in cfg.get("_config_errors") or []:
        print(f"WARNING: config: {note} (builtin defaults in force)",
              file=sys.stderr)


def _resolve_config(args, overrides: dict, config_loader) -> dict:
    """Engine merge when available; honest degradation to builtins if not."""
    try:
        cfg = config.load_config(path=args.config, task_id=args.task,
                                 overrides=overrides, loader=config_loader)
    except config.EngineUnavailableError:
        print("WARNING: vulndog.engine unavailable — config file ignored; "
              "using built-in capture defaults.", file=sys.stderr)
        cfg = config.builtin_defaults()
        if overrides:
            cfg = config._deep_merge(cfg, overrides)
        return cfg
    _warn_config_errors(cfg)
    return cfg


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulndog",
        description="VulnDog — observing forward proxy that highlights "
                    "potentially vulnerable requests against an offline "
                    "knowledge base (advisory candidates, never findings).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="capture traffic through the proxy, "
                                       "then analyze the run on clean stop")
    p_run.add_argument("--project", default=".",
                       help="project root; run folders land under its runs.dir "
                            "(default: current directory)")
    p_run.add_argument("--config", default=None, help="config JSON path")
    p_run.add_argument("--task", default=None, help="per-run task entry key")
    p_run.add_argument("--tag", default=None,
                       help="custom run tag [A-Za-z0-9._-]{1,64} for parallel "
                            "instances (no trailing dot/dash)")
    p_run.add_argument("--host", default=None, help="proxy listen host (default 127.0.0.1)")
    p_run.add_argument("--port", type=int, default=None, help="proxy listen port (default 8080)")
    p_run.add_argument("--allow-remote-bind", action="store_true",
                       help="explicitly allow a non-loopback listen address")
    p_run.add_argument("--allow-private", action="store_true",
                       help="explicitly allow forwarding to private targets "
                            "(loopback, RFC1918, link-local/cloud metadata, "
                            "internal names) — default-DENIED by the SSRF rail")
    p_run.add_argument("--client-token", default=None,
                       help="client credential required with "
                            "--allow-remote-bind: requests must carry "
                            "Proxy-Authorization: Bearer <token>")
    p_run.add_argument("--client-allow", default=None,
                       help="client CIDR allowed with --allow-remote-bind "
                            "(alternative to --client-token)")
    p_run.add_argument("--store", default=None, help="vulnkb.sqlite path (overrides db.store_path)")
    p_run.add_argument("--duration", type=float, default=None,
                       help="auto-stop after N seconds (bounded capture)")

    p_status = sub.add_parser("status", help="show the latest run")
    p_status.add_argument("--project", default=".", help="project root")
    p_status.add_argument("--config", default=None, help="config JSON path")
    p_status.add_argument("--task", default=None, help="per-run task entry key")
    p_status.add_argument("--json", action="store_true", help="machine-readable output")

    sub.add_parser("version", help="print the VulnDog version")
    # M2.5: the mcp flag surface belongs to vulndog.mcp.server.main (one
    # decision in one place). add_help=False lets -h/--help pass through
    # to that parser, so `vulndog mcp --help` shows the real server flags.
    sub.add_parser("mcp", add_help=False,
                   help="MCP server over stdio (tools: vuln_query, "
                        "highlights, run_status); see `vulndog mcp --help`")
    # M3.1: the db flag surface belongs to vulndog.db.main (one decision
    # in one place, the mcp pattern). add_help=False lets -h/--help pass
    # through, so `vulndog db --help` shows the real db flags.
    sub.add_parser("db", add_help=False,
                   help="vulnerability store management: build / info / "
                        "verify + release-asset dry-run; see "
                        "`vulndog db --help`")
    return parser


def main(argv: list[str] | None = None, *, analyzer=None, config_loader=None) -> int:
    parser = _build_parser()
    args, extra = parser.parse_known_args(argv)
    if extra and args.command not in ("mcp", "db"):
        parser.error(f"unrecognized arguments: {' '.join(extra)}")

    if args.command == "version":
        print(f"vulndog {_package_version()}")
        return EXIT_OK

    if args.command == "mcp":
        # M2.5: delegate to the shipped M2.3 server — the remaining argv
        # passes through untouched (its parser owns the mcp flag surface).
        from vulndog.mcp.server import main as mcp_main

        return mcp_main(extra, config_loader=config_loader)

    if args.command == "db":
        # M3.1: delegate to the db package — the remaining argv passes
        # through untouched (its parser owns the db flag surface, the
        # same pattern as mcp).
        from vulndog.db import main as db_main

        return db_main(extra, config_loader=config_loader)

    try:
        if args.command == "status":
            return _cmd_status(args, config_loader)
        return _cmd_run(args, analyzer, config_loader)
    except ValueError as exc:
        # Product-config shape errors (config._validate_product_shape)
        # fail fast with a usage exit BEFORE any capture. Tag/bind
        # ValueErrors are handled locally with their own messages.
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE


# ---------------------------------------------------------------- status


def _status_info(run) -> dict:
    """The status payload for one run (meta read is fail-soft: an
    unreadable watchdog-run.json is reported, never raised)."""
    meta: dict = {}
    if run.meta_path.exists():
        try:
            meta = json.loads(run.meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {"_meta_error": "watchdog-run.json unreadable"}
    pid = meta.get("pid")
    alive = runs.pid_alive(int(pid)) if isinstance(pid, int) else False
    return {
        "hunt_id": run.hunt_id,
        "run_dir": str(run.path),
        "pid": pid,
        "alive": alive,
        "mode": meta.get("mode"),
        "counters": meta.get("counters", {}),
        "stop_requested": run.stop_requested(),
    }


def _cmd_status(args, config_loader) -> int:
    cfg = _resolve_config(args, {}, config_loader)
    project_root = Path(args.project).resolve()
    runs_root = project_root / cfg["runs"]["dir"]
    run = runs.latest_run(project_root, cfg["runs"]["dir"])
    if run is None:
        print(f"no runs found under {runs_root}")
        return EXIT_OK

    info = _status_info(run)
    if args.json:
        print(json.dumps(info, ensure_ascii=False))
        return EXIT_OK
    _print_status_human(info)
    return EXIT_OK


def _print_status_human(info: dict) -> None:
    pid = info["pid"]
    state = "alive" if info["alive"] else "not running"
    print(f"run:    {info['hunt_id']}")
    print(f"dir:    {info['run_dir']}")
    print(f"pid:    {pid if pid is not None else '-'} ({state})")
    print(f"mode:   {info['mode'] or '-'}")
    print(f"events: {info['counters'].get('events', '-')}")
    print(f"stop requested: {'yes' if info['stop_requested'] else 'no'}")


# ------------------------------------------------------------------- run


def _cli_overrides(args) -> dict:
    """CLI layer (wins last): only the flags the user actually passed."""
    overrides: dict = {}
    if args.host is not None or args.port is not None:
        overrides["proxy"] = {}
        if args.host is not None:
            overrides["proxy"]["host"] = args.host
        if args.port is not None:
            overrides["proxy"]["port"] = args.port
    if args.store is not None:
        overrides["db"] = {"store_path": args.store}
    return overrides


def _meta_payload(run, cfg, mode, started_at, listen, events,
                  stopped_at=None, tap_counters=None) -> dict:
    """watchdog-run.json payload — ONE shape for the capture and stopped
    writes (the stop-time rewrite preserves started_at). M4: the tap's
    drop/refusal counters ride alongside the event count (additive)."""
    payload = {
        "pid": os.getpid(),
        "hunt_id": run.hunt_id,
        "mode": mode,
        "started_at": started_at,
    }
    if stopped_at is not None:
        payload["stopped_at"] = stopped_at
    counters = {"events": events}
    if tap_counters:
        counters.update(tap_counters)
    # UX-2: _json_safe returns a fresh copy, so sanitizing the snapshot
    # never mutates the caller's resolved cfg. The engine's internal
    # floor_note provenance (internal calibration artifact paths) is
    # replaced with a product-appropriate string on this user-facing surface.
    config_snap = _json_safe(cfg)
    if "floor_note" in config_snap:
        config_snap["floor_note"] = _PRODUCT_FLOOR_NOTE
    payload.update({
        "listen": listen,
        "counters": counters,
        "config": config_snap,
        # M2.4 (ADR-6): the provider choice is part of the run state — a
        # non-loopback ai.base_url carries its disclosure here, never silent.
        "ai": provider_meta(cfg["ai"]),
        "paths": {"run_dir": str(run.path), "events": str(run.events_path)},
    })
    return payload


def _tap_counters(server) -> dict:
    """M4 visibility: every drop/refusal class the tap counts.
    R2-E: flush_dropped (events lost to a writer failure) joins them."""
    return {
        "redaction_dropped": server.redaction_dropped,
        "queue_drops": server.queue.drop_count,
        "spool_dropped": server.spool_dropped,
        "connections_refused": server.connections_refused,
        "flush_dropped": server.flush_dropped,
    }


def _print_drop_summary(counters: dict) -> None:
    """R2-E: non-zero drop/refusal counters are an operator signal —
    visible on the console at run end, not only in watchdog-run.json.
    All-zero stays silent (no noise on a clean run)."""
    dropped = {k: v for k, v in counters.items() if v}
    if dropped:
        print("WARNING: tap drop/refusal counters: "
              + ", ".join(f"{k}={v}" for k, v in dropped.items()),
              file=sys.stderr)


def _bind_proxy(cfg, run, args, stop_event, writer):
    """(server, None) on success; (None, exit_code) on a handled bind
    failure — the writer is closed on every error path."""
    host = cfg["proxy"]["host"]
    port = cfg["proxy"]["port"]
    try:
        return ProxyServer(host, port, writer=writer, hunt_id=run.hunt_id,
                           scope=cfg["scope"],
                           allow_remote_bind=args.allow_remote_bind,
                           allow_private=args.allow_private,
                           client_token=args.client_token,
                           client_allow=args.client_allow,
                           stop_event=stop_event, stop_file=run.stop_path), None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        writer.close()
        return None, EXIT_USAGE
    except OSError as exc:
        print(f"error: cannot bind {host}:{port} — {exc}", file=sys.stderr)
        writer.close()
        return None, EXIT_RUNTIME


def _capture_loop(server, writer, args, stop_event) -> None:
    """Start serving; block until clean stop; always close the surfaces.
    SIGINT -> stop_event (only registrable from the main thread)."""
    try:
        signal.signal(signal.SIGINT, lambda *_: stop_event.set())
    except ValueError:
        pass
    timer = None
    if args.duration is not None:
        timer = threading.Timer(args.duration, stop_event.set)
        timer.daemon = True
        timer.start()

    server.start()
    print("listening — Ctrl-C or a stop-request file ends the run", flush=True)
    try:
        server.wait()
    finally:
        if timer is not None:
            timer.cancel()
        server.stop()
        writer.close()


def _cmd_run(args, analyzer, config_loader) -> int:
    cfg = _resolve_config(args, _cli_overrides(args), config_loader)
    project_root = Path(args.project).resolve()

    try:
        run = runs.create_run(project_root, runs_dir=cfg["runs"]["dir"], tag=args.tag)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    host = cfg["proxy"]["host"]
    port = cfg["proxy"]["port"]
    if not isinstance(port, int) or not (0 <= port <= 65535):
        print(f"error: invalid proxy.port {port!r}", file=sys.stderr)
        return EXIT_USAGE

    stop_event = threading.Event()
    writer = runs.EventWriter(run.events_path)
    server, bind_error = _bind_proxy(cfg, run, args, stop_event, writer)
    if server is None:
        return bind_error

    bound_host, bound_port = server.address
    started_at = _utc_now()
    listen = {"host": bound_host, "port": bound_port}
    run.write_pid(os.getpid())
    run.write_meta(_meta_payload(run, cfg, "capture", started_at, listen, 0,
                                 tap_counters=_tap_counters(server)))
    _print_banner(run, bound_host, bound_port, cfg["scope"],
                  allow_private=args.allow_private, ai_cfg=cfg["ai"])

    _capture_loop(server, writer, args, stop_event)

    run.write_meta(_meta_payload(run, cfg, "stopped", started_at, listen,
                                 writer.count, stopped_at=_utc_now(),
                                 tap_counters=_tap_counters(server)))
    # state.json — the resume-offset file of the documented per-run layout
    # (docs/RUNS-AND-LOGS.md "Per-run layout"). The engine-canonical shape
    # is a flat {"offset": <int>} dict (engine run.py:715 reads
    # `spool_state.get("offset", 0)`), so the proxy tap's appended-event
    # count is written in that shape. MERGE FIX (tech-lead): the file was
    # in the pinned file-ownership list and in the documented layout, but
    # nothing ever wrote it.
    run.write_state({"offset": writer.count})
    print(f"run stopped: {writer.count} event(s) captured in {run.events_path}")
    _print_drop_summary(_tap_counters(server))
    return _analyze_and_report(run, cfg, writer.count, analyzer, project_root)


def _resolve_store_path(cfg, project_root) -> str | None:
    """F-4 + UX-3: db.store_path null RESOLVES through the SAME tiered
    door the db commands use (integrity.resolve_store_path): configured
    path -> the project data/vulnkb store root -> the engine default.
    With nothing on disk this returns the user-facing project path
    (source 'default-missing'), never the phantom site-packages engine
    default — so the missing-store error names a location the user can
    act on. None must never reach the facade when the engine is present
    (the old 'got None' exit-4 defect made EVERY default run fail)."""
    try:
        from vulndog.db import integrity
    except ImportError:
        # Engine half absent: only an INJECTED analyzer can reach this
        # path (the real facade resolves to exit 3 before analysis), so
        # the test seam keeps its unconfigured value. The real facade
        # never sees None — it cannot exist without the engine.
        return None
    path, _source = integrity.resolve_store_path(cfg, project_root)
    return path


def _analysis_config(cfg: dict) -> dict:
    """M2.4 (ADR-6): hand the facade the embedder built from ``ai.*``.

    The engine's own injection key (``config["embedder"]``, engine/api.py)
    is the door — no engine module is edited. An embedder already present
    in the config is the documented OFFLINE seam (P1 stub tests, the M1.4
    drill) and always wins. The import is lazy: this runs only after the
    analyzer resolved, i.e. the engine half is present. The caller's cfg
    is never mutated (the run-meta snapshot stays the config as resolved).
    """
    if cfg.get("embedder") is not None:
        return cfg
    from vulndog.aihook.embedder import build_embedder

    return {**cfg, "embedder": build_embedder(cfg["ai"])}


def _analyze_and_report(run, cfg, captured: int, analyzer, project_root) -> int:
    """Hand the spool to the engine; report honestly (exit-code law:
    3 engine absent, 4 analysis failed/not performed, 0 ok)."""
    analyze = _resolve_analyzer(analyzer)
    if analyze is None:
        print(
            "ERROR: vulndog.engine unavailable — analysis NOT performed. "
            f"{captured} event(s) are preserved in {run.events_path}, but no "
            "highlights were produced. An unanalyzed run tells you nothing "
            "about whether vulnerabilities exist. Install the engine half "
            "(vulndog.engine) to analyze this run.",
            file=sys.stderr,
        )
        return EXIT_ENGINE_ABSENT

    store_path = _resolve_store_path(cfg, project_root)
    try:
        result = analyze(events_path=run.events_path, run_dir=run.path,
                         store_path=store_path, config=_analysis_config(cfg))
    except Exception as exc:
        print(f"error: analysis failed: {exc}", file=sys.stderr)
        return EXIT_ANALYSIS_FAILED

    status = result.get("status", "ok")
    _print_analysis_summary(run, result, captured)
    if status != "ok":
        if not os.path.exists(store_path):
            # F-4 + UX-3: explicit + actionable — name the ACTUAL resolved
            # path (the user-facing project store root, never the phantom
            # site-packages default) and the concrete way out. Never the
            # boundary leak "store_path must be a non-empty path, got None".
            print(
                f"ERROR: no vulnerability store found at {store_path} — "
                "build one with `vulndog db build --raw-dir "
                "<dir-with-4-archives>` (see docs/VULNERABILITY-DB.md) or "
                "pass --store <path to vulnkb.sqlite>. The captured events "
                f"are preserved in {run.events_path}.",
                file=sys.stderr,
            )
        _report_analysis_outage(run, result, status)
        return EXIT_ANALYSIS_FAILED
    return EXIT_OK


def _print_analysis_summary(run, result, captured: int) -> None:
    events_read = result.get("events_read", captured)
    highlights = result.get("highlights", 0)
    print(f"analysis: events_read={events_read} highlights={highlights} "
          f"(advisory candidates only — never findings)")
    if result.get("errors"):
        print(f"analysis errors: {result['errors']}", file=sys.stderr)
    print(f"flagged-request log: {run.path / 'highlights.md'}")


def _report_analysis_outage(run, result, status: str) -> None:
    # H2/F2: "skipped" (embedder down/hung) or "disabled" (KB store
    # unavailable) means the match path never ran — zero highlights
    # here is NOT a clean bill of health. Exit 0 would report an
    # outage as success (the same class as the engine-absent law).
    print(
        f"ERROR: analysis {status} (mode={result.get('mode')}) — "
        "highlights were NOT produced from a working match path; "
        "zero highlights here is NOT a clean bill of health. The captured "
        f"events are preserved in {run.events_path}; the run summary "
        f"in {run.path / 'highlights.md'} carries the failure counters.",
        file=sys.stderr,
    )


def _scope_banner_line(scope: dict, allow_private: bool) -> str:
    in_patterns = scope.get("in") or []
    out_patterns = scope.get("out") or []
    if not in_patterns and not out_patterns:
        rail = ("private targets ALLOWED (--allow-private)" if allow_private
                else "private/metadata targets DENIED (SSRF rail; "
                     "--allow-private to override)")
        return ("  WARNING: no scope configured — all PUBLIC hosts are "
                f"forwarded (allow-all passive-monitor default); {rail}.")
    return f"  scope:   in={in_patterns} out={out_patterns} (out wins)"


def _print_banner(run, host: str, port: int, scope: dict,
                  allow_private: bool = False, ai_cfg: dict | None = None) -> None:
    print(f"VulnDog run {run.hunt_id}")
    print(f"  run dir: {run.path}")
    print(f"  proxy:   http://{host}:{port}")
    print(_scope_banner_line(scope, allow_private))
    if ai_cfg is not None:
        # M2.4: the embedding provider (and a non-loopback address warning)
        # is announced at startup, alongside the scope/rail disclosure.
        for line in ai_banner_lines(ai_cfg):
            print(line)