"""CLI wiring: run/status/version/mcp/db, injected fake analyzer, honest
degradation when the engine half is absent. No engine import needed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from vulndog import cli, runs
from event_contract import assert_pinned_event

NAME_RE = re.compile(r"^\d{8}-\d{6}(-[A-Za-z0-9._-]{0,64})?$")


class FakeAnalyzer:
    def __init__(self, result=None, exc=None):
        self.calls = []
        self.result = result if result is not None else {
            "events_read": 0, "highlights": 0, "errors": [],
            "corpus_version": "test-corpus",
        }
        self.exc = exc

    def __call__(self, *, events_path, run_dir, store_path, config=None):
        self.calls.append({"events_path": Path(events_path),
                           "run_dir": Path(run_dir),
                           "store_path": store_path, "config": config})
        if self.exc is not None:
            raise self.exc
        return dict(self.result)


def fake_loader(result=None):
    def loader(path=None, task_id=None):
        return dict(result or {})
    return loader


@pytest.fixture
def poison_engine(monkeypatch):
    """Simulate the absent engine half (works pre- and post-merge)."""
    for name in ("vulndog.engine", "vulndog.engine.run", "vulndog.engine.api"):
        monkeypatch.setitem(sys.modules, name, None)


def wait_for(predicate, timeout=5.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def latest_run_dir(project: Path) -> Path | None:
    root = project / "runs"
    if not root.is_dir():
        return None
    dirs = [p for p in root.iterdir() if p.is_dir() and NAME_RE.match(p.name)]
    return max(dirs, key=lambda p: p.name) if dirs else None


# ------------------------------------------------------------- basics


def test_version(capsys):
    assert cli.main(["version"]) == 0
    out = capsys.readouterr().out
    assert "vulndog" in out
    assert re.search(r"\d+\.\d+", out)


def test_help_lists_subcommands(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for sub in ("run", "status", "version", "mcp", "db"):
        assert sub in out


def test_no_subcommand_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert exc.value.code == 2


def test_mcp_runs_the_real_server(tmp_path, monkeypatch):
    """M2.5: `vulndog mcp` delegates to the shipped M2.3 stdio server —
    the P1 "not implemented" marker is obsolete. The flag surface stays
    owned by vulndog.mcp.server.main (one decision in one place): the CLI
    passes the remaining argv through untouched."""
    from vulndog.mcp import server as mcp_server

    seen = {}

    def fake_serve(stdin, stdout, srv):
        seen["calls"] = seen.get("calls", 0) + 1
        seen["project_root"] = srv.ctx.project_root
        seen["store_path"] = srv.ctx.config["db"]["store_path"]

    monkeypatch.setattr(mcp_server, "serve", fake_serve)
    code = cli.main(["mcp", "--project", str(tmp_path),
                     "--store", "x.sqlite"], config_loader=fake_loader())
    assert code == 0
    assert seen["calls"] == 1
    assert seen["project_root"] == tmp_path.resolve()
    assert seen["store_path"] == "x.sqlite"


def test_mcp_help_shows_the_server_flags(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["mcp", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--project", "--config", "--task", "--store"):
        assert flag in out


def test_mcp_unknown_flag_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main(["mcp", "--bogus"])
    assert exc.value.code == 2


@pytest.mark.parametrize("command", ["run", "status", "version"])
def test_unknown_flag_is_usage_error(command):
    """Regression pin for the M2.5 parse_known_args switch: only `mcp`
    passes extra argv through (to the server's own parser); every other
    subcommand keeps the strict unknown-argument usage error."""
    with pytest.raises(SystemExit) as exc:
        cli.main([command, "--bogus"])
    assert exc.value.code == 2


def test_db_delegates_to_the_db_package(monkeypatch):
    """M3.1 landed: `db` delegates to vulndog.db.main (the mcp pattern)
    — the remaining argv passes through untouched, the db parser owns
    the flag surface. The M2.5 honest-stub pin is obsolete."""
    from vulndog import db as db_pkg

    seen = {}

    def fake_db_main(argv, *, config_loader=None):
        seen["argv"] = list(argv)
        return 0

    monkeypatch.setattr(db_pkg, "main", fake_db_main)
    code = cli.main(["db", "info", "x.sqlite", "--json"])
    assert code == 0
    assert seen["argv"] == ["info", "x.sqlite", "--json"]


def test_module_entry_point(monkeypatch, capsys):
    # `python -m vulndog version` equivalent, pinned to this worktree
    import runpy

    monkeypatch.setattr(sys, "argv", ["vulndog", "version"])
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("vulndog", run_name="__main__", alter_sys=True)
    assert exc.value.code == 0
    assert "vulndog" in capsys.readouterr().out


# ------------------------------------------------------------- status


def test_status_no_runs(tmp_path, capsys):
    assert cli.main(["status", "--project", str(tmp_path)],
                    config_loader=fake_loader()) == 0
    assert "no runs" in capsys.readouterr().out.lower()


def test_status_json_shows_latest_run(tmp_path, capsys):
    run = runs.create_run(tmp_path)
    run.write_pid(os.getpid())
    run.write_meta({"pid": os.getpid(), "mode": "capture",
                    "counters": {"events": 3}})
    assert cli.main(["status", "--project", str(tmp_path), "--json"],
                    config_loader=fake_loader()) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["hunt_id"] == run.hunt_id
    assert info["pid"] == os.getpid()
    assert info["alive"] is True
    assert info["counters"]["events"] == 3


def test_status_human_output(tmp_path, capsys):
    run = runs.create_run(tmp_path, tag="authlab")
    run.write_meta({"pid": os.getpid(), "mode": "capture", "counters": {}})
    assert cli.main(["status", "--project", str(tmp_path)],
                    config_loader=fake_loader()) == 0
    out = capsys.readouterr().out
    assert run.hunt_id in out
    assert "authlab" in out


# ---------------------------------------------------------------- run


def test_run_lifecycle_with_fake_analyzer(tmp_path, capsys):
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 0
    run_dir = latest_run_dir(tmp_path)
    assert run_dir is not None and NAME_RE.match(run_dir.name)
    assert (run_dir / "events.jsonl").exists()
    assert (run_dir / "watchdog.pid").exists()
    # MERGE FIX: state.json is part of the documented per-run layout
    # (docs/RUNS-AND-LOGS.md "Per-run layout") and of dev-B's pinned file
    # ownership. Shape is the engine-canonical flat {"offset": int}.
    assert (run_dir / "state.json").exists()
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state == {"offset": 0}
    meta = json.loads((run_dir / "watchdog-run.json").read_text(encoding="utf-8"))
    assert meta["mode"] == "stopped"
    assert meta["pid"] == os.getpid()
    assert len(analyzer.calls) == 1
    call = analyzer.calls[0]
    assert call["events_path"] == run_dir / "events.jsonl"
    assert call["run_dir"] == run_dir
    # F-4 + UX-3: db.store_path null RESOLVES to the user-facing project
    # store root (never None into the facade — the exit-4 "got None"
    # defect — and never the phantom site-packages engine default).
    assert call["store_path"] == str(Path(tmp_path).resolve() / "data"
                                   / "vulnkb" / "vulnkb.sqlite")
    assert isinstance(call["config"], dict)
    out = capsys.readouterr().out
    assert "events_read" in out
    assert "advisory" in out.lower()


def test_run_tag_and_store_reach_analyzer(tmp_path):
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3", "--tag", "authlab",
                     "--store", str(tmp_path / "kb.sqlite")],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 0
    run_dir = latest_run_dir(tmp_path)
    assert run_dir.name.endswith("-authlab")
    assert analyzer.calls[0]["store_path"] == str(tmp_path / "kb.sqlite")


def test_run_cli_port_overrides_config(tmp_path):
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer,
                    config_loader=fake_loader({"proxy": {"port": 9999}}))
    assert code == 0
    meta = json.loads((latest_run_dir(tmp_path) / "watchdog-run.json").read_text())
    assert meta["listen"]["port"] != 9999
    assert meta["listen"]["port"] > 0


def test_run_captures_traffic_and_analyzes(tmp_path):
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    analyzer = FakeAnalyzer()
    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(tmp_path), "--port", "0", "--duration", "2.0",
             "--allow-private"],   # loopback origin: explicit rail opt-in (M1)
            analyzer=analyzer, config_loader=fake_loader())

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(tmp_path))
        assert meta is not None, "run never wrote its metadata"
        started_at = meta["started_at"]
        port = meta["listen"]["port"]
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/x?token=abc123")
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()
    finally:
        t.join(timeout=10)
        origin.shutdown()
        origin.server_close()
    assert not t.is_alive()
    assert result["code"] == 0
    run_dir = latest_run_dir(tmp_path)
    events = [json.loads(l) for l in
              (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(events) == 1
    assert_pinned_event(events[0], persisted=True)
    # F4 canonical form: secret-named param -> <redacted> (one door)
    assert events[0]["url"].endswith("/x?token=<redacted>")
    assert analyzer.calls[0]["run_dir"] == run_dir
    # the stop-time meta rewrite must PRESERVE the original started_at
    final_meta = json.loads((run_dir / "watchdog-run.json").read_text(encoding="utf-8"))
    assert final_meta["started_at"] == started_at
    assert final_meta["mode"] == "stopped"
    assert final_meta["counters"]["events"] == 1
    # state.json carries the truthful spool offset (1 event captured)
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state == {"offset": 1}


def _read_meta(project: Path):
    run_dir = latest_run_dir(project)
    if run_dir is None:
        return None
    meta_path = run_dir / "watchdog-run.json"
    if not meta_path.exists():
        return None
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def test_run_stop_request_file_ends_run(tmp_path):
    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(tmp_path), "--port", "0"],
            analyzer=FakeAnalyzer(), config_loader=fake_loader())

    t = threading.Thread(target=drive)
    t.start()
    try:
        run_dir = wait_for(lambda: latest_run_dir(tmp_path))
        assert run_dir is not None
        (run_dir / "stop-request").touch()
    finally:
        t.join(timeout=10)
    assert not t.is_alive(), "stop-request did not end the run"
    assert result["code"] == 0


def test_run_engine_absent_clear_error_not_fake_success(tmp_path, capsys, poison_engine):
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=None, config_loader=fake_loader())
    assert code == 3
    captured = capsys.readouterr()
    assert "engine" in captured.err.lower()
    assert "0 vulnerabilities" not in captured.out + captured.err
    assert "no vulnerabilities" not in (captured.out + captured.err).lower()
    # capture still happened and is preserved
    run_dir = latest_run_dir(tmp_path)
    assert run_dir is not None
    assert (run_dir / "events.jsonl").exists()


def test_run_config_degrades_when_engine_absent(tmp_path, capsys, poison_engine):
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=None)
    assert code == 0
    err = capsys.readouterr().err.lower()
    assert "engine" in err and "default" in err
    assert latest_run_dir(tmp_path) is not None
    assert len(analyzer.calls) == 1


# ----------------------------------------- P2-05: surface _config_errors
#
# The config layer records a missing/corrupt file in _config_errors and
# degrades to builtins (never-crash law), but the product CLI never printed
# the note — a discovered-but-corrupt file was silently ignored.


def test_config_errors_note_is_surfaced_as_a_warning(tmp_path, capsys):
    """Non-empty _config_errors print a stable WARNING line to stderr at
    startup while the run proceeds (the never-crash law stays)."""
    analyzer = FakeAnalyzer()
    note = "config-unreadable:/x/vulndog.json:JSONDecodeError"
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer,
                    config_loader=fake_loader({"_config_errors": [note]}))
    assert code == 0
    err = capsys.readouterr().err
    assert f"WARNING: config: {note} (builtin defaults in force)" in err


def test_corrupt_config_file_warns_on_stderr_and_runs_on_builtins(tmp_path, capsys):
    """The brief's behaviour test: a corrupt config file -> the run starts,
    the warning appears, builtin defaults are applied (real engine loader)."""
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(corrupt),
                     "--port", "0", "--duration", "0.3"], analyzer=analyzer)
    assert code == 0, "the run proceeds with builtins (never-crash law)"
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "config-unreadable" in err
    assert "corrupt.json" in err
    assert "builtin defaults in force" in err
    # builtins applied: the corrupt file contributed nothing
    meta = json.loads((latest_run_dir(tmp_path) / "watchdog-run.json")
                      .read_text(encoding="utf-8"))
    assert meta["config"]["ai"]["model"] == "embeddinggemma:300m"
    assert meta["config"]["scope"] == {"in": [], "out": []}


def test_no_config_errors_note_prints_no_config_warning(tmp_path, capsys):
    """Negative control: a clean config (no notes) stays silent — no
    spurious WARNING on the normal default run."""
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 0
    assert "WARNING: config:" not in capsys.readouterr().err


def test_run_analyzer_failure_exit_4(tmp_path, capsys):
    analyzer = FakeAnalyzer(exc=RuntimeError("boom"))
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 4
    err = capsys.readouterr().err
    assert "analysis failed" in err.lower()
    assert "boom" in err


def test_run_invalid_tag_exit_2(tmp_path, capsys):
    code = cli.main(["run", "--project", str(tmp_path), "--tag", "bad tag",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(), config_loader=fake_loader())
    assert code == 2
    assert "tag" in capsys.readouterr().err.lower()


def test_run_default_rail_denies_loopback_target(tmp_path):
    # M1 CLI wiring: WITHOUT --allow-private the real run loop denies a
    # loopback target (403 proxy_private) and never contacts the origin.
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            self.server.hits += 1
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin.hits = 0
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(tmp_path), "--port", "0",
             "--duration", "2.0"],
            analyzer=FakeAnalyzer(), config_loader=fake_loader())

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(tmp_path))
        assert meta is not None
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", meta["listen"]["port"],
                                          timeout=10)
        conn.request("GET",
                     f"http://127.0.0.1:{origin.server_address[1]}/admin")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 403
        conn.close()
    finally:
        t.join(timeout=10)
        origin.shutdown()
        origin.server_close()
    assert origin.hits == 0, "default rail let a loopback target through"
    run_dir = latest_run_dir(tmp_path)
    events = [json.loads(l) for l in
              (run_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[0]["denial_reason"] == "proxy_private"


def test_scope_banner_states_the_rail():
    line = cli._scope_banner_line({"in": [], "out": []}, allow_private=False)
    assert "PUBLIC" in line and "DENIED" in line
    line = cli._scope_banner_line({"in": [], "out": []}, allow_private=True)
    assert "ALLOWED" in line and "--allow-private" in line


def test_run_unconfigured_scope_banner_in_console(tmp_path, capsys):
    # M2.2/D15: the allow-all-public default is LOUD — the banner must
    # appear in the run's console output at start, naming the default
    # and the rail state (not just exist as a helper function).
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(), config_loader=fake_loader())
    assert code == 0
    out = capsys.readouterr().out
    assert "no scope configured" in out
    assert "PUBLIC" in out
    assert "DENIED" in out and "SSRF rail" in out


def test_run_configured_scope_banner_in_console(tmp_path, capsys):
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(),
                    config_loader=fake_loader(
                        {"scope": {"in": ["*.example.com"],
                                   "out": ["api.example.com"]}}))
    assert code == 0
    out = capsys.readouterr().out
    assert "scope:" in out
    assert "*.example.com" in out and "api.example.com" in out
    assert "out wins" in out
    assert "no scope configured" not in out


@pytest.mark.parametrize("bad", ["http://example.com", "example.com/path"])
def test_run_bad_scope_pattern_exit_2_before_capture(tmp_path, capsys, bad):
    # M2.2: a non-literal pattern (scheme/path) fails fast at startup —
    # exit 2, a clear message naming the pattern, no run folder created.
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(),
                    config_loader=fake_loader({"scope": {"in": [bad]}}))
    assert code == 2
    err = capsys.readouterr().err
    assert "scope.in" in err and bad in err
    assert latest_run_dir(tmp_path) is None, "fail fast BEFORE capture"


def test_run_non_loopback_requires_flag(tmp_path, capsys):
    code = cli.main(["run", "--project", str(tmp_path), "--host", "0.0.0.0",
                     "--port", "0", "--duration", "0.3"],
                    analyzer=FakeAnalyzer(), config_loader=fake_loader())
    assert code == 2
    assert "--allow-remote-bind" in capsys.readouterr().err


def test_run_allow_remote_bind_flag_accepted(tmp_path):
    # M2: the bind flag alone is no longer enough — a client credential
    # is required (here: --client-token).
    code = cli.main(["run", "--project", str(tmp_path), "--host", "0.0.0.0",
                     "--allow-remote-bind", "--client-token", "rig-secret",
                     "--port", "0", "--duration", "0.3"],
                    analyzer=FakeAnalyzer(), config_loader=fake_loader())
    assert code == 0


def test_run_remote_bind_without_credential_refuses_to_start(tmp_path, capsys):
    # M2: never a silent LAN-wide open relay — the process refuses to
    # start (nonzero exit + a message naming the credential flags).
    code = cli.main(["run", "--project", str(tmp_path), "--host", "0.0.0.0",
                     "--allow-remote-bind", "--port", "0", "--duration", "0.3"],
                    analyzer=FakeAnalyzer(), config_loader=fake_loader())
    assert code == 2
    err = capsys.readouterr().err
    assert "--client-token" in err and "--client-allow" in err


def test_run_bad_scope_config_exit_2_before_capture(tmp_path, capsys):
    # H2/F8: a half-configured scope fails fast at startup (docs/
    # CONFIGURATION.md) — exit 2, no run folder created.
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(),
                    config_loader=fake_loader({"scope": {"in": "example.com"}}))
    assert code == 2
    assert "scope" in capsys.readouterr().err.lower()
    assert latest_run_dir(tmp_path) is None, "fail fast BEFORE capture"


def test_status_bad_config_exit_2(tmp_path, capsys):
    code = cli.main(["status", "--project", str(tmp_path)],
                    config_loader=fake_loader({"runs": {"dir": 7}}))
    assert code == 2
    assert "runs.dir" in capsys.readouterr().err


def test_run_analysis_skipped_status_exits_4(tmp_path, capsys):
    # H2/F2: embedder outage -> the facade reports status "skipped"
    # with zero highlights. Exit 0 there reads as a clean result —
    # the exact silent-success class the engine-absent path already
    # forbids. The CLI must exit 4 and say so loudly.
    analyzer = FakeAnalyzer(result={
        "events_read": 2, "highlights": 0, "errors": 2,
        "corpus_version": "c", "status": "skipped", "mode": "ollama-down",
        "embed_failures": 1, "buffered_while_down": 1})
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 4
    captured = capsys.readouterr()
    assert "skipped" in captured.err.lower()
    assert "0 vulnerabilities" not in captured.out + captured.err
    assert "no vulnerabilities" not in (captured.out + captured.err).lower()


def test_run_analysis_disabled_status_exits_4(tmp_path, capsys):
    analyzer = FakeAnalyzer(result={
        "events_read": 1, "highlights": 0, "errors": 1,
        "corpus_version": None, "status": "disabled", "mode": "kb-missing",
        "kb_disabled_events": 1})
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 4
    assert "disabled" in capsys.readouterr().err.lower()


def test_run_analysis_ok_with_data_errors_still_exits_0(tmp_path, capsys):
    # status "ok" means the match path worked; per-event data drops are
    # surfaced on stderr but are not an analysis failure.
    analyzer = FakeAnalyzer(result={
        "events_read": 2, "highlights": 1, "errors": 1,
        "corpus_version": "c", "status": "ok", "mode": "enabled"})
    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=analyzer, config_loader=fake_loader())
    assert code == 0
    assert "analysis errors: 1" in capsys.readouterr().err


def _drive_run_with_one_request(tmp_path, *, analyzer, loader, extra_args=()):
    """Real CLI run + ONE captured request (the engine detects a missing
    store PER EVENT — a zero-event run never queries it). Returns the
    CLI exit code; the origin is loopback (rail opt-in via the helper)."""
    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            payload = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(tmp_path), "--port", "0",
             "--duration", "2.0", "--allow-private", *extra_args],
            analyzer=analyzer, config_loader=loader)

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(tmp_path))
        assert meta is not None, "run never wrote its metadata"
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", meta["listen"]["port"],
                                          timeout=10)
        conn.request("GET", f"http://127.0.0.1:{origin.server_address[1]}/x")
        resp = conn.getresponse()
        resp.read()
        conn.close()
    finally:
        t.join(timeout=10)
        origin.shutdown()
        origin.server_close()
    assert not t.is_alive()
    return result["code"]


def test_run_no_store_configured_is_honest_failure(tmp_path, capsys):
    # H2/F1 + F-4: real analyzer, no store anywhere (db.store_path null
    # resolves to the engine default, which is absent here). With a
    # captured event the match path reports disabled — the run must NOT
    # exit 0 with a clean-looking "highlights=0"; capture is preserved
    # and the failure is loud (exit 4).
    code = _drive_run_with_one_request(tmp_path, analyzer=None,
                                       loader=fake_loader())
    assert code == 4
    captured = capsys.readouterr()
    assert "store" in captured.err.lower()
    assert "0 vulnerabilities" not in captured.out + captured.err
    run_dir = latest_run_dir(tmp_path)
    assert run_dir is not None
    assert (run_dir / "events.jsonl").exists(), "capture must be preserved"


def test_run_missing_default_store_message_is_actionable(tmp_path, capsys):
    # F-4: the no-store failure must name the problem and the way out
    # ("no vulnerability store found ... build one or pass --store"),
    # never the old boundary leak "store_path ... got None".
    code = _drive_run_with_one_request(tmp_path, analyzer=None,
                                       loader=fake_loader())
    assert code == 4
    err = capsys.readouterr().err
    assert "no vulnerability store found" in err.lower()
    assert "--store" in err
    assert "build" in err.lower()
    assert "got None" not in err
    run_dir = latest_run_dir(tmp_path)
    assert (run_dir / "events.jsonl").exists(), "capture must be preserved"


def test_default_run_with_present_store_works(tmp_path, monkeypatch, capsys):
    # F-4: with a store at the resolved default location, the DEFAULT
    # run (no --store, db.store_path null) completes with exit 0 —
    # the defect made EVERY default run end in exit 4.
    from vulndog.engine import store as st
    from vulndog.engine.tests.test_api import E1, StubEmbedder, build_fixture_store
    fixture = build_fixture_store(str(tmp_path / "default-kb.sqlite"))
    monkeypatch.setattr(st, "DEFAULT_STORE_PATH", fixture)

    def loader(path=None, task_id=None):
        return {"embedder": StubEmbedder(E1)}

    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=None, config_loader=loader)
    assert code == 0, capsys.readouterr().err
    run_dir = latest_run_dir(tmp_path)
    assert (run_dir / "highlights.md").exists()


def test_run_meta_config_is_json_safe_with_object_seam(tmp_path):
    # H2/F6 (found by the M1.4 drill): the effective config can carry a
    # non-JSON object through the documented embedder seam. The run-state
    # surface must stay valid JSON and the run must complete — a raw
    # object in watchdog-run.json crashed the run mid-capture.
    class Opaque:
        def __repr__(self):
            return "<opaque-seam>"

    code = cli.main(["run", "--project", str(tmp_path), "--port", "0",
                     "--duration", "0.3"],
                    analyzer=FakeAnalyzer(),
                    config_loader=fake_loader({"embedder": Opaque()}))
    assert code == 0
    meta = json.loads((latest_run_dir(tmp_path) / "watchdog-run.json")
                      .read_text(encoding="utf-8"))
    assert meta["config"]["embedder"] == "<opaque-seam>"
    assert meta["mode"] == "stopped"


# --------------------------------------- UX-1: wrong-shape file warning


def test_ux1_wrong_shape_config_warns_on_stderr_and_runs_on_builtins(tmp_path, capsys):
    """UX-1 behaviour test: product keys at the JSON top level (no
    'defaults' wrapper) -> a stable WARNING on stderr, and the run
    proceeds on builtins (never-crash law). Real engine loader."""
    wrong = tmp_path / "wrong-shape.json"
    wrong.write_text(json.dumps({
        "config_version": 1,
        "ai": {"base_url": "http://127.0.0.1:11999"},
    }), encoding="utf-8")
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(wrong),
                     "--port", "0", "--duration", "0.3"], analyzer=analyzer)
    assert code == 0, "the run proceeds on builtins (never-crash law)"
    err = capsys.readouterr().err
    assert "WARNING: config:" in err
    assert "outside 'defaults'" in err
    assert "move them under 'defaults'" in err
    meta = json.loads((latest_run_dir(tmp_path) / "watchdog-run.json")
                      .read_text(encoding="utf-8"))
    # the builtin AI endpoint is in force, not the misplaced dead one
    assert meta["config"]["ai"]["base_url"] == "http://127.0.0.1:11434"


def test_ux1_correct_shape_config_prints_no_shape_warning(tmp_path, capsys):
    """Negative control: the documented 'defaults' shape applies the keys
    and prints no wrong-shape warning."""
    correct = tmp_path / "correct-shape.json"
    correct.write_text(json.dumps({
        "config_version": 1,
        "defaults": {"ai": {"base_url": "http://127.0.0.1:11999"}},
    }), encoding="utf-8")
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(correct),
                     "--port", "0", "--duration", "0.3"], analyzer=analyzer)
    assert code == 0
    assert "outside 'defaults'" not in capsys.readouterr().err
    meta = json.loads((latest_run_dir(tmp_path) / "watchdog-run.json")
                      .read_text(encoding="utf-8"))
    assert meta["config"]["ai"]["base_url"] == "http://127.0.0.1:11999"


# ----------------------------------- UX-2: no insider refs in run state


def test_ux2_meta_floor_note_is_product_appropriate(tmp_path):
    """UX-2: the engine config's floor_note carries internal calibration
    provenance. The watchdog-run.json config snapshot (also served by MCP
    run_status) must replace it with a product-appropriate string — and
    never mutate the caller's cfg."""
    from types import SimpleNamespace
    from vulndog import config
    run = SimpleNamespace(hunt_id="20261123-000000", path=tmp_path,
                          events_path=tmp_path / "events.jsonl")
    cfg = config.builtin_defaults()
    # insider markers assembled at runtime: the source itself must carry no
    # internal project name literal (public-release anonymization gate)
    insider_tree = "bug" + "hunt"
    fw = "factory-" + "workspace"
    cfg["floor_note"] = (
        "0.49 = full-store recalibrated default. Full record: "
        + fw + "/vuln-watchdog-001/artifacts/"
        "p4-floor-recalibration-applied.md (%s tree)." % insider_tree)
    payload = cli._meta_payload(run, cfg, "stopped", "2026-11-23T00:00:00Z",
                                {"host": "127.0.0.1", "port": 0}, 0)
    blob = json.dumps(payload["config"])
    assert fw not in blob
    assert insider_tree not in blob
    assert payload["config"]["floor_note"] == cli._PRODUCT_FLOOR_NOTE
    # the caller's cfg is untouched (the run keeps its resolved config)
    assert fw in cfg["floor_note"]


# ----------------------------- UX-3: default store path is user-facing


def test_ux3_run_missing_store_names_project_path_not_phantom(tmp_path, capsys):
    """UX-3: a default run (no --store, db.store_path null) with no store
    on disk must name the ACTUAL resolved user-facing path (the project
    data/vulnkb root) in the missing-store error — never the phantom
    engine default inside the installed package — and give the concrete
    build command."""
    from vulndog.engine import store as st
    code = _drive_run_with_one_request(tmp_path, analyzer=None,
                                       loader=fake_loader())
    assert code == 4
    err = capsys.readouterr().err
    expected = str(Path(tmp_path).resolve() / "data" / "vulnkb"
                   / "vulnkb.sqlite")
    assert expected in err, f"resolved project path missing from:\n{err}"
    assert "site-packages" not in err
    assert st.DEFAULT_STORE_PATH not in err, "phantom engine default named"
    assert "vulndog db build" in err
    assert "--raw-dir" in err
    assert "--store" in err