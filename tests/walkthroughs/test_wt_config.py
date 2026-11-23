"""Walkthrough case 6 — config as a stranger (docs/CONFIGURATION.md).

Builds the docs' example config file, starts the shipped `vulndog run`
with it, and asserts the documented effects: proxy port, scope banner,
403 proxy_oos / proxy_private legs (denied BEFORE any upstream socket —
no egress), runs.dir, the corrupt-config WARNING + never-crash law, the
wrong-typed exit-2 shape law, CLI precedence, cwd discovery, task
overrides. With no store present, a run that captured events exits 4
with the documented actionable message.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

WT = Path(__file__).resolve().parents[2]
ENV = dict(os.environ, PYTHONPATH=str(WT / "src"))

# the docs' example, verbatim (CONFIGURATION.md "Config file example")
DOCS_EXAMPLE = {
    "config_version": 1,
    "floor_note": "0.49 = full-store recalibrated default 2026-10-16 (see docs/VULNERABILITY-DB.md)",
    "defaults": {
        "top_k": 3, "floor": 0.49, "poll_interval_s": 1.0,
        "state_interval_s": 5.0, "backoff_s": 60.0,
        "per_event_deadline_s": 60.0, "console": True,
        "mute_record_ids": [], "mute_url_prefixes": [], "filters": None,
        "store_path": None,
        "proxy": {"host": "127.0.0.1", "port": 8080},
        "scope": {"in": [], "out": []},
        "runs": {"dir": "runs"},
        "db": {"store_path": None},
        "ai": {"provider": "ollama", "base_url": "http://127.0.0.1:11434",
               "model": "embeddinggemma:300m", "dims": 768,
               "doc_prefix": "title: none | text: ",
               "query_prefix": "task: search result | query: "},
    },
    "tasks": {},
}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def write_cfg(tmp_path, cfg, name="vulndog.json"):
    p = tmp_path / name
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return p


def start_run(argv, cwd):
    p = subprocess.Popen([sys.executable, "-m", "vulndog", *argv],
                         cwd=str(cwd), env=ENV, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    lines = []

    def pump(stream):
        for line in stream:
            lines.append(line.rstrip("\n"))

    threading.Thread(target=pump, args=(p.stdout,), daemon=True).start()
    threading.Thread(target=pump, args=(p.stderr,), daemon=True).start()
    return p, lines


def wait_listening(lines, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if any("listening" in l for l in lines):
            return True
        time.sleep(0.05)
    return False


def proxy_get(port, absolute_uri):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
    try:
        c.request("GET", absolute_uri)
        r = c.getresponse()
        r.read()
        return r.status
    finally:
        c.close()


def finish(p, lines, timeout=45):
    code = p.wait(timeout=timeout)
    time.sleep(0.3)  # let the pump threads drain
    return code, list(lines)


def stranger_cfg(port):
    cfg = json.loads(json.dumps(DOCS_EXAMPLE))
    cfg["defaults"]["proxy"]["port"] = port
    cfg["defaults"]["scope"] = {"in": ["*.example.test", "127.0.0.1"],
                                "out": ["blocked.example.test"]}
    cfg["defaults"]["runs"] = {"dir": "myruns"}
    return cfg


def test_docs_config_applies_port_scope_runs_dir_and_403_legs(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    port = free_port()
    cfg_path = write_cfg(tmp_path, stranger_cfg(port))
    p, lines = start_run(["run", "--config", str(cfg_path), "--project",
                          str(proj), "--duration", "3"], tmp_path)
    assert wait_listening(lines), lines
    # out-of-scope: 403 before any upstream socket (out wins)
    assert proxy_get(port, "http://blocked.example.test/x") == 403
    # in-scope private IP: the SSRF rail denies (no upstream, no DNS)
    assert proxy_get(port, "http://127.0.0.1:9/") == 403
    code, out = finish(p, lines)
    assert code == 4  # events captured, no store -> documented exit 4
    banner = "\n".join(out)
    assert f"proxy:   http://127.0.0.1:{port}" in banner
    assert "scope:   in=['*.example.test', '127.0.0.1']" in banner
    assert "out=['blocked.example.test'] (out wins)" in banner
    assert "no vulnerability store found" in banner
    assert "build one" in banner and "--store" in banner
    run_dirs = list((proj / "myruns").glob("*"))
    assert len(run_dirs) == 1  # runs.dir applied
    events = [json.loads(l) for l in
              (run_dirs[0] / "events.jsonl").read_text(
                  encoding="utf-8").splitlines() if l.strip()]
    reasons = [e.get("denial_reason") for e in events]
    assert "proxy_oos" in reasons and "proxy_private" in reasons


def test_no_scope_banner_warns_allow_all_public(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    cfg = json.loads(json.dumps(DOCS_EXAMPLE))
    cfg["defaults"]["proxy"]["port"] = free_port()
    cfg_path = write_cfg(tmp_path, cfg)
    p, lines = start_run(["run", "--config", str(cfg_path), "--project",
                          str(proj), "--duration", "1.5"], tmp_path)
    assert wait_listening(lines), lines
    code, out = finish(p, lines)
    banner = "\n".join(out)
    assert "no scope configured" in banner
    assert "all PUBLIC hosts are forwarded" in banner
    assert "SSRF rail" in banner


def test_corrupt_config_warns_and_run_still_starts(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    bad = tmp_path / "corrupt.json"
    bad.write_text("{ this is not valid JSON", encoding="utf-8")
    p, lines = start_run(["run", "--config", str(bad), "--project",
                          str(proj), "--port", str(free_port()),
                          "--duration", "1.5"], tmp_path)
    assert wait_listening(lines), lines
    code, out = finish(p, lines)
    warn = [l for l in out if l.startswith("WARNING: config:")]
    assert warn and "builtin defaults in force" in warn[0]
    assert code == 0  # 0-event run: config degradation never fails it


def test_wrong_typed_config_exit_2_before_capture(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    cfg = json.loads(json.dumps(DOCS_EXAMPLE))
    cfg["defaults"]["proxy"]["port"] = "8080"  # wrong type
    cfg_path = write_cfg(tmp_path, cfg)
    p = subprocess.run([sys.executable, "-m", "vulndog", "run", "--config",
                        str(cfg_path), "--project", str(proj),
                        "--duration", "1"], cwd=str(tmp_path), env=ENV,
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 2
    assert "proxy.port" in p.stderr
    assert list(proj.glob("runs/*")) == []  # no half-configured proxy


def test_cli_port_overrides_config(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    cfg_port, cli_port = free_port(), free_port()
    cfg_path = write_cfg(tmp_path, stranger_cfg(cfg_port))
    p, lines = start_run(["run", "--config", str(cfg_path), "--project",
                          str(proj), "--port", str(cli_port),
                          "--duration", "1.5"], tmp_path)
    assert wait_listening(lines), lines
    _, out = finish(p, lines)
    banner = "\n".join(out)
    assert f"proxy:   http://127.0.0.1:{cli_port}" in banner
    assert f"http://127.0.0.1:{cfg_port}" not in banner


def test_cwd_discovery_wins_when_config_omitted(tmp_path):
    disc = tmp_path / "disc"
    disc.mkdir()
    proj = disc / "p"
    port = free_port()
    cfg = json.loads(json.dumps(DOCS_EXAMPLE))
    cfg["defaults"]["proxy"]["port"] = port
    cfg["defaults"]["scope"] = {"in": ["discovered.example.test"], "out": []}
    write_cfg(disc, cfg)  # vulndog.json in cwd
    p, lines = start_run(["run", "--project", str(proj), "--duration", "1.5"],
                         disc)
    assert wait_listening(lines), lines
    _, out = finish(p, lines)
    banner = "\n".join(out)
    assert "scope:   in=['discovered.example.test']" in banner
    assert f"proxy:   http://127.0.0.1:{port}" in banner


def test_task_entry_overrides_defaults(tmp_path):
    proj = tmp_path / "project"
    proj.mkdir()
    base_port, task_port = free_port(), free_port()
    cfg = json.loads(json.dumps(DOCS_EXAMPLE))
    cfg["defaults"]["proxy"]["port"] = base_port
    cfg["tasks"] = {"nightly": {"proxy": {"port": task_port}}}
    cfg_path = write_cfg(tmp_path, cfg)
    p, lines = start_run(["run", "--config", str(cfg_path), "--task",
                          "nightly", "--project", str(proj),
                          "--duration", "1.5"], tmp_path)
    assert wait_listening(lines), lines
    _, out = finish(p, lines)
    banner = "\n".join(out)
    assert f"proxy:   http://127.0.0.1:{task_port}" in banner