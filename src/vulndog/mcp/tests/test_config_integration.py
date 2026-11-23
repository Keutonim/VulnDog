"""W4 integration pin (tech-lead-w4): MCP reads db.store_path / runs.dir
from a CONFIG FILE through the merged config layer — no --store crutch.

dev-d shipped while the engine merge still quarantined product namespaces
(pre-M2.1 / F-1), so its conformance passed the store via --store. After
the M2.1 merge those file keys APPLY; these tests pin that resolution over
the real stdio wire so a regression of the known-key extension fails here.
"""
from __future__ import annotations

import json
import sys

from vulndog.mcp.tests.test_conformance import StdioClient


def _child_no_store(child_env):
    return [sys.executable, "-m", "vulndog.mcp.tests.stdio_child",
            "--project", str(child_env["project"]),
            "--config", str(child_env["cfg_path"])]


def _entry_no_store(child_env, cfg_path):
    return [sys.executable, "-m", "vulndog.mcp",
            "--project", str(child_env["project"]),
            "--config", str(cfg_path)]


def _handshake(client):
    init = client.request("initialize", {"protocolVersion": "2024-11-05"})
    assert init["result"]["serverInfo"]["name"] == "vulndog"
    client.notify("notifications/initialized")


def _payload(resp):
    result = resp["result"]
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


def test_file_store_and_runs_dir_apply_without_store_override(child_env):
    """The cross-deviation resolution: the ok-path child runs WITHOUT
    --store; the config file's db.store_path picks the KB and runs.dir
    picks the run tree, both through vulndog.config.load_config."""
    with StdioClient(_child_no_store(child_env), child_env["env"],
                     child_env["project"]) as client:
        _handshake(client)
        out = _payload(client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}}))
        assert out["status"] == "ok", out
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"
        out = _payload(client.request("tools/call",
                                      {"name": "highlights",
                                       "arguments": {}}))
        assert out["total"] == 3
        out = _payload(client.request("tools/call",
                                      {"name": "run_status",
                                       "arguments": {}}))
        assert out["mode"] == "capture"


def test_production_entry_file_store_missing_is_disabled(child_env,
                                                         tmp_path):
    """Production entry WITHOUT --store: a file db.store_path pointing at
    a missing store must yield the honest disabled envelope (proves the
    file key is consumed on the production path, before any embedder
    call), while highlights still serve the file-configured run tree."""
    cfg = tmp_path / "cfg-missing.json"
    cfg.write_text(json.dumps({
        "config_version": 1,
        "defaults": {"runs": {"dir": "runs"},
                     "db": {"store_path": str(tmp_path / "no.sqlite")}},
        "tasks": {}}), encoding="utf-8")
    with StdioClient(_entry_no_store(child_env, cfg), child_env["env"],
                     child_env["project"]) as client:
        _handshake(client)
        out = _payload(client.request("tools/call", {
            "name": "vuln_query", "arguments": {"text": "xss scripting"}}))
        assert out["status"] == "disabled", out
        assert out["reason"] == "store-missing"
        assert out["matches"] == []
        out = _payload(client.request("tools/call",
                                      {"name": "highlights",
                                       "arguments": {}}))
        assert out["total"] == 3


def test_store_cli_override_beats_file_value(child_env, tmp_path):
    """Precedence through the MCP layer: --store (CLI) wins over a file
    db.store_path that points at a missing store."""
    cfg = tmp_path / "cfg-missing.json"
    cfg.write_text(json.dumps({
        "config_version": 1,
        "defaults": {"runs": {"dir": "runs"},
                     "db": {"store_path": str(tmp_path / "no.sqlite")}},
        "tasks": {}}), encoding="utf-8")
    argv = _child_no_store(child_env) + ["--store", str(child_env["kb_store"])]
    with StdioClient(argv, child_env["env"], child_env["project"]) as client:
        _handshake(client)
        out = _payload(client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}}))
        assert out["status"] == "ok", out
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"