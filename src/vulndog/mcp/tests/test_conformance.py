"""M2.3 conformance: drive the REAL server over stdio as a subprocess.

initialize -> notifications/initialized -> tools/list -> tools/call for
EACH documented tool; every call returns valid JSON content
[{type:"text"}] with isError:false. Unknown method -> JSON-RPC error
envelope and the server stays alive.

Offline determinism: the ok-path child (stdio_child.py) injects a
fixed-vector embedder through the engine's documented config["embedder"]
seam — the vendored client is loopback-only by construction (ai.base_url
wiring is M2.4). The production entry (python -m vulndog.mcp) is driven
KB-down, where the engine's store pre-check answers before any embedder
call. The KB is the engine-built fixture store.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys

DOCUMENTED_TOOLS = {"vuln_query", "highlights", "run_status"}


class StdioClient:
    """Newline-delimited JSON-RPC client over the child's stdio."""

    def __init__(self, argv, env, cwd):
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, cwd=str(cwd), text=True,
            encoding="utf-8")
        self._id = 0

    def request(self, method, params=None):
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            stderr = self.proc.stderr.read()
            raise AssertionError(f"server died or stayed silent: {stderr}")
        return json.loads(line)

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def child_argv(child_env, store=None):
    """Real server + serve loop, embedder injected (offline ok path).
    Store via CLI override: file product keys apply only after config v2
    (docs/CONFIGURATION.md, M2.1)."""
    return [sys.executable, "-m", "vulndog.mcp.tests.stdio_child",
            "--project", str(child_env["project"]),
            "--config", str(child_env["cfg_path"]),
            "--store", str(store or child_env["kb_store"])]


def entry_argv(child_env, store=None):
    """The production entry point: python -m vulndog.mcp."""
    return [sys.executable, "-m", "vulndog.mcp",
            "--project", str(child_env["project"]),
            "--config", str(child_env["cfg_path"]),
            "--store", str(store or child_env["kb_store"])]


def unified_entry_argv(child_env, store=None):
    """The unified CLI entry (M2.5): `vulndog mcp`.

    VULNDOG_MCP_ENTRY (optional) names an installed console script — the
    clean-install gate drives the REAL installed entry through this same
    conformance sequence. Unset: the module form of the same unified
    entry (`python -m vulndog mcp`), importable from the source tree.
    """
    entry = os.environ.get("VULNDOG_MCP_ENTRY")
    argv = shlex.split(entry) if entry else [sys.executable, "-m", "vulndog"]
    return argv + ["mcp",
                   "--project", str(child_env["project"]),
                   "--config", str(child_env["cfg_path"]),
                   "--store", str(store or child_env["kb_store"])]


def assert_text_content(result):
    assert result["isError"] is False
    content = result["content"]
    assert isinstance(content, list) and content
    for block in content:
        assert block["type"] == "text"
        assert isinstance(block["text"], str)
    return json.loads(content[0]["text"])


def test_full_conformance_over_stdio(child_env):
    with StdioClient(child_argv(child_env), child_env["env"],
                     child_env["project"]) as client:
        init = client.request("initialize", {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "conformance", "version": "0"}})
        assert init["jsonrpc"] == "2.0"
        assert init["result"]["serverInfo"]["name"] == "vulndog"
        assert init["result"]["protocolVersion"] == "2024-11-05"

        client.notify("notifications/initialized")

        listed = client.request("tools/list")
        tools = listed["result"]["tools"]
        assert {t["name"] for t in tools} == DOCUMENTED_TOOLS

        query = client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}})
        out = assert_text_content(query["result"])
        assert out["status"] == "ok"
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"

        highlights = client.request("tools/call", {
            "name": "highlights", "arguments": {}})
        out = assert_text_content(highlights["result"])
        assert out["total"] == 3
        assert out["highlights"][0]["record_id"] == "CVE-2024-1000"

        status = client.request("tools/call", {
            "name": "run_status", "arguments": {}})
        out = assert_text_content(status["result"])
        assert out["mode"] == "capture"
        assert out["counters"]["events"] == 12

        resources = client.request("resources/list")
        assert len(resources["result"]["resources"]) == 2

        unknown = client.request("bogus/method")
        assert unknown["error"]["code"] == -32601

        # server stays alive after the error envelope
        again = client.request("tools/list")
        assert {t["name"] for t in again["result"]["tools"]} == DOCUMENTED_TOOLS


def test_production_entry_kb_down_over_stdio(child_env, tmp_path):
    """The PRODUCTION entry (python -m vulndog.mcp) over the real wire,
    config through the pinned contract: store-failure path returns the
    disabled status envelope (isError:false, no crash, no fake 'no
    vulnerabilities' answer); highlights/run_status still serve the run
    tree; the server stays alive."""
    missing = tmp_path / "missing.sqlite"
    with StdioClient(entry_argv(child_env, store=missing), child_env["env"],
                     child_env["project"]) as client:
        init = client.request("initialize", {"protocolVersion": "2024-11-05"})
        assert init["result"]["serverInfo"]["name"] == "vulndog"
        client.notify("notifications/initialized")
        listed = client.request("tools/list")
        assert {t["name"] for t in listed["result"]["tools"]} == \
            DOCUMENTED_TOOLS

        resp = client.request("tools/call", {
            "name": "vuln_query", "arguments": {"text": "xss scripting"}})
        out = assert_text_content(resp["result"])
        assert out["status"] == "disabled"
        assert out["reason"] == "store-missing"
        assert out["matches"] == []

        out = assert_text_content(client.request("tools/call", {
            "name": "highlights", "arguments": {}})["result"])
        assert out["total"] == 3
        out = assert_text_content(client.request("tools/call", {
            "name": "run_status", "arguments": {}})["result"])
        assert out["mode"] == "capture"

        # still alive for the next call
        assert client.request("ping")["result"] == {}


def test_unified_cli_entry_kb_down_over_stdio(child_env, tmp_path):
    """M2.5 acceptance: `vulndog mcp` passes the M2.3 conformance sequence
    through the unified entry — same KB-down wire contract as the interim
    `python -m vulndog.mcp` entry above. With VULNDOG_MCP_ENTRY set (the
    clean-install gate), the child is the INSTALLED console script and
    must stand on the installed package alone: ANY PYTHONPATH (the
    fixture's source-tree bootstrap or an outer-environment one) is
    stripped so a source shadow cannot fake the pass."""
    missing = tmp_path / "missing.sqlite"
    env = child_env["env"]
    if os.environ.get("VULNDOG_MCP_ENTRY"):
        env = dict(os.environ)
        # MERGE FIX (tech-lead W7-F1): dict(os.environ) alone still
        # inherits an OUTER PYTHONPATH (e.g. exported by the gate
        # runner), which precedes site-packages in the child and can
        # shadow the installed package. Strip it — the installed entry
        # must stand on the installed package alone.
        env.pop("PYTHONPATH", None)
        env["PYTHONIOENCODING"] = "utf-8"
    with StdioClient(unified_entry_argv(child_env, store=missing), env,
                     child_env["project"]) as client:
        init = client.request("initialize", {"protocolVersion": "2024-11-05"})
        assert init["result"]["serverInfo"]["name"] == "vulndog"
        client.notify("notifications/initialized")
        listed = client.request("tools/list")
        assert {t["name"] for t in listed["result"]["tools"]} == \
            DOCUMENTED_TOOLS

        resp = client.request("tools/call", {
            "name": "vuln_query", "arguments": {"text": "xss scripting"}})
        out = assert_text_content(resp["result"])
        assert out["status"] == "disabled"
        assert out["reason"] == "store-missing"
        assert out["matches"] == []

        out = assert_text_content(client.request("tools/call", {
            "name": "highlights", "arguments": {}})["result"])
        assert out["total"] == 3
        out = assert_text_content(client.request("tools/call", {
            "name": "run_status", "arguments": {}})["result"])
        assert out["mode"] == "capture"

        # still alive for the next call
        assert client.request("ping")["result"] == {}