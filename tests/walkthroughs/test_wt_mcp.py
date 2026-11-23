"""Walkthrough case 5 — MCP as a stranger (docs/MCP.md).

The docs' own handshake (initialize -> notifications/initialized ->
tools/list -> tools/call) against the documented module entry forms,
with the transcript asserted against the documented tool schemas,
error-envelope law, volume caps, resources, and exit codes. The wire
tests use a fixture run folder and a MISSING store (the honest disabled
envelope — no embedder work happens); the ok-path query is pinned
in-process through the documented offline embedder seam. No network.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

from vulndog import runs
from vulndog.engine import record_schema as rs
from vulndog.engine import store as st
from vulndog.mcp.server import McpServer

WT = Path(__file__).resolve().parents[2]
ENV = dict(os.environ, PYTHONPATH=str(WT / "src"))
MISSING_STORE = "no-such-store/vulnkb.sqlite"


# ------------------------------------------------------------------ fixtures

@pytest.fixture
def mcp_project(tmp_path):
    """A project with one real-shaped run folder (stopped, analyzed)."""
    proj = tmp_path / "project"
    proj.mkdir()
    run = runs.create_run(proj, now=datetime(2026, 11, 23, 10, 0, 0))
    run.write_pid(4_000_000)  # a pid that does not exist -> alive False
    run.write_meta({
        "pid": 4_000_000, "hunt_id": run.hunt_id, "mode": "stopped",
        "started_at": "2026-11-23T10:00:00Z",
        "stopped_at": "2026-11-23T10:00:05Z",
        "counters": {"events": 2, "highlights": 2},
        "config": {"api_key": "fixture-secret-value",
                   "proxy": {"host": "127.0.0.1", "port": 8080},
                   "floor": 0.49},
        "paths": {"run_dir": str(run.path),
                  "events": str(run.events_path)},
    })
    run.events_path.write_text("", encoding="utf-8")
    rows = [
        {"record_id": "CVE-2024-1000", "kind": "cve",
         "url": "http://example.test/login", "score": 0.91,
         "cvss": 9.8, "owasp_categories": ["A03:2021-Injection"],
         "matched_snippet": "XSS in login page"},
        {"record_id": "CVE-2024-2000", "kind": "cve",
         "url": "http://example.test/search", "score": 0.83,
         "cvss": 8.1, "owasp_categories": ["A03:2021-Injection"],
         "matched_snippet": "SQLi in search"},
    ]
    (run.path / "highlights.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows)
        + "\nnot-json\n[1]\n", encoding="utf-8")
    return proj


def session(argv, messages, raw_prefix="", cwd=None):
    payload = raw_prefix + "".join(json.dumps(m) + "\n" for m in messages)
    p = subprocess.run([sys.executable, "-m", *argv], input=payload,
                       cwd=str(cwd or WT), env=ENV, capture_output=True,
                       text=True, timeout=90)
    resps = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    return p.returncode, resps, p.stderr


def req(rid, method, params=None):
    m = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        m["params"] = params
    return m


def mcp_argv(proj, *extra):
    return ["vulndog", "mcp", "--project", str(proj),
            "--store", str(proj / MISSING_STORE), *extra]


def tool_result(resp):
    r = resp.get("result", {})
    if r.get("isError"):
        return None, r["content"][0]["text"]
    return json.loads(r["content"][0]["text"]), None


# ------------------------------------------------------------------ handshake

def test_docs_handshake_transcript(mcp_project):
    code, resps, err = session(mcp_argv(mcp_project), [
        req(1, "initialize", {"protocolVersion": "2025-06-18",
                              "capabilities": {},
                              "clientInfo": {"name": "stranger",
                                             "version": "0"}}),
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        req(2, "initialize", {"protocolVersion": "1999-01-01"}),
    ])
    assert code == 0, err  # docs: exit 0 on clean EOF
    assert len(resps) == 2  # no response for the notification
    init = resps[0]["result"]
    assert init["protocolVersion"] == "2025-06-18"  # echo when supported
    assert init["serverInfo"] == {"name": "vulndog", "version": "0.1.0"}
    assert "tools" in init["capabilities"]
    assert "resources" in init["capabilities"]
    # unsupported version falls back to 2024-11-05
    assert resps[1]["result"]["protocolVersion"] == "2024-11-05"


def test_tools_list_matches_the_documented_schemas(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [req(1, "tools/list")])
    tools = {t["name"]: t for t in resps[0]["result"]["tools"]}
    assert set(tools) == {"vuln_query", "highlights", "run_status"}
    vq = tools["vuln_query"]["inputSchema"]
    assert vq["required"] == ["text"]
    assert vq["properties"]["text"]["maxLength"] == 8000
    assert vq["properties"]["top_k"]["minimum"] == 1
    assert vq["properties"]["floor"]["minimum"] == 0
    assert vq["properties"]["floor"]["maximum"] == 1
    fl = vq["properties"]["filters"]
    assert fl["additionalProperties"] is False
    assert set(fl["properties"]) == {"kind", "min_cvss",
                                     "exploit_available", "cwe_id"}
    hl = tools["highlights"]["inputSchema"]
    assert set(hl["properties"]) == {"run_id", "last_n"}
    assert not hl.get("required")
    assert tools["run_status"]["inputSchema"]["properties"] == {}
    # advisory wording is part of the descriptions (docs/MCP.md)
    assert "never a finding" in tools["vuln_query"]["description"]


# ------------------------------------------------------------------ tool calls

def test_run_status_snapshot_and_secret_masking(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "tools/call", {"name": "run_status", "arguments": {}})])
    snap, err = tool_result(resps[0])
    assert snap is not None, err
    for key in ("hunt_id", "run_dir", "pid", "alive", "mode", "counters",
                "config", "paths", "stop_requested"):
        assert key in snap, key
    assert snap["mode"] == "stopped"
    assert snap["alive"] is False
    # P2-04: secret-shaped config keys masked at the serving door
    assert snap["config"]["api_key"] == "<redacted>"
    assert snap["config"]["proxy"] == {"host": "127.0.0.1", "port": 8080}
    assert snap["config"]["floor"] == 0.49


def test_highlights_rows_last_n_and_skipped_lines(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "tools/call", {"name": "highlights", "arguments": {}}),
        req(2, "tools/call", {"name": "highlights",
                              "arguments": {"last_n": 1}})])
    full, err = tool_result(resps[0])
    assert full is not None, err
    assert full["total"] == 2 and full["returned"] == 2
    assert full["skipped_lines"] == 2  # malformed + non-dict lines
    assert full["highlights"][0]["record_id"] == "CVE-2024-1000"
    last, _ = tool_result(resps[1])
    assert last["returned"] == 1
    assert last["highlights"][0]["record_id"] == "CVE-2024-2000"


def test_vuln_query_missing_store_is_honest_disabled(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "tools/call", {"name": "vuln_query",
                              "arguments": {"text": "XSS in login page"}})])
    payload, err = tool_result(resps[0])
    assert payload is not None, err  # structured envelope, never a crash
    assert payload["status"] == "disabled"
    assert payload["matches"] == []


@pytest.mark.parametrize("args,fragment", [
    ({"text": "x" * 8001}, "8001"),
    ({"text": "q", "top_k": 0}, "top_k"),
    ({"text": "q", "floor": 2}, "floor"),
    ({"text": "q", "filters": {"bogus": 1}}, "bogus"),
    ({"text": ""}, "text"),
], ids=["over-cap-text", "top-k-zero", "floor-range", "unknown-filter",
        "empty-text"])
def test_bad_arguments_refused_as_tool_errors(mcp_project, args, fragment):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "tools/call", {"name": "vuln_query", "arguments": args})])
    payload, err = tool_result(resps[0])
    assert payload is None and fragment in err
    if fragment == "8001":
        assert "8000" in err  # names the limit AND the actual length


def test_unknown_tool_and_missing_name(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "tools/call", {"name": "no_such_tool", "arguments": {}}),
        req(2, "tools/call", {"arguments": {}})])
    _, err = tool_result(resps[0])
    assert err is not None and "unknown tool" in err
    assert resps[1]["error"]["code"] == -32602  # INVALID_PARAMS


# ------------------------------------------------------------------ resources

def test_resources_list_read_and_traversal_guard(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [
        req(1, "resources/list"),
        req(2, "resources/read", {"uri": "vulndog://runs/../secret"}),
        req(3, "resources/read", {"uri": "vulndog://runs/19990101-000000"}),
    ])
    resources = resps[0]["result"]["resources"]
    assert len(resources) == 1
    uri = resources[0]["uri"]
    assert uri == "vulndog://runs/20261123-100000"
    assert resps[1]["error"]["code"] == -32602
    assert resps[2]["error"]["code"] == -32602
    _, resps2, _ = session(mcp_argv(mcp_project), [
        req(1, "resources/read", {"uri": uri})])
    contents = resps2[0]["result"]["contents"]
    art = json.loads(contents[0]["text"])
    assert art["run_id"] == "20261123-100000"
    names = {a["name"] for a in art["artifacts"]}
    assert {"events.jsonl", "highlights.jsonl", "watchdog-run.json"} <= names
    assert all(isinstance(a["bytes"], int) for a in art["artifacts"])


# ------------------------------------------------------------------ envelopes

def test_error_envelopes_and_stdin_volume_cap(mcp_project):
    overcap = "z" * 1_048_577 + "\n"
    code, resps, _ = session(mcp_argv(mcp_project),
                             [req(7, "initialize", {})],
                             raw_prefix="not json\n[1,2,3]\n" + overcap)
    assert code == 0
    assert resps[0]["error"]["code"] == -32700  # PARSE_ERROR
    assert resps[0]["id"] is None
    assert resps[1]["error"]["code"] == -32600  # INVALID_REQUEST
    assert resps[1]["id"] is None
    assert resps[2]["error"]["code"] == -32600  # over-cap line, id null
    assert resps[2]["id"] is None
    assert resps[3]["id"] == 7 and "result" in resps[3]  # loop alive


def test_unknown_method_is_method_not_found(mcp_project):
    _, resps, _ = session(mcp_argv(mcp_project), [req(1, "bogus/method")])
    assert resps[0]["error"]["code"] == -32601


def test_entry_form_equivalence_and_config_usage_exit(mcp_project, tmp_path):
    code, resps, _ = session(["vulndog.mcp", "--project", str(mcp_project)],
                             [req(1, "initialize",
                                  {"protocolVersion": "2025-03-26"})])
    assert code == 0
    assert resps[0]["result"]["protocolVersion"] == "2025-03-26"
    assert resps[0]["result"]["serverInfo"]["name"] == "vulndog"
    badcfg = tmp_path / "bad.json"
    badcfg.write_text(json.dumps({"defaults": {"ai": {"provider": "bogus"}}}),
                      encoding="utf-8")
    p = subprocess.run([sys.executable, "-m", "vulndog", "mcp", "--config",
                        str(badcfg), "--project", str(mcp_project)],
                       input="", cwd=str(WT), env=ENV, capture_output=True,
                       text=True, timeout=60)
    assert p.returncode == 2  # docs: config usage error


# ------------------------------------------------------------------ ok path

def unit(*vals):
    n = math.sqrt(sum(v * v for v in vals)) or 1.0
    return [v / n for v in vals]


class FixedEmbedder:
    def __init__(self):
        self.vector = unit(1, 0, 0, 0)

    def embed_query(self, text):
        return self.vector


def test_vuln_query_ok_path_offline_seam(tmp_path, mcp_project):
    """The match path with a fixture store + the documented offline
    embedder seam: status ok, real matches, the engine envelope shape."""
    dest = str(tmp_path / "vulnkb.sqlite")
    rec, errors, _ = rs.normalize_record({
        "id": "CVE-2024-1000", "kind": "cve", "title": "XSS in login page",
        "text_fields": ["XSS in login page"], "cwe_ids": ["CWE-79"],
        "cvss": {"score": 9.8}, "evidence": {"src": "fixture.zip",
                                             "note": "n"},
        "confidence": "documented"})
    assert errors == []
    vec = unit(1, 0, 0, 0)
    with st.StagedStore(dest) as s:
        s.add_record(rec)
        s.add_chunk(rec["id"], 0, 1, "XSS in login page", vec, 5, False)
        s.finish({"manifest_version": 1, "corpus_version": "vkb1-wt-mcp",
                  "counts": {"records_total": 1, "chunks_total": 1}})
        s.swap_into_dest()
    server = McpServer(project_root=mcp_project, config={
        "db": {"store_path": dest}, "embedder": FixedEmbedder(),
        "runs": {"dir": "runs"}})
    resp = server.handle_message(req(1, "tools/call", {
        "name": "vuln_query", "arguments": {"text": "XSS in login page"}}))
    payload, err = tool_result(resp)
    assert payload is not None, err
    assert payload["status"] == "ok"
    assert payload["matches"], payload
    assert payload["matches"][0]["record_id"] == "CVE-2024-1000"
    assert payload["corpus_version"] == "vkb1-wt-mcp"
    for key in ("prefilter_hits", "pinned", "matches"):
        assert key in payload