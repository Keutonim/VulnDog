"""Tool-semantics tests (M2.3): vuln_query / highlights / run_status.

Real handlers against the fixture KB (engine StagedStore + fixed-vector
embedder) and real run folders written through vulndog.runs. The KB-down
and embedder-down paths are negative controls: an outage must surface as
an honest status envelope, never as a fake "no vulnerabilities" answer.
"""
from __future__ import annotations

import json

import pytest

from vulndog.mcp.server import McpServer
from vulndog.mcp.tests.conftest import highlight_row, unit


@pytest.fixture()
def server(mcp_env):
    return McpServer(project_root=mcp_env["project_root"],
                     config=mcp_env["config"],
                     query_api_factory=mcp_env["query_api_factory"])


def call(server, name, arguments=None):
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": params})
    assert "error" not in resp, resp
    return resp["result"]


def payload(result):
    assert result["isError"] is False
    assert result["content"][0]["type"] == "text"
    return json.loads(result["content"][0]["text"])


def error_text(result):
    assert result["isError"] is True
    return result["content"][0]["text"]


class TestVulnQuery:
    def test_ok_match_through_the_engine_door(self, server):
        out = payload(call(server, "vuln_query",
                           {"text": "reflected xss in login page"}))
        assert out["status"] == "ok"
        assert out["corpus_version"] == "vkb1-mcp-test"
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"
        assert out["matches"][0]["reason"] == "semantic"

    def test_top_k_and_floor_pass_through(self, server, mcp_env):
        mcp_env["embedder"].vector = unit(1, 1, 1, 1)
        out = payload(call(server, "vuln_query",
                           {"text": "scripting injection overflow xss",
                            "top_k": 1, "floor": 0.2}))
        sem = [m for m in out["matches"] if m["reason"] == "semantic"]
        assert len(sem) == 1
        out = payload(call(server, "vuln_query",
                           {"text": "scripting injection overflow xss",
                            "floor": 0.99}))
        assert out["status"] == "ok"
        assert out["matches"] == []

    def test_filters_pass_through(self, server, mcp_env):
        mcp_env["embedder"].vector = unit(1, 1, 1, 0)
        out = payload(call(server, "vuln_query",
                           {"text": "scripting injection overflow",
                            "floor": 0.2,
                            "filters": {"min_cvss": 9.0}}))
        ids = {m["record_id"] for m in out["matches"]}
        assert "CVE-2024-1000" in ids
        assert "CVE-2024-2000" not in ids  # 8.1 filtered out

    def test_exact_id_pin(self, server):
        out = payload(call(server, "vuln_query",
                           {"text": "xss CVE-2024-3000"}))
        pinned = [m for m in out["matches"] if m["reason"] == "exact-id"]
        assert [m["record_id"] for m in pinned] == ["CVE-2024-3000"]

    def test_unknown_filter_key_is_clear_tool_error(self, server):
        text = error_text(call(server, "vuln_query",
                               {"text": "xss",
                                "filters": {"nonsense": 1}}))
        assert "nonsense" in text

    def test_bad_filter_value_is_clear_tool_error(self, server):
        text = error_text(call(server, "vuln_query",
                               {"text": "xss",
                                "filters": {"cwe_id": "not-a-cwe"}}))
        assert "cwe_id" in text

    def test_wrong_typed_filter_values_are_clear_tool_errors(self, server):
        # wrong types must fail at the boundary, never leak as internal
        # errors out of the engine's SQL builder
        for filters in ({"min_cvss": [7.0]}, {"min_cvss": "high"},
                        {"kind": 5}, {"kind": [1, 2]},
                        {"cwe_id": 79}, {"exploit_available": "yes"}):
            text = error_text(call(server, "vuln_query",
                                   {"text": "xss", "filters": filters}))
            assert next(iter(filters)) in text

    def test_missing_text_is_tool_error(self, server):
        assert "text" in error_text(call(server, "vuln_query", {}))

    def test_non_string_text_is_tool_error(self, server):
        error_text(call(server, "vuln_query", {"text": 42}))

    def test_empty_text_is_tool_error(self, server):
        error_text(call(server, "vuln_query", {"text": "   "}))

    def test_bad_top_k_is_tool_error(self, server):
        error_text(call(server, "vuln_query", {"text": "xss", "top_k": 0}))
        error_text(call(server, "vuln_query",
                        {"text": "xss", "top_k": "many"}))

    def test_bad_floor_is_tool_error(self, server):
        error_text(call(server, "vuln_query", {"text": "xss", "floor": 1.5}))

    def test_fts_injection_text_never_crashes(self, server):
        out = payload(call(server, "vuln_query",
                           {"text": 'xss OR sql NEAR/2 (a b) "quoted"* '
                                    "col:term ^start {a} NOT x"}))
        assert out["status"] in ("ok", "skipped")


class TestVulnQueryTextCap:
    """P2-01 regression: the query text is volume-capped at the boundary.

    Cap contract: 8000 chars = the engine's own embed ceiling
    (chunking.HARD_CAP_TOKENS 2000 * CHARS_PER_TOKEN 4) — the largest
    text the engine ever embeds. Over-cap input is a clear tool-level
    refusal (isError:true), never a crash, never silent truncation into
    a fake answer, and never reaches the embedder (remote-provider
    amplification / OOM, security probe C5).
    """

    CAP = 8000

    def test_1mb_text_refused_and_never_embedded(self, server, mcp_env):
        # verbatim probe C5 shape: a ~1 MB query must not reach the
        # embedder (a remote provider would receive it verbatim)
        text = "xss " + "B" * 1048576
        result = call(server, "vuln_query", {"text": text})
        message = error_text(result)
        assert str(self.CAP) in message
        assert mcp_env["embedder"].calls == []
        # the loop stays healthy: the next normal query works
        out = payload(call(server, "vuln_query",
                           {"text": "reflected xss in login page"}))
        assert out["status"] == "ok"
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"

    def test_length_boundary_cap_inclusive(self, server, mcp_env):
        at_cap = "xss " + "B" * (self.CAP - 4)
        assert len(at_cap) == self.CAP
        result = call(server, "vuln_query", {"text": at_cap})
        assert result["isError"] is False  # exactly at the cap: accepted
        over_cap = at_cap + "B"
        message = error_text(call(server, "vuln_query", {"text": over_cap}))
        assert str(self.CAP) in message
        # only the at-cap query reached the embedder, never the over-cap one
        assert mcp_env["embedder"].calls == [at_cap]

    def test_cap_precedes_engine_construction(self, mcp_env):
        # the refusal is a boundary decision: it must not depend on the
        # engine half being present (no disabled envelope for over-cap)
        def absent_factory(_config):
            raise ImportError("vulndog.engine unavailable (test)")

        server = McpServer(project_root=mcp_env["project_root"],
                           config=mcp_env["config"],
                           query_api_factory=absent_factory)
        message = error_text(call(server, "vuln_query",
                                  {"text": "B" * (self.CAP + 1)}))
        assert str(self.CAP) in message

    def test_schema_documents_the_cap(self, server):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool = next(t for t in resp["result"]["tools"]
                    if t["name"] == "vuln_query")
        text_schema = tool["inputSchema"]["properties"]["text"]
        assert text_schema["maxLength"] == self.CAP


class TestVulnQueryOutages:
    """Negative controls: outage != clean bill of health."""

    def test_missing_store_returns_disabled_envelope(self, mcp_env):
        cfg = dict(mcp_env["config"])
        cfg["db"] = {"store_path": str(mcp_env["project_root"] / "no.sqlite")}
        server = McpServer(project_root=mcp_env["project_root"], config=cfg,
                           query_api_factory=mcp_env["query_api_factory"])
        result = call(server, "vuln_query", {"text": "xss scripting"})
        out = payload(result)  # isError FALSE: honest status, not a crash
        assert out["status"] == "disabled"
        assert out["reason"] == "store-missing"
        assert out["matches"] == []

    def test_corrupt_store_returns_disabled_envelope(self, mcp_env, tmp_path):
        corrupt = tmp_path / "corrupt.sqlite"
        corrupt.write_bytes(b"not a database at all " * 50)
        cfg = dict(mcp_env["config"])
        cfg["db"] = {"store_path": str(corrupt)}
        server = McpServer(project_root=mcp_env["project_root"], config=cfg,
                           query_api_factory=mcp_env["query_api_factory"])
        out = payload(call(server, "vuln_query", {"text": "xss scripting"}))
        assert out["status"] == "disabled"
        assert out["reason"] == "store-corrupt"

    def test_embedder_down_returns_skipped_envelope(self, server, mcp_env):
        mcp_env["embedder"].fail = True
        out = payload(call(server, "vuln_query",
                           {"text": "reflected scripting"}))
        assert out["status"] == "skipped"
        assert out["reason"] == "embed-failed"
        assert out["matches"] == []
        # recovery: the next call works again (no global disable)
        mcp_env["embedder"].fail = False
        out = payload(call(server, "vuln_query",
                           {"text": "reflected scripting"}))
        assert out["status"] == "ok"
        assert out["matches"]

    def test_engine_absent_is_honest_status_not_fake_empty(self, mcp_env):
        def absent_factory(_config):
            raise ImportError("vulndog.engine unavailable (test)")

        server = McpServer(project_root=mcp_env["project_root"],
                           config=mcp_env["config"],
                           query_api_factory=absent_factory)
        out = payload(call(server, "vuln_query", {"text": "xss"}))
        assert out["status"] == "disabled"
        assert out["reason"] == "engine-unavailable"
        assert out["matches"] == []


class TestHighlights:
    def test_default_is_latest_run(self, server, mcp_env):
        out = payload(call(server, "highlights"))
        assert out["run_id"] == mcp_env["newer"].hunt_id
        assert out["total"] == 3
        assert len(out["highlights"]) == 3
        row = out["highlights"][0]
        assert row["record_id"] == "CVE-2024-1000"
        assert row["hunt_id"] == mcp_env["newer"].hunt_id

    def test_explicit_run_id(self, server, mcp_env):
        out = payload(call(server, "highlights",
                           {"run_id": mcp_env["older"].hunt_id}))
        assert out["run_id"] == mcp_env["older"].hunt_id
        assert out["total"] == 2

    def test_last_n_takes_the_tail(self, server, mcp_env):
        out = payload(call(server, "highlights", {"last_n": 2}))
        assert out["total"] == 3
        assert out["returned"] == 2
        urls = [h["url"] for h in out["highlights"]]
        assert urls == [highlight_row(1, mcp_env["newer"].hunt_id)["url"],
                        highlight_row(2, mcp_env["newer"].hunt_id)["url"]]

    def test_unknown_run_id_clear_answer(self, server):
        text = error_text(call(server, "highlights",
                               {"run_id": "19700101-000000"}))
        assert "19700101-000000" in text

    def test_path_traversal_run_id_rejected(self, server):
        # Pin the BOUNDARY rejection (invalid run_id), not just any error:
        # without the regex guard the id would fall through to the
        # unknown-run lookup (W4-M6 mutant survived the weaker assertion).
        text = error_text(call(server, "highlights",
                               {"run_id": "../../etc"}))
        assert "invalid run_id" in text
        text = error_text(call(server, "highlights", {"run_id": "a/b"}))
        assert "invalid run_id" in text

    def test_no_runs_clear_answer(self, mcp_env, tmp_path):
        empty = tmp_path / "empty-project"
        empty.mkdir()
        server = McpServer(project_root=empty, config=mcp_env["config"],
                           query_api_factory=mcp_env["query_api_factory"])
        text = error_text(call(server, "highlights"))
        assert "no runs" in text.lower()

    def test_run_without_highlights_file(self, server, mcp_env):
        (mcp_env["newer"].path / "highlights.jsonl").unlink()
        text = error_text(call(server, "highlights"))
        assert "highlights.jsonl" in text

    def test_bad_last_n_is_tool_error(self, server):
        error_text(call(server, "highlights", {"last_n": 0}))
        error_text(call(server, "highlights", {"last_n": "two"}))

    def test_corrupt_row_is_skipped_and_counted(self, server, mcp_env):
        path = mcp_env["newer"].path / "highlights.jsonl"
        path.write_text(path.read_text(encoding="utf-8")
                        + "{broken json\n", encoding="utf-8")
        out = payload(call(server, "highlights"))
        assert out["total"] == 3
        assert out["skipped_lines"] == 1


class TestRunStatus:
    def test_latest_run_snapshot(self, server, mcp_env):
        out = payload(call(server, "run_status"))
        assert out["hunt_id"] == mcp_env["newer"].hunt_id
        assert out["mode"] == "capture"
        assert out["alive"] is True  # meta pid == this test process
        assert out["counters"]["events"] == 12
        assert out["paths"]["run_dir"] == str(mcp_env["newer"].path)
        assert "config" in out

    def test_no_runs_clear_answer(self, mcp_env, tmp_path):
        empty = tmp_path / "empty-project"
        empty.mkdir()
        server = McpServer(project_root=empty, config=mcp_env["config"],
                           query_api_factory=mcp_env["query_api_factory"])
        text = error_text(call(server, "run_status"))
        assert "no runs" in text.lower()

    def test_unreadable_meta_is_reported_not_raised(self, server, mcp_env):
        (mcp_env["newer"].path / "watchdog-run.json").write_text(
            "{broken", encoding="utf-8")
        out = payload(call(server, "run_status"))
        assert out["hunt_id"] == mcp_env["newer"].hunt_id
        assert out["meta_error"]
        assert out["alive"] is False


class TestRunStatusConfigRedaction:
    """P2-04 regression (probe A14): run_status must never serve
    secret-shaped config values to the AI agent. The persist-side fix
    (cli _meta_payload) belongs to the CLI owner; this pins the MCP
    serving door — the snapshot shape stays, secret values do not."""

    def _plant_config(self, mcp_env, config):
        meta_path = mcp_env["newer"].path / "watchdog-run.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        meta["config"] = config
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

    def test_secret_values_never_served(self, server, mcp_env):
        self._plant_config(mcp_env, {
            "runs": {"dir": "runs"},
            "ai": {"provider": "custom",
                   "api_key": "SHOULD_NOT_LEAK_12345",
                   "base_url": "http://127.0.0.1:11434"},
            "proxy": {"client_token": "tok-abc123"},
            "custom": {"password": "hunter2",
                       "nested": {"client_secret": "s3cret"}},
        })
        out = payload(call(server, "run_status"))
        blob = json.dumps(out)
        for secret in ("SHOULD_NOT_LEAK_12345", "tok-abc123",
                       "hunter2", "s3cret"):
            assert secret not in blob
        cfg = out["config"]
        assert cfg["ai"]["api_key"] == "<redacted>"
        assert cfg["proxy"]["client_token"] == "<redacted>"
        assert cfg["custom"]["password"] == "<redacted>"
        assert cfg["custom"]["nested"]["client_secret"] == "<redacted>"
        # non-secret values pass through verbatim (contract preserved)
        assert cfg["ai"]["base_url"] == "http://127.0.0.1:11434"
        assert cfg["ai"]["provider"] == "custom"
        assert cfg["runs"] == {"dir": "runs"}

    def test_non_secret_snapshot_unchanged(self, server, mcp_env):
        out = payload(call(server, "run_status"))
        assert out["config"] == {"runs": {"dir": "runs"}}

    def test_key_spelling_variants_masked(self, server, mcp_env):
        self._plant_config(mcp_env, {
            "X-API-Key": "k1", "APIKEY": "k2", "refresh_token": "k3",
            "private_key": "k4", "db": {"store_path": "/tmp/vulnkb.sqlite"},
        })
        cfg = payload(call(server, "run_status"))["config"]
        assert cfg["X-API-Key"] == "<redacted>"
        assert cfg["APIKEY"] == "<redacted>"
        assert cfg["refresh_token"] == "<redacted>"
        assert cfg["private_key"] == "<redacted>"
        assert cfg["db"]["store_path"] == "/tmp/vulnkb.sqlite"

    def test_non_string_secret_values_masked_fail_closed(self, server,
                                                        mcp_env):
        self._plant_config(mcp_env, {"api_key": 12345,
                                     "token": ["a", "b"]})
        cfg = payload(call(server, "run_status"))["config"]
        assert cfg["api_key"] == "<redacted>"
        assert cfg["token"] == "<redacted>"

    def test_secrets_inside_lists_masked(self, server, mcp_env):
        self._plant_config(mcp_env, {
            "providers": [{"name": "p1", "api_key": "list-secret"}],
        })
        out = payload(call(server, "run_status"))
        assert "list-secret" not in json.dumps(out)
        assert out["config"]["providers"][0]["api_key"] == "<redacted>"
        assert out["config"]["providers"][0]["name"] == "p1"