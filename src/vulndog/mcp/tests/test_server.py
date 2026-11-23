"""Wire-contract tests for the MCP JSON-RPC dispatcher (M2.3).

Drives McpServer.handle_message / process_line in-process: the envelope
law (jsonrpc 2.0, id, result/error), the handshake, the exact tool set,
and the never-crash / never-silence rules for malformed input.
"""
from __future__ import annotations

import io
import json

import pytest

from vulndog.mcp.server import McpServer, process_line, serve

DOCUMENTED_TOOLS = {"vuln_query", "highlights", "run_status"}


class ChunkStream:
    """Text-stream double serving scripted chunks through readline(size)
    — models a pipe without materializing a hostile multi-MB line in the
    test process. Faithful TextIOWrapper.readline(size) semantics: at
    most size chars, up to and including the first newline. An unbounded
    readline request fails the test (that is the P2-02 OOM vector)."""

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._buf = ""
        self._eof = False
        self.max_requested = 0

    def __iter__(self):
        # real text streams are iterable too (line by line, unbounded)
        while True:
            line = self.readline(1 << 30)
            if not line:
                return
            yield line

    def readline(self, size=-1):
        if size is None or size < 0:
            raise AssertionError("unbounded readline requested")
        self.max_requested = max(self.max_requested, size)
        while len(self._buf) < size and "\n" not in self._buf \
                and not self._eof:
            try:
                self._buf += next(self._chunks)
            except StopIteration:
                self._eof = True
        nl = self._buf.find("\n")
        if nl != -1 and nl < size:
            out, self._buf = self._buf[:nl + 1], self._buf[nl + 1:]
        else:
            out, self._buf = self._buf[:size], self._buf[size:]
        return out


def huge_line_chunks(total, chunk=65536):
    """One 'B'*total line + newline, produced chunk by chunk."""
    full, rem = divmod(total, chunk)
    for _ in range(full):
        yield "B" * chunk
    if rem:
        yield "B" * rem
    yield "\n"


@pytest.fixture()
def server(mcp_env):
    return McpServer(project_root=mcp_env["project_root"],
                     config=mcp_env["config"],
                     query_api_factory=mcp_env["query_api_factory"])


def call(server, name, arguments=None, rid=1):
    params = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    return server.handle_message(
        {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
         "params": params})


class TestHandshake:
    def test_initialize_result_shape(self, server):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05",
                       "capabilities": {},
                       "clientInfo": {"name": "pytest", "version": "0"}}})
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        result = resp["result"]
        assert result["protocolVersion"] == "2024-11-05"
        assert result["serverInfo"]["name"] == "vulndog"
        assert "tools" in result["capabilities"]
        assert "resources" in result["capabilities"]

    def test_initialize_unknown_version_falls_back_to_supported(self, server):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "1999-01-01"}})
        assert resp["result"]["protocolVersion"] == "2024-11-05"

    def test_initialized_notification_has_no_response(self, server):
        assert server.handle_message(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None

    def test_ping(self, server):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 7, "method": "ping"})
        assert resp["result"] == {}


class TestToolList:
    def test_exact_documented_tool_set(self, server):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = resp["result"]["tools"]
        assert {t["name"] for t in tools} == DOCUMENTED_TOOLS
        for tool in tools:
            assert tool["description"].strip()
            assert tool["inputSchema"]["type"] == "object"

    def test_vuln_query_schema_documents_params(self, server):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool = next(t for t in resp["result"]["tools"]
                    if t["name"] == "vuln_query")
        props = tool["inputSchema"]["properties"]
        assert set(props) == {"text", "top_k", "floor", "filters"}
        assert tool["inputSchema"]["required"] == ["text"]


class TestErrorEnvelopes:
    def test_unknown_method_error_envelope(self, server):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 9, "method": "bogus/method"})
        assert resp["id"] == 9
        assert resp["error"]["code"] == -32601
        assert resp["error"]["message"]
        assert "result" not in resp

    def test_server_stays_alive_after_unknown_method(self, server):
        server.handle_message(
            {"jsonrpc": "2.0", "id": 9, "method": "bogus/method"})
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 10, "method": "tools/list"})
        assert {t["name"] for t in resp["result"]["tools"]} == DOCUMENTED_TOOLS

    def test_invalid_request_missing_method(self, server):
        resp = server.handle_message({"jsonrpc": "2.0", "id": 3})
        assert resp["error"]["code"] == -32600

    def test_non_object_message(self, server):
        resp = server.handle_message([1, 2, 3])
        assert resp["error"]["code"] == -32600

    def test_non_object_params_rejected(self, server):
        for params in ([], "x", 5):
            resp = server.handle_message(
                {"jsonrpc": "2.0", "id": 3, "method": "tools/list",
                 "params": params})
            assert resp["error"]["code"] == -32602, params

    def test_parse_error_line(self, server):
        out = process_line("{not json", server)
        resp = json.loads(out)
        assert resp["error"]["code"] == -32700
        assert resp["id"] is None

    def test_empty_line_is_silence_not_crash(self, server):
        assert process_line("", server) is None
        assert process_line("   ", server) is None

    def test_notification_never_gets_a_response(self, server):
        assert process_line(
            '{"jsonrpc":"2.0","method":"notifications/initialized"}',
            server) is None

    def test_unknown_tool_is_tool_level_error(self, server):
        resp = call(server, "no_such_tool", {})
        assert resp["result"]["isError"] is True
        assert "no_such_tool" in resp["result"]["content"][0]["text"]

    def test_tools_call_missing_name(self, server):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"arguments": {}}})
        assert resp["error"]["code"] == -32602

    def test_handler_exception_becomes_internal_error(self, server, monkeypatch):
        def boom(_args):
            raise RuntimeError("injected handler failure")

        monkeypatch.setitem(server.tool_handlers, "run_status", boom)
        resp = call(server, "run_status", {})
        assert resp["error"]["code"] == -32603
        assert "injected handler failure" not in resp["error"]["message"]


class TestResources:
    def test_resources_list_run_dirs(self, server, mcp_env):
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 5, "method": "resources/list"})
        resources = resp["result"]["resources"]
        uris = {r["uri"] for r in resources}
        assert f"vulndog://runs/{mcp_env['older'].hunt_id}" in uris
        assert f"vulndog://runs/{mcp_env['newer'].hunt_id}" in uris
        for r in resources:
            assert r["mimeType"] == "application/json"

    def test_resources_read_listing(self, server, mcp_env):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 6, "method": "resources/read",
            "params": {"uri": f"vulndog://runs/{mcp_env['newer'].hunt_id}"}})
        contents = resp["result"]["contents"]
        assert contents[0]["mimeType"] == "application/json"
        payload = json.loads(contents[0]["text"])
        names = {a["name"] for a in payload["artifacts"]}
        assert "highlights.jsonl" in names
        assert "watchdog-run.json" in names

    def test_resources_read_unknown_uri(self, server):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 6, "method": "resources/read",
            "params": {"uri": "vulndog://runs/19700101-000000"}})
        assert resp["error"]["code"] == -32602

    def test_resources_read_foreign_scheme(self, server):
        resp = server.handle_message({
            "jsonrpc": "2.0", "id": 6, "method": "resources/read",
            "params": {"uri": "file:///etc/passwd"}})
        assert resp["error"]["code"] == -32602


class TestBoundedStdin:
    """P2-02 regression: the stdio loop reads bounded lines (probe A26 —
    a single multi-MB line was read fully into memory before parsing).

    Contract: a line over MAX_STDIN_LINE_CHARS is answered with one
    JSON-RPC INVALID_REQUEST (id null — the line was never parsed), its
    remainder is drained WITHOUT buffering it whole, and the loop keeps
    answering the next messages. readline(size) is the mechanism: it
    stays responsive on a pipe (a chunked read(n) would block until the
    chunk fills and deadlock an interactive session).
    """

    CAP = 1048576

    def _responses(self, server, stdin):
        out = io.StringIO()
        serve(stdin, out, server)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_over_cap_line_refused_then_loop_continues(self, server):
        stdin = ChunkStream([
            *huge_line_chunks(self.CAP + 1),
            '{"jsonrpc":"2.0","id":7,"method":"ping"}\n',
        ])
        responses = self._responses(server, stdin)
        assert len(responses) == 2
        assert responses[0]["id"] is None
        assert responses[0]["error"]["code"] == -32600
        assert str(self.CAP) in responses[0]["error"]["message"]
        assert responses[1] == {"jsonrpc": "2.0", "id": 7, "result": {}}
        # the reader never asked for an unbounded line, and never
        # buffered more than the cap plus one read chunk
        assert stdin.max_requested <= self.CAP + 1

    def test_over_cap_line_at_eof_without_newline(self, server):
        # drop the trailing newline chunk: EOF terminates the hostile line
        chunks = list(huge_line_chunks(self.CAP + 100))[:-1]
        stdin = ChunkStream(chunks)
        responses = self._responses(server, stdin)
        assert len(responses) == 1
        assert responses[0]["error"]["code"] == -32600

    def test_repeated_over_cap_lines_each_refused(self, server):
        stdin = ChunkStream([
            *huge_line_chunks(self.CAP + 1),
            '{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
            *huge_line_chunks(self.CAP + 2),
            '{"jsonrpc":"2.0","id":2,"method":"ping"}\n',
        ])
        responses = self._responses(server, stdin)
        assert [r.get("id") for r in responses] == [None, 1, None, 2]
        assert responses[0]["error"]["code"] == -32600
        assert responses[2]["error"]["code"] == -32600

    def test_at_cap_valid_message_still_processed(self, server):
        # exactly CAP chars incl. newline: a legal (if padded) request
        pad = self.CAP - len('{"jsonrpc":"2.0","id":5,"method":"ping",'
                             '"params":{"pad":""}}') - 1
        line = ('{"jsonrpc":"2.0","id":5,"method":"ping","params":'
                '{"pad":"' + "B" * pad + '"}}\n')
        assert len(line) == self.CAP
        responses = self._responses(server, io.StringIO(line))
        assert responses == [{"jsonrpc": "2.0", "id": 5, "result": {}}]

    def test_normal_lines_unchanged(self, server):
        stdin = io.StringIO(
            '\n'
            '{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
            '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
            '{not json\n'
            '{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
        responses = self._responses(server, stdin)
        assert [r.get("id") for r in responses] == [1, None, 2]
        assert responses[1]["error"]["code"] == -32700