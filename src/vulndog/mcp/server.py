"""MCP wire layer: raw JSON-RPC 2.0 over stdio (ADR-5, docs/MCP.md).

Stdlib-only, stdio-only in v1 — no HTTP/SSE listener (recorded security
boundary: the server is reachable only by the process that spawned it).
Newline-delimited JSON: one message per line, one response per request,
NO response for notifications. Lines are volume-bounded
(MAX_STDIN_LINE_CHARS, P2-02): an over-cap line is refused with
INVALID_REQUEST and drained, never buffered whole. Unknown method -> a
proper JSON-RPC error envelope; the loop never crashes and never stays
silent on a request.

Envelope law:
  request  {"jsonrpc":"2.0","id":...,"method":...,"params":{...}}
  result   {"jsonrpc":"2.0","id":...,"result":{...}}
  error    {"jsonrpc":"2.0","id":...,"error":{"code":...,"message":...}}

Tool-level failures (bad arguments, unknown tool, missing artifact) are
MCP results with isError:true — the protocol envelope stays successful.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vulndog import runs
from vulndog.mcp import artifacts
from vulndog.mcp.tools import (TOOL_DEFINITIONS, TOOL_HANDLERS, ToolContext,
                               ToolError)

PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
SERVER_NAME = "vulndog"
RUN_URI_PREFIX = "vulndog://runs/"

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

# P2-02: the ONE per-line volume cap for the stdio loop. 1 Mi characters
# (~1 MB for ASCII JSON-RPC) — two orders of magnitude above the 8 KB
# vuln_query text cap (room for any legal message), yet a single hostile
# multi-GB line can no longer be read fully into memory before parsing
# (security probe A26). An over-cap line is answered with INVALID_REQUEST
# (id null — it was never parsed) and its remainder is drained in bounded
# chunks; the loop stays alive. readline(size) is deliberate: it returns
# as soon as a newline arrives, so an interactive pipe never blocks
# waiting for a full read chunk.
MAX_STDIN_LINE_CHARS = 1_048_576


def _error(rid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": code, "message": message}}


def _result(rid, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": rid, "result": result}


def _tool_error_result(rid, message: str) -> dict:
    return _result(rid, {"content": [{"type": "text", "text": message}],
                         "isError": True})


def _tool_ok_result(rid, payload: dict) -> dict:
    return _result(rid, {
        "content": [{"type": "text",
                     "text": json.dumps(payload, ensure_ascii=False)}],
        "isError": False})


class McpServer:
    """Dispatch table + handler context for one stdio session."""

    def __init__(self, project_root: Path, config: dict,
                 query_api_factory=None) -> None:
        self.ctx = ToolContext(project_root, config, query_api_factory)
        self.tool_handlers = dict(TOOL_HANDLERS)

    # ------------------------------------------------------------- dispatch

    def handle_message(self, msg) -> dict | None:
        """One parsed JSON-RPC message -> response dict, or None for a
        notification. Never raises."""
        if not isinstance(msg, dict):
            return _error(None, INVALID_REQUEST, "request must be an object")
        rid = msg.get("id")
        method = msg.get("method")
        if not isinstance(method, str):
            return _error(rid, INVALID_REQUEST, "missing method string")
        is_notification = "id" not in msg
        params = msg.get("params")
        if params is None:
            params = {}
        if not isinstance(params, dict):
            if is_notification:
                return None
            return _error(rid, INVALID_PARAMS, "params must be an object")

        if is_notification:
            # notifications/initialized, notifications/cancelled, unknown:
            # a notification never receives a response (JSON-RPC law).
            return None

        if method == "initialize":
            return _result(rid, self._initialize(params))
        if method == "ping":
            return _result(rid, {})
        if method == "tools/list":
            return _result(rid, {"tools": TOOL_DEFINITIONS})
        if method == "tools/call":
            return self._tools_call(rid, params)
        if method == "resources/list":
            return _result(rid, {"resources": self._resources_list()})
        if method == "resources/read":
            return self._resources_read(rid, params)
        return _error(rid, METHOD_NOT_FOUND, f"unknown method: {method}")

    # ------------------------------------------------------------- methods

    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS \
            else PROTOCOL_VERSION
        from vulndog import __version__

        return {
            "protocolVersion": version,
            "capabilities": {"tools": {}, "resources": {}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
        }

    def _tools_call(self, rid, params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str):
            return _error(rid, INVALID_PARAMS,
                          "tools/call requires a string 'name'")
        args = params.get("arguments", {})
        if not isinstance(args, dict):
            return _error(rid, INVALID_PARAMS, "arguments must be an object")
        handler = self.tool_handlers.get(name)
        if handler is None:
            return _tool_error_result(rid, f"unknown tool: {name}")
        try:
            payload = handler(self.ctx, args)
        except ToolError as exc:
            return _tool_error_result(rid, str(exc))
        except Exception as exc:  # noqa: BLE001 — the loop must survive
            print(f"vulndog mcp: tool {name} failed: {exc!r}",
                  file=sys.stderr)
            return _error(rid, INTERNAL_ERROR, "internal tool error")
        return _tool_ok_result(rid, payload)

    def _resources_list(self) -> list[dict]:
        return [
            {"uri": f"{RUN_URI_PREFIX}{run.hunt_id}",
             "name": run.hunt_id,
             "description": f"Run folder artifacts for {run.hunt_id}",
             "mimeType": "application/json"}
            for run in runs.list_runs(self.ctx.project_root,
                                      self.ctx.runs_dir)
        ]

    def _resources_read(self, rid, params: dict) -> dict:
        uri = params.get("uri")
        if not isinstance(uri, str) or not uri.startswith(RUN_URI_PREFIX):
            return _error(rid, INVALID_PARAMS,
                          f"uri must start with {RUN_URI_PREFIX}")
        run_id = uri[len(RUN_URI_PREFIX):]
        if not runs.RUN_NAME_RE.match(run_id):
            return _error(rid, INVALID_PARAMS, f"invalid run id: {run_id!r}")
        run = artifacts.find_run(self.ctx.project_root, self.ctx.runs_dir,
                                 run_id)
        if run is None:
            return _error(rid, INVALID_PARAMS, f"unknown run: {run_id}")
        payload = {"run_id": run.hunt_id, "run_dir": str(run.path),
                   "artifacts": artifacts.list_artifacts(run)}
        return _result(rid, {"contents": [
            {"uri": uri, "mimeType": "application/json",
             "text": json.dumps(payload, ensure_ascii=False)}]})


# ------------------------------------------------------------------- stdio

def process_line(line: str, server: McpServer) -> str | None:
    """One stdin line -> one stdout line (or None: blank / notification)."""
    if not line.strip():
        return None
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return json.dumps(_error(None, PARSE_ERROR, "invalid JSON"))
    resp = server.handle_message(msg)
    return None if resp is None else json.dumps(resp, ensure_ascii=False)


def _read_bounded_line(stdin, max_chars: int) -> tuple[str, bool]:
    """One stdin line, volume-bounded (P2-02). Returns (line, over_cap).

    Reads at most max_chars + 1 characters: a result shorter than that,
    or ending in a newline, is a complete within-cap line. Otherwise the
    line is over cap — its remainder is DRAINED in bounded chunks (never
    buffered whole) so the next message starts on a clean line boundary.
    EOF mid-line returns the partial tail as a normal line.
    """
    limit = max_chars + 1
    line = stdin.readline(limit)
    if len(line) < limit or line.endswith("\n"):
        return line, False
    while True:
        rest = stdin.readline(limit)
        if not rest or rest.endswith("\n"):
            break
    return line, True


def serve(stdin, stdout, server: McpServer) -> None:
    """The stdio loop: read a bounded line, answer a line, stay alive."""
    while True:
        line, over_cap = _read_bounded_line(stdin, MAX_STDIN_LINE_CHARS)
        if not line:
            break  # EOF
        if over_cap:
            print(f"vulndog mcp: stdin line over {MAX_STDIN_LINE_CHARS} "
                  "chars; refused", file=sys.stderr)
            out = json.dumps(_error(
                None, INVALID_REQUEST,
                f"message exceeds the {MAX_STDIN_LINE_CHARS}-character "
                "line limit"))
        else:
            try:
                out = process_line(line, server)
            except Exception as exc:  # noqa: BLE001 — never crash the loop
                print(f"vulndog mcp: dispatch failure: {exc!r}",
                      file=sys.stderr)
                out = json.dumps(_error(None, INTERNAL_ERROR,
                                        "internal error"))
        if out is not None:
            stdout.write(out + "\n")
            stdout.flush()


# -------------------------------------------------------------------- entry

def main(argv: list[str] | None = None, *, config_loader=None) -> int:
    """``python -m vulndog.mcp`` — the interim Phase-2 entry point
    (docs/MCP.md; the ``vulndog mcp`` CLI wiring belongs to the CLI owner).

    Config comes through the pinned VulnDog contract
    (vulndog.config.load_config: engine merge -> gap-fill -> CLI layer);
    there are no MCP-specific config keys.
    """
    parser = argparse.ArgumentParser(
        prog="vulndog.mcp",
        description="VulnDog MCP server — raw JSON-RPC 2.0 over stdio "
                    "(tools: vuln_query, highlights, run_status).")
    parser.add_argument("--project", default=".",
                        help="project root; run folders live under its "
                             "runs.dir (default: current directory)")
    parser.add_argument("--config", default=None, help="config JSON path")
    parser.add_argument("--task", default=None, help="per-run task entry key")
    parser.add_argument("--store", default=None,
                        help="vulnkb.sqlite path (overrides db.store_path)")
    args = parser.parse_args(argv)

    from vulndog import config as config_layer

    overrides = {"db": {"store_path": args.store}} if args.store else None
    try:
        cfg = config_layer.load_config(path=args.config, task_id=args.task,
                                       overrides=overrides,
                                       loader=config_loader)
    except config_layer.EngineUnavailableError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    server = McpServer(project_root=Path(args.project).resolve(), config=cfg)
    try:
        serve(sys.stdin, sys.stdout, server)
    except KeyboardInterrupt:
        pass
    return 0