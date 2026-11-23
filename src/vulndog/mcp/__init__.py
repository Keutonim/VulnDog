"""VulnDog MCP server (PLAN.md M2.3, docs/MCP.md, ADR-5).

Raw JSON-RPC 2.0 over stdio, stdlib only. Exposes the knowledge base and
run artifacts as agent-ready tools: vuln_query, highlights, run_status,
plus run-dir resources. Interim entry: ``python -m vulndog.mcp``.
"""
from __future__ import annotations

from vulndog.mcp.server import McpServer, main, serve

__all__ = ["McpServer", "main", "serve"]