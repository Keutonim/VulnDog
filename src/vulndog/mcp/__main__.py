"""``python -m vulndog.mcp`` — stdio MCP server entry point."""
from __future__ import annotations

from vulndog.mcp import main

if __name__ == "__main__":
    raise SystemExit(main())