"""Test child process: the REAL McpServer + serve loop over stdio, with
the embedder injected through the engine's documented offline seam
(``config["embedder"]``, engine/api.py). Config still resolves through
the pinned VulnDog contract (vulndog.config.load_config).

Why this exists: the vendored EmbeddingClient is loopback-only by
construction (one constant address, ai.base_url wiring is M2.4), so an
offline deterministic ok-path cannot run through the real Ollama client.
The engine's own suite injects a fixed-vector embedder the same way;
this child applies that discipline to the wire tests. The production
entry (python -m vulndog.mcp) is exercised separately by the KB-down
conformance test, where no embedder call happens.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from vulndog.mcp.tests.conftest import FixedEmbedder, unit


def main() -> int:
    parser = argparse.ArgumentParser(prog="vulndog-mcp-stdio-child")
    parser.add_argument("--project", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--store", default=None,
                        help="db.store_path CLI override (file product "
                             "keys apply only after config v2 / M2.1)")
    parser.add_argument("--vector", default="1,0,0,0",
                        help="comma-separated fixed query vector")
    args = parser.parse_args()

    from vulndog import config as config_layer
    from vulndog.mcp.server import McpServer, serve

    overrides = {"db": {"store_path": args.store}} if args.store else None
    cfg = config_layer.load_config(path=args.config, overrides=overrides)
    cfg["embedder"] = FixedEmbedder(
        unit(*(float(x) for x in args.vector.split(","))))
    server = McpServer(project_root=Path(args.project).resolve(), config=cfg)
    serve(sys.stdin, sys.stdout, server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())