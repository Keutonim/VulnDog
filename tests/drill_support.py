"""Support for the M1.4 end-to-end drill (tests/test_drill.py).

The subprocess CLI leg runs ``python -m vulndog run`` for real. To keep
the drill OFFLINE and deterministic (brief H1: no network egress, stub
embedder), the drill prepends this directory AND tests/drill_site/ to
the subprocess PYTHONPATH; CPython then imports drill_site/sitecustomize
at interpreter startup, which calls install_stub_embedder() below. The
query side's transient-embedder FACTORY is replaced with a fixed-vector
stub before any product code runs. No product file is patched on disk;
the mutation is process-local and dies with the subprocess.

The fixture KB is built with the engine's own StagedStore + chunker
(same code path as a real build, tiny corpus).
"""
from __future__ import annotations

import os


def install_stub_embedder() -> None:
    """Replace the query-side embedder factory with the offline stub.

    Guarded by VULNDOG_DRILL_STUB=1 so an accidental PYTHONPATH entry
    can never silence a real run's embedder.
    """
    if os.environ.get("VULNDOG_DRILL_STUB") != "1":
        return
    from vulndog.engine import query as qy
    from vulndog.engine.tests.test_api import E1, StubEmbedder

    qy.make_transient_embedder = lambda cache_dir=None: StubEmbedder(E1)


def build_drill_store(path: str) -> str:
    """Tiny deterministic KB via the engine's own staged builder."""
    from vulndog.engine.tests.test_api import build_fixture_store

    return build_fixture_store(path)