"""Shared fixtures for the M3.4 stranger walkthroughs (dev-j).

These tests ARE the documented extension paths, executed exactly as
docs/VULNERABILITY-DB.md / docs/CONFIGURATION.md / docs/MCP.md instruct,
on tiny offline fixtures. No network egress; the real ~1.93 GiB store is
never touched. In-process builds ride the engine transport seam (the
same offline pattern as tests/test_db.py); subprocess strangers only
exercise paths that never embed (dry-run, missing store, denial legs).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

WT = Path(__file__).resolve().parents[2]
for _p in (str(WT), str(WT / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from vulndog.engine import embed_client as ec  # noqa: E402
from tests.db_fixture import FakeTransport, make_raw_dir  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_embedder(monkeypatch):
    """Every in-process build rides the fake transport — never a live
    Ollama (deterministic vectors, zero network)."""
    monkeypatch.setattr(ec, "_default_transport", FakeTransport())


@pytest.fixture
def wt_raw(tmp_path):
    """The four mini archives (engine fixture machinery) in a fresh dir."""
    return make_raw_dir(tmp_path)