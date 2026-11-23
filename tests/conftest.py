"""Shared pytest fixtures and the src-layout import seam.

MERGE NOTE (tech-lead, candidate branch): the pre-merge version of this
file installed a SYNTHETIC ``vulndog`` package module whose ``__path__``
pointed at this worktree's ``src/vulndog``, so the CLI half could be
tested while the engine half did not exist yet. Its own docstring made
that seam conditional: "until the halves merge". The halves ARE merged
now, and keeping the seam was a live defect:

  * the real ``src/vulndog/__init__.py`` never executed in the merged
    test session (proved by mutation: deleting ``__version__`` from it
    left all 706 tests green);
  * every ``vulndog.*`` entry (including ``vulndog.engine``) was purged
    from ``sys.modules`` mid-session.

So the seam is replaced by a plain path bootstrap: ``src/`` goes on
``sys.path`` and the REAL merged package is imported. The suite now
covers the package root (including ``vulndog.engine``) the same way the
installed product does. The editable install (``pip install -e .``) makes
this a no-op.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def project_root(tmp_path: Path) -> Path:
    """A fake project root: run folders must land inside it, never in CWD."""
    return tmp_path / "project"


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 10, 23, 8, 55, 1)
