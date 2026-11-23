"""pytest path bootstrap for the vendored engine suite.

Makes ``src/`` importable so ``python -m pytest src/vulndog/engine/tests``
collects standalone from the repo root WITHOUT a prior install (the
editable install ``pip install -e . --no-deps`` also works and makes this
a no-op). Kept inside engine/tests/ -- the repo-root tests/ tree belongs
to the CLI half and is not touched here.
"""
from __future__ import annotations

import os
import sys

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                 os.pardir))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)