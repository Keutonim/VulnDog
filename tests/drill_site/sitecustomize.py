"""Startup hook for the drill's subprocess CLI leg (see drill_support).

Imported automatically by CPython's site machinery because the drill
puts this directory on PYTHONPATH. Activates only under the explicit
VULNDOG_DRILL_STUB=1 guard inside install_stub_embedder.
"""
from drill_support import install_stub_embedder

install_stub_embedder()