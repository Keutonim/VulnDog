"""VulnDog -- observing proxy + offline vulnerability-KB watchdog.

Minimal package marker: version only, no side effects, no imports of
the CLI half (vulndog.cli/config/proxy/runs are owned separately).
"""
from __future__ import annotations

__version__ = "0.1.0"