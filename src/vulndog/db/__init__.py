"""VulnDog vulnerability-DB management (M3.1, PLAN.md R8).

`vulndog db` wraps the vendored engine's proven build/store machinery
(ADR-1: wrap, never rewrite) behind a product CLI surface:

  build   corpus build from the 4 raw archives (EmbedBlocked law surfaced)
  info    manifest / record breakdown of a built store
  verify  manifest sha256 + counts vs the store (tamper gate)
  --release-asset-dry-run   artifact + sha256 + the <2 GiB asset gate

The db wrapper itself never touches the engine's corpus default:
DEFAULT_RAW_DIR (corpus.py) is None per FINAL-01, and builds require an
explicit --raw-dir passed through the build CLI arg surface. Store resolution follows the
documented tiered order (docs/VULNERABILITY-DB.md): explicit store wins,
then db.store_path, then the project data/vulnkb store root (seed or
full), then the engine default; nothing found -> actionable build help.
"""
from vulndog.db.cli import main

__all__ = ["main"]