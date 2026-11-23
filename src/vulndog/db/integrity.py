"""Store resolution + integrity for `vulndog db` (M3.1).

Wraps the engine's read side (store.open_store / read_manifest) — never
rewrites it. The db layer adds ONE artifact the engine manifest cannot
carry: the sha256 of the swapped store FILE (the engine builds its
manifest before the atomic swap, so the file hash cannot live inside
it). ``stamp_store_digest`` records it in manifest.json right after a
successful build; ``verify_store`` re-hashes the file and reconciles the
counts, so a tampered store fails loud.

Pure stdlib. No network, no embedding — this module only reads.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from vulndog.engine import corpus, store

#: GitHub release-asset cap (PLAN.md M3.1 c4 / ADR-7: the 1.93 GiB full
#: store "barely fits the ~2 GiB release-asset cap — verified at release
#: time"). The dry-run checks the artifact against this gate.
RELEASE_ASSET_MAX_BYTES = 2 * 1024 ** 3

#: documented store resolution root (PLAN.md repo layout: data/vulnkb/
#: is the "store resolution root (seed or full, ADR-7)").
PROJECT_STORE_RELPATH = os.path.join("data", "vulnkb", store.STORE_FILENAME)


class DbError(RuntimeError):
    """Store/manifest unreadable — reported, never a silent pass."""


def sha256_file(path: str) -> str:
    """Streamed sha256 (1 MiB blocks — the 1.93 GiB store never loads
    into memory)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def manifest_path_for(store_path: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(store_path)),
                        store.MANIFEST_FILENAME)


def load_manifest_file(store_path: str) -> dict:
    """manifest.json beside the store (the build's convenience artifact,
    extended by the db layer with the store-file digest)."""
    path = manifest_path_for(store_path)
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as exc:
        raise DbError(f"cannot read manifest {path}: {exc}") from exc


def stamp_store_digest(store_dir: str) -> dict:
    """After a successful engine build: record the swapped store file's
    sha256 + size in manifest.json (atomic write via the engine's own
    writer). The meta-embedded manifest stays the engine's untouched
    version stamp; the file digest is the db layer's tamper gate."""
    store_path = os.path.join(store_dir, store.STORE_FILENAME)
    manifest = load_manifest_file(store_path)
    manifest["store"] = {
        "sha256": sha256_file(store_path),
        "size_bytes": os.path.getsize(store_path),
    }
    corpus.write_manifest_atomic(manifest_path_for(store_path), manifest)
    return manifest


def resolve_store_path(cfg: dict, project_root: Path) -> tuple[str, str]:
    """Tiered store resolution (docs/VULNERABILITY-DB.md). Returns
    (path, source); source in {config, project-data, engine-default,
    default-missing}. An explicit store argument is handled by the
    caller BEFORE this function (it always wins).

    Order: configured db.store_path -> the project data/vulnkb store
    root (the documented seed/full location) -> the engine default
    store path. Nothing exists -> the documented root with source
    "default-missing" so the caller can explain how to build one.
    """
    configured = (cfg.get("db") or {}).get("store_path")
    if configured:
        return os.fspath(configured), "config"
    project_store = Path(project_root) / PROJECT_STORE_RELPATH
    if project_store.exists():
        return str(project_store), "project-data"
    if os.path.exists(store.DEFAULT_STORE_PATH):
        return store.DEFAULT_STORE_PATH, "engine-default"
    return str(project_store), "default-missing"


def _db_counts(conn) -> dict:
    by_kind = {kind: n for kind, n in conn.execute(
        "SELECT kind, COUNT(*) FROM records GROUP BY kind ORDER BY kind")}
    return {
        "records_total": conn.execute(
            "SELECT COUNT(*) FROM records").fetchone()[0],
        "chunks_total": conn.execute(
            "SELECT COUNT(*) FROM chunks").fetchone()[0],
        "records_by_kind": by_kind,
    }


def store_info(store_path: str) -> dict:
    """Manifest/record breakdown of a built store. Raises DbError /
    store.StoreError when the store or its meta manifest is unusable."""
    conn = store.open_store(store_path)
    try:
        manifest = store.read_manifest(conn)
        if manifest is None:
            raise DbError(f"store meta carries no manifest: {store_path}")
        db_counts = _db_counts(conn)
        row = conn.execute(
            "SELECT value FROM meta WHERE key='corpus_version'").fetchone()
        meta_cv = row[0] if row else None
    finally:
        conn.close()
    recipe = manifest.get("recipe") or {}
    # W8-D1: the store-file digest is stamped into the FILE manifest after
    # the engine's atomic swap — the meta-embedded manifest predates the
    # swap and never carries it. Source the stamp from the file manifest;
    # an absent/unreadable file manifest means "not stamped" (info still
    # serves the breakdown from the meta manifest alone).
    try:
        file_manifest = load_manifest_file(store_path)
    except DbError:
        file_manifest = {}
    return {
        "store_path": os.path.abspath(store_path),
        "store_bytes": os.path.getsize(store_path),
        "store_sha256": (file_manifest.get("store") or {}).get("sha256"),
        "corpus_version": manifest.get("corpus_version"),
        "meta_corpus_version": meta_cv,
        "stage": manifest.get("stage"),
        "recipe_id": recipe.get("recipe_id"),
        "recipe_version": recipe.get("recipe_version"),
        "created_at": manifest.get("created_at"),
        "counts": manifest.get("counts") or {},
        "db_counts": db_counts,
        "inputs": {name: {"sha256": fp.get("sha256"),
                          "size_bytes": fp.get("size_bytes")}
                   for name, fp in (manifest.get("inputs") or {}).items()},
        "manifest_path": manifest_path_for(store_path),
    }


def verify_store(store_path: str) -> dict:
    """The integrity gate: manifest sha256 + counts vs the store.
    Result-based — every failure class is a named check, never an
    exception and never a silent pass. ok=False on ANY failed check."""
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    try:
        conn = store.open_store(store_path)
    except store.StoreError as exc:
        add("store-open", False, f"{exc.reason}: {exc.detail}")
        return {"ok": False, "checks": checks,
                "store_path": os.path.abspath(store_path)}
    add("store-open", True)
    try:
        try:
            manifest = load_manifest_file(store_path)
        except DbError as exc:
            add("manifest-present", False, str(exc))
            return {"ok": False, "checks": checks,
                    "store_path": os.path.abspath(store_path)}
        add("manifest-present", True)

        # 1. store-file sha256 (the db layer's tamper gate)
        recorded = (manifest.get("store") or {}).get("sha256")
        if not recorded:
            add("store-sha256", False,
                "manifest carries no store.sha256 (pre-M3.1 build? "
                "rebuild with vulndog db build)")
        else:
            actual = sha256_file(store_path)
            add("store-sha256", actual == recorded,
                f"expected {recorded}, got {actual}")

        # 2. corpus_version: manifest vs the store's own meta stamp
        meta = store.read_manifest(conn)
        meta_cv = (meta or {}).get("corpus_version")
        add("corpus-version", bool(manifest.get("corpus_version"))
            and manifest.get("corpus_version") == meta_cv,
            f"manifest={manifest.get('corpus_version')} meta={meta_cv}")

        # 3. counts: manifest vs live DB rows
        db_counts = _db_counts(conn)
        counts = manifest.get("counts") or {}
        for key in ("records_total", "chunks_total"):
            add(f"count-{key}", counts.get(key) == db_counts[key],
                f"manifest={counts.get(key)} store={db_counts[key]}")
        # a kind the recipe considered but included ZERO of is absent
        # from the DB's GROUP BY — normalize zero entries on both sides
        manifest_kinds = {k: v for k, v in
                          (counts.get("records_by_kind") or {}).items() if v}
        store_kinds = {k: v for k, v in
                       db_counts["records_by_kind"].items() if v}
        add("count-records_by_kind", manifest_kinds == store_kinds,
            f"manifest={manifest_kinds} store={store_kinds}")
    finally:
        conn.close()
    return {"ok": all(c["ok"] for c in checks), "checks": checks,
            "store_path": os.path.abspath(store_path),
            "corpus_version": manifest.get("corpus_version")}


def release_asset_report(store_path: str) -> dict:
    """Release-asset dry-run payload (PLAN.md M3.1 c4): the artifact,
    its sha256 + size, and the <2 GiB gate result. No upload ever."""
    if not os.path.exists(store_path):
        raise DbError(f"store not found: {store_path}")
    size = os.path.getsize(store_path)
    return {
        "artifact": os.path.abspath(store_path),
        "sha256": sha256_file(store_path),
        "size_bytes": size,
        "size_gib": round(size / 1024 ** 3, 3),
        "gate_max_bytes": RELEASE_ASSET_MAX_BYTES,
        "gate_ok": size < RELEASE_ASSET_MAX_BYTES,
    }