"""MERGE CONTRACT TEST — the package root of the MERGED tree.

The pinned contract says (dev-a brief, step 8): ``src/vulndog/__init__.py``
is minimal — ``__version__``, no side effects, no imports of the CLI half's
modules. Pre-merge that was dev-a's file alone; post-merge it is the root
of BOTH halves, so its contract is a merge-level contract and needs a
regression lock.

This file also carries the regression test for merge defect #1: the
pre-merge ``tests/conftest.py`` installed a SYNTHETIC ``vulndog`` package
module, so the real ``src/vulndog/__init__.py`` never executed in the
merged test session (mutation-proved: removing ``__version__`` left all
706 tests green). ``test_package_root_is_the_real_module`` pins that the
real module is the one under test.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

import vulndog


def test_package_root_is_the_real_module():
    """The package under test must be the real src/vulndog/__init__.py."""
    assert vulndog.__file__ is not None, (
        "vulndog is a synthetic module (no __file__): the merged suite is "
        "not exercising the real package root")
    assert vulndog.__file__.endswith(
        ("src/vulndog/__init__.py", "src\\vulndog\\__init__.py")), vulndog.__file__


def test_version_is_present_and_well_formed():
    assert isinstance(vulndog.__version__, str)
    assert re.match(r"^\d+\.\d+", vulndog.__version__), vulndog.__version__


def test_package_root_has_no_side_effects():
    """Importing the root must not pull in the CLI half."""
    import os

    code = (
        "import sys; import vulndog; "
        "print(sorted(m for m in sys.modules "
        "if m.startswith('vulndog.')))"
    )
    env = dict(os.environ)
    # the child needs the same src/ the suite uses
    src = str(Path(vulndog.__file__).resolve().parents[1])
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, encoding="utf-8", errors="replace", env=env)
    assert out.returncode == 0, out.stderr
    imported = out.stdout.strip()
    assert "vulndog.cli" not in imported, (
        f"importing the package root pulled in the CLI half: {imported}")
    assert "vulndog.proxy" not in imported
    assert "vulndog.runs" not in imported
    assert "vulndog.config" not in imported


def _repo_root() -> Path:
    return Path(vulndog.__file__).resolve().parents[2]


def test_license_file_and_pyproject_field_present():
    """B3 (fix-round-1): a public release needs a LICENSE and a
    machine-readable license declaration. MIT is the PROVISIONAL
    default (owner GAP-1 decision still open — VENDORING.md records
    the provisional status)."""
    import tomllib

    root = _repo_root()
    license_path = root / "LICENSE"
    assert license_path.is_file(), "no LICENSE file at the repo root"
    text = license_path.read_text(encoding="utf-8")
    assert "MIT License" in text
    assert "WITHOUT WARRANTY" in text.upper()

    pyproject = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8"))
    lic = pyproject["project"]["license"]
    # FINAL-02: PEP 639 SPDX string form, not the deprecated TOML table
    # (setuptools>=77; the table form stops being supported 2027-02-18).
    # MIT stays PROVISIONAL (owner GAP-1 decision still open).
    assert isinstance(lic, str), \
        f"license must be an SPDX string (FINAL-02), got {lic!r}"
    assert lic == "MIT", f"pyproject license field: {lic!r}"
    license_files = pyproject["project"].get("license-files", [])
    assert "LICENSE" in license_files, \
        f"license-files must list LICENSE (FINAL-02): {license_files!r}"


def test_vendoring_provenance_manifest_complete():
    """B3: every vendored runtime file carries a sha256 in the
    VENDORING.md provenance manifest (source path + extraction date +
    authorship statement are already in the record)."""
    root = _repo_root()
    vend = (root / "src" / "vulndog" / "engine" / "VENDORING.md") \
        .read_text(encoding="utf-8")
    assert "sha256" in vend.lower()
    assert "provisional" in vend.lower()
    engine = root / "src" / "vulndog" / "engine"
    runtime_files = sorted(engine.glob("*.py")) + sorted(
        (engine / "data").glob("*.json"))
    for path in runtime_files:
        if path.name == "api.py":      # VulnDog facade, NOT vendored
            continue
        assert path.name in vend, f"no provenance entry for {path.name}"
    # the manifest must carry REAL hashes of the shipped bytes.
    # Hash basis = committed LF bytes: core.autocrlf checkouts
    # materialize CRLF in the worktree, so normalize before hashing
    # (VENDORING.md provenance manifest states the same basis).
    # W10 merge-fix: check EVERY manifest row's vendored hash, not just
    # one file — a behavior edit to a vendored module must update its
    # row (ADR-1 delta bookkeeping), never leave a stale "identical".
    import hashlib
    import re
    rows = re.findall(
        r"^\|\s*`([^`]+)`\s*\|\s*`([0-9a-f]{64})`\s*\|\s*"
        r"`([0-9a-f]{64})`\s*\|\s*([^|]+?)\s*\|\s*$",
        vend, re.MULTILINE)
    assert rows, "no provenance manifest rows parsed"
    seen = set()
    for name, vendored_sha, _upstream_sha, _status in rows:
        path = engine / name
        assert path.is_file(), f"manifest row for missing file {name}"
        canonical = path.read_bytes().replace(b"\r\n", b"\n")
        digest = hashlib.sha256(canonical).hexdigest()
        assert digest == vendored_sha, (
            f"manifest hash != shipped file bytes for {name} "
            f"(stale row: update the vendored sha256 + status, ADR-1)")
        seen.add(name)
    for path in runtime_files:
        if path.name == "api.py":
            continue
        rel = path.relative_to(engine).as_posix()
        assert rel in seen, f"no manifest row for {rel}"


def test_vendored_tests_excluded_from_distribution():
    """R2-G: the vendored engine test package must not ship in the
    wheel/sdist (supply-chain hygiene for an OSS release). The built
    archives are verified by listing their contents (gates-phase2.md,
    fix-round-2); this pins the packaging decision against regression.
    The vendored benchmark helpers (benchutil/tap_sim) STAY — they are
    documented kept modules in the VENDORING.md provenance manifest."""
    import tomllib

    root = _repo_root()
    pyproject = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8"))
    find = pyproject["tool"]["setuptools"]["packages"]["find"]
    exclude = find.get("exclude", [])
    assert any(p.startswith("vulndog.engine.tests") for p in exclude), \
        f"packages.find does not exclude the vendored tests: {exclude}"


def test_mcp_tests_excluded_from_distribution():
    """R2-G law extended to the M2.3 test package (M2.5 carry-over):
    vulndog.mcp.tests* never ships in the wheel/sdist — same supply-chain
    hygiene as the vendored engine tests."""
    import tomllib

    root = _repo_root()
    pyproject = tomllib.loads(
        (root / "pyproject.toml").read_text(encoding="utf-8"))
    find = pyproject["tool"]["setuptools"]["packages"]["find"]
    exclude = find.get("exclude", [])
    assert any(p.startswith("vulndog.mcp.tests") for p in exclude), \
        f"packages.find does not exclude the MCP tests: {exclude}"


def test_engine_half_is_importable_from_the_merged_package():
    """Both halves must coexist in one tree (the merge acceptance test)."""
    import vulndog.cli  # noqa: F401
    import vulndog.config  # noqa: F401
    import vulndog.proxy  # noqa: F401
    import vulndog.runs  # noqa: F401
    from vulndog.engine import api, event_schema, run  # noqa: F401

    assert callable(api.analyze_run)
    assert callable(run.load_config)
    assert event_schema.EVENT_FIELDS
