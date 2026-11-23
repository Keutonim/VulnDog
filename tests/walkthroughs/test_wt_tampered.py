"""Walkthrough case 4 — tampered archives (docs/VULNERABILITY-DB.md).

The documented fail-loud law (Step 1): "a tampered archive fails the
build — a missing expected edition inside the OWASP zip, for example,
aborts with a nonzero exit, never a silent partial store." The documented
exit law: `db build` surfaces the engine build exit codes verbatim
(0 ok / 2 input / 3 aborted / 4 embed-blocked / 5 store).

Every probe runs on FIXTURE COPIES of the mini archives — never the real
~1.93 GiB store. The stranger runs the shipped `vulndog db` surface.
"""
from __future__ import annotations

import json
import zipfile

import pytest

from vulndog import cli
from vulndog.engine import build as bd
from tests.db_fixture import build_fixture_store, text_vector


# ------------------------------------------------------------------ helpers

def _drop_edition(raw, edition):
    """Rewrite the mini Top10 zip without one expected edition."""
    p = raw / "Top10-master.zip"
    with zipfile.ZipFile(p) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    with zipfile.ZipFile(p, "w") as zf:
        for n, b in members.items():
            if f"/{edition}/" not in n:
                zf.writestr(n, b)


def _truncate(raw, name):
    p = raw / name
    p.write_bytes(p.read_bytes()[: p.stat().st_size // 2])


def _no_xml_cwe(raw):
    with zipfile.ZipFile(raw / "cwec_latest.xml.zip", "w") as zf:
        zf.writestr("cwec/README.txt", "not xml")


def _dry(raw, tmp_path, capsys):
    # --project is a top-level db flag (docs: global flags precede the
    # subcommand, whose flag surface is owned by vulndog.db.cli)
    code = cli.main(["db", "--project", str(tmp_path), "build",
                     "--raw-dir", str(raw), "--dry-run"])
    out = capsys.readouterr()
    summary = json.loads(out.out) if out.out.strip() else {}
    return code, summary, out.err


# ------------------------------------------- fail-loud: missing OWASP edition

def test_missing_owasp_edition_fails_loud_dry_run(wt_raw, tmp_path, capsys):
    """Docs Step 1's own example: a missing expected edition aborts with
    a nonzero exit — never a silent partial store (GAP-4)."""
    _drop_edition(wt_raw, "2025")
    code, summary, _ = _dry(wt_raw, tmp_path, capsys)
    assert code == 2, f"silent partial build: {summary}"
    msg = summary.get("message", "")
    assert "2025" in msg and "edition" in msg.lower(), msg


def test_missing_owasp_edition_fails_loud_real_build(wt_raw, tmp_path,
                                                     capsys):
    """Same law on the real (non-dry) build: input exit 2, no store."""
    _drop_edition(wt_raw, "2021")
    out_dir = tmp_path / "out"
    code = cli.main(["db", "build", "--raw-dir", str(wt_raw),
                     "--output", str(out_dir),
                     "--embed-max-retries", "0",
                     "--embed-retry-backoff", "0"])
    capsys.readouterr()
    assert code == 2
    assert not (out_dir / "vulnkb.sqlite").exists()


# ------------------------------------------- fail-loud: structural tampering

@pytest.mark.parametrize("tamper", [
    lambda raw: _truncate(raw, "cvelistV5-main.zip"),
    lambda raw: _truncate(raw, "Top10-master.zip"),
    _no_xml_cwe,
], ids=["truncated-cvelistV5", "truncated-top10", "cwe-without-xml"])
def test_structural_tamper_is_input_exit_2(wt_raw, tmp_path, capsys, tamper):
    """A corrupt archive is an INPUT error (exit 2) with the engine's
    clear message — never a raw traceback (GAP-5, documented exit law)."""
    tamper(wt_raw)
    code, summary, _ = _dry(wt_raw, tmp_path, capsys)
    assert code == 2, f"expected input exit 2, got {code}: {summary}"
    assert "input error" in summary.get("message", "").lower()


@pytest.mark.parametrize("tamper", [
    lambda raw: _drop_edition(raw, "2025"),
    lambda raw: _truncate(raw, "cvelistV5-main.zip"),
    _no_xml_cwe,
], ids=["missing-edition", "truncated-zip", "cwe-without-xml"])
def test_engine_run_build_returns_input_code_never_raises(wt_raw, tmp_path,
                                                          tamper):
    """Engine seam: run_build NEVER raises for handled input failures —
    the summary carries exit_code 2 (build.py's own contract)."""
    tamper(wt_raw)
    summary = bd.run_build("slice", raw_dir=str(wt_raw),
                           store_dir=str(tmp_path / "store"),
                           dry_run=True, embed_max_retries=0,
                           embed_retry_backoff_s=0, log=lambda m: None)
    assert summary["exit_code"] == bd.EXIT_INPUT, summary["message"]
    assert summary["message"]


def test_engine_real_build_missing_edition_no_swap(wt_raw, tmp_path):
    """Real build, missing edition: exit 2, destination untouched."""
    _drop_edition(wt_raw, "2025")
    dest = tmp_path / "store"
    summary = bd.run_build("slice", raw_dir=str(wt_raw),
                           store_dir=str(dest),
                           embedder=lambda texts: [text_vector(t)
                                                   for t in texts],
                           embed_max_retries=0, embed_retry_backoff_s=0,
                           log=lambda m: None)
    assert summary["exit_code"] == bd.EXIT_INPUT
    assert not (dest / "vulnkb.sqlite").exists()


# ------------------------------------------- already-documented input law

def test_missing_archive_file_is_input_exit_2(wt_raw, tmp_path, capsys):
    (wt_raw / "exploitdb-main.zip").unlink()
    code, summary, _ = _dry(wt_raw, tmp_path, capsys)
    assert code == 2
    assert "missing archives" in summary.get("message", "")


def test_fresh_edition_builds_with_new_corpus_version(wt_raw, tmp_path,
                                                      capsys):
    """No pinned-hash allowlist: a fresh edition (different sha256) is
    the documented refresh path — it builds, with a new corpus_version
    (the determinism law: recipe + input sha256s -> version)."""
    _, base, _ = _dry(wt_raw, tmp_path, capsys)
    with zipfile.ZipFile(wt_raw / "cvelistV5-main.zip", "a") as zf:
        zf.writestr("cvelistV5-main/cves/2026/0xxx/CVE-2026-99999.json",
                    json.dumps({"cveMetadata": {"cveId": "CVE-2026-99999",
                                                "state": "RESERVED"}}))
    code, fresh, _ = _dry(wt_raw, tmp_path, capsys)
    assert code == 0
    assert fresh["corpus_version"] != base["corpus_version"]


# ------------------------------------------- tampered STORE (verify gate)

def test_pristine_fixture_store_verifies(wt_raw, tmp_path, capsys):
    store_dir = tmp_path / "kb"
    summary = build_fixture_store(wt_raw, store_dir)
    assert summary["exit_code"] == 0, summary["message"]
    code = cli.main(["db", "verify", str(store_dir / "vulnkb.sqlite")])
    out = capsys.readouterr()
    assert code == 0
    assert "PASS" in out.out


def test_tampered_store_fails_verify_loud(wt_raw, tmp_path, capsys):
    """Docs Step 3: a tampered store fails verify with a nonzero exit."""
    store_dir = tmp_path / "kb"
    assert build_fixture_store(wt_raw, store_dir)["exit_code"] == 0
    src = store_dir / "vulnkb.sqlite"
    data = bytearray(src.read_bytes())
    data[len(data) // 2] ^= 0x01
    tampered = store_dir / "tampered.sqlite"
    tampered.write_bytes(bytes(data))
    code = cli.main(["db", "verify", str(tampered)])
    out = capsys.readouterr()
    assert code == 1
    assert "FAIL" in out.out + out.err