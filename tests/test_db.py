"""M3.1 `vulndog db` — build/info/verify/dry-run + store resolution (dev-h).

Contract under test (brief dev-h, PLAN.md M3.1):
- build wraps the engine build through its CLI-arg surface; the tiny
  fixture (4 mini archives, engine recipe machinery) builds a store +
  manifest carrying sha256 + counts + corpus_version;
- determinism: two builds of the same inputs -> same corpus_version;
- EmbedBlocked law surfaced: an unreachable embedder -> nonzero exit +
  explicit message, never a silent partial build;
- verify: manifest sha256 + counts vs the store; a bit-flipped store
  copy FAILS loud (nonzero);
- resolution: --store/positional wins; db.store_path next; default ->
  the documented data/vulnkb store root; nothing found -> actionable
  build instructions, never a silent None;
- release-asset dry-run: artifact + sha256 + the <2 GiB gate result.

All offline: the embedder double rides the engine's transport seam.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from vulndog import cli
from vulndog.engine import store as st

from db_fixture import FakeTransport, build_fixture_store, make_raw_dir

from vulndog.engine import embed_client as ec

# captured BEFORE any patch: the real urllib transport, restored by the
# EmbedBlocked test to exercise a genuine connection-refused outage.
_REAL_TRANSPORT = ec._default_transport


@pytest.fixture(autouse=True)
def _offline_embedder(monkeypatch):
    """Every db build in this module rides the fake transport — never
    the owner's live Ollama (deterministic vectors, zero network)."""
    monkeypatch.setattr(ec, "_default_transport", FakeTransport())


# --------------------------------------------------------------- fixtures


@pytest.fixture
def raw_dir(tmp_path):
    return make_raw_dir(tmp_path)


@pytest.fixture
def built_store(tmp_path, raw_dir):
    """A tiny store built through the engine runner (fixture machinery)."""
    store_dir = tmp_path / "kb"
    summary = build_fixture_store(raw_dir, store_dir)
    assert summary["exit_code"] == 0, summary["message"]
    return store_dir


def _flip_store_byte(store_dir: Path) -> Path:
    """Copy the store and flip one bit deep in the file (past the SQLite
    header, so the DB still opens but the bytes differ)."""
    src = store_dir / st.STORE_FILENAME
    data = bytearray(src.read_bytes())
    pos = len(data) // 2
    data[pos] ^= 0x01
    tampered = store_dir / "tampered.sqlite"
    tampered.write_bytes(bytes(data))
    return tampered


# ------------------------------------------------------------------ build


def test_db_build_fixture_store_and_manifest(tmp_path, raw_dir, capsys):
    out_dir = tmp_path / "out"
    code = cli.main(["db", "build", "--raw-dir", str(raw_dir),
                     "--output", str(out_dir)])
    assert code == 0
    assert (out_dir / st.STORE_FILENAME).exists()
    manifest = json.loads(
        (out_dir / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert manifest["corpus_version"].startswith("vkb1-")
    assert manifest["counts"]["records_total"] > 0
    assert manifest["counts"]["chunks_total"] > 0
    # every input archive carries its sha256
    for name in ("cvelistV5", "exploitdb", "cwec", "top10"):
        assert len(manifest["inputs"][name]["sha256"]) == 64
    # the db layer stamps the STORE sha256 (verify's tamper gate)
    assert len(manifest["store"]["sha256"]) == 64
    assert manifest["store"]["size_bytes"] == (
        out_dir / st.STORE_FILENAME).stat().st_size


def test_db_build_determinism_same_corpus_version(tmp_path, raw_dir):
    a, b = tmp_path / "a", tmp_path / "b"
    assert cli.main(["db", "build", "--raw-dir", str(raw_dir),
                     "--output", str(a)]) == 0
    assert cli.main(["db", "build", "--raw-dir", str(raw_dir),
                     "--output", str(b)]) == 0
    ma = json.loads((a / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    mb = json.loads((b / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert ma["corpus_version"] == mb["corpus_version"]
    assert ma["counts"] == mb["counts"]
    # the deterministic PAYLOAD is identical row-for-row (the meta
    # built_at timestamp is the engine's documented non-deterministic
    # field, so raw file bytes are not compared)
    def rows(store_dir):
        conn = sqlite3.connect(str(store_dir / st.STORE_FILENAME))
        try:
            return (conn.execute("SELECT * FROM records ORDER BY id").fetchall(),
                    conn.execute(
                        "SELECT * FROM chunks ORDER BY record_id, part").fetchall())
        finally:
            conn.close()
    assert rows(a) == rows(b)


def test_db_build_missing_archives_nonzero(tmp_path, capsys):
    empty = tmp_path / "empty"
    empty.mkdir()
    code = cli.main(["db", "build", "--raw-dir", str(empty),
                     "--output", str(tmp_path / "out")])
    assert code != 0
    captured = capsys.readouterr()
    assert "missing archives" in captured.out + captured.err


def test_db_build_embed_blocked_nonzero_loud(tmp_path, raw_dir, capsys,
                                             monkeypatch):
    """EmbedBlocked law surfaced: no working embedder -> nonzero exit +
    explicit message; no store is left behind (never a partial build).

    Deterministic offline outage: the REAL urllib transport is restored
    and the engine's loopback Ollama endpoint constant is pointed at a
    CLOSED loopback port (connection refused, no traffic leaves the
    machine); the retry budget is zero. This does not depend on whether
    the owner's Ollama happens to be up.
    """
    monkeypatch.setattr(ec, "_default_transport", _REAL_TRANSPORT)
    monkeypatch.setattr(ec, "OLLAMA_BASE_URL", "http://127.0.0.1:9")
    out_dir = tmp_path / "out"
    code = cli.main(["db", "build", "--raw-dir", str(raw_dir),
                     "--output", str(out_dir),
                     "--embed-max-retries", "0",
                     "--embed-retry-backoff", "0"])
    assert code != 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "ollama unreachable" in text.lower()
    assert not (out_dir / st.STORE_FILENAME).exists()


def test_db_build_full_stage_fixture(tmp_path, raw_dir):
    out_dir = tmp_path / "full"
    code = cli.main(["db", "build", "--raw-dir", str(raw_dir),
                     "--output", str(out_dir), "--stage", "full"])
    assert code == 0
    manifest = json.loads(
        (out_dir / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert manifest["stage"] == "full"
    # the full recipe keeps the RESERVED record store-only
    assert manifest["counts"]["records_excluded_store_only"] >= 1


# ------------------------------------------------------------------- info


def test_db_info_fixture(built_store, capsys):
    code = cli.main(["db", "info", str(built_store / st.STORE_FILENAME)])
    assert code == 0
    out = capsys.readouterr().out
    assert "corpus_version" in out
    assert "vkb1-" in out
    assert "records" in out


def test_db_info_json_matches_manifest(built_store, capsys):
    code = cli.main(["db", "info", str(built_store / st.STORE_FILENAME),
                     "--json"])
    assert code == 0
    info = json.loads(capsys.readouterr().out)
    manifest = json.loads(
        (built_store / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    assert info["corpus_version"] == manifest["corpus_version"]
    assert info["counts"]["records_total"] == manifest["counts"]["records_total"]
    assert info["db_counts"]["records_total"] == manifest["counts"]["records_total"]
    assert info["db_counts"]["chunks_total"] == manifest["counts"]["chunks_total"]


def test_db_info_missing_store_nonzero(tmp_path, capsys):
    code = cli.main(["db", "info", str(tmp_path / "nope.sqlite")])
    assert code != 0
    assert "error" in capsys.readouterr().err.lower()


# ----------------------------------------------------------------- verify


def test_db_verify_fixture_passes(built_store, capsys):
    code = cli.main(["db", "verify", str(built_store / st.STORE_FILENAME)])
    assert code == 0
    out = capsys.readouterr().out
    assert "PASS" in out


def test_db_verify_tampered_store_fails_loud(built_store, capsys):
    tampered = _flip_store_byte(built_store)
    code = cli.main(["db", "verify", str(tampered)])
    assert code != 0
    captured = capsys.readouterr()
    assert "FAIL" in captured.out + captured.err
    assert "sha256" in (captured.out + captured.err).lower()


def test_db_verify_count_mismatch_fails(built_store, capsys):
    """A structurally sound store whose counts disagree with the
    manifest must fail verify (the counts gate, not just the hash)."""
    conn = sqlite3.connect(str(built_store / st.STORE_FILENAME))
    conn.execute("DELETE FROM chunks WHERE rowid = "
                 "(SELECT MAX(rowid) FROM chunks)")
    conn.commit()
    conn.close()
    code = cli.main(["db", "verify", str(built_store / st.STORE_FILENAME)])
    assert code != 0
    assert "FAIL" in capsys.readouterr().out


def test_db_verify_missing_manifest_fails(built_store, capsys):
    (built_store / st.MANIFEST_FILENAME).unlink()
    code = cli.main(["db", "verify", str(built_store / st.STORE_FILENAME)])
    assert code != 0
    assert "FAIL" in capsys.readouterr().out


def test_db_verify_missing_store_nonzero(tmp_path, capsys):
    code = cli.main(["db", "verify", str(tmp_path / "nope.sqlite")])
    assert code != 0


# ------------------------------------------------------------- resolution


def test_resolution_positional_store_wins(tmp_path, built_store, capsys):
    # a config pointing elsewhere must not override the explicit store
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({
        "defaults": {"db": {"store_path": str(tmp_path / "other.sqlite")}}}),
        encoding="utf-8")
    code = cli.main(["db", "--config", str(cfg_file),
                     "info", str(built_store / st.STORE_FILENAME), "--json"])
    assert code == 0
    info = json.loads(capsys.readouterr().out)
    assert info["store_path"] == str(built_store / st.STORE_FILENAME)


def test_resolution_config_store_path(tmp_path, built_store, capsys):
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(json.dumps({
        "defaults": {"db": {"store_path": str(built_store / st.STORE_FILENAME)}}}),
        encoding="utf-8")
    code = cli.main(["db", "--config", str(cfg_file),
                     "--project", str(tmp_path), "verify"])
    assert code == 0
    assert "PASS" in capsys.readouterr().out


def test_resolution_default_finds_project_data_vulnkb(tmp_path, raw_dir,
                                                      capsys):
    """db.store_path null + a store at the documented data/vulnkb root
    (the seed/full store location, PLAN.md repo layout) resolves to it."""
    store_dir = tmp_path / "data" / "vulnkb"
    summary = build_fixture_store(raw_dir, store_dir)
    assert summary["exit_code"] == 0
    code = cli.main(["db", "--project", str(tmp_path), "verify"])
    assert code == 0
    assert "PASS" in capsys.readouterr().out


def test_resolution_no_store_explains_build(tmp_path, capsys):
    """Nothing configured, nothing on disk: the resolution must explain
    how to build a store — never a silent None or a fake pass."""
    code = cli.main(["db", "--project", str(tmp_path), "info"])
    assert code != 0
    err = capsys.readouterr().err
    assert "vulndog db build" in err
    assert "--raw-dir" in err


# ---------------------------------------------------- release-asset dry-run


def test_release_asset_dry_run_lists_artifact_sha_gate(built_store, capsys):
    code = cli.main(["db", "--release-asset-dry-run",
                     str(built_store / st.STORE_FILENAME)])
    assert code == 0
    out = capsys.readouterr().out
    assert st.STORE_FILENAME in out
    assert "sha256" in out.lower()
    assert "2 GiB" in out
    assert "PASS" in out  # the tiny fixture is far below the cap


def test_release_asset_dry_run_oversize_gate_fails(tmp_path, built_store,
                                                   capsys, monkeypatch):
    """The gate is a real comparison, not a constant: an artifact over
    the cap must report FAIL and exit nonzero."""
    from vulndog.db import integrity

    monkeypatch.setattr(integrity, "RELEASE_ASSET_MAX_BYTES", 1)
    code = cli.main(["db", "--release-asset-dry-run",
                     str(built_store / st.STORE_FILENAME)])
    assert code != 0
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_release_asset_dry_run_missing_store_nonzero(tmp_path, capsys):
    code = cli.main(["db", "--release-asset-dry-run",
                     str(tmp_path / "nope.sqlite")])
    assert code != 0


# ------------------------------------------------------------- cli wiring


def test_db_help_lists_commands(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["db", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for word in ("build", "info", "verify", "--release-asset-dry-run"):
        assert word in out


def test_db_no_args_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main(["db"])
    assert exc.value.code == 2


def test_db_unknown_flag_is_usage_error():
    with pytest.raises(SystemExit) as exc:
        cli.main(["db", "info", "--bogus"])
    assert exc.value.code == 2


def test_db_bad_config_shape_is_usage_error(tmp_path, capsys):
    """Wrong-typed product config fails fast with a usage exit (the
    same law as run/status) — never a raw traceback."""
    cfg_file = tmp_path / "bad.json"
    cfg_file.write_text(json.dumps(
        {"defaults": {"db": {"store_path": 123}}}), encoding="utf-8")
    code = cli.main(["db", "--config", str(cfg_file), "info"])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


# ------------------------------------------- W8 merge-fix D1 regression


def test_db_info_reports_stamped_store_sha256(built_store, capsys):
    """W8-D1: the store-file digest is stamped into the FILE manifest
    after the engine's atomic swap (the meta-embedded manifest predates
    the swap and cannot carry it). info must report the stamped sha256,
    never '(not stamped)' right after a successful build."""
    store_path = str(built_store / st.STORE_FILENAME)
    manifest = json.loads(
        (built_store / st.MANIFEST_FILENAME).read_text(encoding="utf-8"))
    code = cli.main(["db", "info", store_path, "--json"])
    assert code == 0
    info = json.loads(capsys.readouterr().out)
    assert info["store_sha256"] == manifest["store"]["sha256"]
    # the human surface reports it too (the user-visible defect line)
    code = cli.main(["db", "info", store_path])
    assert code == 0
    out = capsys.readouterr().out
    assert manifest["store"]["sha256"] in out
    assert "(not stamped)" not in out


def test_db_info_without_file_manifest_still_works(built_store, capsys):
    """W8-D1 fallback pin: the meta manifest alone still serves the
    breakdown when manifest.json is absent — info must not crash and
    reports no stamp (honest None, never a fabricated digest)."""
    (built_store / st.MANIFEST_FILENAME).unlink()
    code = cli.main(["db", "info",
                     str(built_store / st.STORE_FILENAME), "--json"])
    assert code == 0
    info = json.loads(capsys.readouterr().out)
    assert info["store_sha256"] is None
    assert info["corpus_version"]
    assert info["db_counts"]["records_total"] > 0


# ------------------------------------ UX-3: --store alias on info/verify


def test_ux3_db_info_store_flag_alias(built_store, capsys):
    """UX-3: db info accepts --store (consistent with run/mcp), not only
    the positional form. The flag resolves to the same explicit store."""
    code = cli.main(["db", "info", "--store",
                     str(built_store / st.STORE_FILENAME), "--json"])
    assert code == 0, capsys.readouterr().err
    info = json.loads(capsys.readouterr().out)
    assert info["store_path"] == str(built_store / st.STORE_FILENAME)


def test_ux3_db_verify_store_flag_alias(built_store, capsys):
    """UX-3: db verify accepts --store too."""
    code = cli.main(["db", "verify", "--store",
                     str(built_store / st.STORE_FILENAME)])
    assert code == 0, capsys.readouterr().err
    assert "PASS" in capsys.readouterr().out


def test_ux3_db_info_positional_still_works(built_store, capsys):
    """Backward compatibility: the shipped positional form is unchanged."""
    code = cli.main(["db", "info",
                     str(built_store / st.STORE_FILENAME), "--json"])
    assert code == 0
    info = json.loads(capsys.readouterr().out)
    assert info["store_path"] == str(built_store / st.STORE_FILENAME)