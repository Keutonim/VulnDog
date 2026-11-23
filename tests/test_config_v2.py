"""M2.1 config system v2 — F-1 closure, precedence, discovery, engine laws.

F-1 (QA round 1): every product key (proxy.*, scope.*, runs.*, db.*, ai.*)
set in a --config file was quarantined into ``_unknown_keys`` by the
engine's known-key merge and NEVER applied — a config file could not even
restrict scope. These tests feed REAL config files through the REAL engine
merge (``vulndog.engine.run.load_config`` — the single door) and assert the
product keys take effect, while the engine's proven laws stay verbatim:
never-crash on a broken file, unknown-key isolation, and the precedence
builtin < file defaults < per-run override < CLI.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulndog import cli, config
from vulndog.engine import run as engine_run

# Every product key M2.1 wires, with a non-default probe value per layer.
# (dotted key, builtin, file-defaults value, per-run value, CLI value)
PRECEDENCE_CASES = [
    ("proxy.host", "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"),
    ("proxy.port", 8080, 9001, 9002, 9003),
    ("scope.in", [], ["file.example"], ["task.example"], ["cli.example"]),
    ("scope.out", [], ["file.out"], ["task.out"], ["cli.out"]),
    ("runs.dir", "runs", "runs-file", "runs-task", "runs-cli"),
    ("db.store_path", None, "file.sqlite", "task.sqlite", "cli.sqlite"),
    ("ai.provider", "ollama", "custom", "ollama", "custom"),
    ("ai.base_url", "http://127.0.0.1:11434",
     "http://127.0.0.1:11500", "http://127.0.0.1:11501",
     "http://127.0.0.1:11502"),
    ("ai.model", "embeddinggemma:300m", "model-file", "model-task",
     "model-cli"),
    ("ai.dims", 768, 512, 256, 128),
    ("ai.doc_prefix", "title: none | text: ", "doc-file: ", "doc-task: ",
     "doc-cli: "),
    ("ai.query_prefix", "task: search result | query: ", "query-file: ",
     "query-task: ", "query-cli: "),
    ("ai.timeout_s", None, 5.0, 6.0, 7.0),
]


def _dig(cfg: dict, dotted: str):
    node = cfg
    for part in dotted.split("."):
        node = node[part]
    return node


def _nest(dotted: str, value) -> dict:
    parts = dotted.split(".")
    node: dict = {parts[-1]: value}
    for part in reversed(parts[:-1]):
        node = {part: node}
    return node


def _write_cfg(path: Path, defaults: dict, tasks: dict | None = None) -> Path:
    path.write_text(json.dumps({"config_version": 1, "defaults": defaults,
                                "tasks": tasks or {}}), encoding="utf-8")
    return path


# ------------------------------------------------------- F-1: keys APPLY


def test_f1_full_config_file_applies_every_product_key(tmp_path):
    """The F-1 acceptance: a full config file applies EVERY product key.

    Before M2.1 the engine merge quarantined proxy/scope/runs/db/ai into
    _unknown_keys, so this file changed nothing. Now each key takes effect
    through the same merge function, and none is quarantined.
    """
    defaults = {
        "proxy": {"host": "127.0.0.9", "port": 9999},
        "scope": {"in": ["*.example.com"], "out": ["evil.example.com"]},
        "runs": {"dir": "my-runs"},
        "db": {"store_path": str(tmp_path / "kb.sqlite")},
        "ai": {"provider": "custom", "base_url": "http://127.0.0.1:11500",
               "model": "other-model", "dims": 512,
               "doc_prefix": "doc: ", "query_prefix": "query: "},
        "top_k": 7,  # an engine key still merges as before
    }
    p = _write_cfg(tmp_path / "full.json", defaults)
    cfg = config.load_config(path=str(p))
    assert cfg["proxy"] == {"host": "127.0.0.9", "port": 9999}
    assert cfg["scope"] == {"in": ["*.example.com"],
                            "out": ["evil.example.com"]}
    assert cfg["runs"]["dir"] == "my-runs"
    assert cfg["db"]["store_path"] == str(tmp_path / "kb.sqlite")
    assert cfg["ai"]["provider"] == "custom"
    assert cfg["ai"]["base_url"] == "http://127.0.0.1:11500"
    assert cfg["ai"]["model"] == "other-model"
    assert cfg["ai"]["dims"] == 512
    assert cfg["ai"]["doc_prefix"] == "doc: "
    assert cfg["ai"]["query_prefix"] == "query: "
    assert cfg["top_k"] == 7
    # The product namespaces are KNOWN now — never quarantined.
    for ns in ("proxy", "scope", "runs", "db", "ai"):
        assert ns not in cfg["_unknown_keys"]
    assert cfg["_config_errors"] == []


def test_f1_config_file_can_restrict_scope(tmp_path):
    """The headline F-1 symptom: a config file restricts forwarding scope."""
    p = _write_cfg(tmp_path / "scope.json",
                   {"scope": {"in": ["app.example"], "out": ["*.evil.test"]}})
    cfg = config.load_config(path=str(p))
    assert cfg["scope"]["in"] == ["app.example"]
    assert cfg["scope"]["out"] == ["*.evil.test"]


def test_f1_product_keys_round_trip_through_the_engine_merge(tmp_path):
    """One door: the ENGINE's load_config itself applies the product keys
    (no second merge path in the VulnDog layer)."""
    p = _write_cfg(tmp_path / "rt.json",
                   {"proxy": {"port": 9100}, "scope": {"in": ["x.test"]},
                    "runs": {"dir": "r2"}, "db": {"store_path": "s.sqlite"},
                    "ai": {"model": "m2"}})
    cfg = engine_run.load_config(str(p))
    assert cfg["proxy"]["port"] == 9100
    assert cfg["scope"]["in"] == ["x.test"]
    assert cfg["runs"]["dir"] == "r2"
    assert cfg["db"]["store_path"] == "s.sqlite"
    assert cfg["ai"]["model"] == "m2"
    assert cfg["_unknown_keys"] == []


# ------------------------------------------- precedence: every new key


@pytest.mark.parametrize("dotted,builtin,file_val,task_val,cli_val",
                         PRECEDENCE_CASES, ids=[c[0] for c in PRECEDENCE_CASES])
def test_precedence_builtin_file_task_cli(tmp_path, dotted, builtin,
                                          file_val, task_val, cli_val):
    """builtin < file defaults < per-run override < CLI, for EVERY new key."""
    # Layer 1: builtin (no file present -> engine records config-missing).
    cfg = config.load_config(path=str(tmp_path / "absent.json"))
    assert _dig(cfg, dotted) == builtin

    # Layer 2: file defaults beat builtin.
    p = _write_cfg(tmp_path / "prec.json", _nest(dotted, file_val),
                   tasks={"t1": _nest(dotted, task_val)})
    cfg = config.load_config(path=str(p))
    assert _dig(cfg, dotted) == file_val

    # Layer 3: per-run task entry beats file defaults.
    cfg = config.load_config(path=str(p), task_id="t1")
    assert _dig(cfg, dotted) == task_val

    # Layer 4: CLI overrides beat everything.
    cfg = config.load_config(path=str(p), task_id="t1",
                             overrides=_nest(dotted, cli_val))
    assert _dig(cfg, dotted) == cli_val


def test_precedence_partial_proxy_dict_keeps_builtin_sibling(tmp_path):
    """Engine merge law is wholesale per key; the VulnDog gap-fill restores
    missing sub-keys from builtins UNDER the file value (P1 behaviour)."""
    p = _write_cfg(tmp_path / "partial.json", {"proxy": {"port": 9300}})
    cfg = config.load_config(path=str(p))
    assert cfg["proxy"] == {"host": "127.0.0.1", "port": 9300}


# ------------------------------------------------- engine laws, verbatim


def test_corrupt_json_never_crashes_and_keeps_builtins(tmp_path):
    p = tmp_path / "corrupt.json"
    p.write_text("{not valid json", encoding="utf-8")
    cfg = config.load_config(path=str(p))  # must NOT raise
    assert cfg["_config_errors"]  # the problem is reported
    assert any("corrupt.json" in e for e in cfg["_config_errors"])
    # Builtins still applied (engine + product).
    assert cfg["top_k"] == engine_run.BUILTIN_DEFAULTS["top_k"]
    assert cfg["proxy"] == {"host": "127.0.0.1", "port": 8080}
    assert cfg["scope"] == {"in": [], "out": []}
    assert cfg["ai"]["model"] == "embeddinggemma:300m"


def test_genuinely_unknown_key_is_isolated_never_applied(tmp_path):
    p = _write_cfg(tmp_path / "unknown.json",
                   {"proxy": {"port": 9400}, "totally_bogus_key": 1,
                    "flor": 0.9})
    cfg = config.load_config(path=str(p))
    assert "totally_bogus_key" in cfg["_unknown_keys"]
    assert "flor" in cfg["_unknown_keys"]
    assert "totally_bogus_key" not in cfg
    assert "flor" not in cfg
    # A known product key in the SAME file still applies.
    assert cfg["proxy"]["port"] == 9400


def test_unknown_subkey_inside_known_namespace_is_not_silently_applied(tmp_path):
    """Isolation granularity is the engine's top-level key law: a known
    namespace applies as a whole; a bogus SUB-key rides inside it (visible
    in the resolved state) but is never consumed by the product."""
    p = _write_cfg(tmp_path / "subkey.json",
                   {"proxy": {"port": 9500, "bogus_sub": 1}})
    cfg = config.load_config(path=str(p))
    assert cfg["proxy"]["port"] == 9500
    assert "proxy" not in cfg["_unknown_keys"]


# ------------------------------------------------------ discovery order


def test_discovery_prefers_cwd_over_home(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    _write_cfg(cwd / "vulndog.json", {"proxy": {"port": 9601}})
    _write_cfg(home / "vulndog.json", {"proxy": {"port": 9602}})
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    cfg = config.load_config()
    assert cfg["proxy"]["port"] == 9601  # cwd wins


def test_discovery_falls_back_to_home(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    _write_cfg(home / "vulndog.json", {"proxy": {"port": 9603}})
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    cfg = config.load_config()
    assert cfg["proxy"]["port"] == 9603  # home wins over builtins


def test_discovery_falls_back_to_builtins(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    cfg = config.load_config()
    assert cfg["proxy"]["port"] == 8080  # builtin
    assert cfg["_config_errors"] == []  # no file is not an error


def test_explicit_path_bypasses_discovery(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    _write_cfg(cwd / "vulndog.json", {"proxy": {"port": 9604}})
    explicit = _write_cfg(tmp_path / "explicit.json", {"proxy": {"port": 9605}})
    monkeypatch.chdir(cwd)
    cfg = config.load_config(path=str(explicit))
    assert cfg["proxy"]["port"] == 9605  # explicit wins over cwd discovery


def test_discovery_corrupt_cwd_file_degrades_not_crash(tmp_path, monkeypatch):
    cwd = tmp_path / "cwd"
    home = tmp_path / "home"
    cwd.mkdir()
    home.mkdir()
    (cwd / "vulndog.json").write_text("{broken", encoding="utf-8")
    _write_cfg(home / "vulndog.json", {"proxy": {"port": 9606}})
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    cfg = config.load_config()  # must NOT raise
    assert cfg["_config_errors"]  # reported
    assert cfg["proxy"]["port"] == 8080  # builtins, NOT the home file


# ------------------------------------------- CLI surface (docs-consistent)


def test_cli_proxy_port_flag_overrides_config_file(tmp_path):
    """--port (the shipped proxy-port flag) beats a config-file proxy.port."""
    p = _write_cfg(tmp_path / "cli.json", {"proxy": {"port": 9700}})
    from test_cli import FakeAnalyzer  # reuse the pinned fake analyzer
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(p),
                     "--port", "0", "--duration", "0.3"],
                    analyzer=analyzer)
    assert code == 0
    meta = json.loads(
        (max((tmp_path / "runs").iterdir(), key=lambda d: d.name)
         / "watchdog-run.json").read_text(encoding="utf-8"))
    assert meta["listen"]["port"] != 9700  # CLI won
    assert meta["config"]["proxy"]["port"] != 9700


def test_cli_config_file_port_reaches_listener(tmp_path):
    """F-1 end-to-end: a config-file proxy.port actually binds the proxy."""
    from test_cli import FakeAnalyzer
    p = _write_cfg(tmp_path / "bind.json", {"proxy": {"port": 0}})
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(p),
                     "--duration", "0.3"], analyzer=analyzer)
    assert code == 0
    meta = json.loads(
        (max((tmp_path / "runs").iterdir(), key=lambda d: d.name)
         / "watchdog-run.json").read_text(encoding="utf-8"))
    assert meta["config"]["proxy"]["port"] == 0
    assert meta["listen"]["port"] > 0  # port 0 -> OS-assigned, file applied


def test_cli_config_file_store_reaches_analyzer(tmp_path):
    """F-1 end-to-end: a config-file db.store_path picks the store."""
    from test_cli import FakeAnalyzer
    store = tmp_path / "chosen.sqlite"
    p = _write_cfg(tmp_path / "store.json", {"db": {"store_path": str(store)}})
    analyzer = FakeAnalyzer()
    code = cli.main(["run", "--project", str(tmp_path), "--config", str(p),
                     "--port", "0", "--duration", "0.3"], analyzer=analyzer)
    assert code == 0
    assert analyzer.calls[0]["store_path"] == str(store)


# --------------------------------------- UX-1: wrong-shape file warning


def test_ux1_top_level_product_keys_warn_and_use_builtins(tmp_path):
    """UX-1: product keys at the JSON top level (outside the 'defaults'
    wrapper) are dropped by the merge without a trace today. They must
    produce a stable warning note while the config stays on builtins
    (the never-crash law holds — builtins proceed)."""
    p = tmp_path / "wrong-shape.json"
    p.write_text(json.dumps({
        "config_version": 1,
        "ai": {"base_url": "http://127.0.0.1:11999"},
        "proxy": {"port": 9999},
    }), encoding="utf-8")
    cfg = config.load_config(path=str(p))
    # builtins in force — the misplaced top-level keys contributed nothing
    assert cfg["ai"]["base_url"] == "http://127.0.0.1:11434"
    assert cfg["proxy"]["port"] == 8080
    # a stable warning note names the misplaced keys and the way out
    notes = cfg["_config_errors"]
    assert any("outside 'defaults'" in n for n in notes), notes
    shape_note = next(n for n in notes if "outside 'defaults'" in n)
    assert "ai" in shape_note and "proxy" in shape_note
    assert "move them under 'defaults'" in shape_note


def test_ux1_correct_shape_config_has_no_shape_warning(tmp_path):
    """Negative control: the documented 'defaults' wrapper applies the
    keys and produces no wrong-shape warning."""
    p = tmp_path / "correct-shape.json"
    p.write_text(json.dumps({
        "config_version": 1,
        "defaults": {"ai": {"base_url": "http://127.0.0.1:11999"}},
    }), encoding="utf-8")
    cfg = config.load_config(path=str(p))
    assert cfg["ai"]["base_url"] == "http://127.0.0.1:11999"
    assert not any("outside 'defaults'" in n for n in cfg["_config_errors"])