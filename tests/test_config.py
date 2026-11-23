"""Config layer: delegate the 3-layer merge to the engine (one decision in
one place), fill VulnDog-specific gaps, apply CLI overrides last.

The engine package is absent in this worktree (dev-A owns it), so every test
injects a fake loader through the seam; engine-absence is simulated with
sys.modules poisoning so the suite also passes once the halves merge.
"""
from __future__ import annotations

import sys

import pytest

from vulndog import config


class FakeLoader:
    def __init__(self, result=None):
        self.result = result if result is not None else {}
        self.calls = []

    def __call__(self, path=None, task_id=None):
        self.calls.append({"path": path, "task_id": task_id})
        return self.result


def test_delegates_merge_to_loader_with_path_and_task():
    fake = FakeLoader({"top_k": 5})
    cfg = config.load_config(path="c.json", task_id="t1", loader=fake)
    assert fake.calls == [{"path": "c.json", "task_id": "t1"}]
    assert cfg["top_k"] == 5


def test_loader_defaults_are_none():
    fake = FakeLoader()
    config.load_config(loader=fake)
    assert fake.calls == [{"path": None, "task_id": None}]


def test_vulndog_defaults_fill_gaps():
    cfg = config.load_config(loader=FakeLoader({}))
    assert cfg["proxy"] == {"host": "127.0.0.1", "port": 8080}
    assert cfg["scope"] == {"in": [], "out": []}
    assert cfg["runs"] == {"dir": "runs"}
    assert cfg["db"] == {"store_path": None}
    assert cfg["ai"]["provider"] == "ollama"
    assert cfg["ai"]["base_url"] == "http://127.0.0.1:11434"
    assert cfg["ai"]["model"] == "embeddinggemma:300m"
    assert cfg["ai"]["dims"] == 768


def test_engine_values_win_over_vulndog_defaults():
    fake = FakeLoader({"proxy": {"host": "0.0.0.0", "port": 1234},
                       "runs": {"dir": "custom"}})
    cfg = config.load_config(loader=fake)
    assert cfg["proxy"]["host"] == "0.0.0.0"
    assert cfg["proxy"]["port"] == 1234
    assert cfg["runs"]["dir"] == "custom"


def test_partial_engine_proxy_keeps_default_host():
    cfg = config.load_config(loader=FakeLoader({"proxy": {"port": 9999}}))
    assert cfg["proxy"] == {"host": "127.0.0.1", "port": 9999}


def test_cli_overrides_win_last():
    fake = FakeLoader({"proxy": {"port": 9999}, "floor": 0.6})
    cfg = config.load_config(loader=fake,
                             overrides={"proxy": {"port": 7777}, "floor": 0.9})
    assert cfg["proxy"]["port"] == 7777
    assert cfg["proxy"]["host"] == "127.0.0.1"  # sibling preserved
    assert cfg["floor"] == 0.9


def test_overrides_none_is_noop():
    cfg = config.load_config(loader=FakeLoader({"proxy": {"port": 9999}}),
                             overrides=None)
    assert cfg["proxy"]["port"] == 9999


def test_deep_merge_nested_and_replace():
    merged = config._deep_merge({"a": {"x": 1, "y": 2}, "keep": True},
                                {"a": {"y": 3, "z": 4}, "new": 1})
    assert merged == {"a": {"x": 1, "y": 3, "z": 4}, "keep": True, "new": 1}
    # non-dict override replaces wholesale
    assert config._deep_merge({"a": {"x": 1}}, {"a": [1, 2]}) == {"a": [1, 2]}


def test_defaults_are_not_mutated_by_callers():
    cfg1 = config.load_config(loader=FakeLoader({}))
    cfg1["proxy"]["port"] = 1
    cfg1["scope"]["in"].append("x")
    cfg2 = config.load_config(loader=FakeLoader({}))
    assert cfg2["proxy"]["port"] == 8080
    assert cfg2["scope"]["in"] == []


def test_engine_absent_raises_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "vulndog.engine", None)
    monkeypatch.setitem(sys.modules, "vulndog.engine.run", None)
    with pytest.raises(config.EngineUnavailableError):
        config.load_config()


def test_injected_loader_works_even_when_engine_absent(monkeypatch):
    monkeypatch.setitem(sys.modules, "vulndog.engine", None)
    monkeypatch.setitem(sys.modules, "vulndog.engine.run", None)
    cfg = config.load_config(loader=FakeLoader({"top_k": 7}))
    assert cfg["top_k"] == 7
    assert cfg["proxy"]["port"] == 8080


def test_non_dict_loader_result_rejected():
    with pytest.raises(ValueError):
        config.load_config(loader=lambda path=None, task_id=None: None)


# ------------------------------------------- product-config shape (H2/F8)


@pytest.mark.parametrize("bad", [
    {"proxy": "nope"},
    {"proxy": {"host": 5}},
    {"proxy": {"port": "8080"}},
    {"proxy": {"port": True}},
    {"proxy": {"port": -1}},
    {"proxy": {"port": 70000}},
    {"scope": "example.com"},
    {"scope": {"in": "example.com"}},
    {"scope": {"out": [5]}},
    {"runs": {"dir": 7}},
    {"db": {"store_path": 7}},
])
def test_wrong_typed_product_config_fails_fast(bad):
    # A config file is external input. Wrong-typed product keys used to
    # crash mid-run (runs.dir -> Path(int)) or silently misbehave
    # (scope as a string iterates its characters as patterns).
    with pytest.raises(ValueError):
        config.load_config(loader=FakeLoader(bad))


def test_valid_product_shapes_pass():
    cfg = config.load_config(loader=FakeLoader({
        "proxy": {"host": "localhost", "port": 0},
        "scope": {"in": ["*.example.com"], "out": []},
        "runs": {"dir": "out"},
        "db": {"store_path": "kb.sqlite"},
    }))
    assert cfg["proxy"]["port"] == 0
    assert cfg["scope"]["in"] == ["*.example.com"]


def test_cli_overrides_are_validated_too():
    with pytest.raises(ValueError):
        config.load_config(loader=FakeLoader({}),
                           overrides={"proxy": {"port": "9999"}})


# ------------------------------------- scope pattern content (M2.2)


@pytest.mark.parametrize("bad", [
    "http://example.com",   # scheme
    "example.com/path",     # path component
    "example.com:8080",     # port
    "user@example.com",     # userinfo
    "*",                    # bare wildcard
    "",                     # empty
])
def test_scope_pattern_content_fails_fast(bad):
    # M2.2: the compile law (vulndog.scope) is enforced through the
    # shipped load path — a non-literal pattern fails fast at startup.
    with pytest.raises(ValueError):
        config.load_config(loader=FakeLoader({"scope": {"in": [bad]}}))
    with pytest.raises(ValueError):
        config.load_config(loader=FakeLoader({"scope": {"out": [bad]}}))


def test_scope_valid_patterns_pass_through_load_path():
    cfg = config.load_config(loader=FakeLoader({
        "scope": {"in": ["*.Example.com"], "out": ["api.example.com"]}}))
    # the raw config lists are preserved (banner + JSON meta read them)
    assert cfg["scope"]["in"] == ["*.Example.com"]
    assert cfg["scope"]["out"] == ["api.example.com"]