"""VulnDog configuration layer (docs/CONFIGURATION.md merge law).

One decision in one place: the 3-layer merge (builtin <- file defaults <-
tasks entry) belongs to the ENGINE (vulndog.engine.run.load_config). This
module delegates to it through an injection seam, then:

1. fills VulnDog-specific gaps UNDER the engine result (proxy host/port,
   scope, runs.dir, db.store_path, ai defaults) — engine/file values win;
2. applies CLI overrides (layer 4) LAST — they win over everything.

M2.1 (config system v2, F-1): the product namespaces (proxy/scope/runs/db/
ai) are now KNOWN to the engine merge, so a config file's values for them
APPLY through that same door (before M2.1 they were quarantined into
``_unknown_keys`` and never used). This layer supplies their built-in
defaults and the config-file discovery order; the merge itself is not
forked. Genuinely unknown keys are still isolated by the engine.

Config discovery order (when no explicit ``path`` is given and the real
engine loader is used): **cwd -> home -> builtins**. The first existing
``vulndog.json`` in the current directory, then the home directory, is
passed to the engine; if neither exists the engine applies its builtins
(and this layer fills the product defaults). A discovered-but-corrupt file
is NOT skipped — the engine's never-crash law reports it in
``_config_errors`` and degrades to builtins. An explicit ``path`` always
bypasses discovery. Discovery is skipped for an injected loader so the
capture-half tests stay deterministic.

The loader is a parameter defaulting to the engine import; tests inject
fakes. When the engine is unavailable, load_config raises
EngineUnavailableError and the CLI degrades with a clear message (never a
silent success).
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Callable

from vulndog.aihook.provider import parse_ai as _parse_ai
from vulndog.scope import compile_scope as _compile_scope

ConfigLoader = Callable[..., dict]

#: Config file name looked up during discovery (cwd -> home).
CONFIG_FILENAME = "vulndog.json"

VULNDOG_DEFAULTS: dict = {
    "proxy": {"host": "127.0.0.1", "port": 8080},
    "scope": {"in": [], "out": []},
    "runs": {"dir": "runs"},
    "db": {"store_path": None},
    "ai": {
        "provider": "ollama",
        "base_url": "http://127.0.0.1:11434",
        "model": "embeddinggemma:300m",
        "dims": 768,
        # Engine constants (embed_client.DOC_PREFIX / QUERY_PREFIX), reproduced
        # byte-for-byte per docs/AI-INTEGRATION.md. M2.1 made them round-trip
        # through the config merge; M2.4 consumes them (vulndog.aihook builds
        # the match-path embedder from this section). These literals are the
        # ONE home of the ai defaults — tests pin them against the engine.
        "doc_prefix": "title: none | text: ",
        "query_prefix": "task: search result | query: ",
        # null = keep the engine's per-request timeout default.
        "timeout_s": None,
    },
}


class EngineUnavailableError(RuntimeError):
    """The vulndog.engine package cannot be imported (dev-A half absent)."""


def builtin_defaults() -> dict:
    """A fresh deep copy — callers may mutate their result freely."""
    return copy.deepcopy(VULNDOG_DEFAULTS)


def _engine_loader() -> ConfigLoader:
    """Resolve the engine's merge function lazily (the injection default)."""
    try:
        from vulndog.engine.run import load_config as engine_load_config
    except ImportError as exc:
        raise EngineUnavailableError(
            "vulndog.engine is unavailable (the matching-engine half is not "
            "installed in this environment)"
        ) from exc
    return engine_load_config


def _discover_config_path() -> str | None:
    """First existing config file in discovery order: cwd -> home -> None.

    None means "no file found" — the engine then applies its builtins and
    this layer fills the product defaults. Home is resolved from HOME
    (POSIX) or USERPROFILE (Windows); if neither is set, only cwd is tried.
    A found file is returned even if corrupt: the engine's never-crash law
    reports the problem in ``_config_errors`` rather than silently falling
    through to the next candidate.
    """
    candidates = [Path.cwd() / CONFIG_FILENAME]
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE")
    if home:
        candidates.append(Path(home) / CONFIG_FILENAME)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursive dict merge; override wins. Non-dict values replace wholesale."""
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _validate_product_shape(cfg: dict) -> None:
    """Fail fast on wrong-typed product config (H2/F8).

    The engine merge never crashes on a broken file (its law); the
    VulnDog keys feed the proxy/runs directly, where a wrong type either
    crashes mid-run (runs.dir -> Path(int)) or silently misbehaves
    (a scope string iterates its characters as patterns). Per
    docs/CONFIGURATION.md: no half-configured scope — fail fast at
    startup with a nonzero exit. M2.2 adds the scope pattern CONTENT
    law (vulndog.scope.compile_scope): non-literal patterns (scheme,
    path, port, userinfo, misplaced wildcard) are rejected too. Only
    the product keys are validated here; engine keys keep the engine's
    own merge law.
    """
    _validate_proxy_cfg(cfg.get("proxy"))
    _validate_scope_cfg(cfg.get("scope"))
    _validate_paths_cfg(cfg.get("runs"), cfg.get("db"))
    # M2.4: ai.* is CONSUMED now (the provider factory builds the match-path
    # embedder from it), so its shape is validated here at startup like every
    # other product namespace. The ai shape law lives in vulndog.aihook
    # (one decision in one place, same pattern as scope.compile_scope).
    _parse_ai(cfg.get("ai"))


def _validate_proxy_cfg(proxy) -> None:
    if not isinstance(proxy, dict):
        raise ValueError("config proxy must be an object")
    if not isinstance(proxy.get("host"), str):
        raise ValueError("config proxy.host must be a string")
    port = proxy.get("port")
    if isinstance(port, bool) or not isinstance(port, int) \
            or not (0 <= port <= 65535):
        raise ValueError("config proxy.port must be an int in 0..65535")


def _validate_scope_cfg(scope) -> None:
    if not isinstance(scope, dict):
        raise ValueError("config scope must be an object with in/out lists")
    for key in ("in", "out"):
        patterns = scope.get(key)
        if not isinstance(patterns, (list, tuple)) \
                or not all(isinstance(p, str) for p in patterns):
            raise ValueError(f"config scope.{key} must be a list of strings")
    # M2.2: pattern CONTENT is the scope module's compile law (one
    # decision in one place) — a scheme/path/port/userinfo or other
    # non-literal pattern fails fast here at startup, never silently
    # normalized into a different target. ScopeError is a ValueError.
    _compile_scope(scope)


def _validate_paths_cfg(runs_cfg, db) -> None:
    if not isinstance(runs_cfg, dict) \
            or not isinstance(runs_cfg.get("dir"), (str, os.PathLike)):
        raise ValueError("config runs.dir must be a path string")
    if not isinstance(db, dict):
        raise ValueError("config db must be an object")
    store = db.get("store_path")
    if store is not None and not isinstance(store, (str, os.PathLike)):
        raise ValueError("config db.store_path must be a path string or null")


def load_config(path: str | None = None, task_id: str | None = None,
                overrides: dict | None = None,
                loader: ConfigLoader | None = None) -> dict:
    """Resolve the effective config: engine merge -> gap-fill -> CLI layer.

    Args:
        path: config JSON path. None triggers discovery (cwd -> home ->
            builtins) when the real engine loader is used; an explicit path
            bypasses discovery. Passed through to the engine loader.
        task_id: per-run task entry key (passed through).
        overrides: CLI-layer values (nested dict), applied last.
        loader: injection seam; defaults to the engine's load_config.
            Discovery is skipped for an injected loader (deterministic tests).

    Raises:
        EngineUnavailableError: no loader injected and the engine is absent.
        ValueError: the loader returned a non-dict (contract violation),
            or a product key has the wrong type/shape (fail fast).
    """
    if loader is None:
        loader = _engine_loader()
        if path is None:
            path = _discover_config_path()
    merged = loader(path=path, task_id=task_id)
    if not isinstance(merged, dict):
        raise ValueError(f"config loader returned {type(merged).__name__}, expected dict")
    cfg = _deep_merge(builtin_defaults(), merged)
    if overrides:
        cfg = _deep_merge(cfg, overrides)
    _validate_product_shape(cfg)
    return cfg