"""Shared fixtures for the MCP server suite (M2.3).

Path bootstrap mirrors engine/tests/conftest.py: makes ``src/`` importable
so the suite collects standalone from the repo root without an install.

All fixtures are OFFLINE and deterministic: the KB is a tiny store built
with the engine's own StagedStore, the embedder is a fixed-vector double,
and run folders are created through vulndog.runs with an injected clock.
No test touches the network or the real 1.93 GiB store.
"""
from __future__ import annotations

import json
import math
import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

_SRC = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, os.pardir,
                 os.pardir))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from vulndog import runs  # noqa: E402
from vulndog.engine import store as st  # noqa: E402
from vulndog.engine import query as qy  # noqa: E402

MANIFEST = {"manifest_version": 1, "corpus_version": "vkb1-mcp-test",
            "counts": {}}


def unit(*vals):
    n = math.sqrt(sum(v * v for v in vals)) or 1.0
    return [v / n for v in vals]


class FixedEmbedder:
    """embed_query protocol double: fixed vector, optional failure flag."""

    def __init__(self, vector=None, fail=False):
        self.vector = vector if vector is not None else unit(1, 0, 0, 0)
        self.fail = fail
        self.calls = []

    def embed_query(self, text):
        self.calls.append(text)
        if self.fail:
            raise RuntimeError("ollama unreachable (test double)")
        return self.vector


def _rec(rid, kind="cve", title=None, **over):
    r = {
        "id": rid, "kind": kind, "title": title or rid,
        "text_fields": ["t"], "cwe_ids": [], "cvss": None,
        "owasp_categories": [], "exploit_refs": [], "cve_refs": [],
        "dates": {}, "confidence": "documented", "source_path": "s",
        "corpus_version": "vkb1-mcp-test",
        "evidence": {"src": "s.zip", "note": "n"},
        "excluded_from_index": False,
    }
    r.update(over)
    return r


@pytest.fixture()
def kb_store(tmp_path):
    """Tiny deterministic KB (same shape as the engine's query tests):
    CVE-2024-1000 xss (e1, 9.8, exploit), CVE-2024-2000 sqli (e2, 8.1),
    CVE-2024-3000 overflow (e3, 5.5), cwe-79 catalog (e4), edb-1 (e1)."""
    path = str(tmp_path / "vulnkb.sqlite")
    with st.StagedStore(path) as s:
        s.add_record(_rec("CVE-2024-1000", title="XSS in login page",
                          cwe_ids=["cwe-79"],
                          cvss={"score": 9.8, "severity": "CRITICAL"},
                          exploit_refs=["edb-1"],
                          owasp_categories=["A03:2021-Injection"],
                          text_fields=["reflected cross-site scripting "
                                       "in the login page"]))
        s.add_chunk("CVE-2024-1000", 0, 1,
                    "reflected cross-site scripting in the login page",
                    [1.0, 0.0, 0.0, 0.0])
        s.add_record(_rec("CVE-2024-2000", title="SQLi in search",
                          cwe_ids=["cwe-89"],
                          cvss={"score": 8.1, "severity": "HIGH"},
                          text_fields=["sql injection in search endpoint"]))
        s.add_chunk("CVE-2024-2000", 0, 1,
                    "sql injection in the search endpoint",
                    [0.0, 1.0, 0.0, 0.0])
        s.add_record(_rec("CVE-2024-3000", title="Overflow in desktop app",
                          cwe_ids=["cwe-120"],
                          cvss={"score": 5.5, "severity": "MEDIUM"},
                          text_fields=["buffer overflow in desktop app"]))
        s.add_chunk("CVE-2024-3000", 0, 1,
                    "classic stack buffer overflow in a desktop binary",
                    [0.0, 0.0, 1.0, 0.0])
        s.add_record(_rec("cwe-79", kind="cwe",
                          title="Cross-site Scripting",
                          text_fields=["xss weakness catalog entry"]))
        s.add_chunk("cwe-79", 0, 1,
                    "the product does not neutralize user input xss",
                    [0.0, 0.0, 0.0, 1.0])
        s.add_record(_rec("edb-1", kind="exploit", title="XSS PoC",
                          cve_refs=["CVE-2024-1000"],
                          exploit_verified=True,
                          text_fields=["xss proof of concept"]))
        s.add_chunk("edb-1", 0, 1, "reflected xss proof of concept",
                    [1.0, 0.0, 0.0, 0.0])
        s.finish(MANIFEST)
        s.swap_into_dest()
    return path


def highlight_row(n, hunt_id, url=None, record_id="CVE-2024-1000"):
    """One canonical 19-field highlights.jsonl row (engine field order)."""
    return {
        "ts": "2026-11-23T10:00:00+00:00",
        "matched_at": "2026-11-23T10:00:02Z",
        "hunt_id": hunt_id,
        "url": url or f"https://shop.example.com/page-{n}?q=<len-4>",
        "method": "GET",
        "status": 200,
        "score": round(0.9 - n * 0.01, 6),
        "reason": "semantic",
        "record_id": record_id,
        "kind": "cve",
        "title": "XSS in login page",
        "cwe_ids": ["cwe-79"],
        "owasp_categories": ["A03:2021-Injection"],
        "cvss": {"score": 9.8, "severity": "CRITICAL"},
        "exploit_available": True,
        "matched_snippet": "reflected cross-site scripting in the login page",
        "corpus_version": "vkb1-mcp-test",
        "tap_class": "browser",
        "provenance": "vulndog.proxy",
    }


@pytest.fixture()
def run_tree(tmp_path):
    """Project root with two run folders (older 2 rows, newer 3 rows),
    each with highlights.jsonl + watchdog-run.json written through the
    real runs.py writers. Returns (project_root, older_run, newer_run)."""
    project = tmp_path / "project"
    project.mkdir()
    older = runs.create_run(project, runs_dir="runs",
                            now=datetime(2026, 11, 23, 9, 0, 0))
    newer = runs.create_run(project, runs_dir="runs",
                            now=datetime(2026, 11, 23, 10, 0, 0))
    for run, count, mode in ((older, 2, "stopped"), (newer, 3, "capture")):
        rows = [highlight_row(i, run.hunt_id) for i in range(count)]
        run.path.joinpath("highlights.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
            encoding="utf-8")
        run.write_meta({
            "pid": os.getpid(),
            "hunt_id": run.hunt_id,
            "mode": mode,
            "started_at": "2026-11-23T09:00:00Z",
            "counters": {"events": count * 4, "highlights": count},
            "config": {"runs": {"dir": "runs"}},
            "paths": {"run_dir": str(run.path),
                      "events": str(run.events_path)},
        })
    return project, older, newer


@pytest.fixture()
def mcp_env(tmp_path, kb_store, run_tree):
    """Server context for in-process tests: config + injected query API
    factory (fixed-vector embedder, fixture store)."""
    project, older, newer = run_tree
    embedder = FixedEmbedder(unit(1, 0, 0, 0))
    cfg = {
        "runs": {"dir": "runs"},
        "db": {"store_path": kb_store},
        "ai": {"provider": "ollama",
               "base_url": "http://127.0.0.1:11434",
               "model": "embeddinggemma:300m", "dims": 768},
    }

    def api_factory(config):
        return qy.QueryAPI(store_path=config["db"]["store_path"],
                           embedder=embedder)

    return {
        "project_root": project,
        "config": cfg,
        "query_api_factory": api_factory,
        "embedder": embedder,
        "older": older,
        "newer": newer,
        "kb_store": kb_store,
    }


@pytest.fixture()
def child_env(tmp_path, kb_store, run_tree):
    """Config file + environment for the child server processes. Children
    run OUR worktree code via PYTHONPATH (no -I: isolated mode would
    ignore PYTHONPATH). The ok-path child injects a fixed-vector embedder
    through the engine's documented seam (stdio_child.py); the production
    entry child is driven KB-down, where no embedder call happens."""
    project, _older, _newer = run_tree
    cfg = {
        "config_version": 1,
        "defaults": {
            "runs": {"dir": "runs"},
            "db": {"store_path": kb_store},
            "ai": {"provider": "ollama",
                   "base_url": "http://127.0.0.1:11434",
                   "model": "embeddinggemma:300m", "dims": 768},
        },
        "tasks": {},
    }
    cfg_path = tmp_path / "mcp-config.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = _SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    return {
        "env": env,
        "project": project,
        "cfg_path": cfg_path,
        "kb_store": kb_store,
    }


def tool_payload(result):
    """Decode a tools/call result: assert the MCP content shape, return
    the parsed JSON payload of the first text block."""
    assert result["isError"] is False
    content = result["content"]
    assert isinstance(content, list) and content
    assert all(b["type"] == "text" for b in content)
    return json.loads(content[0]["text"])