"""M1.4 end-to-end drill — the whole product path as BEHAVIOUR.

Leg 1 (in-process): the real CLI run loop (cli.main -> real ProxyServer
-> real EventWriter -> real run folder) hands events.jsonl to the REAL
engine analyze_run on clean stop. Only the embedder vector source is a
fixed-vector stub (offline, deterministic — PLAN M1.4 D-H prerequisite
declared: stub embed transport, no Ollama, no network egress).

Leg 2 (subprocess): ``python -m vulndog run`` — the real module entry
point in a fresh interpreter — produces the same artefacts; the stub is
injected through sitecustomize on PYTHONPATH (drill_support), no product
file patched.

Asserted per PLAN M1.4: (1) drill exits 0 with the embedder prerequisite
satisfied; (2) highlights.jsonl >= 1 line with reason "exact-id" (pin
law); (3) run summary counters events_in>0, highlights>0,
embed_failures=0, mode "enabled"; (5) full suite green after the drill.
Criterion (4) — the embedder-outage negative control — lives in
test_cli.py (test_run_embed_outage_is_not_success) where the honest
exit-code law is pinned.

Mutation proof (artifacts/gates-phase2.md): breaking the capture-side
F4 door (proxy._redact_capture_event) makes leg 1 fail on the
masked-URL / no-secret assertions (fix-round-1: the door replaced the
local mask_query_values helper — one redaction door, B1+B2).
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

from vulndog import cli
from vulndog.engine import event_schema as es
from vulndog.engine import highlights as hl
from vulndog.engine.tests.test_api import E1, StubEmbedder

from drill_support import build_drill_store
from event_contract import assert_pinned_event
from test_cli import NAME_RE, _read_meta, latest_run_dir, wait_for
from test_proxy import origin_up

PIN_URL_PATH = "/advisory/CVE-2024-2000"
SEMANTIC_BODY = b"login redirect xss in login.php"


def _get_via_proxy(proxy_port: int, origin_port: int, path: str) -> int:
    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    try:
        conn.request("GET", f"http://127.0.0.1:{origin_port}{path}")
        resp = conn.getresponse()
        resp.read()
        return resp.status
    finally:
        conn.close()


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _assert_highlight_surfaces(run_dir: Path, *, expect_pin: bool) -> list[dict]:
    hls = _read_jsonl(run_dir / "highlights.jsonl")
    assert hls, "highlights.jsonl missing or empty"
    for h in hls:
        assert list(h.keys()) == list(hl.HIGHLIGHT_FIELDS), \
            "highlight field order != engine HIGHLIGHT_FIELDS"
        assert h["hunt_id"] == run_dir.name
    if expect_pin:
        assert any(h["reason"] == "exact-id"
                   and h["record_id"] == "CVE-2024-2000" for h in hls), \
            "M1.4 criterion 2: no exact-id pin highlight"
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    assert "## H-0001" in md
    assert "## Run summary" in md
    assert "ADVISORY CANDIDATES ONLY" in md
    return hls


def test_drill_full_product_path(tmp_path):
    """Leg 1: proxy -> events.jsonl -> analyze_run -> highlights.*."""
    proj = tmp_path / "proj"
    proj.mkdir()
    store = build_drill_store(str(tmp_path / "kb.sqlite"))
    stub = StubEmbedder(E1)   # D-H prerequisite: stub embedder, offline

    def loader(path=None, task_id=None):
        return {"db": {"store_path": store}, "embedder": stub}

    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(proj), "--port", "0",
             "--duration", "4.0", "--tag", "drill",
             "--allow-private"],
            config_loader=loader)

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(proj), timeout=10)
        assert meta is not None, "run never wrote its metadata"
        port = meta["listen"]["port"]
        with origin_up(payload=SEMANTIC_BODY,
                       content_type="text/html") as origin:
            origin_port = origin.server_address[1]
            assert _get_via_proxy(
                port, origin_port,
                "/login.php?redirect=abcd&token=secret123") == 200
            assert _get_via_proxy(port, origin_port, PIN_URL_PATH) == 200
            assert len(origin.hits) == 2, "origin must see both requests"
    finally:
        t.join(timeout=15)
    assert not t.is_alive(), "CLI run did not stop within the duration"
    assert result["code"] == 0, "M1.4 criterion 1: drill must exit 0"

    run_dir = latest_run_dir(proj)
    assert run_dir is not None
    assert NAME_RE.match(run_dir.name), run_dir.name
    assert run_dir.name.endswith("-drill")

    # --- the spool: pinned contract, validated by the ENGINE validator
    events = _read_jsonl(run_dir / "events.jsonl")
    assert len(events) == 2
    for ev in events:
        assert es.validate_event(ev) == [], "engine rejected a tap event"
        assert_pinned_event(ev, persisted=True)
    blob = json.dumps(events)
    # F4 canonical forms (one door): secret-named params -> <redacted>
    # (upstream pattern pass); other values -> raw-length <len-N> mask.
    assert "token=<redacted>" in events[0]["url"]
    assert "redirect=<len-4>" in events[0]["url"]
    assert "secret123" not in blob, "query VALUE leaked into the spool"
    assert "corpus_version" not in blob, "tap wrote a matcher-owned field"

    # --- the analyzer ran inside the CLI: surfaces + counters
    hls = _assert_highlight_surfaces(run_dir, expect_pin=True)
    assert any(h["reason"] == "semantic"
               and h["record_id"] == "CVE-2024-1000" for h in hls)
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    # M1.4 criterion 3: run summary counters
    assert "| events_in | 2 |" in md
    assert "| embed_failures | 0 |" in md
    assert "| mode | enabled |" in md
    assert "| highlights | %d |" % len(hls) in md

    # --- documented per-run layout (RUNS-AND-LOGS.md)
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state == {"offset": 2}
    final_meta = json.loads(
        (run_dir / "watchdog-run.json").read_text(encoding="utf-8"))
    assert final_meta["mode"] == "stopped"
    assert final_meta["counters"]["events"] == 2


def test_drill_embed_outage_negative_control(tmp_path):
    """M1.4 criterion 4: embedder raising -> zero highlights, counters
    embed_failures>0, buffered_while_down>0, mode leaves "enabled" —
    and the CLI exits NONZERO (never a silent success). Two requests:
    the first fails the embed, the second must be BUFFERED, not matched
    (matcher down-mode law)."""
    proj = tmp_path / "proj"
    proj.mkdir()
    store = build_drill_store(str(tmp_path / "kb.sqlite"))
    stub = StubEmbedder(fail=True)   # D-H outage: embed transport raises

    def loader(path=None, task_id=None):
        return {"db": {"store_path": store}, "embedder": stub}

    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(proj), "--port", "0",
             "--duration", "4.0", "--tag", "outage",
             "--allow-private"],
            config_loader=loader)

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(proj), timeout=10)
        assert meta is not None, "run never wrote its metadata"
        port = meta["listen"]["port"]
        with origin_up(payload=SEMANTIC_BODY,
                       content_type="text/html") as origin:
            origin_port = origin.server_address[1]
            assert _get_via_proxy(port, origin_port, PIN_URL_PATH) == 200
            assert _get_via_proxy(
                port, origin_port,
                "/login.php?redirect=abcd&token=secret123") == 200
    finally:
        t.join(timeout=15)
    assert not t.is_alive()
    assert result["code"] == 4, "outage must NOT exit 0 (silent success)"

    run_dir = latest_run_dir(proj)
    assert run_dir is not None
    events = _read_jsonl(run_dir / "events.jsonl")
    assert len(events) == 2, "capture is preserved during the outage"
    for ev in events:
        assert es.validate_event(ev) == []
    # zero highlights — the pin in request 1 cannot rescue a failed embed
    assert _read_jsonl(run_dir / "highlights.jsonl") == []
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    assert "## H-" not in md
    assert "## Run summary" in md, "the summary stays honest, not empty"
    assert "| embed_failures | 1 |" in md
    assert "| buffered_while_down | 1 |" in md
    assert "| mode | ollama-down |" in md
    assert "| highlights | 0 |" in md


def test_drill_cli_module_entry_subprocess(tmp_path):
    """Leg 2: `python -m vulndog run` in a fresh interpreter, offline."""
    proj = tmp_path / "proj"
    proj.mkdir()
    store = build_drill_store(str(tmp_path / "kb.sqlite"))
    tests_dir = Path(__file__).resolve().parent
    src_dir = tests_dir.parent / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(tests_dir / "drill_site"), str(tests_dir), str(src_dir)])
    env["VULNDOG_DRILL_STUB"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-m", "vulndog", "run",
         "--project", str(proj), "--port", "0", "--duration", "4.0",
         "--tag", "drillcli", "--store", store,
         "--allow-private"],
        env=env, cwd=str(proj),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        meta = wait_for(lambda: _read_meta(proj), timeout=20)
        assert meta is not None, "subprocess run never wrote metadata"
        port = meta["listen"]["port"]
        with origin_up(payload=SEMANTIC_BODY,
                       content_type="text/html") as origin:
            assert _get_via_proxy(port, origin.server_address[1],
                                  PIN_URL_PATH) == 200
    finally:
        out, err = proc.communicate(timeout=25)
    assert proc.returncode == 0, f"CLI exit {proc.returncode}\n{out}\n{err}"

    run_dir = latest_run_dir(proj)
    assert run_dir is not None
    assert NAME_RE.match(run_dir.name)
    assert run_dir.name.endswith("-drillcli")
    events = _read_jsonl(run_dir / "events.jsonl")
    assert len(events) == 1
    assert es.validate_event(events[0]) == []
    assert_pinned_event(events[0], persisted=True)
    _assert_highlight_surfaces(run_dir, expect_pin=True)
    assert "analysis: events_read=1" in out
    state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
    assert state == {"offset": 1}


# ----------------------------------- UX-2: no insider refs in product output


def test_ux2_highlights_header_has_no_insider_refs():
    """UX-2: the highlights.md header must not cite unshipped insider
    artifacts, while the locked advisory wording stays verbatim."""
    header = hl._MD_HEADER.format(hunt_id="20261123-000000")
    # tokens assembled at runtime so source carries no insider literal
    for token in ("ROU" + "TER", "poc_" + "verifier", "design-" + "spec",
                  "vuln_" + "watchdog", "WD-" + "R2"):
        assert token not in header, f"insider ref {token!r} in header"
    # the advisory law (C8) and resume title are preserved
    assert "ADVISORY" in header
    assert "possible direction" in header
    assert "never a finding" in header
    assert "# Watchdog highlights" in header


def test_drill_output_has_no_insider_references(tmp_path):
    """UX-2 acceptance: run the fixture drill and grep the two product
    output surfaces for insider references -> 0 hits. Uses the REAL engine
    config (floor_note from the shipped watchdog_config.json) so the real
    config path is exercised end-to-end; the insider-string sanitization
    itself is pinned by test_cli.py::test_ux2_meta_floor_note_is_product_appropriate."""
    proj = tmp_path / "proj"
    proj.mkdir()
    store = build_drill_store(str(tmp_path / "kb.sqlite"))
    stub = StubEmbedder(E1)
    from vulndog.engine.run import load_config as real_load_config

    def loader(path=None, task_id=None):
        cfg = real_load_config(path=path, task_id=task_id)  # real floor_note
        cfg["db"] = {"store_path": store}
        cfg["embedder"] = stub
        return cfg

    result = {}

    def drive():
        result["code"] = cli.main(
            ["run", "--project", str(proj), "--port", "0",
             "--duration", "4.0", "--tag", "ux2", "--allow-private"],
            config_loader=loader)

    t = threading.Thread(target=drive)
    t.start()
    try:
        meta = wait_for(lambda: _read_meta(proj), timeout=10)
        assert meta is not None, "run never wrote its metadata"
        port = meta["listen"]["port"]
        with origin_up(payload=SEMANTIC_BODY,
                       content_type="text/html") as origin:
            assert _get_via_proxy(port, origin.server_address[1],
                                  PIN_URL_PATH) == 200
    finally:
        t.join(timeout=15)
    assert not t.is_alive(), "CLI run did not stop within the duration"
    assert result["code"] == 0, "drill must exit 0"

    run_dir = latest_run_dir(proj)
    assert run_dir is not None
    md = (run_dir / "highlights.md").read_text(encoding="utf-8")
    meta_text = (run_dir / "watchdog-run.json").read_text(encoding="utf-8")
    # the internal project name is assembled at runtime so the source
    # itself carries no insider literal (public-release anonymization)
    for token in ("ROU" + "TER", "poc_" + "verifier", "factory-" + "workspace",
                  "bug" + "hunt"):
        assert token not in md, f"insider ref {token!r} in highlights.md"
        assert token not in meta_text, \
            f"insider ref {token!r} in watchdog-run.json"
    # the floor_note is the product-appropriate string, not the insider one
    snap = json.loads(meta_text)["config"]
    assert snap.get("floor_note") == cli._PRODUCT_FLOOR_NOTE