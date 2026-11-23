"""Run-folder lifecycle: naming, collisions, tags, atomic writes, event writer.

Pinned contract (brief + docs/RUNS-AND-LOGS.md):
  runs/<YYYYMMDD-HHMMSS>[-<tag>]/  regex ^\\d{8}-\\d{6}(-[A-Za-z0-9._-]{0,64})?$
  collision-safe numeric suffix; hunt_id == folder name; resolved from the
  project root, not CWD; atomic state/meta writes; append-only flushed events.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

import pytest

from vulndog import runs

NAME_RE = re.compile(r"^\d{8}-\d{6}(-[A-Za-z0-9._-]{0,64})?$")


def test_create_run_name_matches_regex(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    assert NAME_RE.match(run.path.name)
    assert run.path.is_dir()
    assert run.path.parent == project_root / "runs"


def test_hunt_id_equals_folder_name(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    assert run.hunt_id == run.path.name


def test_timestamp_format(project_root):
    now = datetime(2026, 1, 2, 3, 4, 5)
    run = runs.create_run(project_root, now=now)
    assert run.path.name == "20260102-030405"


def test_same_second_collision_gets_distinct_suffix(project_root, fixed_now):
    a = runs.create_run(project_root, now=fixed_now)
    b = runs.create_run(project_root, now=fixed_now)
    c = runs.create_run(project_root, now=fixed_now)
    assert a.path != b.path != c.path
    assert a.path.name == "20261023-085501"
    assert b.path.name == "20261023-085501-1"
    assert c.path.name == "20261023-085501-2"
    # both folders stay intact
    assert a.path.is_dir() and b.path.is_dir() and c.path.is_dir()
    for r in (a, b, c):
        assert NAME_RE.match(r.path.name)


def test_create_run_survives_collision_race(project_root, fixed_now, monkeypatch):
    # H2/F3: parallel instances (the owner's parallel-run directive) can
    # pick the same name between the exists() check and mkdir(). Force
    # the window deterministically: the first candidate already exists
    # on disk, but exists() reports False for it once. The old
    # check-then-create leaked FileExistsError; creation must be atomic
    # (mkdir-or-retry) and both folders must stay intact.
    first = runs.create_run(project_root, now=fixed_now)
    real_exists = Path.exists
    lied = {"done": False}

    def racing_exists(self):
        if not lied["done"] and self.name == first.path.name:
            lied["done"] = True
            return False
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", racing_exists)
    second = runs.create_run(project_root, now=fixed_now)
    assert second.path != first.path
    assert second.path.is_dir() and first.path.is_dir()
    assert NAME_RE.match(second.path.name)
    assert second.hunt_id == second.path.name


def test_create_run_parallel_threads_all_distinct(project_root, fixed_now):
    import threading

    results: list[runs.Run] = []
    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker():
        try:
            run = runs.create_run(project_root, now=fixed_now)
            with lock:
                results.append(run)
        except BaseException as exc:
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert not errors, f"parallel create_run raised: {errors}"
    assert len(results) == 8
    assert len({r.path for r in results}) == 8
    for r in results:
        assert r.path.is_dir()
        assert NAME_RE.match(r.path.name)
        assert r.hunt_id == r.path.name


def test_custom_tag_in_name_and_hunt_id(project_root, fixed_now):
    run = runs.create_run(project_root, tag="authlab", now=fixed_now)
    assert run.path.name == "20261023-085501-authlab"
    assert run.hunt_id == "20261023-085501-authlab"
    assert NAME_RE.match(run.path.name)


def test_tag_collision_suffix(project_root, fixed_now):
    a = runs.create_run(project_root, tag="authlab", now=fixed_now)
    b = runs.create_run(project_root, tag="authlab", now=fixed_now)
    assert a.path.name == "20261023-085501-authlab"
    assert b.path.name == "20261023-085501-authlab-1"
    assert NAME_RE.match(b.path.name)


def test_max_length_tag_collision_stays_within_regex(project_root, fixed_now):
    tag = "x" * 64
    a = runs.create_run(project_root, tag=tag, now=fixed_now)
    b = runs.create_run(project_root, tag=tag, now=fixed_now)
    assert a.path.name == f"20261023-085501-{tag}"
    assert NAME_RE.match(b.path.name), b.path.name
    assert b.path.name.startswith("20261023-085501-")
    assert b.path.name.endswith("-1")
    assert a.path != b.path


def test_invalid_tag_rejected(project_root, fixed_now):
    for bad in ("has space", "bad/slash", "x" * 65, "bad!char"):
        with pytest.raises(ValueError):
            runs.create_run(project_root, tag=bad, now=fixed_now)


def test_tag_trailing_dot_or_dash_rejected(project_root, fixed_now):
    # H2/F5: Win32 strips trailing dots from directory names — a tag
    # ending in '.' would create a folder whose REAL name differs from
    # hunt_id (pinned contract: hunt_id == folder name). Trailing dash
    # is rejected for parity with the engine's COND-6 task-id law.
    for bad in ("trail.", "trail-", ".", "..", "x" * 63 + "."):
        with pytest.raises(ValueError):
            runs.create_run(project_root, tag=bad, now=fixed_now)


def test_tag_internal_dots_and_dashes_still_allowed(project_root, fixed_now):
    run = runs.create_run(project_root, tag="a.b-c", now=fixed_now)
    assert run.path.name == "20261023-085501-a.b-c"
    assert run.hunt_id == run.path.name


def test_runs_dir_resolved_from_project_not_cwd(project_root, fixed_now, tmp_path, monkeypatch):
    # CWD is somewhere else entirely; the run must still land in the project.
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    run = runs.create_run(project_root, now=fixed_now)
    assert run.path.parent == project_root / "runs"
    assert not (elsewhere / "runs").exists()


def test_custom_runs_dir_relative(project_root, fixed_now):
    run = runs.create_run(project_root, runs_dir="out/runs", now=fixed_now)
    assert run.path.parent == project_root / "out" / "runs"


def test_custom_runs_dir_absolute(project_root, fixed_now, tmp_path):
    abs_dir = tmp_path / "abs-runs"
    run = runs.create_run(project_root, runs_dir=abs_dir, now=fixed_now)
    assert run.path.parent == abs_dir


def test_atomic_json_write_no_partial(project_root, tmp_path):
    target = project_root / "state.json"
    project_root.mkdir(parents=True, exist_ok=True)
    runs.write_json_atomic(target, {"offset": 42})
    assert json.loads(target.read_text(encoding="utf-8")) == {"offset": 42}
    # no leftover temp files in the directory
    assert [p.name for p in project_root.iterdir()] == ["state.json"]


def test_atomic_json_write_overwrites(project_root):
    target = project_root / "x.json"
    project_root.mkdir(parents=True, exist_ok=True)
    runs.write_json_atomic(target, {"a": 1})
    runs.write_json_atomic(target, {"a": 2})
    assert json.loads(target.read_text(encoding="utf-8")) == {"a": 2}


def test_run_file_paths(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    assert run.events_path == run.path / "events.jsonl"
    assert run.state_path == run.path / "state.json"
    assert run.meta_path == run.path / "watchdog-run.json"
    assert run.pid_path == run.path / "watchdog.pid"
    assert run.stop_path == run.path / "stop-request"


def test_write_state_and_meta(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    run.write_state({"events_offset": 10})
    run.write_meta({"pid": 123, "mode": "enabled", "counters": {"events_in": 3}})
    assert json.loads(run.state_path.read_text(encoding="utf-8")) == {"events_offset": 10}
    meta = json.loads(run.meta_path.read_text(encoding="utf-8"))
    assert meta["pid"] == 123
    assert meta["counters"]["events_in"] == 3


def test_pid_file_and_stop_flag(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    run.write_pid(4242)
    assert run.pid_path.read_text(encoding="utf-8").strip() == "4242"
    assert run.stop_requested() is False
    run.request_stop()
    assert run.stop_requested() is True
    assert run.stop_path.exists()
    run.clear_stop()
    assert run.stop_requested() is False


def test_event_writer_appends_and_flushes_each_record(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    with runs.EventWriter(run.events_path) as w:
        w.write({"ts": "t1", "url": "http://a/"})
        # flushed per record: readable before close
        lines = run.events_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        w.write({"ts": "t2", "url": "http://b/"})
        lines = run.events_path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
    rows = [json.loads(l) for l in run.events_path.read_text(encoding="utf-8").splitlines()]
    assert [r["ts"] for r in rows] == ["t1", "t2"]


def test_event_writer_is_append_only_across_instances(project_root, fixed_now):
    run = runs.create_run(project_root, now=fixed_now)
    with runs.EventWriter(run.events_path) as w:
        w.write({"n": 1})
    with runs.EventWriter(run.events_path) as w:
        w.write({"n": 2})
    rows = [json.loads(l) for l in run.events_path.read_text(encoding="utf-8").splitlines()]
    assert [r["n"] for r in rows] == [1, 2]


def test_list_and_latest_run(project_root):
    t1 = datetime(2026, 1, 1, 0, 0, 0)
    t2 = datetime(2026, 1, 2, 0, 0, 0)
    runs.create_run(project_root, now=t1)
    newer = runs.create_run(project_root, now=t2)
    found = runs.list_runs(project_root)
    assert len(found) == 2
    latest = runs.latest_run(project_root)
    assert latest is not None
    assert latest.path == newer.path


def test_latest_run_empty(project_root):
    assert runs.latest_run(project_root) is None
    assert runs.list_runs(project_root) == []


def test_pid_alive_current_process():
    import os

    assert runs.pid_alive(os.getpid()) is True


def test_pid_alive_exited_process():
    import subprocess
    import sys

    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    assert runs.pid_alive(proc.pid) is False


def test_pid_alive_rejects_nonpositive():
    assert runs.pid_alive(0) is False
    assert runs.pid_alive(-1) is False


def test_list_runs_ignores_non_matching_dirs(project_root, fixed_now):
    runs.create_run(project_root, now=fixed_now)
    (project_root / "runs" / "not-a-run").mkdir(parents=True)
    (project_root / "runs" / "README.txt").write_text("x", encoding="utf-8")
    found = runs.list_runs(project_root)
    assert len(found) == 1