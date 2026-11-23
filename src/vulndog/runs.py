"""Run-folder lifecycle for VulnDog (docs/RUNS-AND-LOGS.md, ADR-4).

Every run creates ``<project>/runs/<YYYYMMDD-HHMMSS>[-<tag>]/`` resolved from
the project root (never CWD). Folder names match
``^\\d{8}-\\d{6}(-[A-Za-z0-9._-]{0,64})?$``; same-second collisions get a
numeric suffix (-1, -2, ...) and both folders stay intact. ``hunt_id`` is the
folder name (tag included).

Owned files: events.jsonl (append-only, flushed per record), state.json,
watchdog-run.json, watchdog.pid, stop-request. JSON state files are written
atomically (temp file in the same directory -> os.replace) so a crash never
leaves a half-written state. highlights.* belong to the engine (dev-A).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

RUN_NAME_RE = re.compile(r"^\d{8}-\d{6}(-[A-Za-z0-9._-]{0,64})?$")
_TAG_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_MAX_TAG_LEN = 64


def _resolve_runs_root(project_root: Path, runs_dir: str | Path) -> Path:
    """Relative runs.dir resolves against the project root, not CWD."""
    runs_dir = Path(runs_dir)
    if runs_dir.is_absolute():
        return runs_dir
    return Path(project_root) / runs_dir


def _validate_tag(tag: str) -> None:
    if not _TAG_RE.match(tag):
        raise ValueError(
            f"invalid run tag {tag!r}: allowed [A-Za-z0-9._-], 1..64 chars"
        )
    # H2/F5: Win32 strips trailing dots from directory names, so a tag
    # ending in '.' would create a folder whose real name differs from
    # hunt_id (pinned: hunt_id == folder name). Trailing dash rejected
    # for parity with the engine's COND-6 task-id law (run.py).
    if tag[-1] in ".-":
        raise ValueError(
            f"invalid run tag {tag!r}: must not end with '.' or '-'"
        )


def create_run(
    project_root: Path,
    *,
    runs_dir: str | Path = "runs",
    tag: str | None = None,
    now: datetime | None = None,
) -> Run:
    """Create a fresh collision-safe run folder and return its handle.

    Args:
        project_root: the project the run belongs to.
        runs_dir: root for run folders (relative -> under project_root).
        tag: optional custom identifier for parallel instances.
        now: timestamp source (injected in tests; defaults to local now).

    Raises:
        ValueError: the tag contains illegal characters or is too long.
    """
    if tag is not None:
        _validate_tag(tag)
    stamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S")
    base = f"{stamp}-{tag}" if tag else stamp
    root = _resolve_runs_root(project_root, runs_dir)
    root.mkdir(parents=True, exist_ok=True)
    path = _claim_run_dir(root, stamp, base, tag)
    return Run(path=path, hunt_id=path.name)


def _next_collision_name(stamp: str, base: str, tag: str | None,
                         suffix: int) -> str:
    """Numeric-suffix collision name; the tag portion (tag + suffix)
    stays within the 64-char cap."""
    tail = f"-{suffix}"
    if tag:
        keep = _MAX_TAG_LEN - len(tail)
        return f"{stamp}-{tag[:keep]}{tail}"
    return f"{base}{tail}"


def _claim_run_dir(root: Path, stamp: str, base: str,
                   tag: str | None) -> Path:
    """Atomic claim: mkdir IS the existence check (H2/F3). The previous
    exists()-then-mkdir() leaked FileExistsError when a parallel
    instance won the race between check and create — the owner's
    parallel-run directive makes that race real, not theoretical."""
    name = base
    suffix = 0
    while True:
        path = root / name
        try:
            path.mkdir()
            return path
        except FileExistsError:
            suffix += 1
            name = _next_collision_name(stamp, base, tag, suffix)


@dataclass(frozen=True)
class Run:
    """Handle for one run folder; hunt_id == folder name."""

    path: Path
    hunt_id: str

    @property
    def events_path(self) -> Path:
        return self.path / "events.jsonl"

    @property
    def state_path(self) -> Path:
        return self.path / "state.json"

    @property
    def meta_path(self) -> Path:
        return self.path / "watchdog-run.json"

    @property
    def pid_path(self) -> Path:
        return self.path / "watchdog.pid"

    @property
    def stop_path(self) -> Path:
        return self.path / "stop-request"

    def write_state(self, state: dict) -> None:
        """Persist resume offsets atomically."""
        write_json_atomic(self.state_path, state)

    def write_meta(self, meta: dict) -> None:
        """Persist live run state (pid, mode, counters, config, paths)."""
        write_json_atomic(self.meta_path, meta)

    def write_pid(self, pid: int) -> None:
        _write_text_atomic(self.pid_path, f"{pid}\n")

    def request_stop(self) -> None:
        """Create the clean-stop flag file (idempotent)."""
        self.stop_path.touch(exist_ok=True)

    def stop_requested(self) -> bool:
        return self.stop_path.exists()

    def clear_stop(self) -> None:
        self.stop_path.unlink(missing_ok=True)


def write_json_atomic(path: Path, payload: dict) -> None:
    """Write JSON via temp file + os.replace (never a partial file)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_text_atomic(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def _write_text_atomic(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class EventWriter:
    """Append-only events.jsonl writer; flushes after every record.

    Thread-safe: proxy handler threads share one writer. The lock serializes
    whole-line writes so records never interleave.
    """

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._path, "a", encoding="utf-8", newline="\n")
        self._lock = threading.Lock()
        self.count = 0

    def write(self, event: dict) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            self.count += 1

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self) -> EventWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def list_runs(project_root: Path, runs_dir: str | Path = "runs") -> list[Run]:
    """All run folders under runs_dir, oldest first (name sort == time sort)."""
    root = _resolve_runs_root(project_root, runs_dir)
    if not root.is_dir():
        return []
    found = [
        Run(path=p, hunt_id=p.name)
        for p in sorted(root.iterdir())
        if p.is_dir() and RUN_NAME_RE.match(p.name)
    ]
    return found


def latest_run(project_root: Path, runs_dir: str | Path = "runs") -> Run | None:
    found = list_runs(project_root, runs_dir)
    return found[-1] if found else None


def pid_alive(pid: int) -> bool:
    """Cross-platform liveness probe (never os.kill(pid, 0) on Windows:
    there it would TerminateProcess the target instead of probing it)."""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


