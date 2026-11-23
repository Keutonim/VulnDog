"""WD-R3 -- watchdog lifecycle CLI (design-spec 3.4/5.5).

The operator-facing process half of the watchdog (the hunt side is the
tap; this is the SECOND TERMINAL of the lifecycle law):

    python -m vuln_watchdog.run start <task-id>   # begin tailing+matching
    python -m vuln_watchdog.run <task-id>         # bare alias = start
    python -m vuln_watchdog.run stop <task-id>    # clean stop + stats
    python -m vuln_watchdog.run status [task-id]  # process+store+ollama+offsets

Lifecycle law:
- **start** attaches mid-hunt legally: tailers resume from persisted
  offsets and the spool backlog is processed in order (design 3.4).
- **stop** is CLEAN: a stop-request file (or SIGINT/SIGTERM) ends the
  loop -> final drain -> run summary appended to highlights.md ->
  exited run-state persisted -> pid/stop files removed. ``stop`` waits
  for that clean exit, then VERIFIES no lingering process and
  reports the exit stats. A stubborn process is never killed implicitly:
  timeout -> rc 2 with the --force hint; --force is the explicit hard
  path (taskkill/SIGKILL).
- **status** is verifiable: pid + heartbeat + mode + counters, store
  manifest facts, loopback Ollama reachability, and the last tailer
  offsets -- the operator's monitoring surface between highlights.

The watchdog process NEVER: issues target-bound requests (only loopback
Ollama via the embed client + local files), writes hunt state files, or
touches a rail. Degraded modes are the matcher's (design section 7):
Ollama down/hung -> matching DISABLED + capture continues (polling
FREEZES so spool offsets do not advance and the backlog accumulates as
the unprocessed tail) + 60 s backoff; KB missing/corrupt -> capture-only
with auto-detect on the next query.

Per-hunt config: ``data/watchdog_config.json`` (defaults + tasks.<id>
overrides: top_k, floor, mutes, cadence, paths); CLI flags override
everything. A missing/corrupt config degrades to builtin defaults (a
broken config never wedges wave start).

Pure stdlib; ASCII paths; loopback only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.request

if __package__ in (None, ""):
    # Direct-script launch (``python <path>\vuln_watchdog\run.py``): the
    # main script has no parent package, so the relative imports below
    # would raise ImportError. Re-anchor: put the repo root (this dir's
    # parent) on sys.path and declare the package. Module-form launch
    # (``python -m vuln_watchdog.run``) is unaffected.
    sys.path.insert(
        0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    __package__ = "vuln_watchdog"

from . import embed_client as ec
from . import event_schema as es
from . import highlights as hl
from . import matcher as mt
from . import query as qy
from . import store as st
from . import tailers as tl

RUN_STATE_FILENAME = "watchdog-run.json"
PID_FILENAME = "watchdog.pid"
STOP_FILENAME = "stop-request"

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(_HERE, "data", "watchdog_config.json")

#: Last-resort defaults (the checked-in config file layers over these).
BUILTIN_DEFAULTS = {
    "top_k": 3,
    "floor": 0.49,               # recalibrated on the FULL store
                                 # 2026-10-16 (design 5.3.4; rule
                                 # ceil(neg_top1+0.02); record:
                                 # artifacts/p4-floor-recalibration-applied.md)
    "poll_interval_s": 1.0,
    "state_interval_s": 5.0,
    "backoff_s": 60.0,           # design section 7: 60 s retry backoff
    "per_event_deadline_s": 60.0,
    "console": True,
    "mute_record_ids": [],
    "mute_url_prefixes": [],
    "filters": None,
    "spool_root": None,
    "ledger_path": None,
    "evidence_dir": None,
    "store_path": None,
}
# M2.1 (VulnDog config system v2, F-1): the product namespaces are KNOWN to
# the merge so a config file's proxy/scope/runs/db/ai values APPLY through
# this same door. Before M2.1 they were quarantined into _unknown_keys and
# never used (a config file could not even restrict scope). Their built-in
# defaults live in vulndog.config (one decision in one place); the merge
# logic below is unchanged and genuinely unknown keys are still isolated.
# Post-vendoring delta recorded in engine/VENDORING.md (ADR-1).
_PRODUCT_KEYS = frozenset({"proxy", "scope", "runs", "db", "ai"})
_KNOWN_KEYS = frozenset(BUILTIN_DEFAULTS) | _PRODUCT_KEYS

# Task-id law: COND-6 parity with the upstream tap module (mirrored
# locally to avoid coupling runtime behavior to a private helper; parity
# is test-enforced -- tests/test_run.py::TaskIdParityTest).
_TASK_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_WINDOWS_RESERVED_STEMS = frozenset(
    {"con", "prn", "aux", "nul"}
    | {"com%d" % i for i in range(1, 10)}
    | {"lpt%d" % i for i in range(1, 10)})

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def validate_task_id(value) -> bool:
    """ASCII single-path-segment task-id law (traversal, Windows device
    names, trailing dot/dash, 128 cap all rejected)."""
    if not isinstance(value, str) or _TASK_ID_RE.match(value) is None:
        return False
    if ".." in value:
        return False
    if value[-1] in ".-":
        return False
    return value.split(".", 1)[0].lower() not in _WINDOWS_RESERVED_STEMS


# ------------------------------------------------------------------- paths

def repo_root() -> str:
    return os.path.dirname(_HERE)


def default_spool_root() -> str:
    return os.path.join(repo_root(), "evidence", "watchdog")


def default_ledger_path() -> str:
    return os.path.join(repo_root(), "evidence", "guard_log.jsonl")


def default_evidence_dir() -> str:
    return os.path.join(repo_root(), "evidence")


# ------------------------------------------------------------------ config

def load_config(path: str = None, task_id: str = None) -> dict:
    """builtin defaults <- file defaults <- tasks.<task_id> overrides.

    Missing/corrupt file -> builtins + a ``_config_errors`` note (never
    a crash: wave start must not wedge on a broken config). Unknown keys
    are isolated into ``_unknown_keys`` (typo visibility, never applied).
    """
    cfg = dict(BUILTIN_DEFAULTS)
    cfg["mute_record_ids"] = []
    cfg["mute_url_prefixes"] = []
    cfg["_config_errors"] = []
    cfg["_unknown_keys"] = []
    cfg_path = path or DEFAULT_CONFIG_PATH
    data = None
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        cfg["_config_errors"].append("config-missing:%s" % cfg_path)
    except (OSError, ValueError) as exc:
        cfg["_config_errors"].append(
            "config-unreadable:%s:%s" % (cfg_path, type(exc).__name__))

    def merge(section):
        if not isinstance(section, dict):
            return
        for key, value in section.items():
            if key in _KNOWN_KEYS:
                cfg[key] = value
            else:
                cfg["_unknown_keys"].append(key)

    if isinstance(data, dict):
        # UX-1: a known config key sitting at the TOP level (outside the
        # 'defaults' wrapper) is dropped by the merge below without a
        # trace — the user believes it applies when it does not. Surface
        # a stable warning note (the CLI prints it on stderr); builtins
        # proceed (the never-crash law). Legitimate top-level keys
        # (config_version, defaults, tasks, floor_note, _readme) are not
        # in _KNOWN_KEYS, so a correctly-shaped file stays silent.
        misplaced = sorted(k for k in data if k in _KNOWN_KEYS)
        if misplaced:
            cfg["_config_errors"].append(
                "keys found outside 'defaults' (%s) — ignored; move them "
                "under 'defaults' to apply" % ", ".join(misplaced))
        merge(data.get("defaults"))
        tasks = data.get("tasks")
        if isinstance(tasks, dict) and task_id:
            merge(tasks.get(task_id))
        note = data.get("floor_note")
        if isinstance(note, str):
            cfg["floor_note"] = note
    return cfg


def _apply_cli_overrides(cfg: dict, args) -> None:
    pairs = (("floor", "floor"), ("top_k", "top_k"),
             ("poll", "poll_interval_s"), ("backoff", "backoff_s"),
             ("spool_root", "spool_root"), ("ledger", "ledger_path"),
             ("evidence_dir", "evidence_dir"), ("store", "store_path"))
    for attr, key in pairs:
        value = getattr(args, attr, None)
        if value is not None:
            cfg[key] = value


# ------------------------------------------------------------ small helpers

def _safe_print(line) -> None:
    try:
        print(line, flush=True)
    except Exception:  # noqa: BLE001 -- console must never kill the loop
        try:
            print(str(line).encode("ascii", "replace").decode("ascii"))
        except Exception:  # noqa: BLE001
            pass


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _read_pid(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _remove(path) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return None


def pid_alive(pid) -> bool:
    """Cross-platform liveness: tasklist on Windows (os.kill(pid, 0) is
    TERMINATE semantics there -- never use it), signal 0 on POSIX."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            proc = subprocess.run(
                ["tasklist", "/FI", "PID eq %d" % pid, "/NH"],
                capture_output=True, timeout=15,
                creationflags=_NO_WINDOW)
        except Exception:  # noqa: BLE001
            return False
        # bytes -> text with errors="replace": tasklist may emit process
        # names in the OEM codepage (non-UTF-8); pid matching is ASCII
        stdout = (proc.stdout or b"").decode("utf-8", "replace")
        for line in stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == str(pid):
                return True
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def ollama_status(timeout_s: float = 2.0) -> dict:
    """Loopback reachability probe via the embed client's OWN constants
    (single-address law, design 5.1/C7 -- no url is built here)."""
    url = ec.OLLAMA_BASE_URL + "/api/tags"
    try:
        req = urllib.request.Request(url, method="GET")
        with ec.make_no_proxy_opener().open(req, timeout=timeout_s) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        models = [str(m.get("name", "")) for m in data.get("models", [])
                  if isinstance(m, dict)]
        return {"reachable": True, "models": models,
                "has_embed_model": ec.DEFAULT_MODEL in models}
    except Exception as exc:  # noqa: BLE001 -- status must never raise
        return {"reachable": False, "error": type(exc).__name__,
                "models": [], "has_embed_model": False}


def _hard_kill(pid) -> bool:
    try:
        if os.name == "nt":
            proc = subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                                  capture_output=True, timeout=15,
                                  creationflags=_NO_WINDOW)
            return proc.returncode == 0
        os.kill(int(pid), signal.SIGKILL)
        return True
    except Exception:  # noqa: BLE001
        return False


# ------------------------------------------------------------------ runner

class WatchdogRunner:
    """The watchdog process body: tailers -> matcher -> surfaces.

    Injectable seams for tests/drills: ``api`` (query API double),
    ``console`` (line sink), ``clock``/``sleeper``. Production:
    QueryAPI on the store, stdout console, monotonic clock."""

    def __init__(self, task_id, cfg, *, api=None, console=None,
                 clock=time.monotonic, sleeper=time.sleep,
                 spool_root=None, ledger_path=None, evidence_dir=None,
                 store_path=None):
        if not validate_task_id(task_id):
            raise ValueError("invalid task_id: %r" % (task_id,))
        self.task_id = str(task_id)
        self.cfg = dict(cfg or BUILTIN_DEFAULTS)
        self.clock = clock
        self.sleeper = sleeper
        self.spool_root = spool_root or self.cfg.get("spool_root") \
            or default_spool_root()
        self.task_dir = os.path.join(self.spool_root, self.task_id)
        self.ledger_path = ledger_path or self.cfg.get("ledger_path") \
            or default_ledger_path()
        self.evidence_dir = evidence_dir or self.cfg.get("evidence_dir") \
            or default_evidence_dir()
        self.store_path = store_path or self.cfg.get("store_path") \
            or st.DEFAULT_STORE_PATH

        console_flag = self.cfg.get("console", True)
        self.console = console if console is not None \
            else (_safe_print if console_flag else None)

        self.api = api if api is not None \
            else qy.QueryAPI(store_path=self.store_path)
        self.matcher = mt.Matcher(
            self.api,
            floor=self.cfg.get("floor"),
            top_k=self.cfg.get("top_k"),
            filters=self.cfg.get("filters"),
            mute_record_ids=self.cfg.get("mute_record_ids") or (),
            mute_url_prefixes=self.cfg.get("mute_url_prefixes") or (),
            console=self.console,
            clock=clock,
            backoff_s=float(self.cfg.get("backoff_s",
                                         mt.DEFAULT_BACKOFF_S)),
            per_event_deadline_s=float(self.cfg.get(
                "per_event_deadline_s", mt.DEFAULT_PER_EVENT_DEADLINE_S)))
        self.writer = hl.HighlightsWriter(self.task_dir, self.task_id,
                                          console=self.console)
        self.spool_tailer = tl.SpoolTailer(
            os.path.join(self.task_dir, "events.jsonl"),
            hunt_id=self.task_id)
        self.ledger_tailer = tl.LedgerTailer(self.ledger_path) \
            if self.ledger_path else None
        self.evidence_tailer = None      # lazy: created when the dir exists

        self.pid_path = os.path.join(self.task_dir, PID_FILENAME)
        self.stop_path = os.path.join(self.task_dir, STOP_FILENAME)
        self.state_path = os.path.join(self.task_dir, RUN_STATE_FILENAME)
        self._stop_requested = False
        self._cycles = 0
        self._started_ts = None
        self._state_errors = 0
        self._last_state_persist = None

    # ------------------------------------------------------------- control
    def request_stop(self) -> None:
        self._stop_requested = True

    def _check_stop_file(self) -> bool:
        try:
            if os.path.exists(self.stop_path):
                self._stop_requested = True
                return True
        except OSError:
            pass
        return False

    def _install_signals(self) -> None:
        def handler(signum, frame):  # noqa: ANN001 -- stdlib signature
            self._stop_requested = True

        for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError, RuntimeError):
                pass        # non-main thread / platform: stop file still works

    def _announce(self, line: str) -> None:
        if self.console is not None:
            try:
                self.console(line)
            except Exception:  # noqa: BLE001
                pass

    # --------------------------------------------------------------- loop
    def run(self, max_cycles=None) -> int:
        """Foreground loop. Bounded mode (``max_cycles``) drains without
        inter-cycle sleeps (tests/drills/scripts); unbounded mode is the
        operator's wave process."""
        self._started_ts = es.utc_now_iso()
        try:
            os.makedirs(self.task_dir, exist_ok=True)
            with open(self.pid_path, "w", encoding="utf-8") as fh:
                fh.write(str(os.getpid()))
        except OSError:
            self._state_errors += 1
        self._persist_state()
        self._install_signals()
        self._announce("watchdog start: task=%s pid=%d store=%s floor=%s "
                       "top_k=%s" % (self.task_id, os.getpid(),
                                     self.store_path,
                                     self.cfg.get("floor"),
                                     self.cfg.get("top_k")))
        for err in (self.cfg.get("_config_errors") or []):
            self._announce("config: %s (builtin defaults in force)" % err)
        bounded = max_cycles is not None
        self._check_stop_file()
        try:
            while not self._stop_requested:
                if bounded and self._cycles >= int(max_cycles):
                    break
                self.cycle()
                self._cycles += 1
                if self._check_stop_file():
                    break
                self._persist_state_if_due()
                if not bounded:
                    self._sleep_poll()
            self.cycle()          # final drain (clean-stop semantics)
            self._cycles += 1
        finally:
            self._shutdown()
        return 0

    def cycle(self) -> None:
        """One loop iteration: backoff gate -> retry drain -> poll ->
        match -> emit. While Ollama is down/hung and the backoff has NOT
        elapsed, this does NOTHING: no polling, so no offsets advance and
        the backlog accumulates as the unprocessed spool tail (design
        section 7)."""
        if self.matcher.down:
            if self.clock() < self.matcher.next_retry:
                return
            drained, hls = self.matcher.retry_pending()
            self._emit(hls)
            if not drained:
                return
        events = self.poll_all()
        if events:
            self._emit(self.matcher.consume(events))

    def poll_all(self) -> list:
        events = self.spool_tailer.poll()
        if self.ledger_tailer is not None:
            events.extend(self.ledger_tailer.poll())
        if self.evidence_tailer is None and self.evidence_dir:
            try:
                if os.path.isdir(self.evidence_dir):
                    self.evidence_tailer = tl.EvidenceTailer(
                        self.evidence_dir, hunt_id=self.task_id)
            except OSError:
                pass
        if self.evidence_tailer is not None:
            events.extend(self.evidence_tailer.poll())
        return events

    def _emit(self, hls) -> None:
        for h in hls:
            self.writer.emit(h)

    def _sleep_poll(self) -> None:
        remaining = float(self.cfg.get("poll_interval_s", 1.0))
        while remaining > 0 and not self._stop_requested:
            chunk = min(0.25, remaining)
            try:
                self.sleeper(chunk)
            except Exception:  # noqa: BLE001
                pass
            remaining -= chunk
            self._check_stop_file()

    # -------------------------------------------------------------- state
    def state_snapshot(self) -> dict:
        counters = self.matcher.stats()
        mode = counters.pop("mode", self.matcher.mode)
        pending = counters.pop("pending", len(self.matcher.pending))
        return {
            "task_id": self.task_id,
            "pid": os.getpid(),
            "started_ts": self._started_ts,
            "mode": mode,
            "pending": pending,
            "next_retry_in_s": round(max(
                0.0, self.matcher.next_retry - self.clock()), 1)
                if self.matcher.down else 0.0,
            "status_lines": list(self.matcher.status_lines)[-10:],
            "counters": counters,
            "writer": self.writer.stats(),
            "tailers": {
                "spool": self.spool_tailer.stats(),
                "ledger": self.ledger_tailer.stats()
                          if self.ledger_tailer else None,
                "evidence": self.evidence_tailer.stats()
                            if self.evidence_tailer else None,
            },
            "cycles": self._cycles,
            "heartbeat_ts": time.time(),
            "config": {k: self.cfg.get(k) for k in (
                "top_k", "floor", "poll_interval_s", "backoff_s",
                "per_event_deadline_s", "mute_record_ids",
                "mute_url_prefixes", "filters", "store_path")},
            "paths": {
                "spool_root": self.spool_root,
                "task_dir": self.task_dir,
                "ledger_path": self.ledger_path,
                "evidence_dir": self.evidence_dir,
                "store_path": self.store_path,
            },
            "state_errors": self._state_errors,
        }

    def _persist_state(self, extra: dict = None) -> None:
        snap = self.state_snapshot()
        if extra:
            snap.update(extra)
        tmp = self.state_path + ".tmp"
        try:
            os.makedirs(self.task_dir, exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(snap, fh, allow_nan=False)
            os.replace(tmp, self.state_path)
            self._last_state_persist = self.clock()
        except (OSError, ValueError):
            self._state_errors += 1
            _remove(tmp)

    def _persist_state_if_due(self) -> None:
        interval = float(self.cfg.get("state_interval_s", 5.0))
        now = self.clock()
        if self._last_state_persist is None \
                or (now - self._last_state_persist) >= interval:
            self._persist_state()

    def _shutdown(self) -> None:
        try:
            self.writer.write_summary(self.matcher.stats(),
                                      bursts=self.matcher.burst_counts)
        except Exception:  # noqa: BLE001 -- shutdown must complete
            self._state_errors += 1
        stats = self.matcher.stats()
        self._persist_state(extra={
            "exited_ts": es.utc_now_iso(),
            "exit_stats": {
                "cycles": self._cycles,
                "highlights": stats.get("highlights"),
                "write_errors": self.writer.stats().get("write_errors"),
                "state_errors": self._state_errors,
            },
        })
        _remove(self.pid_path)
        _remove(self.stop_path)
        self._announce("watchdog stopped: task=%s cycles=%d highlights=%s"
                       % (self.task_id, self._cycles, stats.get("highlights")))


# -------------------------------------------------------------------- stop

def stop_running(task_dir, *, timeout_s: float = 30.0, force: bool = False,
                 alive_fn=None, sleeper=None, clock=None, out=None) -> int:
    """Clean-stop mechanics: request a clean stop, wait for it, VERIFY
    no lingering process. Never kills implicitly (``force`` is the
    explicit hard path). Returns 0 on verified stop, 2 otherwise."""
    alive_fn = alive_fn or pid_alive
    sleeper = sleeper or time.sleep
    clock = clock or time.monotonic
    out = out or _safe_print
    task_dir = str(task_dir)
    pid_path = os.path.join(task_dir, PID_FILENAME)
    stop_path = os.path.join(task_dir, STOP_FILENAME)
    state_path = os.path.join(task_dir, RUN_STATE_FILENAME)

    pid = _read_pid(pid_path)
    if pid is None:
        state = _read_json(state_path)
        if state and state.get("exited_ts"):
            out("not running (clean exit recorded at %s)"
                % state.get("exited_ts"))
        else:
            out("not running (no pid file at %s)" % pid_path)
        _remove(stop_path)          # stale stop-request hygiene
        return 0

    try:
        os.makedirs(task_dir, exist_ok=True)
        with open(stop_path, "w", encoding="utf-8") as fh:
            fh.write("stop requested %s\n" % es.utc_now_iso())
    except OSError as exc:
        out("stop-request write failed: %r" % (exc,))
        return 2

    deadline = clock() + max(0.1, float(timeout_s))
    exited = False
    while clock() < deadline:
        if not alive_fn(pid):
            exited = True
            break
        try:
            sleeper(0.2)
        except Exception:  # noqa: BLE001
            pass
    if not exited and alive_fn(pid):
        if not force:
            out("watchdog pid %d still running after %.1fs; re-run with "
                "--force to terminate hard" % (pid, timeout_s))
            return 2
        if not _hard_kill(pid):
            out("hard kill failed for pid %d" % pid)
            return 2
        try:
            sleeper(0.3)
        except Exception:  # noqa: BLE001
            pass
        out("watchdog pid %d terminated via --force" % pid)

    state = _read_json(state_path)
    if state and state.get("exited_ts"):
        counters = state.get("counters") or {}
        out("stopped cleanly at %s (highlights=%s events_in=%s)"
            % (state.get("exited_ts"), counters.get("highlights"),
               counters.get("events_in")))
    else:
        out("stopped (no clean-exit run-state; process gone%s)"
            % ("" if exited else ", forced"))

    if alive_fn(pid):
        out("WARNING: pid %d still alive after stop" % pid)
        return 2
    out("verified: no lingering process (pid %d gone)" % pid)
    _remove(pid_path)               # stale pid hygiene (crash/force paths)
    _remove(stop_path)
    return 0


# ------------------------------------------------------------------ status

def status_data(task_id, *, spool_root=None, ledger_path=None,
                evidence_dir=None, store_path=None, ollama_prober=None,
                alive_fn=None, now=None) -> dict:
    """Everything the status command needs: process + matching + store +
    ollama + last offsets + file sizes. Probe/IO failures never raise.
    An INVALID task_id raises ValueError BEFORE any path is built or
    read (D-1, QA qa-p4-1 -- defense in depth behind the CLI check;
    same law as WatchdogRunner.__init__)."""
    if not validate_task_id(task_id):
        raise ValueError("invalid task_id: %r" % (task_id,))
    ollama_prober = ollama_prober or ollama_status
    alive_fn = alive_fn or pid_alive
    now = time.time() if now is None else now
    spool_root = spool_root or default_spool_root()
    task_dir = os.path.join(spool_root, str(task_id))
    ledger_path = ledger_path or default_ledger_path()
    evidence_dir = evidence_dir or default_evidence_dir()
    store_path = store_path or st.DEFAULT_STORE_PATH

    pid = _read_pid(os.path.join(task_dir, PID_FILENAME))
    state = _read_json(os.path.join(task_dir, RUN_STATE_FILENAME)) or {}
    heartbeat = state.get("heartbeat_ts")
    data = {"task_id": str(task_id), "generated_ts": es.utc_now_iso()}
    data["process"] = {
        "pid": pid,
        "running": bool(pid is not None and alive_fn(pid)),
        "started_ts": state.get("started_ts"),
        "exited_ts": state.get("exited_ts"),
        "heartbeat_ts": heartbeat,
        "heartbeat_age_s": round(now - heartbeat, 1)
        if isinstance(heartbeat, (int, float)) else None,
        "cycles": state.get("cycles"),
        "exit_stats": state.get("exit_stats"),
    }
    data["matching"] = {
        "mode": state.get("mode"),
        "pending": state.get("pending"),
        "next_retry_in_s": state.get("next_retry_in_s"),
        "status_lines": state.get("status_lines") or [],
        "counters": state.get("counters") or {},
        "writer": state.get("writer") or {},
    }
    store_sec = {"path": store_path, "exists": os.path.exists(store_path),
                 "bytes": _size(store_path)}
    manifest = _read_json(os.path.join(os.path.dirname(store_path) or ".",
                                       st.MANIFEST_FILENAME)) or {}
    counts = manifest.get("counts") or {}
    store_sec.update({
        "corpus_version": manifest.get("corpus_version"),
        "stage": manifest.get("stage"),
        "records_total": counts.get("records_total"),
        "chunks_total": counts.get("chunks_total"),
    })
    data["store"] = store_sec
    try:
        data["ollama"] = dict(ollama_prober() or {})
    except Exception:  # noqa: BLE001
        data["ollama"] = {"reachable": False, "models": [],
                          "has_embed_model": False}
    spool_state = _read_json(os.path.join(task_dir, "state.json")) or {}
    ledger_state = _read_json(os.path.join(os.path.dirname(ledger_path) or ".",
                                           "watchdog_state_ledger.json")) or {}
    evidence_state = _read_json(os.path.join(
        evidence_dir, "watchdog_state_evidence.json")) or {}
    data["offsets"] = {
        "spool_offset": spool_state.get("offset", 0),
        "ledger_offset": ledger_state.get("offset", 0),
        "evidence_files_tracked": len(evidence_state.get("files") or {}),
    }
    data["files"] = {
        "spool_bytes": _size(os.path.join(task_dir, "events.jsonl")),
        "highlights_jsonl_bytes": _size(os.path.join(task_dir,
                                                     "highlights.jsonl")),
        "highlights_md_bytes": _size(os.path.join(task_dir,
                                                  "highlights.md")),
    }
    return data


def format_status(data: dict) -> list:
    lines = ["task: %s (generated %s)" % (data.get("task_id"),
                                          data.get("generated_ts"))]
    p = data.get("process") or {}
    lines.append("process: pid=%s running=%s started=%s exited=%s "
                 "heartbeat_age_s=%s cycles=%s"
                 % (p.get("pid"), p.get("running"), p.get("started_ts"),
                    p.get("exited_ts"), p.get("heartbeat_age_s"),
                    p.get("cycles")))
    m = data.get("matching") or {}
    counters = m.get("counters") or {}
    lines.append("matching: mode=%s pending=%s highlights=%s events_in=%s"
                 % (m.get("mode"), m.get("pending"),
                    counters.get("highlights"), counters.get("events_in")))
    for sl in (m.get("status_lines") or [])[-5:]:
        lines.append("  | %s" % sl)
    s = data.get("store") or {}
    lines.append("store: exists=%s corpus_version=%s stage=%s records=%s "
                 "bytes=%s" % (s.get("exists"), s.get("corpus_version"),
                               s.get("stage"), s.get("records_total"),
                               s.get("bytes")))
    o = data.get("ollama") or {}
    lines.append("ollama: reachable=%s embed_model=%s"
                 % (o.get("reachable"), o.get("has_embed_model")))
    off = data.get("offsets") or {}
    lines.append("offsets: spool=%s ledger=%s evidence_files=%s"
                 % (off.get("spool_offset"), off.get("ledger_offset"),
                    off.get("evidence_files_tracked")))
    f = data.get("files") or {}
    lines.append("files: spool=%sB highlights.jsonl=%sB highlights.md=%sB"
                 % (f.get("spool_bytes"), f.get("highlights_jsonl_bytes"),
                    f.get("highlights_md_bytes")))
    return lines


def list_tasks(spool_root: str) -> list:
    try:
        names = sorted(os.listdir(spool_root))
    except OSError:
        return []
    return [n for n in names
            if validate_task_id(n) and os.path.isdir(
                os.path.join(spool_root, n))]


# --------------------------------------------------------------------- cli

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m vuln_watchdog.run",
        description="vuln-watchdog lifecycle CLI (WD-R3): start/stop/status;"
                    " bare <task-id> = start.")
    p.add_argument("command",
                   help="start | stop | status | <task-id> (bare = start)")
    p.add_argument("task", nargs="?", default=None,
                   help="task id (the guard-ledger task_id)")
    p.add_argument("--config", default=None,
                   help="config json (default: data/watchdog_config.json)")
    p.add_argument("--spool-root", dest="spool_root", default=None)
    p.add_argument("--ledger", default=None,
                   help="guard_log.jsonl path (default: evidence)")
    p.add_argument("--evidence-dir", dest="evidence_dir", default=None)
    p.add_argument("--store", default=None, help="vulnkb.sqlite path")
    p.add_argument("--floor", type=float, default=None)
    p.add_argument("--top-k", dest="top_k", type=int, default=None)
    p.add_argument("--poll", type=float, default=None,
                   help="poll interval seconds")
    p.add_argument("--backoff", type=float, default=None,
                   help="ollama-down retry backoff seconds")
    p.add_argument("--max-cycles", dest="max_cycles", type=int, default=None,
                   help="bounded drain mode (scripts/drills)")
    p.add_argument("--once", action="store_true",
                   help="alias for --max-cycles 1")
    p.add_argument("--json", action="store_true",
                   help="status: machine-readable output")
    p.add_argument("--timeout", type=float, default=30.0,
                   help="stop: wait seconds for the clean exit")
    p.add_argument("--force", action="store_true",
                   help="stop: hard-kill after timeout (explicit only)")
    return p


def main(argv=None, runner_factory=None, probers=None, out=None) -> int:
    out = out or _safe_print
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return 0 if code is None else int(code)

    command = args.command
    task = args.task
    if command not in ("start", "stop", "status"):
        if task is None:
            command, task = "start", command    # bare alias
        else:
            out("unknown command: %r (start|stop|status)" % command)
            return 2
    if command in ("start", "stop") and not validate_task_id(task):
        out("invalid task-id: %r (ASCII single-segment law; COND-6 parity)"
            % (task,))
        return 2
    if command == "status" and task is not None \
            and not validate_task_id(task):
        # D-1 (QA qa-p4-1): status parity with start/stop -- a hostile
        # task-id is rejected BEFORE status_data joins it into a path
        # (previously it escaped the spool root and read run-state from
        # any directory). The taskless listing branch stays as-is:
        # list_tasks() already filters names through validate_task_id.
        out("invalid task-id: %r (ASCII single-segment law; COND-6 parity)"
            % (task,))
        return 2
    if args.once and args.max_cycles is None:
        args.max_cycles = 1

    cfg = load_config(args.config,
                      task if command in ("start", "stop") else None)
    _apply_cli_overrides(cfg, args)
    probers = probers or {}
    spool_root = args.spool_root or cfg.get("spool_root") \
        or default_spool_root()
    ledger_path = args.ledger or cfg.get("ledger_path")
    evidence_dir = args.evidence_dir or cfg.get("evidence_dir")
    store_path = args.store or cfg.get("store_path")

    if command == "start":
        factory = runner_factory or (lambda tid, c, a: WatchdogRunner(tid, c))
        runner = factory(task, cfg, args)
        return int(runner.run(max_cycles=args.max_cycles) or 0)

    if command == "stop":
        task_dir = os.path.join(spool_root, task)
        return stop_running(task_dir, timeout_s=args.timeout,
                            force=args.force,
                            alive_fn=probers.get("alive"), out=out)

    # status
    if task is None:
        names = list_tasks(spool_root)
        if not names:
            out("no watchdog task dirs under %s" % spool_root)
            return 0
        probe_once = {}

        def prober_fn():
            if "r" not in probe_once:
                probe_once["r"] = (probers.get("ollama") or ollama_status)()
            return probe_once["r"]

        out("watchdog tasks under %s:" % spool_root)
        for name in names:
            data = status_data(
                name, spool_root=spool_root, ledger_path=ledger_path,
                evidence_dir=evidence_dir, store_path=store_path,
                ollama_prober=prober_fn, alive_fn=probers.get("alive"))
            proc = data["process"]
            counters = data["matching"]["counters"]
            out("  %-24s pid=%-8s running=%-5s mode=%-10s highlights=%s"
                % (name, proc.get("pid"), proc.get("running"),
                   data["matching"].get("mode"),
                   counters.get("highlights")))
        return 0

    data = status_data(task, spool_root=spool_root,
                       ledger_path=ledger_path, evidence_dir=evidence_dir,
                       store_path=store_path,
                       ollama_prober=probers.get("ollama"),
                       alive_fn=probers.get("alive"))
    if args.json:
        out(json.dumps(data, indent=1))
    else:
        for line in format_status(data):
            out(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
