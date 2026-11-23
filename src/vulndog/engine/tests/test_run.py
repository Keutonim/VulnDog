"""Tests for vuln_watchdog.run (WD-R3 lifecycle CLI; design-spec 3.4/5.5,
P4). Contract under test:

- task-id law: COND-6 rule conformance (Windows reserved names,
  traversal, trailing dot/dash, 128-cap, ASCII). Upstream tested PARITY
  against the upstream tap module's _valid_task_id; VulnDog does not
  vendor that producer, so the battery asserts the documented rule
  directly (run.py validate_task_id; see VENDORING.md);
- config: builtin defaults <- config-file defaults <- per-task overrides
  <- CLI overrides; missing/corrupt file degrades to builtins (a broken
  config never wedges wave start);
- runner: start = drain from persisted offsets (attach-mid-hunt legal),
  clean stop = final drain + run summary + pid/stop-file cleanup +
  exited run-state (stop is CLEAN); stop-request file and
  signals both stop it; Ollama-down backoff FREEZES polling (offsets do
  not advance; the backlog accumulates as the unprocessed spool tail)
  and the retry drains the pending buffer in order;
- pid_alive: real on this platform (self=alive, absurd pid=dead);
- stop command: writes stop-request, waits for clean exit, verifies NO
  lingering process, reports exit stats; stubborn process
  -> timeout rc 2 with the --force hint (never an implicit kill);
- status: process + store + ollama + last offsets sections
  ("status = verifiable"), machine-readable --json;
- main(): start/stop/status + the bare "<task-id>" alias
  (`run.py <task-id>`), invalid ids exit 2;
- status task-id validation (QA D-1, artifacts/qa-p4-1.md): `status
  <task-id>` validates the id BEFORE any path use (COND-6 parity with
  start/stop), and status_data itself rejects hostile ids with
  ValueError -- a traversal id never reads run-state outside the spool
  root.
"""
import json
import os
import shutil
import tempfile
import threading
import time
import unittest

from vulndog.engine import event_schema as es
from vulndog.engine import matcher as mt
from vulndog.engine import redaction_adapter as ra
from vulndog.engine import run as rn


class FakeClock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def ok_env(matches=(), corpus_version="vkb1-fake"):
    return {"status": "ok", "reason": None, "matches": list(matches),
            "prefilter_hits": 5, "pinned": 0,
            "corpus_version": corpus_version}


def skip_env(reason="embed-failed"):
    return {"status": "skipped", "reason": reason,
            "matches": [], "prefilter_hits": 0, "pinned": 0,
            "corpus_version": None}


def m_entry(record_id="CVE-2026-1", score=0.61, **over):
    m = {"record_id": record_id, "kind": "cve", "title": "T " + record_id,
         "score": score, "reason": "semantic", "cwe_ids": ["cwe-79"],
         "owasp_categories": ["A03:2021-Injection"],
         "cvss": {"score": 7.5, "severity": "HIGH"},
         "exploit_available": False, "matched_snippet": "snip " + record_id}
    m.update(over)
    return m


class FakeAPI:
    def __init__(self, script=None, default=None):
        self.script = list(script or [])
        self.default = default if default is not None else ok_env([])
        self.calls = []

    def match(self, text, top_k=None, filters=None, floor=None, **kw):
        self.calls.append({"text": text, "floor": floor, "top_k": top_k})
        item = self.script.pop(0) if self.script else self.default
        return item(text) if callable(item) else item


def spool_event(url="http://127.0.0.1:9/upload", body="upload php shell",
                hunt_id="t1", **over):
    ev = es.make_event(tap_class="python", url=url, decision="allowed",
                       provenance="net_gate.guarded_request",
                       hunt_id=hunt_id, method="POST", status=200,
                       content_type="text/html", body_redacted=body)
    red, dropped = ra.redact_event(ev)
    assert not dropped
    return red


class BaseTmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-r3-")
        self.spool_root = os.path.join(self.tmp, "spool")
        self.task_dir = os.path.join(self.spool_root, "t1")
        self.ledger_dir = os.path.join(self.tmp, "led")
        os.makedirs(self.ledger_dir, exist_ok=True)
        self.ledger = os.path.join(self.ledger_dir, "guard_log.jsonl")
        self.evidence = os.path.join(self.tmp, "ev")
        self.lines = []

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def cfg(self, **over):
        base = dict(rn.BUILTIN_DEFAULTS)
        base.update({"poll_interval_s": 0.01, "state_interval_s": 0.0,
                     "spool_root": self.spool_root,
                     "ledger_path": self.ledger,
                     "evidence_dir": self.evidence,
                     "store_path": os.path.join(self.tmp, "no-store.sqlite")})
        base.update(over)
        return base

    def seed_spool(self, events):
        os.makedirs(self.task_dir, exist_ok=True)
        with open(os.path.join(self.task_dir, "events.jsonl"), "a",
                  encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")

    def runner(self, api=None, clock=None, **cfgover):
        return rn.WatchdogRunner(
            "t1", self.cfg(**cfgover),
            api=api if api is not None else FakeAPI(),
            console=self.lines.append,
            clock=clock or FakeClock(),
            sleeper=lambda s: None)

    def read_jsonl(self, name):
        p = os.path.join(self.task_dir, name)
        if not os.path.exists(p):
            return []
        with open(p, encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]

    def run_state(self):
        p = os.path.join(self.task_dir, rn.RUN_STATE_FILENAME)
        if not os.path.exists(p):
            return None
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)


# ------------------------------------------------------------------ task id

class TaskIdLawTest(unittest.TestCase):
    def test_cond6_rule_battery(self):
        # Upstream parity battery, expected values fixed by the COND-6
        # rule documented in run.py (ASCII single segment, alnum lead,
        # no "..", no trailing dot/dash, no Windows reserved stem,
        # 128-char cap). The upstream tap is not vendored (VENDORING.md).
        battery = [
            ("t1", True), ("task.id-2", True), ("A_1", True),
            ("drill-task", True), ("x" * 128, True), ("0", True),
            ("", False), ("..", False), (".", False), ("a/b", False),
            ("a\\b", False), ("CON", False), ("con", False),
            ("com1.x", False), ("NUL.json", False), ("trail.", False),
            ("trail-", False), ("-lead", False), ("x" * 129, False),
            ("task id", False), ("task\x00id", False), (None, False),
            (5, False), ("task\tid", False),
        ]
        for value, expected in battery:
            self.assertEqual(rn.validate_task_id(value), expected,
                             repr(value))

    def test_non_ascii_rejected(self):
        self.assertFalse(rn.validate_task_id("\u0442\u0430\u0441\u043a"))


# ------------------------------------------------------------------- config

class ConfigTest(BaseTmp):
    def test_missing_file_builtin_defaults(self):
        cfg = rn.load_config(os.path.join(self.tmp, "nope.json"))
        self.assertEqual(cfg["top_k"], rn.BUILTIN_DEFAULTS["top_k"])
        self.assertEqual(cfg["floor"], rn.BUILTIN_DEFAULTS["floor"])
        self.assertEqual(cfg["backoff_s"], 60.0)

    def test_corrupt_file_builtin_defaults(self):
        p = os.path.join(self.tmp, "bad.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        cfg = rn.load_config(p)
        self.assertEqual(cfg["top_k"], rn.BUILTIN_DEFAULTS["top_k"])
        self.assertTrue(cfg["_config_errors"])

    def test_defaults_and_task_override_merge(self):
        p = os.path.join(self.tmp, "cfg.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"defaults": {"floor": 0.42, "top_k": 5},
                       "tasks": {"t1": {"floor": 0.35,
                                        "mute_record_ids": ["CVE-1"]}}}, fh)
        cfg1 = rn.load_config(p, "t1")
        self.assertEqual(cfg1["floor"], 0.35)
        self.assertEqual(cfg1["top_k"], 5)            # default survives
        self.assertEqual(cfg1["mute_record_ids"], ["CVE-1"])
        cfg2 = rn.load_config(p, "other")
        self.assertEqual(cfg2["floor"], 0.42)

    def test_unknown_keys_isolated(self):
        p = os.path.join(self.tmp, "cfg2.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"defaults": {"flor": 0.9}}, fh)      # typo
        cfg = rn.load_config(p)
        self.assertEqual(cfg["floor"], rn.BUILTIN_DEFAULTS["floor"])
        self.assertIn("flor", cfg["_unknown_keys"])

    def test_checked_in_default_config_valid(self):
        self.assertTrue(os.path.exists(rn.DEFAULT_CONFIG_PATH))
        cfg = rn.load_config(rn.DEFAULT_CONFIG_PATH, "any")
        self.assertIsInstance(cfg["floor"], float)
        self.assertGreaterEqual(cfg["floor"], 0.0)
        self.assertLessEqual(cfg["floor"], 1.0)
        self.assertIsInstance(cfg["top_k"], int)
        self.assertFalse(cfg["_config_errors"])

    def test_floor_pins_full_store_recalibration(self):
        """Config-layer floor = 0.49 in BOTH places it lives
        (BUILTIN_DEFAULTS + checked-in watchdog_config.json).
        Recalibrated 2026-10-16 on the completed FULL store (corpus
        vkb1-20746897a071179b, 456,460 records): pre-registered rule
        ceil_to_0.01(max-negative-top1 + 0.02) = ceil(0.4680 + 0.02)
        -> 0.49; controls pos 12/13, neg 0/12, verbatim 2/2. Record:
        the internal calibration artifact p4/floor-calibration.json.
        query.py DEFAULT_SCORE_FLOOR (design
        layer) stays 0.55 -- the config layer overrides it."""
        self.assertEqual(rn.BUILTIN_DEFAULTS["floor"], 0.49)
        cfg = rn.load_config(rn.DEFAULT_CONFIG_PATH, "any")
        self.assertEqual(cfg["floor"], 0.49)


# ---------------------------------------------------------------- pid alive

class PidAliveTest(unittest.TestCase):
    def test_self_alive(self):
        self.assertTrue(rn.pid_alive(os.getpid()))

    def test_absurd_pid_dead(self):
        self.assertFalse(rn.pid_alive(429496729))

    def test_garbage_dead(self):
        self.assertFalse(rn.pid_alive("abc"))
        self.assertFalse(rn.pid_alive(None))
        self.assertFalse(rn.pid_alive(-1))


# --------------------------------------------------------------- runner core

class RunnerLifecycleTest(BaseTmp):
    def test_run_once_drains_spool_and_writes_surfaces(self):
        self.seed_spool([spool_event(), spool_event(url="http://h/second")])
        api = FakeAPI(default=ok_env([m_entry("CVE-2026-1")]))
        r = self.runner(api=api)
        rc = r.run(max_cycles=1)
        self.assertEqual(rc, 0)
        hls = self.read_jsonl("highlights.jsonl")
        self.assertEqual(len(hls), 2)
        self.assertEqual(hls[0]["record_id"], "CVE-2026-1")
        self.assertTrue(os.path.exists(os.path.join(self.task_dir,
                                                    "highlights.md")))
        st = self.run_state()
        self.assertIsNotNone(st["exited_ts"])
        self.assertEqual(st["counters"]["events_in"], 2)
        self.assertEqual(st["counters"]["highlights"], 2)
        # console carries the compact HL lines
        self.assertTrue(any(l.startswith("HL candidate") for l in self.lines))

    def test_pid_file_removed_after_clean_stop(self):
        r = self.runner()
        r.run(max_cycles=1)
        self.assertFalse(os.path.exists(os.path.join(
            self.task_dir, rn.PID_FILENAME)))
        self.assertFalse(os.path.exists(os.path.join(
            self.task_dir, rn.STOP_FILENAME)))

    def test_second_runner_resumes_without_reprocess(self):
        self.seed_spool([spool_event()])
        api = FakeAPI(default=ok_env([m_entry()]))
        self.runner(api=api).run(max_cycles=1)
        self.assertEqual(len(self.read_jsonl("highlights.jsonl")), 1)
        # simulated restart: a NEW runner on the same dirs
        self.runner(api=api).run(max_cycles=1)
        self.assertEqual(len(self.read_jsonl("highlights.jsonl")), 1,
                         "restart must resume from offsets, not replay")
        st = self.run_state()
        self.assertEqual(st["counters"]["events_in"], 0)

    def test_stop_file_precreated_exits_clean(self):
        os.makedirs(self.task_dir, exist_ok=True)
        with open(os.path.join(self.task_dir, rn.STOP_FILENAME), "w",
                  encoding="utf-8") as fh:
            fh.write("stop")
        r = self.runner()
        rc = r.run(max_cycles=50)
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(os.path.join(self.task_dir,
                                                     rn.STOP_FILENAME)))
        self.assertIsNotNone(self.run_state()["exited_ts"])

    def test_threaded_stop_file_mid_run(self):
        self.seed_spool([spool_event()])
        r = self.runner(api=FakeAPI(default=ok_env([m_entry()])))
        sleeps = []

        def sleeper(s):
            sleeps.append(s)
            if len(sleeps) == 2:
                with open(os.path.join(self.task_dir, rn.STOP_FILENAME),
                          "w", encoding="utf-8") as fh:
                    fh.write("stop")

        r.sleeper = sleeper
        rc = r.run()                     # unbounded; exits via stop file
        self.assertEqual(rc, 0)
        self.assertGreaterEqual(len(sleeps), 2)
        self.assertIsNotNone(self.run_state()["exited_ts"])
        # the seeded event was still processed before the stop
        self.assertEqual(len(self.read_jsonl("highlights.jsonl")), 1)

    def test_request_stop_method(self):
        r = self.runner()
        r.request_stop()
        self.assertEqual(r.run(max_cycles=None), 0)

    def test_run_summary_written(self):
        self.seed_spool([spool_event()])
        api = FakeAPI(default=ok_env([m_entry()]))
        self.runner(api=api).run(max_cycles=1)
        with open(os.path.join(self.task_dir, "highlights.md"),
                  encoding="utf-8") as fh:
            md = fh.read()
        self.assertIn("Run summary", md)

    def test_ledger_and_evidence_tailed(self):
        # ledger line (raw, like RequestMeter writes) + evidence txt delta
        entry = {"ts": "2026-10-16T02:00:00Z", "task_id": "t1",
                 "url": "http://h/led-path?x=1", "decision": "denied",
                 "engine": "net_guarded_request", "denial": "forbidden_paths",
                 "reason": "path", "rule": "SEC-02"}
        with open(self.ledger, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        os.makedirs(self.evidence, exist_ok=True)
        with open(os.path.join(self.evidence, "httpx_output.txt"), "w",
                  encoding="utf-8") as fh:
            fh.write("http://h/found 200\n")
        api = FakeAPI(default=ok_env([m_entry("CVE-LED")]))
        r = self.runner(api=api)
        r.run(max_cycles=1)
        st = self.run_state()
        self.assertGreaterEqual(st["counters"]["events_in"], 2)
        classes = {h["tap_class"] for h in
                   self.read_jsonl("highlights.jsonl")}
        self.assertIn("ledger", classes)
        self.assertIn("evidence", classes)

    def test_invalid_task_id_rejected(self):
        with self.assertRaises(ValueError):
            rn.WatchdogRunner("../evil", self.cfg(), api=FakeAPI())


# ------------------------------------------------------------- backoff mode

class RunnerBackoffTest(BaseTmp):
    def test_down_freezes_polling_and_retry_resumes_in_order(self):
        clock = FakeClock()
        self.seed_spool([spool_event(url="http://h/a", body="one"),
                         spool_event(url="http://h/b", body="two")])
        api = FakeAPI(default=skip_env("embed-failed"))
        r = self.runner(api=api, clock=clock)
        r.run(max_cycles=3)
        st = self.run_state()
        self.assertEqual(st["mode"], "ollama-down")
        self.assertEqual(st["pending"], 2)
        self.assertIn(mt.LINE_OLLAMA_DOWN, st["status_lines"])
        # both events were consumed into the pending buffer exactly once
        self.assertEqual(len(api.calls), 1)   # 2nd buffered, not matched
        self.assertEqual(len(self.read_jsonl("highlights.jsonl")), 0)

        # --- Ollama "returns": backoff elapsed, api now healthy
        clock.advance(61.0)
        api.script = [ok_env([m_entry("CVE-A")]), ok_env([m_entry("CVE-B")])]
        api.default = ok_env([])
        r2 = rn.WatchdogRunner("t1", self.cfg(), api=api,
                               console=self.lines.append, clock=clock,
                               sleeper=lambda s: None)
        # simulate the SAME process recovering: reuse r (in-memory pending)
        r.matcher.api = api
        r.run(max_cycles=1)
        hls = self.read_jsonl("highlights.jsonl")
        self.assertEqual([h["record_id"] for h in hls], ["CVE-A", "CVE-B"])
        st = self.run_state()
        self.assertEqual(st["mode"], "enabled")
        self.assertTrue(any(l.startswith("matching: ENABLED")
                            for l in self.lines), self.lines)
        self.assertIsNotNone(r2)   # constructed cleanly (restart path)

    def test_backoff_honored_no_retry_before_deadline(self):
        clock = FakeClock()
        self.seed_spool([spool_event()])
        api = FakeAPI(default=skip_env("embed-failed"))
        r = self.runner(api=api, clock=clock)
        r.run(max_cycles=1)
        calls_after_down = len(api.calls)
        clock.advance(30.0)          # < 60 s backoff
        r.run(max_cycles=2)
        self.assertEqual(len(api.calls), calls_after_down,
                         "no retry before the backoff deadline")


# -------------------------------------------------------------------- stop

class StopCommandTest(BaseTmp):
    def _make_running(self):
        os.makedirs(self.task_dir, exist_ok=True)
        with open(os.path.join(self.task_dir, rn.PID_FILENAME), "w",
                  encoding="utf-8") as fh:
            fh.write(str(os.getpid()))

    def test_stop_not_running(self):
        out = []
        rc = rn.stop_running(self.task_dir, out=out.append,
                             alive_fn=lambda pid: False,
                             sleeper=lambda s: None)
        self.assertEqual(rc, 0)
        self.assertTrue(any("not running" in l for l in out), out)

    def test_stop_reactive_clean_exit(self):
        self._make_running()
        stop_path = os.path.join(self.task_dir, rn.STOP_FILENAME)
        pid_path = os.path.join(self.task_dir, rn.PID_FILENAME)

        def fake_runner():
            for _ in range(200):
                if os.path.exists(stop_path):
                    state = {"exited_ts": es.utc_now_iso(),
                             "counters": {"highlights": 3}}
                    with open(os.path.join(self.task_dir,
                                           rn.RUN_STATE_FILENAME), "w",
                              encoding="utf-8") as fh:
                        json.dump(state, fh)
                    os.remove(pid_path)
                    return
                time.sleep(0.01)

        t = threading.Thread(target=fake_runner, daemon=True)
        t.start()
        out = []
        rc = rn.stop_running(self.task_dir, timeout_s=5.0, out=out.append,
                             alive_fn=lambda pid: os.path.exists(pid_path),
                             sleeper=time.sleep)
        t.join(5)
        self.assertEqual(rc, 0)
        joined = "\n".join(out)
        self.assertIn("stopped", joined)
        self.assertIn("no lingering process", joined)   # clean-stop law
        self.assertFalse(os.path.exists(stop_path))

    def test_stop_stubborn_timeout_rc2(self):
        self._make_running()
        out = []
        rc = rn.stop_running(self.task_dir, timeout_s=0.3, out=out.append,
                             alive_fn=lambda pid: True,
                             sleeper=lambda s: time.sleep(min(s, 0.05)))
        self.assertEqual(rc, 2)
        joined = "\n".join(out)
        self.assertIn("--force", joined)
        # pid file NOT removed by a non-force stop (honest state)
        self.assertTrue(os.path.exists(os.path.join(self.task_dir,
                                                    rn.PID_FILENAME)))
        # cleanup the stop-request the command wrote
        p = os.path.join(self.task_dir, rn.STOP_FILENAME)
        if os.path.exists(p):
            os.remove(p)


# ------------------------------------------------------------------ status

class StatusDataTest(BaseTmp):
    def test_sections_present(self):
        # a completed run leaves the run-state behind
        self.seed_spool([spool_event()])
        self.runner(api=FakeAPI(default=ok_env([m_entry()]))).run(max_cycles=1)
        # store fixture: file + manifest
        store_path = os.path.join(self.tmp, "vulnkb.sqlite")
        with open(store_path, "wb") as fh:
            fh.write(b"SQLite format 3\x00" + b"\x00" * 100)
        with open(os.path.join(self.tmp, "manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"corpus_version": "vkb1-stat", "stage": "slice",
                       "counts": {"records_total": 10, "chunks_total": 12}},
                      fh)
        data = rn.status_data(
            "t1", spool_root=self.spool_root, ledger_path=self.ledger,
            evidence_dir=self.evidence, store_path=store_path,
            ollama_prober=lambda: {"reachable": True,
                                    "models": ["embeddinggemma:300m"],
                                    "has_embed_model": True},
            alive_fn=lambda pid: False)
        for section in ("task_id", "process", "matching", "store",
                        "ollama", "offsets", "files"):
            self.assertIn(section, data)
        self.assertEqual(data["store"]["corpus_version"], "vkb1-stat")
        self.assertEqual(data["store"]["records_total"], 10)
        self.assertTrue(data["store"]["exists"])
        self.assertTrue(data["ollama"]["reachable"])
        self.assertFalse(data["process"]["running"])   # run exited
        self.assertIsNone(data["process"]["pid"])
        self.assertIsNotNone(data["process"]["exited_ts"])
        self.assertEqual(data["matching"]["mode"], "enabled")
        self.assertGreater(data["offsets"]["spool_offset"], 0)
        self.assertGreater(data["files"]["highlights_jsonl_bytes"], 0)
        self.assertGreater(data["files"]["highlights_md_bytes"], 0)

    def test_missing_everything_no_crash(self):
        data = rn.status_data(
            "ghost", spool_root=self.spool_root, ledger_path=self.ledger,
            evidence_dir=self.evidence,
            store_path=os.path.join(self.tmp, "none.sqlite"),
            ollama_prober=lambda: {"reachable": False, "models": [],
                                    "has_embed_model": False},
            alive_fn=lambda pid: False)
        self.assertFalse(data["store"]["exists"])
        self.assertFalse(data["process"]["running"])
        text = "\n".join(rn.format_status(data))
        self.assertIn("ghost", text)


# --------------------------------------------------------------------- cli

class MainCliTest(BaseTmp):
    def test_start_via_factory_and_overrides(self):
        made = {}

        class FakeRunner:
            def __init__(self, task_id, cfg, args):
                made["task_id"] = task_id
                made["cfg"] = cfg
                made["args"] = args

            def run(self, max_cycles=None):
                made["max_cycles"] = max_cycles
                return 0

        rc = rn.main(["start", "t1", "--spool-root", self.spool_root,
                      "--store", os.path.join(self.tmp, "s.sqlite"),
                      "--floor", "0.44", "--top-k", "4", "--max-cycles", "2",
                      "--config", os.path.join(self.tmp, "nope.json")],
                     runner_factory=FakeRunner, out=self.lines.append)
        self.assertEqual(rc, 0)
        self.assertEqual(made["task_id"], "t1")
        self.assertEqual(made["cfg"]["floor"], 0.44)
        self.assertEqual(made["cfg"]["top_k"], 4)
        self.assertEqual(made["cfg"]["spool_root"], self.spool_root)
        self.assertEqual(made["max_cycles"], 2)

    def test_bare_task_id_alias_is_start(self):
        made = {}

        class FakeRunner:
            def __init__(self, task_id, cfg, args):
                made["task_id"] = task_id

            def run(self, max_cycles=None):
                return 0

        rc = rn.main(["t1", "--spool-root", self.spool_root, "--once",
                      "--config", os.path.join(self.tmp, "nope.json")],
                     runner_factory=FakeRunner, out=self.lines.append)
        self.assertEqual(rc, 0)
        self.assertEqual(made["task_id"], "t1")

    def test_invalid_task_id_exit2(self):
        rc = rn.main(["start", "../evil"], out=self.lines.append)
        self.assertEqual(rc, 2)
        rc = rn.main(["start", "CON"], out=self.lines.append)
        self.assertEqual(rc, 2)

    def test_status_json(self):
        captured = []
        rc = rn.main(["status", "t1", "--json",
                      "--spool-root", self.spool_root,
                      "--store", os.path.join(self.tmp, "none.sqlite"),
                      "--config", os.path.join(self.tmp, "nope.json")],
                     probers={"ollama": lambda: {"reachable": False,
                                                  "models": [],
                                                  "has_embed_model": False},
                               "alive": lambda pid: False},
                     out=captured.append)
        self.assertEqual(rc, 0)
        data = json.loads("\n".join(captured))
        self.assertEqual(data["task_id"], "t1")
        self.assertFalse(data["ollama"]["reachable"])

    def test_status_no_task_lists(self):
        os.makedirs(self.task_dir, exist_ok=True)
        captured = []
        rc = rn.main(["status", "--spool-root", self.spool_root,
                      "--config", os.path.join(self.tmp, "nope.json")],
                     probers={"ollama": lambda: {"reachable": False,
                                                  "models": [],
                                                  "has_embed_model": False},
                               "alive": lambda pid: False},
                     out=captured.append)
        self.assertEqual(rc, 0)
        self.assertTrue(any("t1" in l for l in captured), captured)

    def test_stop_cli_not_running(self):
        rc = rn.main(["stop", "t1", "--spool-root", self.spool_root,
                      "--config", os.path.join(self.tmp, "nope.json")],
                     probers={"alive": lambda pid: False},
                     out=self.lines.append)
        self.assertEqual(rc, 0)
        self.assertTrue(any("not running" in l for l in self.lines))

    def test_help_rc0(self):
        rc = rn.main(["--help"], out=self.lines.append)
        self.assertEqual(rc, 0)


# --------------------------------------------- status task-id law (QA D-1)

class StatusTaskIdValidationTest(BaseTmp):
    """D-1 (artifacts/qa-p4-1.md): `status <task-id>` must validate the
    id BEFORE it is used in a path -- COND-6 parity with start/stop. A
    hostile id is rejected with rc 2 + a clear error and NEVER reaches
    status_data (no filesystem touch); status_data itself fail-fasts with
    ValueError as the defense-in-depth layer."""

    HOSTILE = ["../../etc", "a/b", "..", ".", "a\\b", "CON", "com1.x",
               "trail.", "trail-", "x" * 129, "task id", "task\x00id",
               "\u0442\u0430\u0441\u043a"]

    PROBERS = {"ollama": lambda: {"reachable": False, "models": [],
                                   "has_embed_model": False},
               "alive": lambda pid: False}

    def test_cli_status_rejects_hostile_ids_before_status_data(self):
        real = rn.status_data
        reached = []

        def spy(*a, **k):
            reached.append(a[0] if a else k.get("task_id"))
            return real(*a, **k)

        for hid in self.HOSTILE:
            lines = []
            rn.status_data = spy
            try:
                rc = rn.main(
                    ["status", hid, "--spool-root", self.spool_root,
                     "--config", os.path.join(self.tmp, "nope.json")],
                    probers=self.PROBERS, out=lines.append)
            finally:
                rn.status_data = real
            self.assertEqual(rc, 2, repr(hid))
            self.assertTrue(any("invalid task-id" in l for l in lines),
                            (repr(hid), lines))
        self.assertEqual(reached, [],
                         "status_data reached for hostile ids: %r"
                         % (reached,))

    def test_cli_status_traversal_cannot_read_outside_run_state(self):
        # canary: a run-state file OUTSIDE the spool root; a traversal id
        # must never surface its contents (QA repro: run.py:874 passed the
        # raw task to status_data -> os.path.join escaped the spool root).
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside, exist_ok=True)
        with open(os.path.join(outside, rn.RUN_STATE_FILENAME), "w",
                  encoding="utf-8") as fh:
            json.dump({"task_id": "canary-marker", "heartbeat_ts": 123.0,
                       "cycles": 77}, fh)
        lines = []
        rc = rn.main(["status", "../outside", "--json",
                      "--spool-root", self.spool_root,
                      "--config", os.path.join(self.tmp, "nope.json")],
                     probers=self.PROBERS, out=lines.append)
        self.assertEqual(rc, 2)
        joined = "\n".join(lines)
        self.assertNotIn("canary-marker", joined)
        self.assertNotIn("77", joined)

    def test_status_data_raises_valueerror_on_hostile_id(self):
        for hid in ("../evil", "a/b", "..", "CON", "", None, 5):
            with self.assertRaises(ValueError, msg=repr(hid)):
                rn.status_data(
                    hid, spool_root=self.spool_root,
                    ledger_path=self.ledger, evidence_dir=self.evidence,
                    store_path=os.path.join(self.tmp, "none.sqlite"),
                    ollama_prober=lambda: {"reachable": False,
                                            "models": [],
                                            "has_embed_model": False},
                    alive_fn=lambda pid: False)

    def test_cli_status_valid_ids_still_work(self):
        # the fix must not over-reject: dotted/underscored/hyphen ids are
        # lawful (COND-6 pattern) and status keeps working for them.
        for tid in ("t1", "hunt-1.2_x", "A_1", "x" * 128):
            lines = []
            rc = rn.main(["status", tid,
                          "--spool-root", self.spool_root,
                          "--config", os.path.join(self.tmp, "nope.json")],
                         probers=self.PROBERS, out=lines.append)
            self.assertEqual(rc, 0, tid)
            self.assertTrue(any(tid in l for l in lines), (tid, lines))

    def test_cli_status_no_task_still_lists(self):
        # taskless `status` (the listing branch) is untouched by D-1.
        os.makedirs(self.task_dir, exist_ok=True)
        lines = []
        rc = rn.main(["status", "--spool-root", self.spool_root,
                      "--config", os.path.join(self.tmp, "nope.json")],
                     probers=self.PROBERS, out=lines.append)
        self.assertEqual(rc, 0)
        self.assertTrue(any("t1" in l for l in lines), lines)


if __name__ == "__main__":
    unittest.main()
