"""SpoolTailer hunt_id restamp: the literal "<redacted>" placeholder is
treated as missing (plan arsenal-tune-002 item B1-2 / verify gap C6-2).

The WD-T1 flusher runs F4 BEFORE the spool append, so an event whose
hunt_id itself was an opaque high-entropy value lands in the spool as
``hunt_id == "<redacted>"``. SpoolTailer already stamps a MISSING hunt_id
from the spool-directory task id (normalization to full F3); the same
normalization must cover the redacted placeholder: the spool-directory
task id is local spool metadata (layout
``<spool_root>/<task-id>/events.jsonl``), so the restamp is NOT
de-redaction. A real hunt_id and an absent field keep their existing
behavior. All secrets SYNTHETIC; loopback/local files only.
"""
import json
import os
import shutil
import tempfile
import unittest

from vulndog.engine import tailers as tl


def spool_event(seq=0, **over):
    e = {"ts": "2026-10-15T12:00:00Z", "hunt_id": "task-spool",
         "tap_class": "python", "url": "https://t.local/p?q=shoes",
         "method": "GET", "decision": "allowed", "status": 200,
         "provenance": "net_gate.guarded_request", "seq": seq}
    e.update(over)
    return e


class HuntIdRestampTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wd-restamp-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def spool(self, task):
        return os.path.join(self.tmp, "watchdog", task, "events.jsonl")

    def write(self, path, events):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def test_redacted_hunt_id_restamped_from_spool_dir(self):
        # F4 replaced an opaque hunt_id with "<redacted>" before the spool
        # append; poll() must restamp it with the spool-directory task id.
        path = self.spool("task-restamp")
        self.write(path, [spool_event(0, hunt_id="<redacted>")])
        tailer = tl.SpoolTailer(path)
        events = tailer.poll()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["hunt_id"], "task-restamp")
        self.assertEqual(tailer.stats()["hunt_id_stamped"], 1)

    def test_missing_hunt_id_still_stamped(self):
        # Pre-existing normalization unchanged: absent field -> stamp.
        path = self.spool("task-absent")
        ev = spool_event(0)
        del ev["hunt_id"]
        self.write(path, [ev])
        tailer = tl.SpoolTailer(path)
        events = tailer.poll()
        self.assertEqual(events[0]["hunt_id"], "task-absent")
        self.assertEqual(tailer.stats()["hunt_id_stamped"], 1)

    def test_real_hunt_id_untouched(self):
        # A genuine hunt_id survives verbatim (spool dir name differs, so a
        # wrongly applied restamp would overwrite it) and nothing counts as
        # stamped.
        path = self.spool("task-real")
        self.write(path, [spool_event(0, hunt_id="task-genuine")])
        tailer = tl.SpoolTailer(path)
        events = tailer.poll()
        self.assertEqual(events[0]["hunt_id"], "task-genuine")
        self.assertEqual(tailer.stats()["hunt_id_stamped"], 0)


if __name__ == "__main__":
    unittest.main()
