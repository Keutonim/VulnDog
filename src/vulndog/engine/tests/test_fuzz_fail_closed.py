"""Fuzz drills for the fail-closed paths (brief P1 item 5).

Deterministic seeded mutation fuzzing of the F4 adapter: mutated/
garbage/hostile events must NEVER raise out of redact_event and must
never persist a scrub-class secret. Upstream also fuzzed the upstream
watchdog_tap flusher (TapFuzzTest); that producer is not vendored, so
the class is EXCLUDED here (recorded in VENDORING.md).

Secret vectors are the synthetic design-6 classes that the contract
promises to kill anywhere in a string field: >=16-char opaque runs
(entropy class) and pattern-class tokens (JWT/AKIA/ghp_/sk-, password=
form). KNOWN LIMIT (design-acknowledged denylist+entropy boundary): a
BARE 15-char mixed-case password with no pattern context is not caught
by any layer -- recorded as residual risk, not asserted here.
"""
import json
import random
import unittest

from vulndog.engine import event_schema as es
from vulndog.engine import redaction_adapter as ra

SEED = 20261015
FUZZ_ADAPTER_N = 300

OPAQUE_TOKENS = [
    "8fKx2QpLm9ZrTv4Wb7NsYc1Jd6Gh",       # reset-token class (28, 3-class)
    "a8Xk29LmPq47ZwTvB3cR6yHn",           # opaque query value (24)
    "xK9mP2qL7vR4tW8yB3nF6jH1z",          # token= value class (24)
    "aB3dE5fG7hI9jK1lM3nO5p",             # session-id value class (22)
    "Qw9Er8Ty7Ui6Op5As4Df3Gh2Jk1L",       # jsessionid class (28)
]
PATTERN_SECRETS = [
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9.AbCdEf1234567890",  # full JWT
    "AKIAIOSFODNN7EXAMPLE",                                 # AWS key id
    "ghp_1234567890abcdefghijklmnopqrstuvwx",               # GitHub token
    "sk-abcDEF123456789xyzWvUt",                            # sk- key
    "password=Sup3rS3cretPass!",                            # password= form
]
ALL_SECRETS = OPAQUE_TOKENS + PATTERN_SECRETS

SCHEMA_KEYS = list(es.EVENT_FIELDS) + list(es.LEDGER_EXTRA_FIELDS) + ["seq"]
FORBIDDEN_KEYS = ["headers", "Cookie", "authorization", "x-api-key",
                  "set_cookie", "user_agent", "My-Header", "token"]
JUNK_VALUES = [None, 42, -1, 3.14, True, False, b"raw\x00bytes",
               {"nested": "dict"}, [1, 2, 3], (1,), {1, 2}, object(),
               "\ud800invalid-lone-surrogate", "control\x00\x1fchars",
               "юникод-строка", "x" * 20000]


def base_event(rng):
    return es.make_event(
        tap_class=rng.choice(["python", "browser", "tool_http", "ledger",
                              "evidence"]),
        url="https://t.local/p/{}?sid={}&q=shoes".format(
            rng.choice(OPAQUE_TOKENS), rng.choice(OPAQUE_TOKENS)),
        method=rng.choice(["GET", "POST", "head"]),
        decision=rng.choice(["allowed", "denied"]),
        provenance="fuzz", hunt_id="task-fuzz",
        status=rng.choice([200, 301, 403, 429, 500]),
        denial_reason="rate {} hit".format(rng.choice(PATTERN_SECRETS)),
        ua_present=True, cookie_present=False,
        content_type="text/html",
        body_redacted="<html>{} {}</html>".format(
            rng.choice(ALL_SECRETS), rng.choice(ALL_SECRETS)),
    )


def mutate(rng, event):
    event = dict(event)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(8)
        if op == 0:                                   # drop a key
            keys = [k for k in event if k not in ("tap_class", "url")]
            if keys:
                event.pop(rng.choice(keys))
        elif op == 1:                                 # junk into schema key
            event[rng.choice(SCHEMA_KEYS)] = rng.choice(JUNK_VALUES)
        elif op == 2:                                 # forbidden key inject
            event[rng.choice(FORBIDDEN_KEYS)] = rng.choice(ALL_SECRETS)
        elif op == 3:                                 # secret-laden url
            event["url"] = "https://u:{}@t.local/r/{}?t={}#{}".format(
                rng.choice(OPAQUE_TOKENS), rng.choice(OPAQUE_TOKENS),
                rng.choice(OPAQUE_TOKENS), rng.choice(PATTERN_SECRETS))
        elif op == 4:                                 # secret-laden body
            event["body_redacted"] = "\n".join(
                rng.choice(ALL_SECRETS) for _ in range(rng.randint(1, 40)))
        elif op == 5:                                 # random extra key
            event["rand%d" % rng.randrange(1000)] = rng.choice(
                ALL_SECRETS + JUNK_VALUES)
        elif op == 6:                                 # corrupt types
            event[rng.choice(SCHEMA_KEYS)] = rng.choice(JUNK_VALUES)
        else:                                         # unicode/control text
            event["denial_reason"] = "deny \x00\ud83d\udd12 {}".format(
                rng.choice(ALL_SECRETS))
    return event


def assert_no_secrets(testcase, blob: str):
    for secret in ALL_SECRETS:
        testcase.assertNotIn(secret, blob)
    # JWT fragments must not survive either
    testcase.assertNotIn("eyJhbGciOiJIUzI1NiJ9", blob)
    testcase.assertNotIn("AbCdEf1234567890", blob)


class AdapterFuzzTest(unittest.TestCase):
    def test_redact_event_never_raises_never_leaks(self):
        rng = random.Random(SEED)
        kept = dropped = 0
        for i in range(FUZZ_ADAPTER_N):
            event = mutate(rng, base_event(rng))
            out, was_dropped = ra.redact_event(event)   # must NEVER raise
            if was_dropped:
                self.assertIsNone(out)
                dropped += 1
                continue
            kept += 1
            self.assertIsInstance(out, dict)
            # default=repr: non-serializable pass-throughs (object()) are
            # the tap's serialization-drop class, not adapter failures;
            # repr rendering cannot smuggle a string-field secret.
            blob = json.dumps(out, default=repr)
            assert_no_secrets(self, blob)
            for key in out:
                self.assertNotIn("header", str(key).lower())
                self.assertNotIn(str(key).lower(), ra.FORBIDDEN_EVENT_KEYS)
        # the fuzz must actually exercise BOTH outcomes
        self.assertGreater(kept, 50, "fuzz degenerate: nothing kept")
        self.assertGreater(dropped, 50, "fuzz degenerate: nothing dropped")

    def test_non_dict_inputs_never_raise(self):
        non_dicts = [x for x in JUNK_VALUES if not isinstance(x, dict)]
        for junk in non_dicts + ["str", "", 0]:
            out, dropped = ra.redact_event(junk)
            self.assertIsNone(out)
            self.assertTrue(dropped)

    def test_dict_with_scalar_values_is_an_event_not_a_drop(self):
        # a plain dict of scalars is redactable (unknown keys pass through);
        # only forbidden keys / non-scalar values force the fail-closed drop
        out, dropped = ra.redact_event({"nested": "dict"})
        self.assertFalse(dropped)
        self.assertEqual(out, {"nested": "dict"})


if __name__ == "__main__":
    unittest.main()
