"""M2.3 smoke: replay the recorded agent transcript against the real
stdio server (fixtures/agent_transcript.json).

The transcript is the scripted agent session required by the milestone;
this test is its mechanical replay. A notification step asserts
no-response indirectly: the next response read must carry the NEXT
request's id (an unsolicited reply would shift the stream).
"""
from __future__ import annotations

import json
from pathlib import Path

from vulndog.mcp.tests.test_conformance import StdioClient, child_argv

TRANSCRIPT = Path(__file__).parent / "fixtures" / "agent_transcript.json"


def _check(expect, resp):
    if "error_code" in expect:
        assert resp["error"]["code"] == expect["error_code"], resp
        return
    assert "error" not in resp, resp
    result = resp["result"]
    if "result_has" in expect:
        for key, value in expect["result_has"].items():
            assert result[key] == value, resp
    if "tool_names" in expect:
        assert sorted(t["name"] for t in result["tools"]) == \
            sorted(expect["tool_names"])
    if "resources_count" in expect:
        assert len(result["resources"]) == expect["resources_count"]
    if "isError" in expect:
        assert result["isError"] is expect["isError"], resp
    if "payload_has" in expect:
        assert result["isError"] is False
        payload = json.loads(result["content"][0]["text"])
        for key, value in expect["payload_has"].items():
            assert payload[key] == value, resp


def test_agent_transcript_smoke(child_env):
    transcript = json.loads(TRANSCRIPT.read_text(encoding="utf-8"))
    with StdioClient(child_argv(child_env), child_env["env"],
                     child_env["project"]) as client:
        for step in transcript["steps"]:
            if "notify" in step:
                client.notify(step["notify"]["method"],
                              step["notify"].get("params"))
                assert step["expect"].get("no_response") is True
                continue
            msg = step["send"]
            resp = client.request(msg["method"], msg.get("params"))
            # id echo also proves notifications produced no extra reply
            assert resp["id"] == msg["id"], (msg, resp)
            _check(step["expect"], resp)