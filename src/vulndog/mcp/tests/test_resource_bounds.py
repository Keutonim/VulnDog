"""P2-01/P2-02 behaviour over the REAL stdio wire (security probes C5/A26).

A ~1 MB vuln_query text and a multi-MB raw stdin line are hostile inputs
on the spawning-process trust boundary. Both must be refused with a
clear envelope, the child must stay healthy (answers the next request),
and its memory must stay sane. The ok-path child injects the fixed-vector
embedder through the engine's documented seam (stdio_child.py), so the
normal-size path is exercised against the same fake embedder transport.
"""
from __future__ import annotations

import json
import sys

from vulndog.mcp.tests.test_conformance import StdioClient, child_argv


def _working_set_bytes(pid: int) -> int | None:
    """Read-only resident-size probe (never terminates anything). Windows:
    GetProcessMemoryInfo via ctypes, the same read-only discipline as
    runs.pid_alive. Elsewhere: /proc VmRSS. None when unavailable."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32
        kernel32.OpenProcess.argtypes = [
            wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        psapi = ctypes.windll.psapi
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS),
            wintypes.DWORD]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters),
                                          counters.cb):
                return int(counters.WorkingSetSize)
            return None
        finally:
            kernel32.CloseHandle(handle)
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) * 1024
    except OSError:
        pass
    return None


def test_1mb_query_refused_over_stdio_and_child_stays_healthy(child_env):
    """Probe C5 behaviour: a ~1 MB text (under the 1 Mi stdin line cap,
    over the 8000-char tool cap) returns the tool refusal envelope —
    isError:true, never a crash, never a fake match answer — and the
    child's memory stays sane while the normal path keeps working."""
    with StdioClient(child_argv(child_env), child_env["env"],
                     child_env["project"]) as client:
        client.request("initialize", {"protocolVersion": "2024-11-05"})
        client.notify("notifications/initialized")

        # warm the normal path first (fake embedder transport)
        ok = client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}})
        assert ok["result"]["isError"] is False
        warm = json.loads(ok["result"]["content"][0]["text"])
        assert warm["status"] == "ok"
        baseline = _working_set_bytes(client.proc.pid)

        # ~1 MB text: 1_000_004 chars + JSON envelope stays under the
        # 1_048_576-char stdin cap, so the TOOL cap is the refusing layer
        hostile = "xss " + "B" * 1_000_000
        resp = client.request("tools/call", {
            "name": "vuln_query", "arguments": {"text": hostile}})
        assert "error" not in resp  # a tool RESULT, not a protocol error
        result = resp["result"]
        assert result["isError"] is True
        message = result["content"][0]["text"]
        assert "8000" in message
        assert "refused" in message

        # memory sanity: the refusal path must not balloon the child
        after = _working_set_bytes(client.proc.pid)
        if baseline is not None and after is not None:
            assert after < baseline + 32 * 1024 * 1024, (baseline, after)

        # the child is healthy: the normal-size path is unchanged
        again = client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}})
        assert again["result"]["isError"] is False
        out = json.loads(again["result"]["content"][0]["text"])
        assert out["status"] == "ok"
        assert out["matches"][0]["record_id"] == "CVE-2024-1000"
        assert client.request("ping")["result"] == {}


def test_oversized_stdin_line_refused_and_child_stays_alive(child_env):
    """Probe A26 behaviour: a single 2 Mi-char raw line (over the stdin
    cap) is answered with INVALID_REQUEST, its remainder drained, and
    the child keeps serving — including a normal query afterwards."""
    with StdioClient(child_argv(child_env), child_env["env"],
                     child_env["project"]) as client:
        client.request("initialize", {"protocolVersion": "2024-11-05"})
        client.notify("notifications/initialized")

        # 2 Mi chars of garbage on ONE line, then a normal request
        client.proc.stdin.write("B" * (2 * 1048576) + "\n")
        client.proc.stdin.flush()
        line = client.proc.stdout.readline()
        assert line, "server died or stayed silent on the oversized line"
        resp = json.loads(line)
        assert resp["id"] is None
        assert resp["error"]["code"] == -32600
        assert "1048576" in resp["error"]["message"]

        # the drained remainder did not wedge the loop
        assert client.request("ping")["result"] == {}
        ok = client.request("tools/call", {
            "name": "vuln_query",
            "arguments": {"text": "reflected xss in login page"}})
        assert ok["result"]["isError"] is False
        out = json.loads(ok["result"]["content"][0]["text"])
        assert out["status"] == "ok"
