"""Benchmark helpers: percentiles, corpus replication, machine-state facts.

Pure stdlib. Used by the P0 benchmark scripts; kept in the package (with
tests) so the measured numbers rest on tested logic.
"""
from __future__ import annotations

import os
import platform
import sqlite3
import sys


def percentile(data, p: float) -> float:
    """Linear-interpolated percentile (p in 0..100). Raises on empty data."""
    if not data:
        raise ValueError("percentile of empty sequence")
    s = sorted(data)
    n = len(s)
    if n == 1:
        return float(s[0])
    idx = (p / 100.0) * (n - 1)
    lo = int(idx)
    hi = min(lo + 1, n - 1)
    frac = idx - lo
    return s[lo] * (1.0 - frac) + s[hi] * frac


def replicate_to_size(chunks, vectors, n: int):
    """Scale a pilot corpus to n rows by CYCLING the same records/vectors.

    Documented benchmark method (brief item 4): replication with repeated
    identical vectors is acceptable for LATENCY measurement -- FTS5 and the
    cosine re-rank costs depend on row count and text, not on uniqueness.
    """
    src = len(chunks)
    if src == 0:
        raise ValueError("empty source corpus")
    if n <= src:
        return list(chunks[:n]), list(vectors[:n])
    out_c = []
    out_v = []
    while len(out_c) < n:
        take = min(src, n - len(out_c))
        out_c.extend(chunks[:take])
        out_v.extend(vectors[:take])
    return out_c, out_v


def _ram_bytes() -> int:
    if sys.platform == "win32":
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        st = MEMORYSTATUSEX()
        st.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
            return int(st.ullTotalPhys)
        return 0
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (ValueError, OSError, AttributeError):
        return 0


def machine_state() -> dict:
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "cpu": platform.processor(),
        "cpu_count": os.cpu_count(),
        "ram_bytes": _ram_bytes(),
        "sqlite_version": sqlite3.sqlite_version,
    }
