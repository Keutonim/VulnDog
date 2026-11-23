"""Read-only run-artifact access for the MCP tools (M2.3).

All folder naming/resolution decisions stay in vulndog.runs (one decision
in one place): this module only reads what the capture half wrote.
Nothing here writes, creates, or deletes anything.
"""
from __future__ import annotations

import json
from pathlib import Path

from vulndog import runs

HIGHLIGHTS_NAME = "highlights.jsonl"
META_NAME = "watchdog-run.json"

# P2-04: secret-shaped config keys whose VALUES must never reach the AI
# agent (and its transcripts) through run_status. The snapshot duplicates
# anything the user puts in a config file (P1 m6); the MCP door widens the
# audience, so the serving side masks fail-closed. The persist-side fix
# (cli _meta_payload, same patterns) belongs to the CLI owner.
# Vocabulary mirrors the redaction door's credential key families (engine
# FORBIDDEN_EVENT_KEYS) restricted to secret-bearing names — event-only
# keys (headers, user-agent, referer) are not config secrets and stay
# readable. Match is on the normalized key (lowercase, '-'/'_' removed),
# so api_key / APIKEY / X-API-Key all mask. No real product/engine config
# key collides with these parts (checked against watchdog_config.json +
# the M2.1 product keys); a future collision masks fail-closed.
_SECRET_KEY_PARTS = ("apikey", "token", "secret", "password", "passwd",
                     "pwd", "credential", "privatekey")
_REDACTED = "<redacted>"


def _is_secret_key(key: str) -> bool:
    normalized = key.lower().replace("-", "").replace("_", "")
    return any(part in normalized for part in _SECRET_KEY_PARTS)


def _redact_config_secrets(value):
    """Deep-copy walk of the config snapshot: a secret-shaped key's value
    becomes ``<redacted>`` (any type — fail-closed); dicts/lists recurse;
    every other value passes through verbatim (the snapshot contract)."""
    if isinstance(value, dict):
        return {k: (_REDACTED if _is_secret_key(k)
                    else _redact_config_secrets(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_config_secrets(v) for v in value]
    return value


def find_run(project_root: Path, runs_dir: str | Path,
             run_id: str) -> runs.Run | None:
    """Locate a run by folder name; None when absent. The caller must
    validate run_id against runs.RUN_NAME_RE first (traversal guard)."""
    for run in runs.list_runs(project_root, runs_dir):
        if run.hunt_id == run_id:
            return run
    return None


def read_highlights(run: runs.Run) -> tuple[list[dict], int] | None:
    """(rows, skipped_lines) from highlights.jsonl; None when the file
    does not exist. Malformed lines are skipped and counted — a partial
    log still serves its valid rows (never a crash, never silent loss)."""
    path = run.path / HIGHLIGHTS_NAME
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    rows: list[dict] = []
    skipped = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            skipped += 1
            continue
        if isinstance(row, dict):
            rows.append(row)
        else:
            skipped += 1
    return rows, skipped


def read_meta(run: runs.Run) -> dict:
    """watchdog-run.json snapshot, fail-soft: an unreadable file becomes
    a ``_meta_error`` note (same law as the CLI status command)."""
    path = run.path / META_NAME
    if not path.exists():
        return {}
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"_meta_error": "watchdog-run.json unreadable"}
    return meta if isinstance(meta, dict) else {"_meta_error":
                                                "watchdog-run.json not an object"}


def run_status_payload(run: runs.Run) -> dict:
    """The run_status tool payload: live state of one run folder."""
    meta = read_meta(run)
    pid = meta.get("pid")
    alive = runs.pid_alive(int(pid)) if isinstance(pid, int) else False
    payload = {
        "hunt_id": run.hunt_id,
        "run_dir": str(run.path),
        "pid": pid,
        "alive": alive,
        "mode": meta.get("mode"),
        "started_at": meta.get("started_at"),
        "stopped_at": meta.get("stopped_at"),
        "counters": meta.get("counters", {}),
        # P2-04: never serve secret-shaped config values to the agent
        "config": _redact_config_secrets(meta.get("config", {})),
        "paths": meta.get("paths", {}),
        "stop_requested": run.stop_requested(),
    }
    if "_meta_error" in meta:
        payload["meta_error"] = meta["_meta_error"]
    return payload


def list_artifacts(run: runs.Run) -> list[dict]:
    """Per-run artifact listing for the run-dir resources."""
    return [
        {"name": p.name, "bytes": p.stat().st_size}
        for p in sorted(run.path.iterdir()) if p.is_file()
    ]