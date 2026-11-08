"""Hash-chained, append-only audit log.

Each row's hash covers its own content plus the previous row's hash, so editing or
deleting any past row breaks verification from that row onward.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from badge.clock import to_ms
from badge.config import TrialConfig
from badge.jsonutil import canonical_json, sha256_hex
from badge.scanners import canary_pattern

GENESIS_HASH = "0" * 64
# Strings longer than this are logged as length + hash even if the arg is not free text,
# so an unexpected payload never gets copied into the log verbatim.
MAX_LOGGED_STRING_LEN = 128

_HASHED_COLUMNS = (
    "seq",
    "ts_ms",
    "agent_id",
    "badge_id",
    "role",
    "tool",
    "args_json",
    "decision",
    "reason",
    "action",
    "severity",
    "detail",
    "prev_hash",
)


@dataclass(frozen=True)
class AuditEntry:
    agent_id: str | None
    badge_id: str | None
    role: str | None
    tool: str | None
    args: dict[str, Any]
    decision: str  # ALLOW | DENY | EVENT
    reason: str
    action: str = "none"
    severity: str = "normal"
    detail: str = ""


def _digest(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else canonical_json(value)
    return {"len": len(text), "sha256": sha256_hex(text)}


def sanitize_args(config: TrialConfig, tool: str | None, args: Any) -> dict[str, Any]:
    """Return a loggable copy of `args`: free text becomes {len, sha256}.

    Unknown args, long strings, and nested values are digested too. That keeps clinical
    notes and attacker payloads out of the log while still proving what was sent.
    """
    if not isinstance(args, dict):
        return {"_raw": _digest(args)}
    spec = config.tools.get(tool) if tool else None
    logged: dict[str, Any] = {}
    for name, value in args.items():
        key = str(name)[:MAX_LOGGED_STRING_LEN]
        arg_spec = spec.args.get(name) if spec else None
        is_free_text = arg_spec is not None and arg_spec.type == "text"
        is_simple = isinstance(value, (int, float, bool)) or value is None
        is_short_string = isinstance(value, str) and len(value) <= MAX_LOGGED_STRING_LEN
        if is_free_text:
            logged[key] = None if value is None else _digest(value)
        elif is_simple or is_short_string:
            logged[key] = value
        elif tool == "declare_plan" and name == "steps" and isinstance(value, list):
            logged[key] = [sanitize_args(config, None, step) for step in value]
        else:
            logged[key] = _digest(value)
    return logged


def _scrub_canaries(pattern: Any, value: Any) -> Any:
    """Replace any string containing a canary with its digest, keys included.

    The audit log is shown to monitors (a blinded role), so a canary an attacker sent must
    never be copied into it verbatim.
    """
    if isinstance(value, str):
        return f"[canary {sha256_hex(value)[:16]}]" if pattern.search(value) else value
    if isinstance(value, dict):
        return {_scrub_canaries(pattern, k): _scrub_canaries(pattern, v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub_canaries(pattern, item) for item in value]
    return value


def _row_hash(row: dict[str, Any]) -> str:
    entry = {column: row[column] for column in _HASHED_COLUMNS}
    return sha256_hex(row["prev_hash"] + canonical_json(entry))


def append(conn: sqlite3.Connection, config: TrialConfig, now: float, entry: AuditEntry) -> int:
    """Append one entry. Runs inside the caller's write transaction. Returns its seq."""
    pattern = canary_pattern(config)
    last = conn.execute("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
    seq = 1 if last is None else last["seq"] + 1
    row = {
        "seq": seq,
        "ts_ms": to_ms(now),
        "agent_id": entry.agent_id,
        "badge_id": entry.badge_id,
        "role": entry.role,
        "tool": _scrub_canaries(pattern, entry.tool),
        "args_json": canonical_json(_scrub_canaries(pattern, entry.args)),
        "decision": entry.decision,
        "reason": entry.reason,
        "action": entry.action,
        "severity": entry.severity,
        "detail": _scrub_canaries(pattern, entry.detail),
        "prev_hash": GENESIS_HASH if last is None else last["hash"],
    }
    row["hash"] = _row_hash(row)
    columns = ", ".join(row)
    placeholders = ", ".join("?" for _ in row)
    conn.execute(f"INSERT INTO audit_log ({columns}) VALUES ({placeholders})", tuple(row.values()))
    return seq


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    rows_checked: int
    first_bad_seq: int | None = None


def verify_chain(conn: sqlite3.Connection) -> ChainReport:
    """Walk the whole chain. Reports the first row whose link or hash does not match."""
    expected_prev = GENESIS_HASH
    expected_seq = 1
    rows_checked = 0
    for raw in conn.execute("SELECT * FROM audit_log ORDER BY seq"):
        row = dict(raw)
        link_ok = row["prev_hash"] == expected_prev and row["seq"] == expected_seq
        if not link_ok or _row_hash(row) != row["hash"]:
            return ChainReport(ok=False, rows_checked=rows_checked, first_bad_seq=row["seq"])
        expected_prev = row["hash"]
        expected_seq += 1
        rows_checked += 1
    return ChainReport(ok=True, rows_checked=rows_checked)
