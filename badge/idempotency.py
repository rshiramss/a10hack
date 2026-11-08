"""Idempotency keys for mutating tools (section 8).

Replaying a key returns the original result without running the tool again. Reusing a key
with different args (or as a different agent or tool) is denied.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from badge import reasons
from badge.clock import to_ms
from badge.context import CallContext
from badge.decisions import Allow, Decision, Deny, Replay
from badge.jsonutil import canonical_json, hash_value

UUID_PATTERN = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def args_hash(args: Any) -> str:
    return hash_value(args)


def lookup(conn: sqlite3.Connection, key: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM idempotency_keys WHERE idempotency_key = ?", (key,)
    ).fetchone()


def decide(row: sqlite3.Row | None, agent_id: str, tool: str, args: Any) -> Decision:
    """Replay if the key was used for exactly this call, deny if for anything else."""
    if row is None:
        return Allow()
    same_call = (
        row["agent_id"] == agent_id and row["tool"] == tool and row["args_hash"] == args_hash(args)
    )
    if same_call:
        return Replay(json.loads(row["result_json"]))
    return Deny(reasons.DENY_IDEMPOTENCY_CONFLICT, detail="key already used for a different call")


def check_replay(ctx: CallContext) -> Decision:
    """Runs right after ownership so a retried call returns its first result.

    DECISION: the spec lists the idempotency check at step 11, but a replayed submit would
    otherwise be denied by the plan/lease/state checks (its lease is already used). So
    replay detection happens here, after badge, role, and ownership have passed, and the
    key is re-checked inside the execute transaction to close the race.
    """
    if not ctx.tool_spec.mutating:
        return Allow()
    key = ctx.request.idempotency_key
    if not isinstance(key, str) or not UUID_PATTERN.fullmatch(key):
        return Deny(reasons.DENY_SCHEMA, detail="mutating tools need a UUID idempotency_key")
    return decide(lookup(ctx.conn, key), ctx.badge.agent_id, ctx.request.tool, ctx.request.args)


def store(
    conn: sqlite3.Connection,
    now: float,
    key: str,
    agent_id: str,
    tool: str,
    args: Any,
    result: dict[str, Any],
) -> None:
    """Record a key with its result. Runs inside the execute transaction."""
    conn.execute(
        "INSERT INTO idempotency_keys (idempotency_key, agent_id, tool, args_hash, result_json,"
        " created_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
        (key, agent_id, tool, args_hash(args), canonical_json(result), to_ms(now)),
    )
