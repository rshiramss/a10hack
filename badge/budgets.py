"""Exploration budgets (section 4.4), pipeline step 9.

Counts come from the audit log, so budgets are reproducible from database state + clock.
"""

from __future__ import annotations

import sqlite3

from badge import reasons
from badge.clock import to_ms
from badge.context import CallContext
from badge.decisions import Action, Allow, Decision, Deny

RATE_WINDOW_MS = 60_000


def calls_in_window(conn: sqlite3.Connection, agent_id: str, now: float) -> int:
    """Gateway calls (allowed or denied) by this agent in the trailing minute."""
    row = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND decision IN ('ALLOW', 'DENY')"
        " AND ts_ms > ?",
        (agent_id, to_ms(now) - RATE_WINDOW_MS),
    ).fetchone()
    return row[0]


def reads_for_task(
    conn: sqlite3.Connection, agent_id: str, tool: str, resource_arg: str, resource_id: str
) -> int:
    """Successful executions of a read tool by this agent against one task resource."""
    row = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE agent_id = ? AND tool = ? AND decision = 'ALLOW'"
        " AND reason = ? AND json_extract(args_json, ?) = ?",
        (agent_id, tool, reasons.OK, f"$.{resource_arg}", resource_id),
    ).fetchone()
    return row[0]


def denied_calls(conn: sqlite3.Connection, badge_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE badge_id = ? AND decision = 'DENY'", (badge_id,)
    ).fetchone()
    return row[0]


def check_budgets(ctx: CallContext) -> Decision:
    """Rate limit (sliding minute) and reads-per-task. Over budget expires the plan."""
    budgets = ctx.config.role(ctx.badge.role).budgets
    if calls_in_window(ctx.conn, ctx.badge.agent_id, ctx.now) >= budgets.max_calls_per_minute:
        return Deny(reasons.DENY_BUDGET, Action.EXPIRE_PLAN, detail="rate limit exceeded")
    spec = ctx.tool_spec
    if spec.counts_as_read and ctx.task is not None:
        reads = reads_for_task(
            ctx.conn,
            ctx.badge.agent_id,
            ctx.request.tool,
            spec.resource_arg,
            ctx.task.resource_id,
        )
        if reads >= budgets.max_reads_per_task:
            return Deny(reasons.DENY_BUDGET, Action.EXPIRE_PLAN, detail="read budget used up")
    return Allow()
