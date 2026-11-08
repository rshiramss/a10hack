"""Leases: one per planned step, plus standing leases (emergency unblind).

A call is allowed only if it matches the next unused lease of the active plan: same tool,
args equal to the bound args, lease active and unexpired, uses remaining.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from badge import reasons
from badge.clock import to_ms
from badge.config import ToolSpec
from badge.context import CallContext, Lease
from badge.decisions import Action, Allow, Decision, Deny
from badge.ids import new_uuid
from badge.jsonutil import canonical_json

PLAN_WILDCARD = "*"
END_REASON_PLAN_TTL = "PLAN_TTL"
END_REASON_COMPLETED = "COMPLETED"


def _row_to_lease(row: sqlite3.Row) -> Lease:
    return Lease(
        lease_id=row["lease_id"],
        plan_id=row["plan_id"],
        step_index=row["step_index"],
        agent_id=row["agent_id"],
        tool=row["tool"],
        bound_args=json.loads(row["bound_args_json"]),
        max_uses=row["max_uses"],
        uses=row["uses"],
        status=row["status"],
        expires_at_ms=row["expires_at_ms"],
    )


def insert_lease(
    conn: sqlite3.Connection,
    now: float,
    *,
    plan_id: str | None,
    step_index: int,
    agent_id: str,
    badge_id: str,
    tool: str,
    bound_args: dict[str, Any],
    expires_at: float,
) -> str:
    """Mint one single-use lease. Runs inside the caller's write transaction."""
    lease_id = new_uuid()
    conn.execute(
        "INSERT INTO leases (lease_id, plan_id, step_index, agent_id, badge_id, tool,"
        " bound_args_json, max_uses, uses, status, created_at_ms, expires_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, 'active', ?, ?)",
        (
            lease_id,
            plan_id,
            step_index,
            agent_id,
            badge_id,
            tool,
            canonical_json(bound_args),
            to_ms(now),
            to_ms(expires_at),
        ),
    )
    return lease_id


def get_lease(conn: sqlite3.Connection, lease_id: str) -> Lease | None:
    row = conn.execute("SELECT * FROM leases WHERE lease_id = ?", (lease_id,)).fetchone()
    return _row_to_lease(row) if row else None


def next_unused(conn: sqlite3.Connection, plan_id: str) -> Lease | None:
    row = conn.execute(
        "SELECT * FROM leases WHERE plan_id = ? AND status != 'used' ORDER BY step_index LIMIT 1",
        (plan_id,),
    ).fetchone()
    return _row_to_lease(row) if row else None


def args_match(spec: ToolSpec, bound_args: dict[str, Any], call_args: dict[str, Any]) -> bool:
    """Every bound arg must equal the call's value ("*" allows any value of an enum)."""
    for name in spec.bound_arg_names():
        if name not in bound_args or name not in call_args:
            return False
        bound, actual = bound_args[name], call_args[name]
        arg_spec = spec.args[name]
        if bound == PLAN_WILDCARD and arg_spec.plan_wildcard:
            if actual not in (arg_spec.values or []):
                return False
        elif type(bound) is not type(actual) or bound != actual:
            return False
    return True


def lease_problem(lease: Lease, now: float) -> str | None:
    """Why a lease can't be used right now, as a reason code, or None if it's usable."""
    if lease.status == "used" or lease.uses >= lease.max_uses:
        return reasons.DENY_LEASE_USED
    if lease.status != "active" or to_ms(now) >= lease.expires_at_ms:
        return reasons.DENY_LEASE_EXPIRED
    return None


def check_lease(ctx: CallContext) -> Decision:
    """Pipeline step 5: lease active, unexpired, uses left, args equal the bound args."""
    from badge.plans import escalation_action  # local import: plans imports this module

    problem = lease_problem(ctx.lease, ctx.now)
    if problem is None and to_ms(ctx.now) >= ctx.plan.expires_at_ms:
        problem = reasons.DENY_LEASE_EXPIRED
    if problem is not None:
        return Deny(problem, Action.EXPIRE_PLAN, detail="lease no longer usable")
    if not args_match(ctx.tool_spec, ctx.lease.bound_args, ctx.raw_args):
        action = escalation_action(ctx.conn, ctx.task, ctx.badge.agent_id)
        return Deny(reasons.DENY_ARG_MISMATCH, action, detail="args differ from the plan")
    return Allow()


def find_standing_lease(
    conn: sqlite3.Connection, agent_id: str, tool: str, bound_args: dict[str, Any]
) -> Lease | None:
    """Most recent plan-less lease for exactly this agent, tool, and args."""
    row = conn.execute(
        "SELECT * FROM leases WHERE plan_id IS NULL AND agent_id = ? AND tool = ?"
        " AND bound_args_json = ? ORDER BY created_at_ms DESC LIMIT 1",
        (agent_id, tool, canonical_json(bound_args)),
    ).fetchone()
    return _row_to_lease(row) if row else None


def check_standing_lease(ctx: CallContext) -> Decision:
    """For unplanned tools marked `standing_lease`: a matching single-use lease must exist."""
    if not ctx.tool_spec.standing_lease:
        return Allow()
    bound = {name: ctx.raw_args.get(name) for name in ctx.tool_spec.args}
    lease = find_standing_lease(ctx.conn, ctx.badge.agent_id, ctx.request.tool, bound)
    if lease is None:
        return Deny(reasons.DENY_NO_LEASE, detail="no lease for this request")
    problem = lease_problem(lease, ctx.now)
    if problem is not None:
        return Deny(problem, detail="lease no longer usable")
    return Allow({"lease": lease})


def consume(conn: sqlite3.Connection, lease_id: str) -> None:
    """Use one lease use. Runs inside the caller's write transaction."""
    conn.execute(
        "UPDATE leases SET uses = uses + 1,"
        " status = CASE WHEN uses + 1 >= max_uses THEN 'used' ELSE status END"
        " WHERE lease_id = ?",
        (lease_id,),
    )


def end_plan(conn: sqlite3.Connection, plan_id: str, status: str, end_reason: str) -> None:
    """Close a plan: its unused leases follow its status, its resource holds are released.

    `status` is 'completed', 'expired', or 'revoked'. Runs inside the caller's tx.
    """
    lease_status = "revoked" if status == "revoked" else "expired"
    conn.execute(
        "UPDATE plans SET status = ?, end_reason = ? WHERE plan_id = ? AND status = 'active'",
        (status, end_reason, plan_id),
    )
    conn.execute(
        "UPDATE leases SET status = ? WHERE plan_id = ? AND status = 'active'",
        (lease_status, plan_id),
    )
    conn.execute(
        "UPDATE slot_holds SET status = 'released' WHERE plan_id = ? AND status = 'active'",
        (plan_id,),
    )


def end_active_plans(
    conn: sqlite3.Connection, agent_id: str, task_id: str | None, status: str, end_reason: str
) -> None:
    """End the agent's active plans (for one task, or all tasks if task_id is None)."""
    if task_id is None:
        rows = conn.execute(
            "SELECT plan_id FROM plans WHERE agent_id = ? AND status = 'active'", (agent_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT plan_id FROM plans WHERE agent_id = ? AND task_id = ? AND status = 'active'",
            (agent_id, task_id),
        ).fetchall()
    for row in rows:
        end_plan(conn, row["plan_id"], status, end_reason)


def revoke_standing_leases(conn: sqlite3.Connection, agent_id: str) -> None:
    conn.execute(
        "UPDATE leases SET status = 'revoked'"
        " WHERE agent_id = ? AND plan_id IS NULL AND status = 'active'",
        (agent_id,),
    )


def expire_stale(conn: sqlite3.Connection, now: float) -> None:
    """Materialize TTL expiry: close plans past their TTL and expire stale standing leases.

    Runs inside the caller's write transaction. Expiry is also enforced at call time
    (check_lease), so this only makes the database state, holds, and dashboard catch up.
    """
    now_ms = to_ms(now)
    stale = conn.execute(
        "SELECT plan_id FROM plans WHERE status = 'active' AND expires_at_ms <= ?", (now_ms,)
    ).fetchall()
    for row in stale:
        end_plan(conn, row["plan_id"], "expired", END_REASON_PLAN_TTL)
    conn.execute(
        "UPDATE leases SET status = 'expired'"
        " WHERE plan_id IS NULL AND status = 'active' AND expires_at_ms <= ?",
        (now_ms,),
    )
