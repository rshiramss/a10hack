"""Declared plans (section 4).

Agents lay out their tool calls before making them. `validate_plan` checks a plan
deterministically; `create_plan` mints one lease per step. `check_plan_match` is pipeline
step 4: every planned call must be the next unused step of the agent's active plan.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from badge import reasons
from badge.clock import to_ms
from badge.config import ArgSpec, ToolSpec
from badge.context import BadgeInfo, CallContext, Plan, Runtime, Task
from badge.decisions import Action, Allow, Decision, DeniedError, Deny
from badge.ids import new_uuid
from badge.jsonutil import canonical_json
from badge.leases import END_REASON_COMPLETED, PLAN_WILDCARD, end_plan, insert_lease, next_unused
from badge.state_machine import first_invalid_step, get_state, slot_for, workflow_for_role
from badge.tasks import get_task

VIOLATION_REASONS = (reasons.DENY_OFF_PLAN, reasons.DENY_ARG_MISMATCH)


def _row_to_plan(row: sqlite3.Row) -> Plan:
    return Plan(
        plan_id=row["plan_id"],
        task_id=row["task_id"],
        agent_id=row["agent_id"],
        badge_id=row["badge_id"],
        status=row["status"],
        expires_at_ms=row["expires_at_ms"],
    )


def get_active_plan(conn: sqlite3.Connection, task_id: str, agent_id: str) -> Plan | None:
    row = conn.execute(
        "SELECT * FROM plans WHERE task_id = ? AND agent_id = ? AND status = 'active'",
        (task_id, agent_id),
    ).fetchone()
    return _row_to_plan(row) if row else None


def count_plans(conn: sqlite3.Connection, task_id: str, agent_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM plans WHERE task_id = ? AND agent_id = ?", (task_id, agent_id)
    ).fetchone()
    return row[0]


def escalation_action(conn: sqlite3.Connection, task: Task, agent_id: str) -> Action:
    """First off-plan/mismatch on a task expires the plan; a second one suspends the badge."""
    placeholders = ", ".join("?" for _ in VIOLATION_REASONS)
    prior = conn.execute(
        "SELECT COUNT(*) FROM plans WHERE task_id = ? AND agent_id = ?"
        f" AND end_reason IN ({placeholders})",
        (task.task_id, agent_id, *VIOLATION_REASONS),
    ).fetchone()[0]
    return Action.SUSPEND if prior >= 1 else Action.EXPIRE_PLAN


def get_any_active_plan(conn: sqlite3.Connection, agent_id: str) -> Plan | None:
    row = conn.execute(
        "SELECT * FROM plans WHERE agent_id = ? AND status = 'active'"
        " ORDER BY created_at_ms DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    return _row_to_plan(row) if row else None


def check_plan_match(ctx: CallContext) -> Decision:
    """Pipeline step 4: the call must be the next unused step of the active plan."""
    plan = get_active_plan(ctx.conn, ctx.task.task_id, ctx.badge.agent_id)
    if plan is None:
        return _no_plan_for_task(ctx)
    lease = next_unused(ctx.conn, plan.plan_id)
    if lease is None:
        return Deny(reasons.DENY_NO_PLAN, detail="plan has no steps left")
    if lease.tool != ctx.request.tool:
        action = escalation_action(ctx.conn, ctx.task, ctx.badge.agent_id)
        return Deny(reasons.DENY_OFF_PLAN, action, detail=f"next planned step is {lease.tool}")
    return Allow({"plan": plan, "lease": lease})


def _no_plan_for_task(ctx: CallContext) -> Deny:
    """The call's task has no active plan. Decide whether that's a deviation or just unplanned.

    DECISION: if the agent is mid-plan on another task, this call deviates from that plan
    (e.g. planned V-07, called V-08): same tool means DENY_ARG_MISMATCH, another tool means
    DENY_OFF_PLAN, and the deviated plan is the one that expires.
    """
    # DECISION: once a task is done its resource is locked, so a further call is reported
    # as a bad transition (what it is) rather than a missing plan.
    if ctx.task.status == "done":
        return Deny(reasons.DENY_BAD_TRANSITION, detail="resource is locked")
    other_plan = get_any_active_plan(ctx.conn, ctx.badge.agent_id)
    if other_plan is None:
        return Deny(reasons.DENY_NO_PLAN, detail="declare a plan first")
    other_task = get_task(ctx.conn, other_plan.task_id)
    expected = next_unused(ctx.conn, other_plan.plan_id)
    action = escalation_action(ctx.conn, other_task, ctx.badge.agent_id)
    if expected is not None and expected.tool == ctx.request.tool:
        return Deny(
            reasons.DENY_ARG_MISMATCH,
            action,
            detail="args differ from the plan",
            plan_id=other_plan.plan_id,
        )
    return Deny(
        reasons.DENY_OFF_PLAN,
        action,
        detail="call is not in your active plan",
        plan_id=other_plan.plan_id,
    )


# ---- validation ------------------------------------------------------------------


def _bound_value_ok(spec: ArgSpec, value: Any) -> bool:
    if spec.type == "id":
        return isinstance(value, str) and re.fullmatch(spec.pattern, value) is not None
    if spec.type == "enum":
        if value == PLAN_WILDCARD:
            return spec.plan_wildcard
        return isinstance(value, str) and value in spec.values
    if spec.type == "int":
        return type(value) is int and spec.min <= value <= spec.max
    return False  # text and bool args are never bindable


def _step_args_problem(
    conn: sqlite3.Connection, spec: ToolSpec, args: dict[str, Any], task: Task
) -> Deny | None:
    expected = set(spec.bound_arg_names())
    if set(args) != expected:
        return Deny(reasons.DENY_PLAN_INVALID, detail=f"steps must bind exactly {sorted(expected)}")
    for name, value in args.items():
        if not _bound_value_ok(spec.args[name], value):
            return Deny(reasons.DENY_PLAN_INVALID, detail=f"bad bound value for {name}")
    if args[spec.resource_arg] != task.resource_id:
        return Deny(reasons.DENY_NOT_OWNER, detail="plan step targets a resource outside your task")
    if spec.patient_arg:
        visit = conn.execute(
            "SELECT patient_id FROM visits WHERE visit_id = ?", (task.resource_id,)
        ).fetchone()
        if visit is None or visit["patient_id"] != args[spec.patient_arg]:
            return Deny(reasons.DENY_NOT_OWNER, detail="patient does not match your task")
    return None


def validate_plan(ctx: CallContext, plan_args: dict[str, Any]) -> Task | Deny:
    """All seven plan rules (section 4.1) plus the replan limit. Returns the task or a Deny.

    Runs inside the declare transaction so rule 7 can't race.
    """
    config, conn, badge = ctx.config, ctx.conn, ctx.badge
    role = config.role(badge.role)
    steps = plan_args["steps"]

    # 1. Task exists and is assigned to this agent.
    task = get_task(conn, plan_args["task_id"])
    if task is None or task.agent_id != badge.agent_id or task.role != badge.role:
        return Deny(reasons.DENY_NOT_OWNER, detail="task is not assigned to you")
    if task.status != "assigned":
        return Deny(reasons.DENY_BAD_TRANSITION, detail="task is already finished")

    # Replan limit: the first plan plus max_replans_per_task more.
    if count_plans(conn, task.task_id, badge.agent_id) >= 1 + role.budgets.max_replans_per_task:
        return Deny(
            reasons.DENY_REPLAN_LIMIT,
            detail="too many plans; task returned to the pool",
            return_task_id=task.task_id,
        )

    # 2. Every step's tool is on the role's allowlist.
    for step in steps:
        if config.is_platform_tool(step["tool"]):
            return Deny(reasons.DENY_PLAN_INVALID, detail="platform tools can't be planned")
        if step["tool"] not in role.tools:
            # DECISION: planning another role's tool is treated like calling it.
            return Deny(reasons.DENY_ROLE_FORBIDDEN, Action.REVOKE, detail="tool not in your role")

    # 3. Step order is valid under the state machine, starting from the current state.
    workflow_name = workflow_for_role(config, badge.role)
    step_workflows = {config.tool(step["tool"]).workflow for step in steps}
    if workflow_name is None or step_workflows != {workflow_name}:
        return Deny(reasons.DENY_PLAN_INVALID, detail="steps span more than one workflow")
    workflow = config.workflows[workflow_name]
    state = get_state(conn, config, workflow_name, task.resource_id, slot_for(workflow, task))
    bad_index = first_invalid_step(workflow, state, [s["tool"] for s in steps])
    if bad_index is not None:
        return Deny(
            reasons.DENY_BAD_TRANSITION,
            detail=f"step {bad_index} ({steps[bad_index]['tool']}) is invalid after {state!r}",
        )

    # 4. Bound args refer only to this task's resources.
    for step in steps:
        problem = _step_args_problem(conn, config.tool(step["tool"]), step["args"], task)
        if problem is not None:
            return problem

    # 5. Step count within budget.
    if len(steps) > role.budgets.max_steps_per_plan:
        return Deny(reasons.DENY_BUDGET, detail="too many steps for your role")

    # 6. Single-use tools appear at most once.
    for tool_name, spec in config.tools.items():
        if spec.single_use and sum(s["tool"] == tool_name for s in steps) > 1:
            return Deny(reasons.DENY_PLAN_INVALID, detail=f"{tool_name} may appear only once")

    # 7. No other active plan for this task.
    if get_active_plan(conn, task.task_id, badge.agent_id) is not None:
        return Deny(reasons.DENY_PLAN_ACTIVE, detail="you already have an active plan")

    return task


def create_plan(
    conn: sqlite3.Connection,
    runtime: Runtime,
    now: float,
    badge: BadgeInfo,
    task: Task,
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    """Persist an approved plan, one lease per step, and the slot hold if the workflow uses one.

    Runs inside the declare transaction. Raises DeniedError if the slot is already held.
    """
    config = runtime.config
    plan_id = new_uuid()
    plan_expires_at = now + config.plan_ttl_minutes * 60
    conn.execute(
        "INSERT INTO plans (plan_id, task_id, agent_id, badge_id, status, steps_json,"
        " created_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, 'active', ?, ?, ?)",
        (
            plan_id,
            task.task_id,
            badge.agent_id,
            badge.badge_id,
            canonical_json(steps),
            to_ms(now),
            to_ms(plan_expires_at),
        ),
    )
    leases = []
    for index, step in enumerate(steps):
        spec = config.tool(step["tool"])
        lease_ttl = spec.lease_ttl_minutes or config.plan_ttl_minutes
        expires_at = min(now + lease_ttl * 60, plan_expires_at)
        lease_id = insert_lease(
            conn,
            now,
            plan_id=plan_id,
            step_index=index,
            agent_id=badge.agent_id,
            badge_id=badge.badge_id,
            tool=step["tool"],
            bound_args=step["args"],
            expires_at=expires_at,
        )
        leases.append(
            {
                "lease_id": lease_id,
                "step_index": index,
                "tool": step["tool"],
                "bound_args": step["args"],
                "expires_at_ms": to_ms(expires_at),
            }
        )
    workflow = config.workflows[config.tool(steps[0]["tool"]).workflow]
    if workflow.hold_slot:
        _hold_slot(conn, now, plan_id, badge.agent_id, task)
    return {
        "plan_id": plan_id,
        "task_id": task.task_id,
        "expires_at_ms": to_ms(plan_expires_at),
        "leases": leases,
    }


def _hold_slot(
    conn: sqlite3.Connection, now: float, plan_id: str, agent_id: str, task: Task
) -> None:
    try:
        conn.execute(
            "INSERT INTO slot_holds (hold_id, visit_id, slot, plan_id, agent_id, status,"
            " created_at_ms) VALUES (?, ?, ?, ?, ?, 'active', ?)",
            (new_uuid(), task.resource_id, task.slot, plan_id, agent_id, to_ms(now)),
        )
    except sqlite3.IntegrityError as error:
        raise DeniedError(Deny(reasons.DENY_RESOURCE_HELD, detail="slot is held")) from error


def complete_if_finished(conn: sqlite3.Connection, plan_id: str) -> bool:
    """Mark the plan completed once every lease is used. Runs inside the caller's tx."""
    if next_unused(conn, plan_id) is not None:
        return False
    end_plan(conn, plan_id, "completed", END_REASON_COMPLETED)
    return True


def plan_progress(conn: sqlite3.Connection, agent_id: str) -> list[dict[str, Any]]:
    """Active plans with step counts, for get_my_status and the dashboard."""
    rows = conn.execute(
        "SELECT p.plan_id, p.task_id, p.expires_at_ms,"
        " COUNT(l.lease_id) AS steps_total,"
        " SUM(CASE WHEN l.status = 'used' THEN 1 ELSE 0 END) AS steps_used"
        " FROM plans p JOIN leases l ON l.plan_id = p.plan_id"
        " WHERE p.agent_id = ? AND p.status = 'active'"
        " GROUP BY p.plan_id ORDER BY p.created_at_ms",
        (agent_id,),
    ).fetchall()
    progress = []
    for row in rows:
        lease = next_unused(conn, row["plan_id"])
        progress.append(
            {
                "plan_id": row["plan_id"],
                "task_id": row["task_id"],
                "steps_total": row["steps_total"],
                "steps_used": row["steps_used"],
                "next_tool": lease.tool if lease else None,
                "expires_at_ms": row["expires_at_ms"],
            }
        )
    return progress
