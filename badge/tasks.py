"""Task assignment and ownership (section 7).

Only the orchestrator assigns or reassigns tasks. Agents can only act on tasks assigned
to them, and one assessor can never hold both read slots of a visit.
"""

from __future__ import annotations

import sqlite3

from badge import reasons
from badge.audit import AuditEntry, append
from badge.clock import to_ms
from badge.context import CallContext, Runtime, Task
from badge.decisions import Allow, Decision, Deny
from badge.state_machine import reset_if_unfinished, workflow_for_role

MAX_RESOURCE_ID_LEN = 64


class OrchestratorError(Exception):
    """The orchestrator refused an assignment (e.g. the independence rule)."""


def _row_to_task(row: sqlite3.Row) -> Task:
    return Task(
        task_id=row["task_id"],
        role=row["role"],
        agent_id=row["agent_id"],
        resource_id=row["resource_id"],
        slot=row["slot"],
        status=row["status"],
    )


def get_task(conn: sqlite3.Connection, task_id: str) -> Task | None:
    row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
    return _row_to_task(row) if row else None


def tasks_for_agent(conn: sqlite3.Connection, agent_id: str) -> list[Task]:
    rows = conn.execute(
        "SELECT * FROM tasks WHERE agent_id = ? ORDER BY task_id", (agent_id,)
    ).fetchall()
    return [_row_to_task(row) for row in rows]


def find_owned_task(
    conn: sqlite3.Connection, agent_id: str, role: str, resource_id: str
) -> Task | None:
    """The agent's task (assigned or done) for a resource, if it has one."""
    row = conn.execute(
        "SELECT * FROM tasks WHERE agent_id = ? AND role = ? AND resource_id = ?"
        " AND status IN ('assigned', 'done')",
        (agent_id, role, resource_id),
    ).fetchone()
    return _row_to_task(row) if row else None


def create_task(
    conn: sqlite3.Connection, now: float, task_id: str, role: str, resource_id: str, slot: int = 0
) -> None:
    """Create an unassigned task. Runs inside the caller's write transaction."""
    conn.execute(
        "INSERT INTO tasks (task_id, role, agent_id, resource_id, slot, status, created_at_ms)"
        " VALUES (?, ?, NULL, ?, ?, 'open', ?)",
        (task_id, role, resource_id, slot, to_ms(now)),
    )


def _violates_independence(conn: sqlite3.Connection, task: Task, agent_id: str) -> bool:
    """True if the agent holds, or has ever written outcomes for, another slot of the resource."""
    other_task = conn.execute(
        "SELECT 1 FROM tasks WHERE role = ? AND resource_id = ? AND slot != ? AND agent_id = ?",
        (task.role, task.resource_id, task.slot, agent_id),
    ).fetchone()
    other_outcomes = conn.execute(
        "SELECT 1 FROM outcomes WHERE visit_id = ? AND slot != ? AND agent_id = ?",
        (task.resource_id, task.slot, agent_id),
    ).fetchone()
    return other_task is not None or other_outcomes is not None


def assign_task(conn: sqlite3.Connection, runtime: Runtime, task_id: str, agent_id: str) -> None:
    """Assign an open task. Runs inside the caller's write transaction.

    Raises OrchestratorError if the task isn't open, the agent isn't an active agent of
    the task's role, or the assignment would break the independence rule.
    """
    task = get_task(conn, task_id)
    if task is None or task.status != "open":
        raise OrchestratorError(f"task {task_id} is not open")
    agent = conn.execute(
        "SELECT role, status FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if agent is None or agent["status"] != "active" or agent["role"] != task.role:
        raise OrchestratorError(f"agent {agent_id} can't take a {task.role} task")
    if _violates_independence(conn, task, agent_id):
        raise OrchestratorError(
            f"independence rule: {agent_id} already holds another slot of {task.resource_id}"
        )
    conn.execute(
        "UPDATE tasks SET agent_id = ?, status = 'assigned' WHERE task_id = ?",
        (agent_id, task_id),
    )
    append(
        conn,
        runtime.config,
        runtime.clock.now(),
        AuditEntry(
            agent_id=agent_id,
            badge_id=None,
            role=task.role,
            tool=None,
            args={"task_id": task_id},
            decision="EVENT",
            reason=reasons.EVENT_TASK_ASSIGNED,
        ),
    )


def mark_done(conn: sqlite3.Connection, task_id: str) -> None:
    conn.execute("UPDATE tasks SET status = 'done' WHERE task_id = ?", (task_id,))


def return_to_pool(conn: sqlite3.Connection, runtime: Runtime, task_id: str, why: str) -> None:
    """Unassign an unfinished task and reset its workflow. Runs inside the caller's tx."""
    task = get_task(conn, task_id)
    if task is None or task.status != "assigned":
        return
    conn.execute("UPDATE tasks SET agent_id = NULL, status = 'open' WHERE task_id = ?", (task_id,))
    workflow_name = workflow_for_role(runtime.config, task.role)
    if workflow_name:
        workflow = runtime.config.workflows[workflow_name]
        slot = task.slot if workflow.slotted else 0
        reset_if_unfinished(conn, runtime.config, workflow_name, task.resource_id, slot)
    append(
        conn,
        runtime.config,
        runtime.clock.now(),
        AuditEntry(
            agent_id=task.agent_id,
            badge_id=None,
            role=task.role,
            tool=None,
            args={"task_id": task_id},
            decision="EVENT",
            reason=reasons.EVENT_TASK_RETURNED,
            detail=why,
        ),
    )


def reassign_open_tasks(
    conn: sqlite3.Connection, runtime: Runtime, role: str
) -> list[tuple[str, str]]:
    """Give each open task of `role` to the eligible active agent with the fewest tasks.

    Runs inside the caller's write transaction. Returns (task_id, agent_id) pairs.
    Tasks with no eligible agent stay open.
    """
    assigned: list[tuple[str, str]] = []
    open_tasks = conn.execute(
        "SELECT * FROM tasks WHERE role = ? AND status = 'open' ORDER BY task_id", (role,)
    ).fetchall()
    for row in open_tasks:
        task = _row_to_task(row)
        candidates = conn.execute(
            "SELECT a.agent_id, COUNT(t.task_id) AS load FROM agents a"
            " LEFT JOIN tasks t ON t.agent_id = a.agent_id AND t.status = 'assigned'"
            " WHERE a.role = ? AND a.status = 'active'"
            " GROUP BY a.agent_id ORDER BY load, a.agent_id",
            (role,),
        ).fetchall()
        for candidate in candidates:
            if not _violates_independence(conn, task, candidate["agent_id"]):
                assign_task(conn, runtime, task.task_id, candidate["agent_id"])
                assigned.append((task.task_id, candidate["agent_id"]))
                break
    return assigned


def check_ownership(ctx: CallContext) -> Decision:
    """Pipeline step 3: the call's resource must belong to a task assigned to this agent."""
    spec = ctx.tool_spec
    resource_id = ctx.raw_args.get(spec.resource_arg)
    if not isinstance(resource_id, str) or len(resource_id) > MAX_RESOURCE_ID_LEN:
        return Deny(reasons.DENY_NOT_OWNER, detail="missing or malformed resource id")
    task = find_owned_task(ctx.conn, ctx.badge.agent_id, ctx.badge.role, resource_id)
    if task is None:
        return Deny(reasons.DENY_NOT_OWNER, detail=f"{resource_id} is not your task")
    if spec.patient_arg:
        patient_id = ctx.raw_args.get(spec.patient_arg)
        visit = ctx.conn.execute(
            "SELECT patient_id FROM visits WHERE visit_id = ?", (resource_id,)
        ).fetchone()
        if visit is None or visit["patient_id"] != patient_id:
            return Deny(reasons.DENY_NOT_OWNER, detail="patient does not match the visit")
    return Allow({"task": task})
