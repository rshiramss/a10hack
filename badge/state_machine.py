"""Server-side workflow state machines (section 5).

State lives in `workflow_state`, keyed by (workflow, resource_id, slot). A missing row
means the workflow's initial state. The agent's own claims about state never count.
"""

from __future__ import annotations

import sqlite3

from badge import reasons
from badge.clock import to_ms
from badge.config import Transition, TrialConfig, WorkflowSpec
from badge.context import CallContext, Task
from badge.decisions import Allow, Decision, Deny


def workflow_for_role(config: TrialConfig, role: str) -> str | None:
    """The single workflow a role's planned tools run under, or None if it has none."""
    names = {
        config.tool(tool).workflow for tool in config.role(role).tools if config.tool(tool).planned
    }
    if len(names) != 1:
        return None
    return names.pop()


def slot_for(workflow: WorkflowSpec, task: Task) -> int:
    return task.slot if workflow.slotted else 0


def get_state(
    conn: sqlite3.Connection, config: TrialConfig, workflow_name: str, resource_id: str, slot: int
) -> str:
    row = conn.execute(
        "SELECT state FROM workflow_state WHERE workflow = ? AND resource_id = ? AND slot = ?",
        (workflow_name, resource_id, slot),
    ).fetchone()
    return row["state"] if row else config.workflows[workflow_name].initial


def set_state(
    conn: sqlite3.Connection,
    now: float,
    workflow_name: str,
    resource_id: str,
    slot: int,
    state: str,
) -> None:
    """Upsert one state. Runs inside the caller's write transaction."""
    conn.execute(
        "INSERT INTO workflow_state (workflow, resource_id, slot, state, updated_at_ms)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT (workflow, resource_id, slot)"
        " DO UPDATE SET state = excluded.state, updated_at_ms = excluded.updated_at_ms",
        (workflow_name, resource_id, slot, state, to_ms(now)),
    )


def reset_if_unfinished(
    conn: sqlite3.Connection,
    config: TrialConfig,
    workflow_name: str,
    resource_id: str,
    slot: int,
) -> None:
    """Send a resource back to its initial state unless it already reached a terminal one.

    Used when a task returns to the pool, so the next agent starts clean.
    """
    workflow = config.workflows[workflow_name]
    if get_state(conn, config, workflow_name, resource_id, slot) in workflow.terminal:
        return
    conn.execute(
        "DELETE FROM workflow_state WHERE workflow = ? AND resource_id = ? AND slot = ?",
        (workflow_name, resource_id, slot),
    )


def find_transition(workflow: WorkflowSpec, tool: str, state: str) -> Transition | None:
    for transition in workflow.transitions:
        if transition.tool == tool and state in transition.from_states:
            return transition
    return None


def first_invalid_step(workflow: WorkflowSpec, start_state: str, tools: list[str]) -> int | None:
    """Walk `tools` from `start_state`. Returns the index of the first invalid step, or None."""
    state = start_state
    for index, tool in enumerate(tools):
        transition = find_transition(workflow, tool, state)
        if transition is None:
            return index
        state = transition.to
    return None


def check_transition(ctx: CallContext) -> Decision:
    """Pipeline step 6: the call must be a valid transition from the current state."""
    workflow_name = ctx.tool_spec.workflow
    workflow = ctx.config.workflows[workflow_name]
    slot = slot_for(workflow, ctx.task)
    state = get_state(ctx.conn, ctx.config, workflow_name, ctx.task.resource_id, slot)
    transition = find_transition(workflow, ctx.request.tool, state)
    if transition is None:
        return Deny(reasons.DENY_BAD_TRANSITION, detail=f"not allowed from state {state!r}")
    return Allow({"transition": (state, transition.to)})
