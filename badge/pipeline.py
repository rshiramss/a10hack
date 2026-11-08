"""The ordered check pipeline (section 9.1). Every gateway call goes through `handle_call`.

Order for a planned tool call (first failure stops it):
  1 badge  2 role  3 ownership  (idempotent replay)  4 plan match  5 lease  6 state machine
  7 handoff preconditions  8 input schema  9 budgets  10 content scanners
  11 execute (one transaction)  12 output filter  13 audit (every outcome, at any step)

Unplanned tools (platform tools, monitor tools) skip steps 3-7, except that a tool marked
`standing_lease` still needs its single-use lease. Any exception anywhere means DENY.
"""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from badge import (
    broker,
    budgets,
    idempotency,
    identity,
    leases,
    plans,
    policy,
    reasons,
    scanners,
    schemas,
    state_machine,
    tasks,
)
from badge.audit import AuditEntry, append, sanitize_args
from badge.clock import to_ms
from badge.context import CallContext, CallRequest, Runtime
from badge.db import write_tx
from badge.decisions import Action, Decision, DeniedError, Deny, Replay
from badge.models import OUTPUT_MODELS
from badge.redaction import redact
from badge.revocation import revoke_agent, suspend_agent
from badge.tools.base import ToolContext
from badge.tools.registry import TOOL_FUNCTIONS

logger = logging.getLogger(__name__)

MAX_LOGGED_TOOL_NAME_LEN = 64

Check = Callable[[CallContext], Decision]

PLANNED_CHECKS: tuple[Check, ...] = (
    tasks.check_ownership,
    idempotency.check_replay,
    plans.check_plan_match,
    leases.check_lease,
    state_machine.check_transition,
    broker.check_preconditions,
    schemas.check_input,
    budgets.check_budgets,
    scanners.check_input_content,
)

# DECISION: monitor tools are used by humans clicking a dashboard, so they are not planned
# (no declare_plan / per-step leases). They still pass badge, role, schema, budget, scanner,
# and audit checks, and break-the-glass keeps its own single-use lease.
UNPLANNED_CHECKS: tuple[Check, ...] = (
    idempotency.check_replay,
    leases.check_standing_lease,
    schemas.check_input,
    budgets.check_budgets,
    scanners.check_input_content,
)

_REVOKE_TRIGGERS = {
    reasons.DENY_ROLE_FORBIDDEN: reasons.TRIGGER_ROLE_FORBIDDEN,
    reasons.DENY_CANARY: reasons.TRIGGER_CANARY,
}


@dataclass(frozen=True)
class CallResult:
    allowed: bool
    reason: str
    result: dict[str, Any] | None = None
    detail: str = ""
    action: str = "none"

    def to_json(self) -> dict[str, Any]:
        return {
            "ok": self.allowed,
            "reason": self.reason,
            "result": self.result,
            "detail": self.detail,
            "action": self.action,
        }


def handle_call(runtime: Runtime, conn: sqlite3.Connection, request: CallRequest) -> CallResult:
    """Run one gateway call end to end. Never raises: failures become DENY (fail closed)."""
    ctx = CallContext(runtime=runtime, conn=conn, request=request, now=runtime.clock.now())
    try:
        return _run(ctx)
    except Exception:
        logger.exception("gateway call failed; denying (tool=%r)", _logged_tool(request))
        return _deny(ctx, Deny(reasons.DENY_INTERNAL, detail="internal error"))


def _run(ctx: CallContext) -> CallResult:
    for check in (identity.check_badge, policy.check_role):
        decision = check(ctx)
        if isinstance(decision, Deny):
            return _deny(ctx, decision)
        ctx = replace(ctx, **decision.updates)

    if ctx.request.tool == "declare_plan":
        return _declare_plan(ctx)

    checks = PLANNED_CHECKS if ctx.tool_spec.planned else UNPLANNED_CHECKS
    for check in checks:
        decision = check(ctx)
        if isinstance(decision, Deny):
            return _deny(ctx, decision)
        if isinstance(decision, Replay):
            return _replay(ctx, decision.result)
        ctx = replace(ctx, **decision.updates)
    return _execute(ctx)


# ---- declare_plan -------------------------------------------------------------------


def _declare_plan(ctx: CallContext) -> CallResult:
    for check in (schemas.check_input, budgets.check_budgets, scanners.check_input_content):
        decision = check(ctx)
        if isinstance(decision, Deny):
            return _deny(ctx, decision)
        ctx = replace(ctx, **decision.updates)
    try:
        with write_tx(ctx.conn):
            leases.expire_stale(ctx.conn, ctx.now)
            validated = plans.validate_plan(ctx, ctx.args)
            if isinstance(validated, Deny):
                raise DeniedError(validated)
            ctx = replace(ctx, task=validated)
            output = plans.create_plan(
                ctx.conn, ctx.runtime, ctx.now, ctx.badge, validated, ctx.args["steps"]
            )
            output = OUTPUT_MODELS["declare_plan"].model_validate(output).model_dump()
            _audit_allow(ctx, reasons.OK, detail=f"plan={output['plan_id']}")
    except DeniedError as error:
        return _deny(ctx, error.deny)
    return CallResult(allowed=True, reason=reasons.OK, result=output)


# ---- execute (steps 11-13) ---------------------------------------------------------


def _execute(ctx: CallContext) -> CallResult:
    spec = ctx.tool_spec
    try:
        with write_tx(ctx.conn):
            if spec.mutating:
                decision = _recheck_idempotency(ctx)
                if isinstance(decision, Replay):
                    _audit_allow(ctx, reasons.ALLOW_REPLAY, detail="idempotent replay")
                    return CallResult(True, reasons.ALLOW_REPLAY, decision.result)
            _recheck_inside_tx(ctx)
            output = TOOL_FUNCTIONS[ctx.request.tool](_tool_context(ctx))
            _advance_plan_and_state(ctx)
            output, redactions = _filter_output(ctx, output)
            if spec.mutating:
                idempotency.store(
                    ctx.conn,
                    ctx.now,
                    ctx.request.idempotency_key,
                    ctx.badge.agent_id,
                    ctx.request.tool,
                    ctx.request.args,
                    output,
                )
            # Last re-check right before commit: a revoked badge rolls everything back.
            if identity.is_badge_revoked(ctx.conn, ctx.badge.badge_id):
                raise DeniedError(Deny(reasons.DENY_REVOKED, detail="revoked mid-transaction"))
            detail = f"redactions={redactions}" if redactions else ""
            _audit_allow(ctx, reasons.OK, detail=detail)
    except DeniedError as error:
        return _deny(ctx, error.deny)
    except sqlite3.IntegrityError:
        # A unique constraint caught a duplicate the earlier checks missed (a race).
        return _deny(ctx, Deny(reasons.DENY_DUPLICATE, detail="duplicate blocked by constraint"))
    return CallResult(allowed=True, reason=reasons.OK, result=output)


def _recheck_idempotency(ctx: CallContext) -> Decision:
    """Inside the transaction: a concurrent call may have used the key since step 3."""
    row = idempotency.lookup(ctx.conn, ctx.request.idempotency_key)
    decision = idempotency.decide(row, ctx.badge.agent_id, ctx.request.tool, ctx.request.args)
    if isinstance(decision, Deny):
        raise DeniedError(decision)
    return decision


def _recheck_inside_tx(ctx: CallContext) -> None:
    """Re-verify what a concurrent writer could have changed since the checks ran."""
    if identity.is_badge_revoked(ctx.conn, ctx.badge.badge_id):
        raise DeniedError(Deny(reasons.DENY_REVOKED, detail="badge revoked"))
    agent = ctx.conn.execute(
        "SELECT status FROM agents WHERE agent_id = ?", (ctx.badge.agent_id,)
    ).fetchone()
    if agent is None or agent["status"] != "active":
        raise DeniedError(Deny(reasons.DENY_SUSPENDED, detail="agent no longer active"))
    if ctx.lease is not None:
        lease = leases.get_lease(ctx.conn, ctx.lease.lease_id)
        problem = leases.lease_problem(lease, ctx.now) if lease else reasons.DENY_NO_LEASE
        if problem is not None:
            raise DeniedError(Deny(problem, detail="lease used or expired concurrently"))
    if ctx.transition is not None:
        workflow = ctx.config.workflows[ctx.tool_spec.workflow]
        current = state_machine.get_state(
            ctx.conn,
            ctx.config,
            ctx.tool_spec.workflow,
            ctx.task.resource_id,
            state_machine.slot_for(workflow, ctx.task),
        )
        if current != ctx.transition[0]:
            raise DeniedError(Deny(reasons.DENY_BAD_TRANSITION, detail="state changed"))


def _tool_context(ctx: CallContext) -> ToolContext:
    return ToolContext(
        conn=ctx.conn,
        runtime=ctx.runtime,
        now=ctx.now,
        badge=ctx.badge,
        args=ctx.args,
        task=ctx.task,
        lease=ctx.lease,
        handoff_inputs=ctx.handoff_inputs,
        arm_term_hits=ctx.arm_term_hits,
    )


def _advance_plan_and_state(ctx: CallContext) -> None:
    """Consume the lease, move the state machine, and close the plan/task when finished."""
    if ctx.lease is not None:
        leases.consume(ctx.conn, ctx.lease.lease_id)
    if ctx.transition is None:
        return
    workflow = ctx.config.workflows[ctx.tool_spec.workflow]
    slot = state_machine.slot_for(workflow, ctx.task)
    new_state = ctx.transition[1]
    state_machine.set_state(
        ctx.conn, ctx.now, ctx.tool_spec.workflow, ctx.task.resource_id, slot, new_state
    )
    plans.complete_if_finished(ctx.conn, ctx.plan.plan_id)
    if new_state in workflow.terminal:
        tasks.mark_done(ctx.conn, ctx.task.task_id)


def _filter_output(ctx: CallContext, output: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Step 12: validate the output schema, redact for blinded roles, scan for canaries."""
    validated = OUTPUT_MODELS[ctx.request.tool].model_validate(output).model_dump()
    redactions = 0
    if ctx.config.role(ctx.badge.role).blinded:
        for field_name in ctx.tool_spec.redact_output:
            validated[field_name], count = redact(ctx.config, validated[field_name])
            redactions += count
        if scanners.contains_canary(ctx.config, validated):
            raise DeniedError(Deny(reasons.DENY_CANARY, Action.REVOKE, detail="canary in output"))
    return validated, redactions


def _replay(ctx: CallContext, result: dict[str, Any]) -> CallResult:
    with write_tx(ctx.conn):
        _audit_allow(ctx, reasons.ALLOW_REPLAY, detail="idempotent replay")
    return CallResult(allowed=True, reason=reasons.ALLOW_REPLAY, result=result)


# ---- denial -------------------------------------------------------------------------


def _deny(ctx: CallContext, deny: Deny) -> CallResult:
    """Apply the denial's action, audit it, and escalate if the denied-call budget is spent.

    Actions apply only to a verified badge. A call whose badge failed verification is
    logged (attributed when the signature is valid) but can't trigger actions.
    """
    action = deny.action if ctx.badge is not None else Action.NONE
    try:
        with write_tx(ctx.conn):
            _apply_deny(ctx, deny, action)
    except Exception:
        logger.exception("failed to record denial %s", deny.reason)
    return CallResult(allowed=False, reason=deny.reason, detail=deny.detail, action=action.label)


def _apply_deny(ctx: CallContext, deny: Deny, action: Action) -> None:
    conn, runtime = ctx.conn, ctx.runtime
    agent_id, badge_id, role = _attribution(ctx)
    append(
        conn,
        runtime.config,
        ctx.now,
        AuditEntry(
            agent_id=agent_id,
            badge_id=badge_id,
            role=role,
            tool=_logged_tool(ctx.request),
            args=sanitize_args(runtime.config, _logged_tool(ctx.request), ctx.request.args),
            decision="DENY",
            reason=deny.reason,
            action=action.label,
            severity="high" if action >= Action.SUSPEND else "normal",
            detail=deny.detail[:300],
        ),
    )
    if deny.alert:
        _raise_alert(ctx, deny.alert, agent_id)
    if ctx.badge is None:
        return

    if action >= Action.EXPIRE_PLAN:
        _expire_targeted_plans(ctx, deny, agent_id)
    if deny.return_task_id:
        leases.end_active_plans(conn, agent_id, deny.return_task_id, "expired", deny.reason)
        tasks.return_to_pool(conn, runtime, deny.return_task_id, why=deny.reason)
    if action == Action.SUSPEND:
        suspend_agent(conn, runtime, agent_id, deny.reason, actor="gateway")
    if action == Action.REVOKE:
        trigger = _REVOKE_TRIGGERS.get(deny.reason, deny.reason)
        revoke_agent(conn, runtime, agent_id, trigger, actor="gateway")
        return

    budget = runtime.config.role(role).budgets.max_denied_calls_per_badge
    # DECISION: section 9.2 lists "denied-call budget exceeded" as a revocation trigger,
    # while 4.4 says "suspend". Revocation is the more restrictive reading.
    if budgets.denied_calls(conn, badge_id) >= budget and _agent_not_revoked(conn, agent_id):
        revoke_agent(conn, runtime, agent_id, reasons.TRIGGER_DENIED_BUDGET, actor="gateway")


def _expire_targeted_plans(ctx: CallContext, deny: Deny, agent_id: str) -> None:
    """End the plan the denial is about: the one named on the Deny, else the call's own
    plan, else the call's task's plans, else (no task context) all of the agent's plans."""
    plan_id = deny.plan_id or (ctx.plan.plan_id if ctx.plan else None)
    if plan_id:
        leases.end_plan(ctx.conn, plan_id, "expired", deny.reason)
        return
    task_id = ctx.task.task_id if ctx.task else None
    leases.end_active_plans(ctx.conn, agent_id, task_id, "expired", deny.reason)


def _agent_not_revoked(conn: sqlite3.Connection, agent_id: str) -> bool:
    row = conn.execute("SELECT status FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return row is not None and row["status"] != "revoked"


def _raise_alert(ctx: CallContext, message: str, agent_id: str | None) -> None:
    ctx.conn.execute(
        "INSERT INTO alerts (created_at_ms, kind, detail, agent_id) VALUES (?, ?, ?, ?)",
        (to_ms(ctx.now), reasons.EVENT_HANDOFF_REJECTED, message[:300], agent_id),
    )
    append(
        ctx.conn,
        ctx.config,
        ctx.now,
        AuditEntry(
            agent_id=agent_id,
            badge_id=None,
            role=None,
            tool=None,
            args={},
            decision="EVENT",
            reason=reasons.EVENT_HANDOFF_REJECTED,
            severity="high",
            detail=message[:300],
        ),
    )


# ---- audit helpers -------------------------------------------------------------------


def _attribution(ctx: CallContext) -> tuple[str | None, str | None, str | None]:
    if ctx.badge is not None:
        return ctx.badge.agent_id, ctx.badge.badge_id, ctx.badge.role
    peeked = identity.peek_identity(ctx.runtime, ctx.request.token)
    return peeked if peeked else (None, None, None)


def _logged_tool(request: CallRequest) -> str | None:
    if not isinstance(request.tool, str):
        return None
    return request.tool[:MAX_LOGGED_TOOL_NAME_LEN]


def _audit_allow(ctx: CallContext, reason: str, detail: str = "") -> None:
    append(
        ctx.conn,
        ctx.config,
        ctx.now,
        AuditEntry(
            agent_id=ctx.badge.agent_id,
            badge_id=ctx.badge.badge_id,
            role=ctx.badge.role,
            tool=ctx.request.tool,
            args=sanitize_args(ctx.config, ctx.request.tool, ctx.request.args),
            decision="ALLOW",
            reason=reason,
            severity=ctx.tool_spec.severity,
            detail=detail,
        ),
    )
