"""Monitor tools (humans, via the dashboard), including two-person emergency unblinding."""

from __future__ import annotations

import json
from typing import Any

from badge import reasons
from badge.clock import to_ms
from badge.decisions import DeniedError, Deny
from badge.ids import random_code
from badge.leases import insert_lease
from badge.revocation import flag_agent_outcomes, flag_patient_outcomes, revoke_agent
from badge.tools.base import ToolContext

DEFAULT_AUDIT_LIMIT = 100
REQUEST_CODE_LEN = 8


def view_audit(ctx: ToolContext) -> dict[str, Any]:
    limit = ctx.args.get("limit", DEFAULT_AUDIT_LIMIT)
    agent_id = ctx.args.get("agent_id")
    if agent_id:
        rows = ctx.conn.execute(
            "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY seq DESC LIMIT ?",
            (agent_id, limit),
        ).fetchall()
    else:
        rows = ctx.conn.execute(
            "SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)
        ).fetchall()
    return {"entries": [_entry_from_row(row) for row in rows]}


def _entry_from_row(row: Any) -> dict[str, Any]:
    entry = dict(row)
    entry["args"] = json.loads(entry.pop("args_json"))
    return entry


def _require_agent(ctx: ToolContext, agent_id: str) -> None:
    row = ctx.conn.execute("SELECT 1 FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if row is None:
        raise DeniedError(Deny(reasons.DENY_UNKNOWN_TARGET, detail="no such agent"))


def revoke_badge(ctx: ToolContext) -> dict[str, Any]:
    agent_id = ctx.args["agent_id"]
    _require_agent(ctx, agent_id)
    if agent_id == ctx.badge.agent_id:
        # Self-revocation would also trip the pre-commit revocation re-check and roll back.
        raise DeniedError(Deny(reasons.DENY_UNKNOWN_TARGET, detail="can't revoke yourself"))
    revoked = revoke_agent(
        ctx.conn, ctx.runtime, agent_id, reasons.TRIGGER_MONITOR, ctx.badge.agent_id
    )
    return {"agent_id": agent_id, "badges_revoked": revoked}


def flag_outcomes(ctx: ToolContext) -> dict[str, Any]:
    agent_id = ctx.args["agent_id"]
    _require_agent(ctx, agent_id)
    flagged = flag_agent_outcomes(
        ctx.conn, ctx.now, agent_id, reasons.FLAG_MONITOR, ctx.badge.agent_id
    )
    return {"agent_id": agent_id, "outcomes_flagged": flagged}


def request_emergency_unblind(ctx: ToolContext) -> dict[str, Any]:
    patient_id = ctx.args["patient_id"]
    patient = ctx.conn.execute(
        "SELECT is_decoy FROM patients WHERE patient_id = ?", (patient_id,)
    ).fetchone()
    if patient is None or patient["is_decoy"]:
        raise DeniedError(Deny(reasons.DENY_UNKNOWN_TARGET, detail="no such patient"))
    request_id = f"UNB-{random_code(REQUEST_CODE_LEN)}"
    ctx.conn.execute(
        "INSERT INTO unblind_requests (request_id, patient_id, reason, requested_by, status,"
        " created_at_ms) VALUES (?, ?, ?, ?, 'pending', ?)",
        (request_id, patient_id, ctx.args["reason"], ctx.badge.agent_id, to_ms(ctx.now)),
    )
    return {"request_id": request_id, "patient_id": patient_id, "status": "pending"}


def approve_emergency_unblind(ctx: ToolContext) -> dict[str, Any]:
    """Second monitor approves: mint a 5-minute single-use lease for the approver only."""
    request_id = ctx.args["request_id"]
    request = ctx.conn.execute(
        "SELECT * FROM unblind_requests WHERE request_id = ?", (request_id,)
    ).fetchone()
    if request is None or request["status"] != "pending":
        raise DeniedError(Deny(reasons.DENY_UNKNOWN_TARGET, detail="no pending request"))
    if request["requested_by"] == ctx.badge.agent_id:
        raise DeniedError(Deny(reasons.DENY_TWO_PERSON, detail="requester can't self-approve"))
    ctx.conn.execute(
        "UPDATE unblind_requests SET status = 'approved', approved_by = ?, approved_at_ms = ?"
        " WHERE request_id = ?",
        (ctx.badge.agent_id, to_ms(ctx.now), request_id),
    )
    expires_at = ctx.now + ctx.runtime.config.emergency_lease_ttl_minutes * 60
    lease_id = insert_lease(
        ctx.conn,
        ctx.now,
        plan_id=None,
        step_index=0,
        agent_id=ctx.badge.agent_id,
        badge_id=ctx.badge.badge_id,
        tool="view_emergency_unblind",
        bound_args={"request_id": request_id},
        expires_at=expires_at,
    )
    flagged = flag_patient_outcomes(
        ctx.conn,
        ctx.now,
        request["patient_id"],
        reasons.FLAG_EMERGENCY_UNBLINDED,
        ctx.badge.agent_id,
    )
    return {
        "request_id": request_id,
        "lease_id": lease_id,
        "expires_at_ms": to_ms(expires_at),
        "outcomes_flagged": flagged,
    }


def view_emergency_unblind(ctx: ToolContext) -> dict[str, Any]:
    """Returns the arm to the approving monitor only. The pipeline consumes the lease.

    DECISION: section 9.5 says approval issues a single-use lease and the assignment goes to
    the monitor, but names no tool to spend the lease. This tool is that step, so approval
    and disclosure stay separate, auditable events.
    """
    request_id = ctx.args["request_id"]
    row = ctx.conn.execute(
        "SELECT u.patient_id, a.arm FROM unblind_requests u"
        " JOIN assignments a ON a.patient_id = u.patient_id"
        " WHERE u.request_id = ? AND u.status = 'approved' AND u.approved_by = ?",
        (request_id, ctx.badge.agent_id),
    ).fetchone()
    if row is None:
        raise DeniedError(Deny(reasons.DENY_NO_LEASE, detail="not the approver"))
    return {"request_id": request_id, "patient_id": row["patient_id"], "arm": row["arm"]}
