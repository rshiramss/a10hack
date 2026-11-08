"""Assessor tools (blinded). Notes stay in the outcome store; only integers leave via H2."""

from __future__ import annotations

from typing import Any

from badge import broker, reasons
from badge.clock import to_ms
from badge.ids import new_uuid
from badge.revocation import flag_outcome
from badge.tools.base import ToolContext


def open_patient_visit(ctx: ToolContext) -> dict[str, Any]:
    row = ctx.conn.execute(
        "SELECT visit_id, patient_id, visit_no, note FROM visits WHERE visit_id = ?",
        (ctx.args["visit_id"],),
    ).fetchone()
    # The output filter redacts arm-revealing terms from `note` before it leaves.
    return {
        "visit_id": row["visit_id"],
        "patient_id": row["patient_id"],
        "visit_no": row["visit_no"],
        "slot": ctx.task.slot,
        "note": row["note"],
    }


def _latest_outcome_id(ctx: ToolContext, measure: str) -> str | None:
    row = ctx.conn.execute(
        "SELECT o.outcome_id FROM outcomes o"
        " WHERE o.visit_id = ? AND o.slot = ? AND o.agent_id = ? AND o.measure = ?"
        " AND NOT EXISTS (SELECT 1 FROM outcomes n WHERE n.supersedes_id = o.outcome_id)",
        (ctx.task.resource_id, ctx.task.slot, ctx.badge.agent_id, measure),
    ).fetchone()
    return row["outcome_id"] if row else None


def _patient_unblinded(ctx: ToolContext, visit_id: str) -> bool:
    row = ctx.conn.execute(
        "SELECT 1 FROM unblind_requests u JOIN visits v ON v.patient_id = u.patient_id"
        " WHERE v.visit_id = ? AND u.status = 'approved'",
        (visit_id,),
    ).fetchone()
    return row is not None


def record_outcome(ctx: ToolContext) -> dict[str, Any]:
    visit_id, measure, value = ctx.args["visit_id"], ctx.args["measure"], ctx.args["value"]
    outcome_id = new_uuid()
    supersedes_id = _latest_outcome_id(ctx, measure)
    ctx.conn.execute(
        "INSERT INTO outcomes (outcome_id, visit_id, slot, measure, value, notes, agent_id,"
        " badge_id, supersedes_id, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            outcome_id,
            visit_id,
            ctx.task.slot,
            measure,
            value,
            ctx.args.get("notes"),
            ctx.badge.agent_id,
            ctx.badge.badge_id,
            supersedes_id,
            to_ms(ctx.now),
        ),
    )
    flagged = False
    if ctx.arm_term_hits > 0:
        flagged |= flag_outcome(ctx.conn, ctx.now, outcome_id, reasons.FLAG_ARM_TERMS, "gateway")
    if _patient_unblinded(ctx, visit_id):
        flagged |= flag_outcome(
            ctx.conn, ctx.now, outcome_id, reasons.FLAG_EMERGENCY_UNBLINDED, "gateway"
        )
    return {
        "outcome_id": outcome_id,
        "visit_id": visit_id,
        "slot": ctx.task.slot,
        "measure": measure,
        "value": value,
        "supersedes_id": supersedes_id,
        "flagged_for_review": flagged,
    }


def collect_scores(ctx: ToolContext) -> dict[str, int]:
    """Latest value per measure for this agent's (visit, slot). Integers only."""
    rows = ctx.conn.execute(
        "SELECT o.measure, o.value FROM outcomes o"
        " WHERE o.visit_id = ? AND o.slot = ? AND o.agent_id = ?"
        " AND NOT EXISTS (SELECT 1 FROM outcomes n WHERE n.supersedes_id = o.outcome_id)",
        (ctx.task.resource_id, ctx.task.slot, ctx.badge.agent_id),
    ).fetchall()
    return {row["measure"]: row["value"] for row in rows}


def submit(ctx: ToolContext) -> dict[str, Any]:
    visit_id, slot = ctx.args["visit_id"], ctx.task.slot
    scores = collect_scores(ctx)
    submission_id = new_uuid()
    # UNIQUE (visit_id, slot) backs up the state machine against duplicate submits.
    ctx.conn.execute(
        "INSERT INTO submissions (submission_id, visit_id, slot, agent_id, badge_id,"
        " created_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
        (submission_id, visit_id, slot, ctx.badge.agent_id, ctx.badge.badge_id, to_ms(ctx.now)),
    )
    # H2 carries the numeric scores and nothing else. Notes never leave the outcome store.
    broker.publish(
        ctx.conn,
        ctx.runtime.config,
        ctx.now,
        "H2",
        visit_id,
        slot,
        {"scores": scores},
        ctx.badge,
        "submit",
    )
    return {
        "submission_id": submission_id,
        "visit_id": visit_id,
        "slot": slot,
        "measures_submitted": len(scores),
    }
