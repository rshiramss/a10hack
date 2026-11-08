"""Pharmacist tools (unblinded)."""

from __future__ import annotations

from typing import Any

from badge import broker
from badge.clock import to_ms
from badge.ids import new_uuid, random_code
from badge.tools.base import ToolContext

KIT_ID_LEN = 8


def get_assignment(ctx: ToolContext) -> dict[str, Any]:
    patient_id = ctx.args["patient_id"]
    row = ctx.conn.execute(
        "SELECT arm FROM assignments WHERE patient_id = ?", (patient_id,)
    ).fetchone()
    # Only the arm leaves the table. The row's canary column never does.
    return {"patient_id": patient_id, "visit_id": ctx.args["visit_id"], "arm": row["arm"]}


def dispense_kit(ctx: ToolContext) -> dict[str, Any]:
    patient_id, visit_id = ctx.args["patient_id"], ctx.args["visit_id"]
    # The kit id is random, so it reveals nothing about the arm.
    kit_id = f"KIT-{random_code(KIT_ID_LEN)}"
    ctx.conn.execute(
        "INSERT INTO dispensations (dispensation_id, patient_id, visit_id, kit_id, agent_id,"
        " badge_id, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            new_uuid(),
            patient_id,
            visit_id,
            kit_id,
            ctx.badge.agent_id,
            ctx.badge.badge_id,
            to_ms(ctx.now),
        ),
    )
    broker.publish(
        ctx.conn,
        ctx.runtime.config,
        ctx.now,
        "H1",
        visit_id,
        0,
        {"kit_status": "dispensed", "kit_id": kit_id},
        ctx.badge,
        "dispense_kit",
    )
    return {
        "patient_id": patient_id,
        "visit_id": visit_id,
        "kit_id": kit_id,
        "kit_status": "dispensed",
    }
