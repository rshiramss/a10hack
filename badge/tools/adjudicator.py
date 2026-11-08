"""Adjudicator tool (blinded). Sees only the two numeric score sets, via H2."""

from __future__ import annotations

from typing import Any

from badge import broker
from badge.clock import to_ms
from badge.tools.base import ToolContext

MAX_DELTA = 10


def max_score_delta(first: dict[str, int], second: dict[str, int]) -> int:
    """Largest per-measure difference. A measure only one read scored counts as the max."""
    deltas = [
        abs(first[m] - second[m]) if m in first and m in second else MAX_DELTA
        for m in set(first) | set(second)
    ]
    return max(deltas, default=0)


def compare_reads(ctx: ToolContext) -> dict[str, Any]:
    visit_id = ctx.args["visit_id"]
    reads = ctx.handoff_inputs["H2"]
    max_delta = max_score_delta(reads[1]["scores"], reads[2]["scores"])
    result = "agree" if max_delta <= ctx.runtime.config.agree_threshold else "disagree"
    ctx.conn.execute(
        "INSERT INTO comparisons (visit_id, result, max_delta, agent_id, badge_id, created_at_ms)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (visit_id, result, max_delta, ctx.badge.agent_id, ctx.badge.badge_id, to_ms(ctx.now)),
    )
    broker.publish(
        ctx.conn,
        ctx.runtime.config,
        ctx.now,
        "H3",
        visit_id,
        0,
        {"result": result, "max_delta": max_delta},
        ctx.badge,
        "compare_reads",
    )
    return {"visit_id": visit_id, "result": result, "max_delta": max_delta}
