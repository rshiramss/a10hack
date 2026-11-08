"""Read-only dashboard snapshot for the monitor console.

DECISION: the dashboard polls this once a second. It verifies the monitor's badge but
isn't routed through the tool pipeline, because auditing every poll would flood the log
and burn the monitor's rate budget. It never returns notes, arms, or canaries: only the
state a blinded monitor may see. Mutating monitor actions do go through the pipeline.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from badge import broker
from badge.audit import verify_chain
from badge.clock import to_ms
from badge.context import Runtime
from badge.plans import plan_progress

AUDIT_FEED_LIMIT = 80
ALERT_LIMIT = 20


def dashboard_snapshot(
    conn: sqlite3.Connection, runtime: Runtime, audit_agent: str | None = None
) -> dict[str, Any]:
    chain = verify_chain(conn)
    return {
        "trial_id": runtime.config.trial_id,
        "now_ms": to_ms(runtime.clock.now()),
        "agents": _agents(conn),
        "audit": _audit(conn, audit_agent),
        "audit_filter": audit_agent,
        "leases": _leases(conn, runtime),
        "handoffs": _handoffs(conn, runtime),
        "outcomes": _outcomes(conn),
        "escalations": _escalations(conn, runtime),
        "alerts": _alerts(conn),
        "unblind_requests": _unblind_requests(conn),
        "chain": {"ok": chain.ok, "rows": chain.rows_checked, "first_bad_seq": chain.first_bad_seq},
        "totals": _totals(conn),
    }


def _agents(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    agents = []
    for row in conn.execute("SELECT agent_id, role, status FROM agents ORDER BY role, agent_id"):
        badge = conn.execute(
            "SELECT expires_at_ms FROM badges WHERE agent_id = ?"
            " ORDER BY issued_at_ms DESC LIMIT 1",
            (row["agent_id"],),
        ).fetchone()
        tasks = conn.execute(
            "SELECT task_id, status FROM tasks WHERE agent_id = ? ORDER BY status, task_id",
            (row["agent_id"],),
        ).fetchall()
        agents.append(
            {
                "agent_id": row["agent_id"],
                "role": row["role"],
                "status": row["status"],
                "badge_expires_at_ms": badge["expires_at_ms"] if badge else None,
                "tasks": [dict(task) for task in tasks],
                "plans": plan_progress(conn, row["agent_id"]),
            }
        )
    return agents


def _audit(conn: sqlite3.Connection, agent_id: str | None) -> list[dict[str, Any]]:
    columns = "seq, ts_ms, agent_id, role, tool, decision, reason, action, severity, detail"
    if agent_id:
        rows = conn.execute(
            f"SELECT {columns} FROM audit_log WHERE agent_id = ? ORDER BY seq DESC LIMIT ?",
            (agent_id, AUDIT_FEED_LIMIT),
        )
    else:
        rows = conn.execute(
            f"SELECT {columns} FROM audit_log ORDER BY seq DESC LIMIT ?", (AUDIT_FEED_LIMIT,)
        )
    return [dict(row) for row in rows]


def _leases(conn: sqlite3.Connection, runtime: Runtime) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT lease_id, plan_id, step_index, agent_id, tool, bound_args_json, expires_at_ms"
        " FROM leases WHERE status = 'active' AND expires_at_ms > ?"
        " ORDER BY agent_id, created_at_ms, step_index",
        (to_ms(runtime.clock.now()),),
    )
    return [
        {
            **{
                k: row[k]
                for k in ("lease_id", "plan_id", "step_index", "agent_id", "tool", "expires_at_ms")
            },
            "bound_args": json.loads(row["bound_args_json"]),
        }
        for row in rows
    ]


def _handoffs(conn: sqlite3.Connection, runtime: Runtime) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT h.channel, h.resource_id, h.slot, h.value_json, h.producer_agent_id,"
        " h.created_at_ms, r.badge_id AS revoked"
        " FROM handoffs h LEFT JOIN revocations r ON r.badge_id = h.producer_badge_id"
        " ORDER BY h.created_at_ms DESC"
    )
    handoffs = []
    for row in rows:
        schema = runtime.config.handoffs[row["channel"]].schema_
        try:
            value = json.loads(row["value_json"])
        except json.JSONDecodeError:
            value = None
        valid = broker.value_problem(schema, value) is None
        handoffs.append(
            {
                "channel": row["channel"],
                "resource_id": row["resource_id"],
                "slot": row["slot"],
                # An invalid stored value is never shown: it could carry anything.
                "value": value if valid else None,
                "valid": valid,
                "producer_agent_id": row["producer_agent_id"],
                "producer_revoked": row["revoked"] is not None,
                "created_at_ms": row["created_at_ms"],
            }
        )
    return handoffs


def _outcomes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT o.outcome_id, o.visit_id, o.slot, o.measure, o.value, o.agent_id, o.created_at_ms,"
        " EXISTS (SELECT 1 FROM outcomes n WHERE n.supersedes_id = o.outcome_id) AS superseded,"
        " EXISTS (SELECT 1 FROM submissions s WHERE s.visit_id = o.visit_id AND s.slot = o.slot"
        "         AND s.agent_id = o.agent_id) AS submitted,"
        " (SELECT group_concat(f.reason, ', ') FROM outcome_flags f"
        "  WHERE f.outcome_id = o.outcome_id) AS flags"
        " FROM outcomes o ORDER BY o.visit_id, o.slot, o.measure, o.created_at_ms"
    )
    return [
        {
            **dict(row),
            "superseded": bool(row["superseded"]),
            "submitted": bool(row["submitted"]),
            "flags": row["flags"].split(", ") if row["flags"] else [],
        }
        for row in rows
    ]


def _escalations(conn: sqlite3.Connection, runtime: Runtime) -> list[dict[str, Any]]:
    """Visits whose H3 says the two reads disagree: the human escalation queue."""
    consumer = runtime.config.handoffs["H3"].consumer
    queue = []
    for row in conn.execute("SELECT visit_id FROM comparisons ORDER BY created_at_ms"):
        result = broker.read(
            conn, runtime.config, "H3", row["visit_id"], 0, consumer.role, consumer.tool
        )
        if result.value is not None and result.value["result"] == "disagree":
            queue.append({"visit_id": row["visit_id"], **result.value})
    return queue


def _alerts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT alert_id, created_at_ms, kind, detail, agent_id FROM alerts"
        " ORDER BY alert_id DESC LIMIT ?",
        (ALERT_LIMIT,),
    )
    return [dict(row) for row in rows]


def _unblind_requests(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT request_id, patient_id, requested_by, status, approved_by, created_at_ms,"
        " approved_at_ms FROM unblind_requests ORDER BY created_at_ms DESC"
    )
    return [dict(row) for row in rows]


def _totals(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute("SELECT decision, COUNT(*) AS n FROM audit_log GROUP BY decision")
    totals = {"ALLOW": 0, "DENY": 0, "EVENT": 0}
    totals.update({row["decision"]: row["n"] for row in rows})
    return totals
