"""Revocation, suspension, and outcome flagging (section 9.2).

Revocation is per agent, never a global stop: other agents keep working untouched.
Every function here runs inside the caller's write transaction, so a revocation's five
effects land together or not at all.
"""

from __future__ import annotations

import sqlite3

from badge import reasons
from badge.audit import AuditEntry, append
from badge.clock import to_ms
from badge.context import Runtime
from badge.ids import new_uuid
from badge.leases import end_active_plans, revoke_standing_leases
from badge.tasks import return_to_pool


def flag_outcome(
    conn: sqlite3.Connection, now: float, outcome_id: str, reason: str, actor: str
) -> bool:
    """Add a flag (never a mutation). Returns False if that flag already existed."""
    cursor = conn.execute(
        "INSERT OR IGNORE INTO outcome_flags (flag_id, outcome_id, reason, actor, created_at_ms)"
        " VALUES (?, ?, ?, ?, ?)",
        (new_uuid(), outcome_id, reason, actor, to_ms(now)),
    )
    return cursor.rowcount == 1


def flag_agent_outcomes(
    conn: sqlite3.Connection, now: float, agent_id: str, reason: str, actor: str
) -> int:
    """Flag every outcome row the agent ever wrote. Returns how many new flags were added.

    DECISION: "every outcome the agent ever submitted" is read as every outcome row it wrote,
    drafts and superseded rows included, which is the more restrictive reading.
    """
    rows = conn.execute("SELECT outcome_id FROM outcomes WHERE agent_id = ?", (agent_id,))
    return sum(flag_outcome(conn, now, row["outcome_id"], reason, actor) for row in rows.fetchall())


def flag_patient_outcomes(
    conn: sqlite3.Connection, now: float, patient_id: str, reason: str, actor: str
) -> int:
    rows = conn.execute(
        "SELECT o.outcome_id FROM outcomes o JOIN visits v ON v.visit_id = o.visit_id"
        " WHERE v.patient_id = ?",
        (patient_id,),
    ).fetchall()
    return sum(flag_outcome(conn, now, row["outcome_id"], reason, actor) for row in rows)


def revoke_agent(
    conn: sqlite3.Connection, runtime: Runtime, agent_id: str, trigger: str, actor: str
) -> int:
    """Revoke every badge the agent holds and contain the damage. Returns badges revoked.

    1. Add the agent's badges to `revocations` (checked on every call).
    2. Revoke its active leases and release its resource holds.
    3. Flag every outcome it ever wrote (flagged rows drop out of analysis, never deleted).
    4. Return its unfinished tasks to the pool.
    5. Write a high-severity REVOKE audit entry.
    """
    now = runtime.clock.now()
    agent = conn.execute("SELECT role FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    if agent is None:
        raise ValueError(f"unknown agent {agent_id!r}")
    badges = conn.execute(
        "SELECT b.badge_id FROM badges b LEFT JOIN revocations r ON r.badge_id = b.badge_id"
        " WHERE b.agent_id = ? AND r.badge_id IS NULL",
        (agent_id,),
    ).fetchall()
    for badge in badges:
        conn.execute(
            "INSERT INTO revocations (badge_id, agent_id, revoked_at_ms, trigger, actor)"
            " VALUES (?, ?, ?, ?, ?)",
            (badge["badge_id"], agent_id, to_ms(now), trigger, actor),
        )
    conn.execute("UPDATE agents SET status = 'revoked' WHERE agent_id = ?", (agent_id,))
    end_active_plans(conn, agent_id, None, "revoked", reasons.EVENT_REVOKE)
    revoke_standing_leases(conn, agent_id)
    flagged = flag_agent_outcomes(
        conn, now, agent_id, reasons.flag_reason_for_revoke(trigger), actor
    )
    open_tasks = conn.execute(
        "SELECT task_id FROM tasks WHERE agent_id = ? AND status = 'assigned'", (agent_id,)
    ).fetchall()
    for task in open_tasks:
        return_to_pool(conn, runtime, task["task_id"], why=f"agent revoked ({trigger})")
    append(
        conn,
        runtime.config,
        now,
        AuditEntry(
            agent_id=agent_id,
            badge_id=None,
            role=agent["role"],
            tool=None,
            args={"trigger": trigger, "actor": actor},
            decision="EVENT",
            reason=reasons.EVENT_REVOKE,
            action="revoke",
            severity="high",
            detail=(
                f"badges={len(badges)} outcomes_flagged={flagged} tasks_returned={len(open_tasks)}"
            ),
        ),
    )
    return len(badges)


def suspend_agent(
    conn: sqlite3.Connection, runtime: Runtime, agent_id: str, trigger: str, actor: str
) -> None:
    """Suspend pending human review: badge stops working, plans end, tasks stay assigned.

    DECISION: unlike revocation, suspension doesn't flag outcomes or return tasks. A human
    reviews first; reassignment after a suspension is the orchestrator's call (section 7).
    """
    now = runtime.clock.now()
    agent = conn.execute(
        "SELECT role, status FROM agents WHERE agent_id = ?", (agent_id,)
    ).fetchone()
    if agent is None or agent["status"] != "active":
        return
    conn.execute("UPDATE agents SET status = 'suspended' WHERE agent_id = ?", (agent_id,))
    end_active_plans(conn, agent_id, None, "expired", reasons.EVENT_SUSPEND)
    append(
        conn,
        runtime.config,
        now,
        AuditEntry(
            agent_id=agent_id,
            badge_id=None,
            role=agent["role"],
            tool=None,
            args={"trigger": trigger, "actor": actor},
            decision="EVENT",
            reason=reasons.EVENT_SUSPEND,
            action="suspend",
            severity="high",
        ),
    )
