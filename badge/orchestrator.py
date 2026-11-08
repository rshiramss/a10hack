"""Orchestrator helpers: the only code that registers agents, issues badges, and creates or
assigns tasks. Agents never call these; demo scripts and tests do."""

from __future__ import annotations

import sqlite3

from badge import identity, leases, tasks
from badge.context import Runtime
from badge.db import write_tx

ASSESSOR_SLOTS = (1, 2)


def pharmacist_task_id(visit_id: str) -> str:
    return f"T-PH-{visit_id}"


def assessor_task_id(visit_id: str, slot: int) -> str:
    return f"T-AS-{visit_id}-s{slot}"


def adjudicator_task_id(visit_id: str) -> str:
    return f"T-AD-{visit_id}"


def enroll_agent(conn: sqlite3.Connection, runtime: Runtime, agent_id: str, role: str) -> str:
    """Register an agent and issue its first badge. Returns the badge token."""
    with write_tx(conn):
        identity.register_agent(conn, runtime, agent_id, role)
        return identity.issue_badge(conn, runtime, agent_id)


def reissue_badge(conn: sqlite3.Connection, runtime: Runtime, agent_id: str) -> str:
    with write_tx(conn):
        return identity.issue_badge(conn, runtime, agent_id)


def create_visit_tasks(conn: sqlite3.Connection, runtime: Runtime, visit_ids: list[str]) -> None:
    """One pharmacist task, two assessor read tasks, and one adjudicator task per visit."""
    now = runtime.clock.now()
    with write_tx(conn):
        for visit_id in visit_ids:
            tasks.create_task(conn, now, pharmacist_task_id(visit_id), "pharmacist", visit_id)
            for slot in ASSESSOR_SLOTS:
                tasks.create_task(
                    conn, now, assessor_task_id(visit_id, slot), "assessor", visit_id, slot
                )
            tasks.create_task(conn, now, adjudicator_task_id(visit_id), "adjudicator", visit_id)


def assign(conn: sqlite3.Connection, runtime: Runtime, task_id: str, agent_id: str) -> None:
    """Assign one task. Raises tasks.OrchestratorError if the assignment is refused."""
    with write_tx(conn):
        tasks.assign_task(conn, runtime, task_id, agent_id)


def reassign_pool(conn: sqlite3.Connection, runtime: Runtime, role: str) -> list[tuple[str, str]]:
    """Expire stale plans, then hand open tasks of `role` to eligible agents."""
    with write_tx(conn):
        leases.expire_stale(conn, runtime.clock.now())
        return tasks.reassign_open_tasks(conn, runtime, role)
