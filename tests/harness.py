"""Test harness: a seeded database, a frozen clock, and helpers that call the pipeline
directly (the same code path the HTTP server uses)."""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from badge import db
from badge.clock import FrozenClock
from badge.config import load_config
from badge.context import CallRequest, Runtime
from badge.orchestrator import (
    adjudicator_task_id,
    assessor_task_id,
    assign,
    create_visit_tasks,
    enroll_agent,
    pharmacist_task_id,
)
from badge.pipeline import CallResult, handle_call
from scripts.seed import seed

TEST_SIGNING_KEY = "test-signing-key-that-is-long-enough-0123456789"
DEFAULT_SCORES = {"pain_score": 4, "mobility_score": 6}


def new_key() -> str:
    return str(uuid.uuid4())


@dataclass
class Harness:
    conn: sqlite3.Connection
    runtime: Runtime
    clock: FrozenClock
    db_path: Path

    # ---- setup ---------------------------------------------------------------------

    def enroll(self, agent_id: str, role: str) -> str:
        return enroll_agent(self.conn, self.runtime, agent_id, role)

    def setup_visit(
        self,
        visit_id: str,
        *,
        pharmacist: str | None = None,
        slot1: str | None = None,
        slot2: str | None = None,
        adjudicator: str | None = None,
    ) -> None:
        create_visit_tasks(self.conn, self.runtime, [visit_id])
        if pharmacist:
            assign(self.conn, self.runtime, pharmacist_task_id(visit_id), pharmacist)
        if slot1:
            assign(self.conn, self.runtime, assessor_task_id(visit_id, 1), slot1)
        if slot2:
            assign(self.conn, self.runtime, assessor_task_id(visit_id, 2), slot2)
        if adjudicator:
            assign(self.conn, self.runtime, adjudicator_task_id(visit_id), adjudicator)

    def patient_for(self, visit_id: str) -> str:
        row = self.conn.execute(
            "SELECT patient_id FROM visits WHERE visit_id = ?", (visit_id,)
        ).fetchone()
        return row["patient_id"]

    def new_connection(self) -> sqlite3.Connection:
        return db.connect(self.db_path)

    # ---- calls ---------------------------------------------------------------------

    def call(
        self,
        token: str | None,
        tool: str,
        args: Any = None,
        key: str | None = None,
        conn: sqlite3.Connection | None = None,
    ) -> CallResult:
        request = CallRequest(
            token=token, tool=tool, args={} if args is None else args, idempotency_key=key
        )
        return handle_call(self.runtime, conn or self.conn, request)

    def mutate(self, token: str, tool: str, args: dict[str, Any]) -> CallResult:
        return self.call(token, tool, args, key=new_key())

    def declare(self, token: str, task_id: str, steps: list[tuple[str, dict]]) -> CallResult:
        return self.call(
            token,
            "declare_plan",
            {
                "task_id": task_id,
                "steps": [{"tool": tool, "args": args} for tool, args in steps],
            },
        )

    # ---- honest flows --------------------------------------------------------------

    def dispense(self, token: str, visit_id: str) -> CallResult:
        args = {"patient_id": self.patient_for(visit_id), "visit_id": visit_id}
        plan = self.declare(
            token, pharmacist_task_id(visit_id), [("get_assignment", args), ("dispense_kit", args)]
        )
        assert plan.allowed, plan
        assert self.call(token, "get_assignment", args).allowed
        result = self.mutate(token, "dispense_kit", args)
        assert result.allowed, result
        return result

    def assessor_steps(self, visit_id: str, scores: dict[str, int]) -> list[tuple[str, dict]]:
        steps = [("open_patient_visit", {"visit_id": visit_id})]
        steps += [("record_outcome", {"visit_id": visit_id, "measure": m}) for m in scores]
        steps.append(("submit", {"visit_id": visit_id}))
        return steps

    def assess(
        self,
        token: str,
        visit_id: str,
        slot: int,
        scores: dict[str, int] | None = None,
        notes: str | None = None,
    ) -> CallResult:
        """Honest assessor: plan, open, record each score, submit. Returns the submit result."""
        scores = scores or DEFAULT_SCORES
        plan = self.declare(
            token, assessor_task_id(visit_id, slot), self.assessor_steps(visit_id, scores)
        )
        assert plan.allowed, plan
        assert self.call(token, "open_patient_visit", {"visit_id": visit_id}).allowed
        for measure, value in scores.items():
            args = {"visit_id": visit_id, "measure": measure, "value": value}
            if notes is not None:
                args["notes"] = notes
            recorded = self.mutate(token, "record_outcome", args)
            assert recorded.allowed, recorded
        return self.mutate(token, "submit", {"visit_id": visit_id})

    # ---- inspection ----------------------------------------------------------------

    def audit_rows(self, **filters: Any) -> list[sqlite3.Row]:
        where = " AND ".join(f"{column} = ?" for column in filters) or "1 = 1"
        return self.conn.execute(
            f"SELECT * FROM audit_log WHERE {where} ORDER BY seq", tuple(filters.values())
        ).fetchall()

    def agent_status(self, agent_id: str) -> str:
        row = self.conn.execute(
            "SELECT status FROM agents WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return row["status"]

    def count(self, sql: str, *params: Any) -> int:
        return self.conn.execute(sql, params).fetchone()[0]


def build_harness(tmp_path: Path) -> Harness:
    db_path = tmp_path / "badge.db"
    conn = db.connect(db_path)
    db.migrate(conn)
    seed(conn)
    clock = FrozenClock()
    runtime = Runtime(config=load_config(), clock=clock, signing_key=TEST_SIGNING_KEY)
    return Harness(conn=conn, runtime=runtime, clock=clock, db_path=db_path)
