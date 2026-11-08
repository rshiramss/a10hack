"""SQLite connection, schema migration, and transaction helpers.

Connections run in autocommit mode (`isolation_level=None`) so every write happens inside
an explicit `write_tx` block that starts with `BEGIN IMMEDIATE`. That takes the database
write lock up front, which serializes writers and makes the race tests deterministic.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
BUSY_TIMEOUT_MS = 10_000

_APPEND_ONLY_TABLES = ("audit_log", "outcomes", "outcome_flags", "submissions")

SCHEMA_SQL = """
CREATE TABLE agents (
    agent_id      TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE badges (
    badge_id      TEXT PRIMARY KEY,
    agent_id      TEXT NOT NULL REFERENCES agents(agent_id),
    role          TEXT NOT NULL,
    issued_at_ms  INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);

CREATE TABLE revocations (
    badge_id      TEXT PRIMARY KEY REFERENCES badges(badge_id),
    agent_id      TEXT NOT NULL,
    revoked_at_ms INTEGER NOT NULL,
    trigger       TEXT NOT NULL,
    actor         TEXT NOT NULL
);

CREATE TABLE patients (
    patient_id TEXT PRIMARY KEY,
    is_decoy   INTEGER NOT NULL DEFAULT 0
);

-- Unblinded data. Only the pharmacist's get_assignment tool reads it.
CREATE TABLE assignments (
    patient_id TEXT PRIMARY KEY REFERENCES patients(patient_id),
    arm        TEXT NOT NULL CHECK (arm IN ('active', 'placebo')),
    canary     TEXT NOT NULL
);

CREATE TABLE visits (
    visit_id   TEXT PRIMARY KEY,
    patient_id TEXT NOT NULL REFERENCES patients(patient_id),
    visit_no   INTEGER NOT NULL,
    note       TEXT NOT NULL,
    is_decoy   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE tasks (
    task_id       TEXT PRIMARY KEY,
    role          TEXT NOT NULL,
    agent_id      TEXT REFERENCES agents(agent_id),
    resource_id   TEXT NOT NULL,
    slot          INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL CHECK (status IN ('open', 'assigned', 'done')),
    created_at_ms INTEGER NOT NULL,
    UNIQUE (role, resource_id, slot)
);
-- Independence backstop: one agent can never hold two tasks (e.g. both read slots)
-- for the same resource.
CREATE UNIQUE INDEX ux_tasks_agent_resource
    ON tasks(role, resource_id, agent_id) WHERE agent_id IS NOT NULL;

CREATE TABLE plans (
    plan_id       TEXT PRIMARY KEY,
    task_id       TEXT NOT NULL REFERENCES tasks(task_id),
    agent_id      TEXT NOT NULL,
    badge_id      TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'completed', 'expired', 'revoked')),
    end_reason    TEXT,
    steps_json    TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_plans_one_active_per_task ON plans(task_id) WHERE status = 'active';

CREATE TABLE leases (
    lease_id        TEXT PRIMARY KEY,
    plan_id         TEXT REFERENCES plans(plan_id),  -- NULL for standing (emergency) leases
    step_index      INTEGER NOT NULL,
    agent_id        TEXT NOT NULL,
    badge_id        TEXT NOT NULL,
    tool            TEXT NOT NULL,
    bound_args_json TEXT NOT NULL,
    max_uses        INTEGER NOT NULL,
    uses            INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL CHECK (status IN ('active', 'used', 'expired', 'revoked')),
    created_at_ms   INTEGER NOT NULL,
    expires_at_ms   INTEGER NOT NULL
);
CREATE INDEX ix_leases_plan ON leases(plan_id, step_index);

CREATE TABLE slot_holds (
    hold_id       TEXT PRIMARY KEY,
    visit_id      TEXT NOT NULL,
    slot          INTEGER NOT NULL,
    plan_id       TEXT NOT NULL REFERENCES plans(plan_id),
    agent_id      TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('active', 'released')),
    created_at_ms INTEGER NOT NULL
);
CREATE UNIQUE INDEX ux_slot_holds_active ON slot_holds(visit_id, slot) WHERE status = 'active';

CREATE TABLE workflow_state (
    workflow      TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    slot          INTEGER NOT NULL,
    state         TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (workflow, resource_id, slot)
);

-- Append-only. A correction is a new row with supersedes_id.
CREATE TABLE outcomes (
    outcome_id    TEXT PRIMARY KEY,
    visit_id      TEXT NOT NULL,
    slot          INTEGER NOT NULL,
    measure       TEXT NOT NULL,
    value         INTEGER NOT NULL CHECK (value BETWEEN 0 AND 10),
    notes         TEXT,
    agent_id      TEXT NOT NULL,
    badge_id      TEXT NOT NULL,
    supersedes_id TEXT REFERENCES outcomes(outcome_id),
    created_at_ms INTEGER NOT NULL
);

-- A submission row is what "final" means for a (visit, slot).
CREATE TABLE submissions (
    submission_id TEXT PRIMARY KEY,
    visit_id      TEXT NOT NULL,
    slot          INTEGER NOT NULL,
    agent_id      TEXT NOT NULL,
    badge_id      TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (visit_id, slot)
);

CREATE TABLE outcome_flags (
    flag_id       TEXT PRIMARY KEY,
    outcome_id    TEXT NOT NULL REFERENCES outcomes(outcome_id),
    reason        TEXT NOT NULL,
    actor         TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    UNIQUE (outcome_id, reason)
);

CREATE TABLE dispensations (
    dispensation_id TEXT PRIMARY KEY,
    patient_id      TEXT NOT NULL,
    visit_id        TEXT NOT NULL,
    kit_id          TEXT NOT NULL UNIQUE,
    agent_id        TEXT NOT NULL,
    badge_id        TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    UNIQUE (patient_id, visit_id)
);

CREATE TABLE handoffs (
    handoff_id        TEXT PRIMARY KEY,
    channel           TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    slot              INTEGER NOT NULL,
    value_json        TEXT NOT NULL,
    producer_agent_id TEXT NOT NULL,
    producer_badge_id TEXT NOT NULL,
    created_at_ms     INTEGER NOT NULL,
    UNIQUE (channel, resource_id, slot)
);

CREATE TABLE comparisons (
    visit_id      TEXT PRIMARY KEY,
    result        TEXT NOT NULL CHECK (result IN ('agree', 'disagree')),
    max_delta     INTEGER NOT NULL,
    agent_id      TEXT NOT NULL,
    badge_id      TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE idempotency_keys (
    idempotency_key TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    tool            TEXT NOT NULL,
    args_hash       TEXT NOT NULL,
    result_json     TEXT NOT NULL,
    created_at_ms   INTEGER NOT NULL
);

CREATE TABLE alerts (
    alert_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at_ms INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    detail        TEXT NOT NULL,
    agent_id      TEXT
);

CREATE TABLE unblind_requests (
    request_id     TEXT PRIMARY KEY,
    patient_id     TEXT NOT NULL REFERENCES patients(patient_id),
    reason         TEXT NOT NULL,
    requested_by   TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('pending', 'approved')),
    approved_by    TEXT,
    created_at_ms  INTEGER NOT NULL,
    approved_at_ms INTEGER
);

-- Tamper-evident: hash = sha256(prev_hash + canonical_json(entry_without_hash)).
CREATE TABLE audit_log (
    seq        INTEGER PRIMARY KEY,
    ts_ms      INTEGER NOT NULL,
    agent_id   TEXT,
    badge_id   TEXT,
    role       TEXT,
    tool       TEXT,
    args_json  TEXT NOT NULL,
    decision   TEXT NOT NULL CHECK (decision IN ('ALLOW', 'DENY', 'EVENT')),
    reason     TEXT NOT NULL,
    action     TEXT NOT NULL,
    severity   TEXT NOT NULL,
    detail     TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX ix_audit_agent_ts ON audit_log(agent_id, ts_ms);

-- Analysis view: final, unsuperseded, unflagged outcomes only.
CREATE VIEW analysis_outcomes AS
SELECT o.*
FROM outcomes o
JOIN submissions s
  ON s.visit_id = o.visit_id AND s.slot = o.slot AND s.agent_id = o.agent_id
WHERE NOT EXISTS (SELECT 1 FROM outcomes newer WHERE newer.supersedes_id = o.outcome_id)
  AND NOT EXISTS (SELECT 1 FROM outcome_flags f WHERE f.outcome_id = o.outcome_id);
"""


def _append_only_triggers() -> str:
    statements = []
    for table in _APPEND_ONLY_TABLES:
        for operation in ("UPDATE", "DELETE"):
            statements.append(
                f"CREATE TRIGGER trg_{table}_no_{operation.lower()} "
                f"BEFORE {operation} ON {table} "
                f"BEGIN SELECT RAISE(ABORT, '{table} is append-only'); END;"
            )
    return "\n".join(statements)


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open a connection configured for explicit transactions, WAL, and foreign keys."""
    conn = sqlite3.connect(
        str(db_path),
        isolation_level=None,
        timeout=BUSY_TIMEOUT_MS / 1000,
        check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Create the schema if the database is new. Idempotent."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version >= SCHEMA_VERSION:
        return
    conn.executescript(
        "BEGIN IMMEDIATE;\n"
        + SCHEMA_SQL
        + _append_only_triggers()
        + f"\nPRAGMA user_version = {SCHEMA_VERSION};\nCOMMIT;"
    )


@contextmanager
def write_tx(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block in one `BEGIN IMMEDIATE` transaction. Any exception rolls back.

    Do not nest: functions documented as "runs inside the caller's transaction"
    expect to be called within one of these blocks.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def in_transaction(conn: sqlite3.Connection) -> bool:
    return conn.in_transaction
