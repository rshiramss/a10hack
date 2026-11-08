"""Shared value types passed through the check pipeline."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any

from badge.clock import Clock
from badge.config import ToolSpec, TrialConfig

MIN_SIGNING_KEY_LEN = 32


@dataclass(frozen=True)
class Runtime:
    """Everything a decision depends on besides the database and the request."""

    config: TrialConfig
    clock: Clock
    signing_key: str

    def __post_init__(self) -> None:
        if len(self.signing_key) < MIN_SIGNING_KEY_LEN:
            raise ValueError(f"BADGE_SIGNING_KEY must be at least {MIN_SIGNING_KEY_LEN} chars")


@dataclass(frozen=True)
class CallRequest:
    token: str | None
    tool: str
    args: Any
    idempotency_key: str | None = None


@dataclass(frozen=True)
class BadgeInfo:
    agent_id: str
    badge_id: str
    role: str
    expires_at: float


@dataclass(frozen=True)
class Task:
    task_id: str
    role: str
    agent_id: str | None
    resource_id: str
    slot: int
    status: str


@dataclass(frozen=True)
class Plan:
    plan_id: str
    task_id: str
    agent_id: str
    badge_id: str
    status: str
    expires_at_ms: int


@dataclass(frozen=True)
class Lease:
    lease_id: str
    plan_id: str | None
    step_index: int
    agent_id: str
    tool: str
    bound_args: dict[str, Any]
    max_uses: int
    uses: int
    status: str
    expires_at_ms: int


@dataclass(frozen=True)
class CallContext:
    """One gateway call. Checks read it; the pipeline adds fields as checks pass."""

    runtime: Runtime
    conn: sqlite3.Connection
    request: CallRequest
    now: float
    badge: BadgeInfo | None = None
    tool_spec: ToolSpec | None = None
    task: Task | None = None
    plan: Plan | None = None
    lease: Lease | None = None
    args: dict[str, Any] | None = None  # set once the input schema check passes
    transition: tuple[str, str] | None = None  # (from_state, to_state)
    handoff_inputs: dict[str, Any] = field(default_factory=dict)
    arm_term_hits: int = 0

    @property
    def config(self) -> TrialConfig:
        return self.runtime.config

    @property
    def raw_args(self) -> dict[str, Any]:
        """The request args if they are a dict, else empty (schema check denies later)."""
        return self.request.args if isinstance(self.request.args, dict) else {}
