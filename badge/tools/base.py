"""What a tool implementation receives. Tools run only after every check has passed,
inside the execute transaction. A tool refuses by raising DeniedError."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from badge.context import BadgeInfo, Lease, Runtime, Task


@dataclass(frozen=True)
class ToolContext:
    conn: sqlite3.Connection
    runtime: Runtime
    now: float
    badge: BadgeInfo
    args: dict[str, Any]
    task: Task | None = None
    lease: Lease | None = None
    handoff_inputs: dict[str, Any] = field(default_factory=dict)
    arm_term_hits: int = 0


ToolFunction = Callable[[ToolContext], dict[str, Any]]
