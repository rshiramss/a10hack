"""The values every check returns: Allow, Deny, or Replay.

A check is a small function `check_x(ctx) -> Decision`. The pipeline runs checks in a
fixed order, stops at the first Deny, and applies that Deny's action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Action(IntEnum):
    """What the gateway does to the caller on a denial. Higher value = stronger."""

    NONE = 0
    EXPIRE_PLAN = 1
    SUSPEND = 2
    REVOKE = 3

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Allow:
    """Check passed. `updates` are fields the pipeline copies onto the call context."""

    updates: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Deny:
    reason: str
    action: Action = Action.NONE
    detail: str = ""
    # Extra effects some denials carry, applied in the same transaction as the audit entry.
    return_task_id: str | None = None
    alert: str | None = None
    # The plan an EXPIRE_PLAN action targets, when it isn't the call's own plan.
    plan_id: str | None = None


@dataclass(frozen=True)
class Replay:
    """An idempotent replay: return the stored result without running the tool again."""

    result: dict[str, Any]


Decision = Allow | Deny | Replay


class DeniedError(Exception):
    """Raised inside a transaction to abort it and turn into a Deny after rollback."""

    def __init__(self, deny: Deny) -> None:
        super().__init__(deny.reason)
        self.deny = deny
