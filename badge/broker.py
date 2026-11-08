"""Brokered handoffs (section 6): typed values between agents, never free text.

Producers write through `publish` from inside their own tool. Consumers only see values
through their tool's precondition or injected input (`check_preconditions`). There is no
tool for reading handoffs. Values are validated on write and again on read.
"""

from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass
from typing import Any

from badge import reasons
from badge.clock import to_ms
from badge.config import ArgSpec, TrialConfig
from badge.context import BadgeInfo, CallContext
from badge.decisions import Allow, Decision, DeniedError, Deny
from badge.ids import new_uuid
from badge.jsonutil import canonical_json
from badge.state_machine import get_state, set_state

MAX_ID_LEN = 64


def field_problem(spec: ArgSpec, value: Any) -> str | None:
    """Why `value` doesn't fit `spec`, or None. Only typed scalars and enum-keyed maps pass."""
    if spec.type == "enum":
        ok = isinstance(value, str) and value in spec.values
    elif spec.type == "int":
        ok = type(value) is int and spec.min <= value <= spec.max
    elif spec.type == "bool":
        ok = type(value) is bool
    elif spec.type == "id":
        ok = (
            isinstance(value, str)
            and len(value) <= MAX_ID_LEN
            and re.fullmatch(spec.pattern, value) is not None
        )
    elif spec.type == "map":
        return _map_problem(spec, value)
    else:
        return f"type {spec.type!r} is never allowed in a handoff"
    return None if ok else f"value does not match {spec.type}"


def _map_problem(spec: ArgSpec, value: Any) -> str | None:
    if not isinstance(value, dict) or not value:
        return "expected a non-empty map"
    for key, item in value.items():
        if key not in spec.keys:
            return "map key outside the allowed enum"
        problem = field_problem(spec.value_spec, item)
        if problem:
            return f"map value: {problem}"
    return None


def value_problem(schema: dict[str, ArgSpec], value: Any) -> str | None:
    """Why a whole handoff value is invalid, or None. Every schema field is required."""
    if not isinstance(value, dict) or set(value) != set(schema):
        return "fields do not match the channel schema"
    for name, spec in schema.items():
        problem = field_problem(spec, value[name])
        if problem:
            return f"{name}: {problem}"
    return None


def publish(
    conn: sqlite3.Connection,
    config: TrialConfig,
    now: float,
    channel_id: str,
    resource_id: str,
    slot: int,
    value: Any,
    producer: BadgeInfo,
    producer_tool: str,
) -> None:
    """Validate and store a handoff value, then advance any workflow waiting on it.

    Runs inside the producer tool's transaction. An invalid value, or a producer that
    isn't the channel's declared producer, raises DeniedError carrying a monitor alert:
    the whole tool call rolls back and nothing is stored.
    """
    channel = config.handoffs[channel_id]
    if (producer.role, producer_tool) != (channel.producer.role, channel.producer.tool):
        raise DeniedError(
            Deny(
                reasons.DENY_SCHEMA,
                detail="not the channel's producer",
                alert=f"{channel_id}: write attempted by {producer.role}.{producer_tool}",
            )
        )
    problem = value_problem(channel.schema_, value)
    if problem:
        raise DeniedError(
            Deny(
                reasons.DENY_SCHEMA,
                detail="handoff value rejected",
                alert=f"{channel_id} {resource_id}/{slot}: rejected on write ({problem})",
            )
        )
    conn.execute(
        "INSERT INTO handoffs (handoff_id, channel, resource_id, slot, value_json,"
        " producer_agent_id, producer_badge_id, created_at_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            new_uuid(),
            channel_id,
            resource_id,
            slot,
            canonical_json(value),
            producer.agent_id,
            producer.badge_id,
            to_ms(now),
        ),
    )
    _advance_waiting_workflows(conn, config, now, channel_id, resource_id)


def _advance_waiting_workflows(
    conn: sqlite3.Connection, config: TrialConfig, now: float, channel_id: str, resource_id: str
) -> None:
    for workflow_name, workflow in config.workflows.items():
        rule = workflow.ready_when
        if rule is None or rule.channel != channel_id:
            continue
        consumer = config.handoffs[channel_id].consumer
        all_present = all(
            read(conn, config, channel_id, resource_id, slot, consumer.role, consumer.tool).value
            is not None
            for slot in rule.slots
        )
        current = get_state(conn, config, workflow_name, resource_id, 0)
        if all_present and current == rule.from_state:
            set_state(conn, now, workflow_name, resource_id, 0, rule.to)


@dataclass(frozen=True)
class ReadResult:
    value: dict[str, Any] | None
    problem: str | None = None
    alert: str | None = None  # set when the problem means tampering or a bug


def read(
    conn: sqlite3.Connection,
    config: TrialConfig,
    channel_id: str,
    resource_id: str,
    slot: int,
    consumer_role: str,
    consumer_tool: str,
) -> ReadResult:
    """Read and re-validate one handoff value for its declared consumer. Read-only."""
    channel = config.handoffs[channel_id]
    if (consumer_role, consumer_tool) != (channel.consumer.role, channel.consumer.tool):
        return ReadResult(
            None,
            "not the channel's consumer",
            alert=f"{channel_id}: read attempted by {consumer_role}.{consumer_tool}",
        )
    row = conn.execute(
        "SELECT h.value_json, h.producer_badge_id, r.badge_id AS revoked"
        " FROM handoffs h LEFT JOIN revocations r ON r.badge_id = h.producer_badge_id"
        " WHERE h.channel = ? AND h.resource_id = ? AND h.slot = ?",
        (channel_id, resource_id, slot),
    ).fetchone()
    if row is None:
        return ReadResult(None, f"{channel_id} not yet available")
    if row["revoked"] is not None:
        return ReadResult(None, f"{channel_id} came from a revoked badge")
    try:
        value = json.loads(row["value_json"])
    except json.JSONDecodeError:
        value = None
    problem = value_problem(channel.schema_, value)
    if problem:
        return ReadResult(
            None,
            "stored value is invalid",
            alert=f"{channel_id} {resource_id}/{slot}: rejected on read ({problem})",
        )
    return ReadResult(value)


def _input_slots(config: TrialConfig, workflow_name: str, channel_id: str) -> list[int]:
    rule = config.workflows[workflow_name].ready_when
    if config.handoffs[channel_id].slotted and rule is not None and rule.channel == channel_id:
        return list(rule.slots)
    return [0]


def check_preconditions(ctx: CallContext) -> Decision:
    """Pipeline step 7: required handoff values exist, validate, and meet conditions."""
    spec, task = ctx.tool_spec, ctx.task
    role, tool = ctx.badge.role, ctx.request.tool
    for condition in spec.preconditions:
        slot = task.slot if ctx.config.handoffs[condition.channel].slotted else 0
        result = read(ctx.conn, ctx.config, condition.channel, task.resource_id, slot, role, tool)
        if result.value is None:
            return Deny(reasons.DENY_PRECONDITION, detail=result.problem or "", alert=result.alert)
        if result.value.get(condition.field) != condition.equals:
            return Deny(reasons.DENY_PRECONDITION, detail=f"{condition.channel} not satisfied")
    inputs: dict[str, Any] = {}
    for channel_id in spec.inputs:
        values = {}
        for slot in _input_slots(ctx.config, spec.workflow, channel_id):
            result = read(ctx.conn, ctx.config, channel_id, task.resource_id, slot, role, tool)
            if result.value is None:
                return Deny(
                    reasons.DENY_PRECONDITION, detail=result.problem or "", alert=result.alert
                )
            values[slot] = result.value
        inputs[channel_id] = values
    return Allow({"handoff_inputs": inputs})
