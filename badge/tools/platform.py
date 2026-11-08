"""Platform tools every role has. (declare_plan is handled by the pipeline itself.)"""

from __future__ import annotations

from typing import Any

from badge.models import DeclarePlanArgs
from badge.plans import plan_progress
from badge.policy import list_tools_for_role
from badge.tasks import tasks_for_agent
from badge.tools.base import ToolContext


def list_my_tools(ctx: ToolContext) -> dict[str, Any]:
    tools = list_tools_for_role(ctx.runtime.config, ctx.badge.role)
    for tool in tools:
        if tool["name"] == "declare_plan":
            tool["args_schema"] = DeclarePlanArgs.model_json_schema()
    return {"tools": tools}


def get_my_status(ctx: ToolContext) -> dict[str, Any]:
    agent = ctx.conn.execute(
        "SELECT status FROM agents WHERE agent_id = ?", (ctx.badge.agent_id,)
    ).fetchone()
    tasks = [
        {"task_id": t.task_id, "resource_id": t.resource_id, "slot": t.slot, "status": t.status}
        for t in tasks_for_agent(ctx.conn, ctx.badge.agent_id)
    ]
    return {
        "agent_id": ctx.badge.agent_id,
        "role": ctx.badge.role,
        "badge_id": ctx.badge.badge_id,
        "badge_expires_at_ms": int(ctx.badge.expires_at * 1000),
        "status": agent["status"],
        "tasks": tasks,
        "active_plans": plan_progress(ctx.conn, ctx.badge.agent_id),
    }
