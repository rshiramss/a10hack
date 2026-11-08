"""Role allowlists and filtered tool listings."""

from __future__ import annotations

from typing import Any

from badge import reasons
from badge.config import ArgSpec, TrialConfig
from badge.context import CallContext
from badge.decisions import Action, Allow, Decision, Deny


def check_role(ctx: CallContext) -> Decision:
    """Pipeline step 2: the tool must be on the badge role's allowlist.

    Calling anything else (another role's tool, or a tool that doesn't exist) is treated
    as exploitation and revokes the badge.
    """
    # DECISION: unknown tool names are handled exactly like another role's tools
    # (deny + revoke). A tool outside the role's list "doesn't exist" for that agent, and
    # probing for tools is the behavior this check exists to catch.
    allowed = ctx.config.tools_for_role(ctx.badge.role)
    if ctx.request.tool not in allowed:
        return Deny(
            reasons.DENY_ROLE_FORBIDDEN,
            Action.REVOKE,
            detail=f"role {ctx.badge.role} may not call this tool",
        )
    return Allow({"tool_spec": ctx.config.tool(ctx.request.tool)})


def describe_arg(spec: ArgSpec) -> dict[str, Any]:
    """Public description of one argument, for tool listings."""
    described: dict[str, Any] = {"type": spec.type, "optional": spec.optional}
    for key in ("pattern", "values", "min", "max", "max_len"):
        value = getattr(spec, key)
        if value is not None:
            described[key] = value
    if spec.bind:
        described["bind_in_plan"] = True
    if spec.plan_wildcard:
        described["plan_wildcard"] = True
    return described


def list_tools_for_role(config: TrialConfig, role: str) -> list[dict[str, Any]]:
    """Only the tools this role may call. Other roles' tools never appear."""
    listing = []
    for name in config.tools_for_role(role):
        spec = config.tool(name)
        listing.append(
            {
                "name": name,
                "description": spec.description,
                "planned": spec.planned,
                "mutating": spec.mutating,
                "single_use": spec.single_use,
                "args": {arg: describe_arg(arg_spec) for arg, arg_spec in spec.args.items()},
            }
        )
    return listing
