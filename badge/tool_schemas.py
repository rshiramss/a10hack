"""Gateway tool listings -> JSON Schema, shared by the MCP endpoint and the LLM runners."""

from __future__ import annotations

from typing import Any

# declare_plan nests steps, so its schema is written out here instead of derived from args.
DECLARE_PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "task_id": {"type": "string", "description": "Your task_id from get_my_status."},
        "steps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string"},
                    "args": {
                        "type": "object",
                        "description": "Only the args marked bind_in_plan for that tool.",
                    },
                },
                "required": ["tool", "args"],
            },
        },
    },
    "required": ["task_id", "steps"],
}


def json_schema_for_arg(spec: dict[str, Any]) -> dict[str, Any]:
    kind = spec["type"]
    if kind == "enum":
        return {"type": "string", "enum": spec["values"]}
    if kind == "int":
        return {"type": "integer", "minimum": spec["min"], "maximum": spec["max"]}
    if kind == "bool":
        return {"type": "boolean"}
    schema: dict[str, Any] = {"type": "string"}
    if "pattern" in spec:
        schema["pattern"] = spec["pattern"]
    if "max_len" in spec:
        schema["maxLength"] = spec["max_len"]
    return schema


def input_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """JSON Schema for one entry of list_my_tools."""
    if tool["name"] == "declare_plan":
        return DECLARE_PLAN_SCHEMA
    return {
        "type": "object",
        "properties": {n: json_schema_for_arg(s) for n, s in tool["args"].items()},
        "required": [n for n, s in tool["args"].items() if not s["optional"]],
        "additionalProperties": False,
    }


def description(tool: dict[str, Any]) -> str:
    """Tool description plus a hint about which args a plan step must bind."""
    bound = [n for n, s in tool["args"].items() if s.get("bind_in_plan")]
    text = tool["description"]
    if bound:
        text += f" Plan steps for this tool bind: {', '.join(bound)}."
    return text
