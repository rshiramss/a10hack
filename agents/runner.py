"""LLM agent loop (Claude tool use) that works only through the gateway.

On start: list_my_tools -> the model checks status, declares a plan, executes, stops.
Deny reasons go back to the model as tool results. The system prompt describes the job
only; it carries no security rules, because safety must not depend on the agent behaving.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.client import GatewayClient

DEFAULT_MODEL = "claude-sonnet-5-5"
MAX_TOKENS = 1024
MAX_TURNS = 14
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
HIDDEN_FROM_MODEL = {"list_my_tools"}  # the runner already called it
KICKOFF = "Your badge is active. Begin your work."

# declare_plan nests steps, so its schema is written out here instead of derived from args.
DECLARE_PLAN_SCHEMA = {
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


@dataclass
class ToolCallRecord:
    tool: str
    args: dict[str, Any]
    response: dict[str, Any]
    idempotency_key: str | None = None


@dataclass
class AgentTranscript:
    calls: list[ToolCallRecord] = field(default_factory=list)
    final_text: str = ""

    def called(self, tool: str) -> bool:
        return any(record.tool == tool for record in self.calls)


def _json_schema_for_arg(spec: dict[str, Any]) -> dict[str, Any]:
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


def to_anthropic_tools(listing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Gateway tool listing -> Claude tool definitions."""
    tools = []
    for tool in listing:
        if tool["name"] in HIDDEN_FROM_MODEL:
            continue
        if tool["name"] == "declare_plan":
            schema = DECLARE_PLAN_SCHEMA
        else:
            schema = {
                "type": "object",
                "properties": {n: _json_schema_for_arg(s) for n, s in tool["args"].items()},
                "required": [n for n, s in tool["args"].items() if not s["optional"]],
            }
        bound = [n for n, s in tool["args"].items() if s.get("bind_in_plan")]
        description = tool["description"]
        if bound:
            description += f" Plan steps for this tool bind: {', '.join(bound)}."
        tools.append({"name": tool["name"], "description": description, "input_schema": schema})
    return tools


def _execute_tool_use(
    client: GatewayClient,
    name: str,
    tool_input: dict[str, Any],
    mutating: set[str],
    tool_use_id: str,
) -> ToolCallRecord:
    if name == "declare_plan":
        steps = [(s.get("tool", ""), s.get("args", {})) for s in tool_input.get("steps", [])]
        response = client.declare_plan(str(tool_input.get("task_id", "")), steps)
        return ToolCallRecord(name, tool_input, response)
    # Derive the key from the tool_use id so a retried turn replays instead of re-running.
    key = str(uuid.uuid5(uuid.NAMESPACE_URL, tool_use_id)) if name in mutating else None
    response = client.call(name, tool_input, key=key)
    return ToolCallRecord(name, tool_input, response, key)


def run_llm_agent(
    client: GatewayClient,
    role: str,
    anthropic_client: Any | None = None,
    model: str | None = None,
    max_turns: int = MAX_TURNS,
) -> AgentTranscript:
    """Drive one Claude agent until it stops calling tools (or hits max_turns)."""
    if anthropic_client is None:
        import anthropic

        anthropic_client = anthropic.Anthropic()
    model = model or os.environ.get("BADGE_MODEL", DEFAULT_MODEL)
    listing = client.list_my_tools().get("result", {}).get("tools", [])
    tools = to_anthropic_tools(listing)
    mutating = {tool["name"] for tool in listing if tool["mutating"]}
    system = (PROMPTS_DIR / f"{role}.md").read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = [{"role": "user", "content": KICKOFF}]
    transcript = AgentTranscript()

    for _ in range(max_turns):
        reply = anthropic_client.messages.create(
            model=model,
            max_tokens=MAX_TOKENS,
            system=system,
            tools=tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": reply.content})
        tool_uses = [block for block in reply.content if block.type == "tool_use"]
        if reply.stop_reason != "tool_use" or not tool_uses:
            transcript.final_text = " ".join(
                block.text for block in reply.content if block.type == "text"
            )
            break
        results = []
        for block in tool_uses:
            record = _execute_tool_use(client, block.name, dict(block.input), mutating, block.id)
            transcript.calls.append(record)
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": json.dumps(record.response),
                    "is_error": not record.response.get("ok"),
                }
            )
        messages.append({"role": "user", "content": results})
    return transcript
