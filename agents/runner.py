"""LLM agent loops that work only through the gateway.

Two backends, picked by BADGE_LLM_PROVIDER (see `run_agent`):
  ollama     (default) a small local model through Ollama's OpenAI-compatible API
  openai     any OpenAI-compatible endpoint (Groq, LM Studio, vLLM, OpenAI) via
             BADGE_LLM_BASE_URL + BADGE_LLM_API_KEY
  anthropic  Claude via ANTHROPIC_API_KEY


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
from badge import tool_schemas

DEFAULT_MODEL = "claude-sonnet-5-5"  # anthropic backend
DEFAULT_LOCAL_MODEL = "qwen2.5:3b"  # small, fast, solid at tool calls
OLLAMA_BASE_URL = "http://localhost:11434/v1"
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_GROQ_MODEL = "llama-3.3-70b-versatile"
MAX_TOKENS = 1024
MAX_TURNS = 14
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
HIDDEN_FROM_MODEL = {"list_my_tools"}  # the runner already called it
KICKOFF = "Your badge is active. Begin your work."


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


def to_anthropic_tools(listing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Gateway tool listing -> Claude tool definitions."""
    return [
        {
            "name": tool["name"],
            "description": tool_schemas.description(tool),
            "input_schema": tool_schemas.input_schema(tool),
        }
        for tool in listing
        if tool["name"] not in HIDDEN_FROM_MODEL
    ]


def to_openai_tools(listing: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Gateway tool listing -> OpenAI-style function tools (Ollama, Groq, LM Studio...)."""
    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool_schemas.description(tool),
                "parameters": tool_schemas.input_schema(tool),
            },
        }
        for tool in listing
        if tool["name"] not in HIDDEN_FROM_MODEL
    ]


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
    model = model or os.environ.get("BADGE_MODEL") or DEFAULT_MODEL
    # A denied listing (e.g. the badge is already revoked) leaves the model no tools.
    listing = (client.list_my_tools().get("result") or {}).get("tools", [])
    tools = to_anthropic_tools(listing)
    if not tools:
        return AgentTranscript(final_text="no tools available for this badge")
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


# ---- OpenAI-compatible backend (Ollama by default) ----------------------------------


def llm_settings() -> tuple[str, str, str, str]:
    """(provider, base_url, api_key, model) from the environment."""
    # Groq is optional: setting GROQ_API_KEY switches to it unless a provider is named.
    default = "groq" if os.environ.get("GROQ_API_KEY") else "ollama"
    provider = (os.environ.get("BADGE_LLM_PROVIDER") or default).strip().lower()
    if provider == "anthropic":
        return provider, "", "", os.environ.get("BADGE_MODEL") or DEFAULT_MODEL
    if provider == "groq":
        key = os.environ.get("GROQ_API_KEY") or os.environ.get("BADGE_LLM_API_KEY") or ""
        model = os.environ.get("BADGE_MODEL") or DEFAULT_GROQ_MODEL
        return provider, os.environ.get("BADGE_LLM_BASE_URL") or GROQ_BASE_URL, key, model
    base_url = os.environ.get("BADGE_LLM_BASE_URL") or OLLAMA_BASE_URL
    api_key = os.environ.get("BADGE_LLM_API_KEY") or "ollama"  # Ollama ignores the key
    model = os.environ.get("BADGE_MODEL") or DEFAULT_LOCAL_MODEL
    return provider, base_url, api_key, model


def run_openai_agent(
    client: GatewayClient,
    role: str,
    openai_client: Any | None = None,
    model: str | None = None,
    max_turns: int = MAX_TURNS,
) -> AgentTranscript:
    """Drive one agent through an OpenAI-compatible chat API with tool calling."""
    _, base_url, api_key, default_model = llm_settings()
    if openai_client is None:
        from openai import OpenAI

        openai_client = OpenAI(base_url=base_url, api_key=api_key, timeout=60)
    model = model or default_model
    # A denied listing (e.g. the badge is already revoked) leaves the model no tools.
    listing = (client.list_my_tools().get("result") or {}).get("tools", [])
    tools = to_openai_tools(listing)
    if not tools:
        return AgentTranscript(final_text="no tools available for this badge")
    mutating = {tool["name"] for tool in listing if tool["mutating"]}
    system = (PROMPTS_DIR / f"{role}.md").read_text(encoding="utf-8")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": KICKOFF},
    ]
    transcript = AgentTranscript()

    for _ in range(max_turns):
        reply = openai_client.chat.completions.create(
            model=model,
            messages=messages,
            tools=tools,
            temperature=0,
            max_tokens=MAX_TOKENS,
        )
        message = reply.choices[0].message
        tool_calls = list(message.tool_calls or [])
        messages.append(
            {
                "role": "assistant",
                "content": message.content or "",
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.function.name,
                            "arguments": call.function.arguments or "{}",
                        },
                    }
                    for call in tool_calls
                ],
            }
            if tool_calls
            else {"role": "assistant", "content": message.content or ""}
        )
        if not tool_calls:
            transcript.final_text = message.content or ""
            break
        for call in tool_calls:
            try:
                tool_input = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                tool_input = {}
            if not isinstance(tool_input, dict):
                tool_input = {}
            # Small models sometimes return a tool call with no id; give it a stable one.
            call_id = call.id or str(uuid.uuid4())
            record = _execute_tool_use(client, call.function.name, tool_input, mutating, call_id)
            transcript.calls.append(record)
            messages.append(
                {"role": "tool", "tool_call_id": call_id, "content": json.dumps(record.response)}
            )
    return transcript


def run_agent(client: GatewayClient, role: str, model: str | None = None) -> AgentTranscript:
    """Run one LLM agent with whichever backend BADGE_LLM_PROVIDER selects."""
    provider = llm_settings()[0]
    if provider == "anthropic":
        return run_llm_agent(client, role, model=model)
    return run_openai_agent(client, role, model=model)


def check_llm_ready() -> str | None:
    """None if the configured LLM backend looks usable, else a message saying what's wrong."""
    provider, base_url, api_key, model = llm_settings()
    if provider == "anthropic":
        return None if os.environ.get("ANTHROPIC_API_KEY") else "set ANTHROPIC_API_KEY"
    if provider not in ("ollama", "openai", "groq"):
        return f"unknown BADGE_LLM_PROVIDER {provider!r} (use ollama, groq, openai, or anthropic)"
    if provider == "groq":
        return None if api_key else "set GROQ_API_KEY"
    if provider == "openai":
        return None if os.environ.get("BADGE_LLM_API_KEY") else "set BADGE_LLM_API_KEY"
    import httpx

    root = base_url.rstrip("/").removesuffix("/v1")
    try:
        tags = httpx.get(f"{root}/api/tags", timeout=3).json()
    except (httpx.HTTPError, ValueError):
        return f"Ollama isn't reachable at {root}. Install it and run `ollama serve`"
    names = {m.get("name", "") for m in tags.get("models", [])}
    if model not in names and f"{model}:latest" not in names:
        return f"model {model} isn't pulled. Run: ollama pull {model}"
    return None
