"""LLM client for the master agent.

For Ollama we call its native /api/chat so we can set the context window (`num_ctx`).
Ollama's OpenAI-compatible endpoint can't, and its default window (2-4K tokens) silently
truncates the planner prompt, which makes small models return nothing usable. Everything
else goes through the OpenAI-compatible client (Groq, LM Studio, OpenAI, ...).

Both expose the same `client.chat.completions.create(...)` shape the master uses.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import httpx


class OllamaNative:
    def __init__(self, base_url: str, num_ctx: int = 8192, timeout: float = 180) -> None:
        root = base_url.rstrip("/").removesuffix("/v1")
        self._http = httpx.Client(base_url=root, timeout=timeout)
        self.num_ctx = num_ctx
        self.chat = SimpleNamespace(completions=self)

    @staticmethod
    def _message(message: dict[str, Any]) -> dict[str, Any]:
        out = {"role": message["role"], "content": message.get("content") or ""}
        if message.get("tool_calls"):
            out["tool_calls"] = []
            for call in message["tool_calls"]:
                args = call["function"].get("arguments") or {}
                if isinstance(args, str):
                    try:
                        args = json.loads(args)
                    except json.JSONDecodeError:
                        args = {}
                out["tool_calls"].append(
                    {"function": {"name": call["function"]["name"], "arguments": args}}
                )
        return out

    def create(
        self,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0,
        max_tokens: int = 900,
        **_: Any,
    ) -> SimpleNamespace:
        body: dict[str, Any] = {
            "model": model,
            "messages": [self._message(m) for m in messages],
            "stream": False,
            "keep_alive": "30m",  # avoid a cold reload (and a watchdog trip) mid-demo
            "options": {
                "temperature": temperature,
                "num_ctx": self.num_ctx,
                "num_predict": max_tokens,
            },
        }
        if tools:
            body["tools"] = tools
        response = self._http.post("/api/chat", json=body)
        response.raise_for_status()
        message = response.json()["message"]
        calls = [
            SimpleNamespace(
                id=f"call_{i}",
                function=SimpleNamespace(
                    name=c["function"]["name"],
                    arguments=json.dumps(c["function"].get("arguments") or {}),
                ),
            )
            for i, c in enumerate(message.get("tool_calls") or [])
        ]
        reply = SimpleNamespace(content=message.get("content") or "", tool_calls=calls or None)
        return SimpleNamespace(choices=[SimpleNamespace(message=reply)])


# Groq models good at tool calling, best first. The first one this key can use wins.
GROQ_PREFERENCE = (
    "llama-3.3-70b-versatile",
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "llama-3.1-8b-instant",
)


class ReasoningAware:
    """Wraps an OpenAI-compatible client. For reasoning models (gpt-oss), asks for low
    reasoning effort and leaves room for the answer after the reasoning tokens."""

    def __init__(self, client: Any) -> None:
        self._client = client
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs: Any) -> Any:
        if "gpt-oss" in str(kwargs.get("model", "")):
            kwargs.setdefault("reasoning_effort", "low")
            kwargs["max_tokens"] = max(int(kwargs.get("max_tokens") or 0), 4096)
        return self._client.chat.completions.create(**kwargs)


def pick_groq_model(client: Any, preferred: str | None) -> str:
    """The configured model if set; else the best model this key can actually use."""
    if preferred:
        return preferred
    try:
        available = {m.id for m in client.models.list().data}
    except Exception:  # noqa: BLE001 - fall back to the first preference
        return GROQ_PREFERENCE[0]
    for name in GROQ_PREFERENCE:
        if name in available:
            return name
    chat_models = sorted(m for m in available if "whisper" not in m and "guard" not in m)
    return chat_models[0] if chat_models else GROQ_PREFERENCE[0]


def make_llm(num_ctx: int = 8192) -> tuple[Any, str]:
    """(client, model) for the configured backend."""
    import os

    from agents.runner import llm_settings

    provider, base_url, api_key, model = llm_settings()
    if provider == "ollama":
        return OllamaNative(base_url, num_ctx=num_ctx), model
    from openai import OpenAI

    client = OpenAI(base_url=base_url, api_key=api_key, timeout=120)
    if provider == "groq":
        model = pick_groq_model(client, os.environ.get("BADGE_MODEL") or None)
    return ReasoningAware(client), model
