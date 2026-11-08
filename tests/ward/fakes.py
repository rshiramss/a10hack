"""A fake OpenAI-compatible client: replays scripted model turns."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any


def plan_turn(steps: list[dict[str, Any]]) -> SimpleNamespace:
    call = SimpleNamespace(
        id="c1",
        function=SimpleNamespace(name="declare_plan", arguments=json.dumps({"steps": steps})),
    )
    return SimpleNamespace(content=None, tool_calls=[call])


def text_turn(text: str) -> SimpleNamespace:
    return SimpleNamespace(content=text, tool_calls=None)


class FakeLLM:
    def __init__(self, turns: list[SimpleNamespace]) -> None:
        self.turns = list(turns)
        self.requests: list[dict[str, Any]] = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.requests.append(kwargs)
        message = self.turns.pop(0) if self.turns else text_turn("done")
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])
