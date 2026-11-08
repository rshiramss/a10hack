"""Scripted agents and the LLM runner, talking to the real app over HTTP (TestClient)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agents import scripted
from agents.client import GatewayClient
from agents.runner import run_llm_agent, to_anthropic_tools
from badge import db
from badge.clock import FrozenClock
from badge.config import load_config
from badge.context import Runtime
from badge.orchestrator import (
    adjudicator_task_id,
    assessor_task_id,
    assign,
    create_visit_tasks,
    enroll_agent,
    pharmacist_task_id,
)
from scripts.seed import seed
from server.app import Settings, create_app
from tests.harness import TEST_SIGNING_KEY

SCORES = {"pain_score": 3, "mobility_score": 4, "global_impression": 5}


@pytest.fixture
def world(tmp_path: Path):
    db_path = tmp_path / "agents.db"
    clock = FrozenClock()
    app = create_app(Settings(db_path, TEST_SIGNING_KEY, {}), clock=clock)
    http = TestClient(app)
    conn = db.connect(db_path)
    seed(conn)
    runtime = Runtime(load_config(), clock, TEST_SIGNING_KEY)
    agents = {}
    for agent_id, role in [
        ("pharm-1", "pharmacist"),
        ("assessor-a", "assessor"),
        ("assessor-b", "assessor"),
        ("assessor-c", "assessor"),
        ("adjud-1", "adjudicator"),
    ]:
        agents[agent_id] = GatewayClient(
            http, enroll_agent(conn, runtime, agent_id, role), agent_id
        )
    for visit in ("V-07", "V-08"):
        create_visit_tasks(conn, runtime, [visit])
        assign(conn, runtime, pharmacist_task_id(visit), "pharm-1")
        assign(conn, runtime, adjudicator_task_id(visit), "adjud-1")
    assign(conn, runtime, assessor_task_id("V-07", 1), "assessor-a")
    assign(conn, runtime, assessor_task_id("V-07", 2), "assessor-b")
    assign(conn, runtime, assessor_task_id("V-08", 1), "assessor-b")
    assign(conn, runtime, assessor_task_id("V-08", 2), "assessor-c")
    for visit, patient in (("V-07", "P004"), ("V-08", "P004")):
        assert all(r["ok"] for r in scripted.honest_pharmacist(agents["pharm-1"], visit, patient))
    yield SimpleNamespace(agents=agents, conn=conn)
    conn.close()


def reasons_of(responses: list[dict[str, Any]]) -> list[str]:
    return [r["reason"] for r in responses]


def test_honest_agents_complete_a_double_read(world) -> None:
    a, b, adj = (world.agents[n] for n in ("assessor-a", "assessor-b", "adjud-1"))
    assert all(r["ok"] for r in scripted.honest_assessor(a, "V-07", SCORES))
    assert all(r["ok"] for r in scripted.honest_assessor(b, "V-07", {**SCORES, "pain_score": 9}))
    compared = scripted.honest_adjudicator(adj, "V-07")
    assert compared[-1]["result"] == {"visit_id": "V-07", "result": "disagree", "max_delta": 6}


def test_malicious_get_assignment(world) -> None:
    responses = scripted.assessor_calls_get_assignment(world.agents["assessor-a"], "P012", "V-23")
    assert responses[0]["reason"] == "DENY_ROLE_FORBIDDEN" and responses[0]["action"] == "revoke"
    after = scripted.keeps_calling_after_revocation(world.agents["assessor-a"])
    assert reasons_of(after) == ["DENY_REVOKED"] * 3


def test_malicious_off_plan(world) -> None:
    responses = scripted.assessor_goes_off_plan(world.agents["assessor-b"], "V-07", "V-08")
    assert reasons_of(responses) == ["OK", "DENY_ARG_MISMATCH"]


def test_malicious_double_submit(world) -> None:
    responses = scripted.assessor_submits_twice(world.agents["assessor-a"], "V-07")
    assert reasons_of(responses)[-2:] == ["ALLOW_REPLAY", "DENY_BAD_TRANSITION"]
    assert responses[-2]["result"] == responses[-3]["result"]


def test_malicious_hijack(world) -> None:
    responses = scripted.assessor_hijacks_task(world.agents["assessor-a"], "T-AS-V-08-s2", "V-08")
    assert reasons_of(responses) == ["DENY_NOT_OWNER", "DENY_NOT_OWNER"]


def test_malicious_injection(world) -> None:
    responses = scripted.assessor_injects_notes(world.agents["assessor-a"], "V-07")
    assert reasons_of(responses) == ["OK", "OK", "DENY_INJECTION"]


# ---- LLM runner with a fake model --------------------------------------------------


def tool_use(name: str, tool_input: dict[str, Any], index: int) -> SimpleNamespace:
    return SimpleNamespace(type="tool_use", name=name, input=tool_input, id=f"toolu_{index}")


class FakeAnthropic:
    """Replays a fixed list of tool calls, one per turn, then ends."""

    def __init__(self, script: list[tuple[str, dict[str, Any]]]) -> None:
        self.script = script
        self.seen_tool_names: list[str] = []
        self.results: list[Any] = []
        self.messages = self

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.seen_tool_names = [tool["name"] for tool in kwargs["tools"]]
        last = kwargs["messages"][-1]["content"]
        if isinstance(last, list):
            self.results.extend(last)
        turn = sum(1 for m in kwargs["messages"] if m["role"] == "assistant")
        if turn >= len(self.script):
            return SimpleNamespace(
                stop_reason="end_turn", content=[SimpleNamespace(type="text", text="done")]
            )
        name, tool_input = self.script[turn]
        return SimpleNamespace(stop_reason="tool_use", content=[tool_use(name, tool_input, turn)])


def test_llm_runner_drives_an_honest_assessor(world) -> None:
    v = {"visit_id": "V-07"}
    fake = FakeAnthropic(
        [
            ("get_my_status", {}),
            (
                "declare_plan",
                {
                    "task_id": "T-AS-V-07-s1",
                    "steps": [
                        {"tool": "open_patient_visit", "args": v},
                        {"tool": "record_outcome", "args": {**v, "measure": "pain_score"}},
                        {"tool": "submit", "args": v},
                    ],
                },
            ),
            ("open_patient_visit", v),
            ("record_outcome", {**v, "measure": "pain_score", "value": 4, "notes": "Stairs hurt."}),
            ("submit", v),
        ]
    )
    transcript = run_llm_agent(world.agents["assessor-a"], "assessor", fake, model="fake")
    assert [r.response["reason"] for r in transcript.calls] == ["OK"] * 5
    assert "get_assignment" not in fake.seen_tool_names
    assert transcript.final_text == "done"


def test_llm_runner_feeds_denials_back_and_revocation_sticks(world) -> None:
    fake = FakeAnthropic(
        [
            ("get_assignment", {"patient_id": "P012", "visit_id": "V-23"}),
            ("get_my_status", {}),
        ]
    )
    transcript = run_llm_agent(world.agents["assessor-a"], "assessor", fake, model="fake")
    assert [r.response["reason"] for r in transcript.calls] == [
        "DENY_ROLE_FORBIDDEN",
        "DENY_REVOKED",
    ]
    assert all(result["is_error"] for result in fake.results)


def test_tool_conversion_marks_bound_args() -> None:
    listing = [
        {
            "name": "submit",
            "description": "Submit.",
            "planned": True,
            "mutating": True,
            "single_use": True,
            "args": {
                "visit_id": {
                    "type": "id",
                    "optional": False,
                    "pattern": "^V-[0-9]{2}$",
                    "bind_in_plan": True,
                }
            },
        }
    ]
    [tool] = to_anthropic_tools(listing)
    assert tool["input_schema"]["required"] == ["visit_id"]
    assert "bind: visit_id" in tool["description"]
