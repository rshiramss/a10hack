"""Workload identity (client credentials -> badge) and the MCP front door.

This is the A10 demo as tests: authenticate an agent, it sees only its role's MCP tools,
revoke it mid-task, and every later request is blocked (and audited).
"""

from __future__ import annotations

import asyncio
import socket
import threading
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agents import scripted
from agents.mcp_client import McpError, McpGatewayClient
from agents.runner import run_openai_agent
from badge import db
from badge.clock import FrozenClock
from badge.config import load_config
from badge.context import Runtime
from badge.orchestrator import (
    assessor_task_id,
    assign,
    create_visit_tasks,
    pharmacist_task_id,
    provision_workload,
)
from scripts.seed import seed
from server.app import Settings, create_app
from tests.harness import TEST_SIGNING_KEY

CSRF = {"X-Badge-Dashboard": "1"}
VISIT = "V-07"


@pytest.fixture
def world(tmp_path: Path):
    db_path = tmp_path / "mcp.db"
    clock = FrozenClock()
    settings = Settings(
        db_path=db_path, signing_key=TEST_SIGNING_KEY, monitor_passwords={"alice": "pw-a"}
    )
    app = create_app(settings, clock=clock)
    conn = db.connect(db_path)
    seed(conn)
    runtime = Runtime(load_config(), clock, TEST_SIGNING_KEY)
    secrets = {
        "pharm-1": provision_workload(conn, runtime, "pharm-1", "pharmacist"),
        "assessor-a": provision_workload(conn, runtime, "assessor-a", "assessor"),
    }
    create_visit_tasks(conn, runtime, [VISIT])
    assign(conn, runtime, pharmacist_task_id(VISIT), "pharm-1")
    assign(conn, runtime, assessor_task_id(VISIT, 1), "assessor-a")
    http = TestClient(app)
    yield SimpleNamespace(http=http, conn=conn, secrets=secrets, app=app, settings=settings)
    conn.close()


def get_token(http: httpx.Client, client_id: str, secret: str) -> httpx.Response:
    return http.post(
        "/auth/agent/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
    )


def mcp_agent(world: Any, agent_id: str) -> McpGatewayClient:
    token = get_token(world.http, agent_id, world.secrets[agent_id]).json()["access_token"]
    client = McpGatewayClient(world.http, token, agent_id)
    client.initialize()
    return client


def dispense(world: Any) -> None:
    pharm = mcp_agent(world, "pharm-1")
    patient = world.conn.execute(
        "SELECT patient_id FROM visits WHERE visit_id = ?", (VISIT,)
    ).fetchone()[0]
    assert [r["reason"] for r in scripted.honest_pharmacist(pharm, VISIT, patient)] == ["OK"] * 3


def revoke(world: Any, agent_id: str) -> dict[str, Any]:
    world.http.post("/auth/login", json={"username": "alice", "password": "pw-a"}, headers=CSRF)
    return world.http.post(
        "/api/monitor/revoke_badge",
        json={
            "args": {"agent_id": agent_id, "reason": "test"},
            "idempotency_key": str(uuid.uuid4()),
        },
        headers=CSRF,
    ).json()


# ---- workload identity ---------------------------------------------------------------


def test_client_credentials_issue_a_badge(world) -> None:
    response = get_token(world.http, "assessor-a", world.secrets["assessor-a"])
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] > 0
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("client_id", "secret"),
    [("assessor-a", "wrong-secret"), ("nobody", "anything"), ("assessor-a", "")],
)
def test_bad_credentials_are_refused_and_audited(world, client_id: str, secret: str) -> None:
    response = get_token(world.http, client_id, secret)
    assert response.status_code == 401
    assert response.json() == {"error": "invalid_client", "reason": "DENY_BAD_CREDENTIALS"}
    count = world.conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE reason = 'AUTH_FAILED'"
    ).fetchone()[0]
    assert count == 1


def test_wrong_grant_type_is_refused(world) -> None:
    response = world.http.post("/auth/agent/token", data={"grant_type": "password"})
    assert response.status_code == 400


def test_secret_is_never_stored_in_plaintext(world) -> None:
    rows = world.conn.execute("SELECT secret_hmac FROM agent_credentials").fetchall()
    stored = {row["secret_hmac"] for row in rows}
    assert not stored & set(world.secrets.values())


# ---- MCP: selected tools -------------------------------------------------------------


def test_mcp_tools_list_is_filtered_by_role(world) -> None:
    assessor = {t["name"] for t in mcp_agent(world, "assessor-a").list_tools()}
    pharmacist = {t["name"] for t in mcp_agent(world, "pharm-1").list_tools()}
    assert "get_assignment" not in assessor and "open_patient_visit" in assessor
    assert "get_assignment" in pharmacist and "open_patient_visit" not in pharmacist


def test_mcp_needs_a_badge_to_connect(world) -> None:
    with pytest.raises(McpError) as caught:
        McpGatewayClient(world.http, "not-a-badge").initialize()
    assert caught.value.reason == "DENY_BAD_BADGE"


def test_calling_a_tool_outside_the_role_over_mcp_revokes(world) -> None:
    agent = mcp_agent(world, "assessor-a")
    response = agent.call_tool("get_assignment", {"patient_id": "P001", "visit_id": "V-01"})
    assert response["reason"] == "DENY_ROLE_FORBIDDEN" and response["action"] == "revoke"
    assert agent.status()["reason"] == "DENY_REVOKED"


def test_mcp_tool_result_shape(world) -> None:
    agent = mcp_agent(world, "assessor-a")
    raw = agent._rpc("tools/call", {"name": "get_my_status", "arguments": {}})
    assert raw["isError"] is False
    assert raw["structuredContent"]["agent_id"] == "assessor-a"
    assert raw["content"][0]["type"] == "text"


# ---- the demo: revoke mid-task, block what follows --------------------------------------


def test_revoke_mid_task_blocks_every_later_request(world) -> None:
    dispense(world)
    agent = mcp_agent(world, "assessor-a")
    v = {"visit_id": VISIT}
    task = scripted.find_task(agent, VISIT)
    plan = agent.declare_plan(
        task["task_id"], scripted.assessor_plan(VISIT, {"pain_score": 3, "mobility_score": 4})
    )
    assert plan["ok"]
    assert agent.call("open_patient_visit", v)["ok"]
    first = {**v, "measure": "pain_score", "value": 3, "notes": "Better on stairs."}
    assert agent.call("record_outcome", first, mutating=True)["ok"]

    revoked = revoke(world, "assessor-a")
    assert revoked["ok"], revoked

    second = {**v, "measure": "mobility_score", "value": 4, "notes": "Walks unaided."}
    assert agent.call("record_outcome", second, mutating=True)["reason"] == "DENY_REVOKED"
    assert agent.call("submit", v, mutating=True)["reason"] == "DENY_REVOKED"
    with pytest.raises(McpError, match="DENY_REVOKED"):
        agent.list_tools()
    with pytest.raises(McpError, match="DENY_REVOKED"):
        agent.initialize()
    reauth = get_token(world.http, "assessor-a", world.secrets["assessor-a"])
    assert reauth.status_code == 401 and reauth.json()["reason"] == "DENY_REVOKED"

    denied = world.conn.execute(
        "SELECT tool FROM audit_log WHERE agent_id = 'assessor-a' AND reason = 'DENY_REVOKED'"
        " ORDER BY seq"
    ).fetchall()
    assert [row["tool"] for row in denied] == ["record_outcome", "submit", "list_my_tools"]
    flagged = world.conn.execute(
        "SELECT COUNT(*) FROM outcome_flags f JOIN outcomes o ON o.outcome_id = f.outcome_id"
        " WHERE o.agent_id = 'assessor-a'"
    ).fetchone()[0]
    assert flagged >= 1


# ---- the LLM runner over MCP, with a fake OpenAI-compatible model -------------------------


class FakeOpenAI:
    """Replays a fixed list of tool calls, one per turn, then answers in text."""

    def __init__(self, script: list[tuple[str, str]]) -> None:
        self.script = script
        self.seen_tools: list[str] = []
        self.chat = SimpleNamespace(completions=self)

    def create(self, **kwargs: Any) -> SimpleNamespace:
        self.seen_tools = [tool["function"]["name"] for tool in kwargs["tools"]]
        turn = sum(1 for m in kwargs["messages"] if m["role"] == "assistant")
        if turn >= len(self.script):
            message = SimpleNamespace(content="done", tool_calls=None)
        else:
            name, arguments = self.script[turn]
            call = SimpleNamespace(
                id=f"call_{turn}", function=SimpleNamespace(name=name, arguments=arguments)
            )
            message = SimpleNamespace(content=None, tool_calls=[call])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_openai_runner_over_mcp(world) -> None:
    dispense(world)
    agent = mcp_agent(world, "assessor-a")
    plan = (
        '{"task_id": "T-AS-V-07-s1", "steps": ['
        '{"tool": "open_patient_visit", "args": {"visit_id": "V-07"}},'
        '{"tool": "record_outcome", "args": {"visit_id": "V-07", "measure": "pain_score"}},'
        '{"tool": "submit", "args": {"visit_id": "V-07"}}]}'
    )
    fake = FakeOpenAI(
        [
            ("get_my_status", "{}"),
            ("declare_plan", plan),
            ("open_patient_visit", '{"visit_id": "V-07"}'),
            (
                "record_outcome",
                '{"visit_id": "V-07", "measure": "pain_score", "value": 4, "notes": "Ok."}',
            ),
            ("submit", '{"visit_id": "V-07"}'),
            ("get_assignment", "not json at all"),
        ]
    )
    transcript = run_openai_agent(agent, "assessor", fake, model="fake")
    reasons = [record.response["reason"] for record in transcript.calls]
    assert reasons == ["OK"] * 5 + ["DENY_ROLE_FORBIDDEN"]
    assert "get_assignment" not in fake.seen_tools and "list_my_tools" not in fake.seen_tools
    assert transcript.final_text == "done"


# ---- interop: the official MCP Python SDK -------------------------------------------------


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_official_mcp_sdk_client_interop(world) -> None:
    pytest.importorskip("mcp")
    import uvicorn
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    from mcp.shared._httpx_utils import create_mcp_http_client

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(world.app, host="127.0.0.1", port=port, log_level="warning")
    )
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    token = get_token(world.http, "assessor-a", world.secrets["assessor-a"]).json()["access_token"]

    async def session() -> tuple[str, list[str], bool, bool]:
        http = create_mcp_http_client(headers={"Authorization": f"Bearer {token}"})
        async with (
            streamable_http_client(f"http://127.0.0.1:{port}/mcp", http_client=http) as streams,
            ClientSession(streams[0], streams[1]) as client,
        ):
            init = await client.initialize()
            tools = [tool.name for tool in (await client.list_tools()).tools]
            status = await client.call_tool("get_my_status", {})
            forbidden = await client.call_tool("get_assignment", {"patient_id": "P001"})
            return init.server_info.name, tools, status.is_error, forbidden.is_error

    try:
        name, tools, status_error, forbidden_error = asyncio.run(session())
    finally:
        server.should_exit = True
    assert name == "badge-gateway"
    assert "get_assignment" not in tools and "submit" in tools
    assert status_error is False and forbidden_error is True


def test_openai_runner_stops_cleanly_when_badge_is_revoked(world) -> None:
    agent = mcp_agent(world, "assessor-a")
    assert revoke(world, "assessor-a")["ok"]
    transcript = run_openai_agent(agent, "assessor", FakeOpenAI([("get_my_status", "{}")]))
    assert transcript.calls == [] and "no tools" in transcript.final_text
