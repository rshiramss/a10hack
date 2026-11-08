"""MCP front door: external clients only ask_ward; orchestrator wires specialists."""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from tests.ward.fakes import FakeLLM, plan_turn, text_turn
from ward import crypto
from ward.attestation import badge_agent_path, measure_source_file
from ward.config import load_config
from ward.gateway import Credential, Denied, Gateway
from ward.master import MasterAgent
from ward.mcp import ASK_WARD, proof_op

ROOT = Path(__file__).resolve().parents[2]
CFG = load_config()
BADGE_AGENT = ROOT / "scripts" / "badge_agent.py"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def measurement() -> str:
    return measure_source_file(badge_agent_path())


def provision_external(gw: Gateway, role: str = "clinician_assistant") -> tuple[str, str]:
    return gw.provision(role)


def login_external(gw: Gateway, agent_id: str, secret: str) -> tuple[str, crypto.AgentKey]:
    key = crypto.AgentKey()
    session = gw.authenticate(
        agent_id, secret, key.public_pem, key.proof(secret, "authenticate"), measurement()
    )
    return session["token"], key


def cred(token: str, key: crypto.AgentKey, op: str) -> Credential:
    return Credential(token, key.proof(token, op))


def wire_ask(gw: Gateway, llm: FakeLLM | None = None) -> MasterAgent:
    """Attach OrchestratorAgent as the ask_ward handler (same as the live console)."""
    agent = MasterAgent(gw, llm or FakeLLM([]), "fake", sleep=lambda _s: None)
    agent.ensure_identity()

    def ask(prompt: str) -> dict[str, Any]:
        run_id = agent.handle(prompt)
        row = gw.conn.execute(
            "SELECT status, answer, error FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return {
            "run_id": run_id,
            "status": row["status"],
            "answer": row["answer"] or "",
            "error": row["error"] or "",
        }

    gw.set_mcp_ask_handler(ask)
    return agent


@pytest.fixture
def gw() -> Gateway:
    g = Gateway(CFG, sleep=lambda _s: None)
    g.settings["step_delay_ms"] = 0
    g.settings["approvals_enabled"] = False
    return g


def test_config_loads_external_roles() -> None:
    assert "clinician_assistant" in CFG.roles
    assert "scheduling_assistant" in CFG.roles
    assert CFG.roles["clinician_assistant"].external
    assert not CFG.roles["clinician_assistant"].may_delegate
    assert CFG.roles["clinician_assistant"].tools_allowed is None
    assert not CFG.roles["clinician_assistant"].allows_tool("draft_order")
    assert not CFG.roles["scheduling_assistant"].allows_tool("get_allergies")
    # Specialists only accept the orchestrator.
    assert CFG.roles["med_history"].callable_by == ("orchestrator",)


def test_mcp_lists_only_ask_ward(gw: Gateway) -> None:
    for role in ("clinician_assistant", "scheduling_assistant"):
        aid, secret = provision_external(gw, role)
        token, key = login_external(gw, aid, secret)
        badge = gw.verify(cred(token, key, "mcp:tools/list"), "mcp:tools/list")
        tools = gw.mcp_list_tools_as(badge)
        assert [t["name"] for t in tools] == [ASK_WARD]
        assert "get_allergies" not in {t["name"] for t in tools}


def test_ask_ward_runs_through_orchestrator(gw: Gateway) -> None:
    llm = FakeLLM(
        [
            plan_turn(
                [{"agent": "MedHistoryAgent", "tool": "get_allergies", "args": {"patient_id": "P001"}}]
            ),
            text_turn("No known allergies for P001."),
        ]
    )
    wire_ask(gw, llm)
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(cred(token, key, f"mcp:tools/call:{ASK_WARD}"), f"mcp:tools/call:{ASK_WARD}")
    out = gw.mcp_call_tool_as(badge, ASK_WARD, {"prompt": "What allergies does P001 have?"})
    assert out["tool"] == ASK_WARD
    assert out["result"]["status"] == "done"
    assert "allerg" in out["result"]["answer"].lower() or out["result"]["answer"]
    # Specialist was spun for the orchestrator run, then retired when the run ended.
    meds = gw.conn.execute(
        "SELECT status FROM agents WHERE role = 'med_history' ORDER BY created_ms DESC LIMIT 1"
    ).fetchone()
    assert meds is not None
    assert meds["status"] == "retired"


def test_specialist_tool_via_mcp_revokes(gw: Gateway) -> None:
    wire_ask(gw)
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    op = "mcp:tools/call:get_allergies"
    badge = gw.verify(cred(token, key, op), op)
    with pytest.raises(Denied) as exc:
        gw.mcp_call_tool_as(badge, "get_allergies", {"patient_id": "P001"})
    assert exc.value.reason == "DENY_ROLE_FORBIDDEN"
    row = gw.conn.execute("SELECT status FROM agents WHERE agent_id = ?", (aid,)).fetchone()
    assert row["status"] == "revoked"


def test_scheduling_overreach_revokes(gw: Gateway) -> None:
    wire_ask(gw)
    aid, secret = provision_external(gw, "scheduling_assistant")
    token, key = login_external(gw, aid, secret)
    op = "mcp:tools/call:draft_order"
    badge = gw.verify(cred(token, key, op), op)
    with pytest.raises(Denied) as exc:
        gw.mcp_call_tool_as(
            badge,
            "draft_order",
            {"patient_id": "P001", "drug": "amoxicillin", "daily_dose_mg": 500},
        )
    assert exc.value.reason == "DENY_ROLE_FORBIDDEN"
    row = gw.conn.execute("SELECT status FROM agents WHERE agent_id = ?", (aid,)).fetchone()
    assert row["status"] == "revoked"


def test_no_credential_refused(gw: Gateway) -> None:
    with pytest.raises(Denied) as exc:
        gw.verify(Credential(None, None), "mcp:initialize")  # type: ignore[arg-type]
    assert exc.value.reason.startswith("DENY_")


def test_stolen_badge_without_key_revokes(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    with pytest.raises(Denied):
        gw.verify(Credential(token, None), "mcp:tools/list")
    row = gw.conn.execute("SELECT status FROM agents WHERE agent_id = ?", (aid,)).fetchone()
    assert row["status"] == "revoked"
    with pytest.raises(Denied) as exc:
        login_external(gw, aid, secret)
    assert exc.value.reason == "DENY_REVOKED"
    _ = key


def test_pre_rotation_badge_refused(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    new_key = crypto.AgentKey()
    session = gw.rotate(
        cred(token, key, "rotate"),
        new_key.public_pem,
        new_key.proof(token, "rotate-new-key"),
    )
    with pytest.raises(Denied) as exc:
        gw.verify(cred(token, key, "mcp:tools/list"), "mcp:tools/list")
    assert exc.value.reason == "DENY_BADGE_SUPERSEDED"
    gw.verify(cred(session["token"], new_key, "mcp:tools/list"), "mcp:tools/list")


def test_operator_revoke_blocks_next_ask(gw: Gateway) -> None:
    wire_ask(gw, FakeLLM([text_turn("ok")]))
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(cred(token, key, f"mcp:tools/call:{ASK_WARD}"), f"mcp:tools/call:{ASK_WARD}")
    gw.mcp_call_tool_as(badge, ASK_WARD, {"prompt": "ping"})
    assert gw.revoke(aid, "operator:alice", "revoked from the console")
    with pytest.raises(Denied) as exc:
        gw.verify(cred(token, key, f"mcp:tools/call:{ASK_WARD}"), f"mcp:tools/call:{ASK_WARD}")
    assert exc.value.reason == "DENY_REVOKED"


def test_close_mcp_sessions_retires_stuck_specialists(gw: Gateway) -> None:
    """Leftover [mcp] session runs must not leave specialists spinning forever."""
    run_id = "MCP-TEST01"
    gw.conn.execute(
        "INSERT INTO runs (run_id, master_id, prompt, status, created_ms, last_progress_ms, flagged)"
        " VALUES (?, 'CursorAgent1', '[mcp] CursorAgent1', 'running', 1, 1, 0)",
        (run_id,),
    )
    aid, _ = gw.provision("med_history", run_id=run_id)
    assert gw.close_mcp_sessions("test cleanup") == 1
    status = gw.conn.execute(
        "SELECT status FROM agents WHERE agent_id = ?", (aid,)
    ).fetchone()["status"]
    assert status == "retired"
    run = gw.conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert run["status"] == "done"


# ---- HTTP + stdio badge_agent -------------------------------------------------------------


@pytest.fixture
def ward_server():
    from server.ward_app import create_app

    port = free_port()
    llm = FakeLLM(
        [
            plan_turn(
                [{"agent": "MedHistoryAgent", "tool": "get_allergies", "args": {"patient_id": "P001"}}]
            ),
            text_turn("No known drug allergies."),
        ]
    )
    app = create_app(
        operators={"alice": "pw"}, llm=llm, model="fake", watchdog=False, sleep=lambda _s: None
    )
    app.state.console.gateway.settings["step_delay_ms"] = 0
    app.state.console.gateway.settings["approvals_enabled"] = False
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            httpx.get(f"http://127.0.0.1:{port}/", timeout=0.2)
            break
        except Exception:  # noqa: BLE001
            time.sleep(0.05)
    yield app, port
    server.should_exit = True
    thread.join(timeout=2)


def issue_mcp(app, role: str = "clinician_assistant") -> tuple[str, str]:
    return app.state.console.gateway.provision(role)


def test_badge_agent_stdio_ask_ward(ward_server) -> None:
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    app, port = ward_server
    client_id, secret = issue_mcp(app)
    env = {
        **os.environ,
        "WARD_URL": f"http://127.0.0.1:{port}",
        "WARD_CLIENT_ID": client_id,
        "WARD_CLIENT_SECRET": secret,
    }
    env.pop("GROQ_API_KEY", None)
    params = StdioServerParameters(
        command="uv",
        args=["run", "python", str(BADGE_AGENT)],
        env=env,
        cwd=str(ROOT),
    )

    async def run() -> None:
        async with (
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            listed = await session.list_tools()
            names = {t.name for t in listed.tools}
            assert names == {ASK_WARD}
            assert "get_allergies" not in names
            result = await session.call_tool(ASK_WARD, {"prompt": "Allergies for P001?"})
            assert not result.is_error
            structured = result.structured_content
            assert structured is not None
            assert structured.get("status") == "done"
            assert structured.get("answer")

    asyncio.run(run())


def test_http_mcp_revoke_mid_session(ward_server) -> None:
    app, port = ward_server
    client_id, secret = issue_mcp(app)
    key = crypto.AgentKey()
    http = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30.0)
    auth = http.post(
        "/api/agent/token",
        json={
            "client_id": client_id,
            "secret": secret,
            "public_pem": key.public_pem,
            "key_proof": key.proof(secret, "authenticate"),
            "measurement": measurement(),
        },
    ).json()
    assert auth["ok"]
    token = auth["token"]

    def mcp(method: str, params: dict | None = None, msg_id: int = 1) -> dict:
        params = params or {}
        op = proof_op(method, params)
        body = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params}
        r = http.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}", "X-Badge-Proof": key.proof(token, op)},
            json=body,
        )
        return r.json()

    init = mcp(
        "initialize",
        {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    )
    assert "result" in init
    listed = mcp("tools/list", {}, msg_id=2)
    names = {t["name"] for t in listed["result"]["tools"]}
    assert names == {ASK_WARD}
    ok = mcp(
        "tools/call",
        {"name": ASK_WARD, "arguments": {"prompt": "Allergies for P001?"}},
        msg_id=3,
    )
    assert ok["result"]["isError"] is False

    assert app.state.console.gateway.revoke(client_id, "operator:alice", "mid-session")
    blocked = mcp(
        "tools/call",
        {"name": ASK_WARD, "arguments": {"prompt": "again"}},
        msg_id=4,
    )
    if "error" in blocked:
        assert blocked["error"]["data"]["reason"] == "DENY_REVOKED"
    else:
        assert blocked["result"]["isError"] is True
        assert "DENY_REVOKED" in blocked["result"]["content"][0]["text"]
