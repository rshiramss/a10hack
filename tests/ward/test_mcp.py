"""MCP front door + badge_agent: bring-your-own agent against Ward."""

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

from ward import crypto
from ward.attestation import badge_agent_path, measure_source_file
from ward.config import load_config
from ward.gateway import Credential, Denied, Gateway
from ward.mcp import proof_op, to_mcp_tools
from ward.typed import check_record

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


@pytest.fixture
def gw() -> Gateway:
    g = Gateway(CFG, sleep=lambda _s: None)
    g.settings["step_delay_ms"] = 0
    g.settings["approvals_enabled"] = False  # Feature 2 tests opt in explicitly
    return g


def test_config_loads_external_roles() -> None:
    assert "clinician_assistant" in CFG.roles
    assert "scheduling_assistant" in CFG.roles
    assert CFG.roles["clinician_assistant"].external
    assert CFG.roles["clinician_assistant"].allows_tool("draft_order")
    assert not CFG.roles["scheduling_assistant"].allows_tool("draft_order")
    assert CFG.roles["scheduling_assistant"].allows_tool("book_appointment")


def test_mcp_list_filtered_by_role(gw: Gateway) -> None:
    aid, secret = provision_external(gw, "scheduling_assistant")
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(cred(token, key, "mcp:tools/list"), "mcp:tools/list")
    names = {c["tool"] for c in gw.mcp_list_tools_as(badge)}
    assert names == {"find_appointment_slots", "book_appointment", "get_patient_profile"}
    assert "draft_order" not in names


def test_mcp_get_allergies_success(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(
        cred(token, key, "mcp:tools/call:get_allergies"), "mcp:tools/call:get_allergies"
    )
    out = gw.mcp_call_tool_as(badge, "get_allergies", {"patient_id": "P001"})
    assert out["tool"] == "get_allergies"
    problem = check_record(CFG.tools["get_allergies"].output, out["result"], "out")
    assert problem is None


def test_draft_order_needs_prerequisites_then_succeeds(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)

    def call(tool: str, args: dict[str, Any]) -> dict[str, Any]:
        op = f"mcp:tools/call:{tool}"
        badge = gw.verify(cred(token, key, op), op)
        return gw.mcp_call_tool_as(badge, tool, args)

    with pytest.raises(Denied) as exc:
        call("draft_order", {"patient_id": "P003", "drug": "amoxicillin", "daily_dose_mg": 1500})
    assert exc.value.reason == "DENY_PRECONDITION"
    assert "get_allergies" in exc.value.detail

    call("get_allergies", {"patient_id": "P003"})
    call("get_active_medications", {"patient_id": "P003"})
    call("lookup_drug", {"drug": "amoxicillin"})
    call("check_interactions", {"patient_id": "P003", "drug": "amoxicillin"})
    call("get_renal_function", {"patient_id": "P003"})
    out = call("draft_order", {"patient_id": "P003", "drug": "amoxicillin", "daily_dose_mg": 1500})
    assert out["result"]["status"] in ("drafted", "blocked")
    assert check_record(CFG.tools["draft_order"].output, out["result"], "draft") is None


def test_scheduling_overreach_revokes(gw: Gateway) -> None:
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
    # Cannot re-authenticate after revoke.
    with pytest.raises(Denied) as exc:
        login_external(gw, aid, secret)
    assert exc.value.reason == "DENY_REVOKED"
    _ = key  # key held but useless after revoke


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
    # New badge works.
    gw.verify(cred(session["token"], new_key, "mcp:tools/list"), "mcp:tools/list")


def test_operator_revoke_blocks_next_call(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(
        cred(token, key, "mcp:tools/call:get_allergies"), "mcp:tools/call:get_allergies"
    )
    gw.mcp_call_tool_as(badge, "get_allergies", {"patient_id": "P001"})
    assert gw.revoke(aid, "operator:alice", "revoked from the console")
    with pytest.raises(Denied) as exc:
        gw.verify(cred(token, key, "mcp:tools/call:get_allergies"), "mcp:tools/call:get_allergies")
    assert exc.value.reason == "DENY_REVOKED"
    with pytest.raises(Denied) as reauth:
        login_external(gw, aid, secret)
    assert reauth.value.reason == "DENY_REVOKED"


def test_rotation_transparent_during_session(gw: Gateway) -> None:
    aid, secret = provision_external(gw)
    token, key = login_external(gw, aid, secret)
    badge = gw.verify(
        cred(token, key, "mcp:tools/call:get_allergies"), "mcp:tools/call:get_allergies"
    )
    gw.mcp_call_tool_as(badge, "get_allergies", {"patient_id": "P001"})
    new_key = crypto.AgentKey()
    session = gw.rotate(
        cred(token, key, "rotate"), new_key.public_pem, new_key.proof(token, "rotate-new-key")
    )
    badge2 = gw.verify(
        cred(session["token"], new_key, "mcp:tools/call:get_patient_profile"),
        "mcp:tools/call:get_patient_profile",
    )
    out = gw.mcp_call_tool_as(badge2, "get_patient_profile", {"patient_id": "P001"})
    assert "age" in out["result"]


def test_json_schema_from_typed_config() -> None:
    caps = [
        {
            "tool": "get_allergies",
            "needs_earlier_steps": [],
            "agent": "MedHistoryAgent",
            "description": "",
            "args": {},
            "returns": {},
        }
    ]
    tools = to_mcp_tools(CFG, caps)
    assert tools[0]["name"] == "get_allergies"
    assert tools[0]["inputSchema"]["properties"]["patient_id"]["type"] == "string"


# ---- HTTP + stdio badge_agent -------------------------------------------------------------


@pytest.fixture
def ward_server():
    from server.ward_app import create_app

    port = free_port()
    app = create_app(
        operators={"alice": "pw"}, llm=object(), model="fake", watchdog=False, sleep=lambda _s: None
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
    client = app.state.console
    # Direct provision (same as operator issue) for test speed.
    return client.gateway.provision(role)


def test_badge_agent_stdio_mcp_sdk(ward_server) -> None:
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
            assert "get_allergies" in names
            assert "draft_order" in names
            result = await session.call_tool("get_allergies", {"patient_id": "P001"})
            assert not result.is_error
            structured = result.structured_content
            assert structured is not None
            assert "allergies" in structured

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
    assert any(t["name"] == "get_allergies" for t in listed["result"]["tools"])
    ok = mcp("tools/call", {"name": "get_allergies", "arguments": {"patient_id": "P001"}}, msg_id=3)
    assert ok["result"]["isError"] is False

    assert app.state.console.gateway.revoke(client_id, "operator:alice", "mid-session")
    blocked = mcp(
        "tools/call", {"name": "get_allergies", "arguments": {"patient_id": "P001"}}, msg_id=4
    )
    if "error" in blocked:
        assert blocked["error"]["data"]["reason"] == "DENY_REVOKED"
    else:
        assert blocked["result"]["isError"] is True
        assert "DENY_REVOKED" in blocked["result"]["content"][0]["text"]
