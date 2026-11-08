"""The HTTP API and dashboard, end to end through FastAPI's TestClient."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from badge import db
from badge.clock import FrozenClock
from badge.config import load_config
from badge.context import Runtime
from badge.orchestrator import assign, create_visit_tasks, enroll_agent, pharmacist_task_id
from scripts.seed import seed
from server.app import Settings, create_app
from tests.harness import TEST_SIGNING_KEY

CSRF = {"X-Badge-Dashboard": "1"}


@pytest.fixture
def setup(tmp_path: Path):
    db_path = tmp_path / "api.db"
    clock = FrozenClock()
    settings = Settings(
        db_path=db_path,
        signing_key=TEST_SIGNING_KEY,
        monitor_passwords={"alice": "pw-a", "bob": "pw-b"},
    )
    app = create_app(settings, clock=clock)
    conn = db.connect(db_path)
    seed(conn)
    runtime = Runtime(load_config(), clock, TEST_SIGNING_KEY)
    tokens = {
        "pharm": enroll_agent(conn, runtime, "pharm-1", "pharmacist"),
        "a": enroll_agent(conn, runtime, "assessor-a", "assessor"),
    }
    create_visit_tasks(conn, runtime, ["V-07"])
    assign(conn, runtime, pharmacist_task_id("V-07"), "pharm-1")
    yield TestClient(app), tokens, conn
    conn.close()


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_tool_list_is_filtered_over_http(setup) -> None:
    client, tokens, _ = setup
    response = client.get("/list_my_tools", headers=auth(tokens["a"]))
    assert response.status_code == 200
    names = {tool["name"] for tool in response.json()["result"]["tools"]}
    assert "get_assignment" not in names and "open_patient_visit" in names


def test_missing_badge_is_403_and_audited(setup) -> None:
    client, _, conn = setup
    response = client.post("/tools/get_assignment", json={"args": {}})
    assert response.status_code == 403
    assert response.json()["reason"] == "DENY_BAD_BADGE"
    assert (
        conn.execute("SELECT COUNT(*) FROM audit_log WHERE reason = 'DENY_BAD_BADGE'").fetchone()[0]
        == 1
    )


def test_pharmacist_flow_over_http(setup) -> None:
    client, tokens, _ = setup
    args = {"patient_id": "P004", "visit_id": "V-07"}
    plan = client.post(
        "/declare_plan",
        headers=auth(tokens["pharm"]),
        json={
            "task_id": "T-PH-V-07",
            "steps": [
                {"tool": "get_assignment", "args": args},
                {"tool": "dispense_kit", "args": args},
            ],
        },
    )
    assert plan.status_code == 200, plan.json()
    assert (
        client.post(
            "/tools/get_assignment", headers=auth(tokens["pharm"]), json={"args": args}
        ).status_code
        == 200
    )
    dispensed = client.post(
        "/tools/dispense_kit",
        headers=auth(tokens["pharm"]),
        json={"args": args, "idempotency_key": str(uuid.uuid4())},
    )
    assert dispensed.json()["result"]["kit_status"] == "dispensed"


def test_malformed_body_is_denied_not_crashed(setup) -> None:
    client, tokens, _ = setup
    response = client.post(
        "/tools/submit",
        headers={**auth(tokens["a"]), "Content-Type": "application/json"},
        content=b"{not json",
    )
    assert response.status_code == 403


def test_oversized_body_is_rejected(setup) -> None:
    client, tokens, _ = setup
    response = client.post("/tools/submit", headers=auth(tokens["a"]), content=b"x" * (65 * 1024))
    assert response.status_code == 413


def test_security_headers_present(setup) -> None:
    client, _, _ = setup
    response = client.get("/healthz")
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["x-frame-options"] == "DENY"


def test_dashboard_requires_login(setup) -> None:
    client, _, _ = setup
    assert client.get("/api/snapshot").status_code == 401
    bad = client.post("/auth/login", headers=CSRF, json={"username": "alice", "password": "no"})
    assert bad.status_code == 401
    no_csrf = client.post("/auth/login", json={"username": "alice", "password": "pw-a"})
    assert no_csrf.status_code == 400


def test_dashboard_snapshot_and_monitor_revoke(setup) -> None:
    client, tokens, _ = setup
    login = client.post("/auth/login", headers=CSRF, json={"username": "alice", "password": "pw-a"})
    assert login.status_code == 200
    snap = client.get("/api/snapshot").json()
    assert snap["chain"]["ok"] and snap["monitor"] == "monitor-alice"
    assert {a["agent_id"] for a in snap["agents"]} >= {"assessor-a", "pharm-1"}

    revoke = client.post(
        "/api/monitor/revoke_badge",
        headers=CSRF,
        json={
            "args": {"agent_id": "assessor-a", "reason": "demo"},
            "idempotency_key": str(uuid.uuid4()),
        },
    )
    assert revoke.status_code == 200, revoke.json()
    after = client.get("/list_my_tools", headers=auth(tokens["a"]))
    assert after.json()["reason"] == "DENY_REVOKED"
    statuses = {a["agent_id"]: a["status"] for a in client.get("/api/snapshot").json()["agents"]}
    assert statuses["assessor-a"] == "revoked"


def test_monitor_action_requires_csrf_header(setup) -> None:
    client, _, _ = setup
    client.post("/auth/login", headers=CSRF, json={"username": "alice", "password": "pw-a"})
    response = client.post("/api/monitor/revoke_badge", json={"args": {}})
    assert response.status_code == 400


def test_login_is_throttled(setup) -> None:
    client, _, _ = setup
    for _ in range(5):
        client.post("/auth/login", headers=CSRF, json={"username": "bob", "password": "x"})
    blocked = client.post("/auth/login", headers=CSRF, json={"username": "bob", "password": "pw-b"})
    assert blocked.status_code == 429


def test_dashboard_page_and_assets_served(setup) -> None:
    client, _, _ = setup
    assert "Badge" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200
