"""Human approval gates and security escalations."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from tests.ward.test_ward import Caller, run_plan, rx_plan
from ward import crypto
from ward.attestation import badge_agent_path, measure_source_file
from ward.config import ApprovalsConfig, load_config
from ward.gateway import Credential, Denied, Gateway

CFG = load_config()


@pytest.fixture
def gw() -> Gateway:
    # Fresh config per test so timeout monkeypatches cannot leak across cases.
    g = Gateway(load_config(), sleep=lambda _s: time.sleep(0.01 if _s else 0))
    g.settings["step_delay_ms"] = 0
    g.settings["approvals_enabled"] = True
    return g


def _approve_when_pending(gw: Gateway, operator: str = "alice", approve: bool = True) -> None:
    for _ in range(200):
        rows = gw.conn.execute(
            "SELECT approval_id FROM approvals WHERE status = 'pending'"
        ).fetchall()
        if rows:
            gw.decide_approval(rows[0]["approval_id"], approve, operator, "" if approve else "no")
            return
        time.sleep(0.02)
    raise AssertionError("no pending approval appeared")


def test_approve_path(gw: Gateway) -> None:
    master = Caller(gw, CFG.master_role)
    steps = rx_plan("P003", "amoxicillin", 1500)
    threading.Thread(target=_approve_when_pending, args=(gw,), daemon=True).start()
    run_id, results = run_plan(gw, master, steps)
    assert results[-1]["tool"] == "draft_order"
    assert results[-1]["result"]["status"] in ("drafted", "blocked")
    row = gw.conn.execute(
        "SELECT status, operator FROM approvals WHERE run_id = ?", (run_id,)
    ).fetchone()
    assert row["status"] == "approved"
    assert row["operator"] == "alice"


def test_deny_path(gw: Gateway) -> None:
    master = Caller(gw, CFG.master_role)
    steps = rx_plan("P003", "amoxicillin", 1500)
    threading.Thread(target=_approve_when_pending, args=(gw, "bob", False), daemon=True).start()
    run_id = gw.start_run(master("start_run"), "deny-test")
    plan = gw.declare_plan(master("declare_plan"), run_id, steps)
    with pytest.raises(Denied) as exc:
        for lease in plan["leases"]:
            gw.consult(master("consult"), lease["lease_id"])
    assert exc.value.reason == "DENY_APPROVAL_DENIED"


def test_timeout_path(gw: Gateway) -> None:
    object.__setattr__(
        gw.config,
        "approvals",
        ApprovalsConfig(timeout_seconds=0, rules=gw.config.approvals.rules),
    )
    master = Caller(gw, CFG.master_role)
    steps = rx_plan("P003", "amoxicillin", 1500)
    run_id = gw.start_run(master("start_run"), "timeout-test")
    plan = gw.declare_plan(master("declare_plan"), run_id, steps)
    with pytest.raises(Denied) as exc:
        for lease in plan["leases"]:
            gw.consult(master("consult"), lease["lease_id"])
    assert exc.value.reason == "DENY_APPROVAL_TIMEOUT"


def test_watchdog_ignores_mcp_session_rows(gw: Gateway) -> None:
    """[mcp] session rows are not watchdog targets; close_mcp_sessions retires them."""
    gw.settings["watchdog_seconds"] = 0.05
    gw.settings["approvals_enabled"] = False
    aid, secret = gw.provision("clinician_assistant")
    key = crypto.AgentKey()
    gw.authenticate(
        aid,
        secret,
        key.public_pem,
        key.proof(secret, "authenticate"),
        measure_source_file(badge_agent_path()),
    )
    run_id = "MCP-IDLE1"
    gw.conn.execute(
        "INSERT INTO runs (run_id, master_id, prompt, status, created_ms, last_progress_ms, flagged)"
        " VALUES (?, ?, '[mcp] CursorAgent1', 'running', 1, 1, 0)",
        (run_id, aid),
    )
    for _ in range(10):
        gw.watchdog_tick()
    assert (
        gw.conn.execute("SELECT status FROM agents WHERE agent_id = ?", (aid,)).fetchone()[
            "status"
        ]
        == "active"
    )
    assert gw.close_mcp_sessions() == 1
    assert (
        gw.conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()["status"]
        == "done"
    )


def test_watchdog_paused_while_awaiting(gw: Gateway) -> None:
    gw.settings["watchdog_seconds"] = 0.05
    master = Caller(gw, CFG.master_role)
    steps = rx_plan("P003", "amoxicillin", 1500)
    run_id = gw.start_run(master("start_run"), "watchdog-pause")
    plan = gw.declare_plan(master("declare_plan"), run_id, steps)
    # Run prerequisite leases first (no approval), then hold on draft_order.
    for lease in plan["leases"][:-1]:
        gw.consult(master("consult"), lease["lease_id"])
    draft_lease = plan["leases"][-1]["lease_id"]

    def consult_draft() -> None:
        with pytest.raises(Denied):
            gw.consult(master("consult"), draft_lease)

    t = threading.Thread(target=consult_draft, daemon=True)
    t.start()
    paused = None
    for _ in range(200):
        paused = gw.conn.execute(
            "SELECT approval_paused FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        pending = gw.conn.execute("SELECT 1 FROM approvals WHERE status = 'pending'").fetchone()
        if paused and paused["approval_paused"] and pending:
            break
        time.sleep(0.02)
    assert paused is not None and paused["approval_paused"] == 1
    time.sleep(0.2)
    for _ in range(10):
        gw.watchdog_tick()
    status = gw.conn.execute(
        "SELECT status FROM agents WHERE agent_id = ?", (master.agent_id,)
    ).fetchone()["status"]
    assert status == "active"
    row = gw.conn.execute("SELECT approval_id FROM approvals WHERE status = 'pending'").fetchone()
    gw.decide_approval(row["approval_id"], False, "alice", "cleanup")
    t.join(timeout=2)


def test_orchestrator_waits_for_approval(gw: Gateway) -> None:
    """Approvals still gate high-impact tools when the orchestrator (not MCP) consults."""
    master = Caller(gw, CFG.master_role)
    steps = rx_plan("P003", "amoxicillin", 1500)
    run_id = gw.start_run(master("start_run"), "mcp-approval-via-orch")
    plan = gw.declare_plan(master("declare_plan"), run_id, steps)
    for lease in plan["leases"][:-1]:
        gw.consult(master("consult"), lease["lease_id"])
    threading.Thread(target=_approve_when_pending, args=(gw,), daemon=True).start()
    out = gw.consult(master("consult"), plan["leases"][-1]["lease_id"])
    assert out["result"]["status"] in ("drafted", "blocked")


@pytest.mark.parametrize(
    "trigger_setup",
    [
        "stolen_badge",
        "role_violation",
        "attestation_failure",
        "watchdog",
        "repeated_denials",
    ],
)
def test_escalation_on_security_revoke(gw: Gateway, trigger_setup: str) -> None:
    gw.settings["approvals_enabled"] = False
    if trigger_setup == "stolen_badge":
        master = Caller(gw, CFG.master_role)
        with pytest.raises(Denied):
            gw.verify(Credential(master.token, None), "capabilities")
    elif trigger_setup == "role_violation":
        aid, secret = gw.provision("scheduling_assistant")
        key = crypto.AgentKey()
        session = gw.authenticate(
            aid,
            secret,
            key.public_pem,
            key.proof(secret, "authenticate"),
            measure_source_file(badge_agent_path()),
        )
        token = session["token"]
        op = "mcp:tools/call:draft_order"
        badge = gw.verify(Credential(token, key.proof(token, op)), op)
        with pytest.raises(Denied):
            gw.mcp_call_tool_as(
                badge,
                "draft_order",
                {"patient_id": "P001", "drug": "amoxicillin", "daily_dose_mg": 500},
            )
    elif trigger_setup == "attestation_failure":
        results = gw.tampered_agent_test()
        assert results[0]["result"] == "DENY_ATTESTATION"
    elif trigger_setup == "watchdog":
        gw.settings["watchdog_seconds"] = 0.05
        master = Caller(gw, CFG.master_role)
        gw.start_run(master("start_run"), "stuck")
        # Force last_progress into the past.
        gw.conn.execute(
            "UPDATE runs SET last_progress_ms = ? WHERE status = 'running'",
            (int(time.time() * 1000) - 5000,),
        )
        gw.watchdog_tick()
    else:  # repeated_denials
        master = Caller(gw, CFG.master_role)
        # Plan rejections don't count against the badge; failed consults do.
        for _ in range(int(CFG.run["max_denied_calls_per_badge"])):
            with pytest.raises(Denied):
                gw.consult(master("consult"), "L-DOES-NOT-EXIST")

    open_esc = gw.conn.execute(
        "SELECT trigger_reason, status, page_id FROM escalations WHERE status = 'open'"
    ).fetchall()
    assert open_esc, f"expected escalation for {trigger_setup}"
    assert open_esc[0]["trigger_reason"] == trigger_setup
    assert open_esc[0]["page_id"]  # CareTeam page fired
    esc_id = gw.conn.execute("SELECT escalation_id FROM escalations").fetchone()[0]
    assert gw.acknowledge_escalation(esc_id, "alice")
