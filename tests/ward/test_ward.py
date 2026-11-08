"""Ward: the master agent, the gateway, and the specialists, with a fake LLM."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from server.ward_app import create_app
from tests.ward.fakes import FakeLLM, done_turn, plan_turn, text_turn
from ward import crypto
from ward.attestation import master_functions, measure
from ward.config import ConfigError, load_config
from ward.gateway import Credential, Denied, Gateway
from ward.master import MasterAgent, _example_plan
from ward.specialist import OfferRefused
from ward.tools import TOOLS

CFG = load_config()


class Caller:
    """A logged-in agent for tests: its own key, a key-bound badge, signed calls."""

    def __init__(self, gw: Gateway, role: str, functions: dict | None = None) -> None:
        self.agent_id, secret = gw.provision(role)
        self.key = crypto.AgentKey()
        if functions is None:
            functions = (
                master_functions()
                if role == CFG.master_role
                else {t: TOOLS[t] for t in CFG.roles[role].tools}
            )
        session = gw.authenticate(
            self.agent_id,
            secret,
            self.key.public_pem,
            self.key.proof(secret, "authenticate"),
            measure(role, CFG, functions),
        )
        self.token = session["token"]
        self.session = session

    def __call__(self, op: str) -> Credential:
        return Credential(self.token, self.key.proof(self.token, op))


def rx_plan(patient: str, drug: str, dose: int, renal: bool = True) -> list[dict[str, Any]]:
    steps = [
        {"agent": "MedHistoryAgent", "tool": "get_allergies", "args": {"patient_id": patient}},
        {
            "agent": "MedHistoryAgent",
            "tool": "get_active_medications",
            "args": {"patient_id": patient},
        },
        {"agent": "PharmacyAgent", "tool": "lookup_drug", "args": {"drug": drug}},
        {
            "agent": "PharmacyAgent",
            "tool": "check_interactions",
            "args": {"patient_id": patient, "drug": drug},
        },
    ]
    if renal:
        steps.append(
            {"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": patient}}
        )
    steps.append(
        {
            "agent": "PrescriberAgent",
            "tool": "draft_order",
            "args": {"patient_id": patient, "drug": drug, "daily_dose_mg": dose},
        }
    )
    return steps


@pytest.fixture
def gw() -> Gateway:
    return Gateway(CFG, sleep=lambda s: None)


@pytest.fixture
def master(gw: Gateway) -> tuple[Gateway, str]:
    return gw, Caller(gw, CFG.master_role)


def run_plan(gw: Gateway, token: Caller, steps: list[dict]) -> tuple[str, list[dict]]:
    run_id = gw.start_run(token("start_run"), "test")
    plan = gw.declare_plan(token("declare_plan"), run_id, steps)
    return run_id, [gw.consult(token("consult"), lease["lease_id"]) for lease in plan["leases"]]


# ---- identity ----------------------------------------------------------------------------


def labs_login(gw: Gateway, agent_id: str, secret: str, key: crypto.AgentKey) -> dict:
    fns = {t: TOOLS[t] for t in CFG.roles["labs"].tools}
    return gw.authenticate(
        agent_id,
        secret,
        key.public_pem,
        key.proof(secret, "authenticate"),
        measure("labs", CFG, fns),
    )


def test_instances_get_numbered_names_and_their_own_badges(gw: Gateway) -> None:
    a, b = Caller(gw, "pharmacy"), Caller(gw, "pharmacy")
    assert (a.agent_id, b.agent_id) == ("PharmacyAgent1", "PharmacyAgent2")
    assert a.session["jti"] != b.session["jti"]
    assert a.session["seal_key"] != b.session["seal_key"]


def test_bad_secret_and_revoked_agents_cannot_authenticate(gw: Gateway) -> None:
    agent_id, secret = gw.provision("labs")
    key = crypto.AgentKey()
    with pytest.raises(Denied, match="DENY_BAD_CREDENTIALS"):
        labs_login(gw, agent_id, "nope", key)
    gw.revoke(agent_id, "test", "test")
    with pytest.raises(Denied, match="DENY_REVOKED"):
        labs_login(gw, agent_id, secret, key)


def test_badge_is_bound_to_the_agents_key(gw: Gateway) -> None:
    session = Caller(gw, "labs").session
    claims = gw.keys.read_badge(session["token"])
    assert len(claims["cnf"]["jkt"]) == 64 and claims["att"]


def test_key_possession_is_proven_at_login(gw: Gateway) -> None:
    agent_id, secret = gw.provision("labs")
    mine, someone_elses = crypto.AgentKey(), crypto.AgentKey()
    fns = {t: TOOLS[t] for t in CFG.roles["labs"].tools}
    with pytest.raises(Denied, match="DENY_POP_MISMATCH"):
        gw.authenticate(
            agent_id,
            secret,
            mine.public_pem,
            someone_elses.proof(secret, "authenticate"),
            measure("labs", CFG, fns),
        )


def test_tampered_code_gets_no_badge_and_is_quarantined(gw: Gateway) -> None:
    results = gw.tampered_agent_test()
    assert results[0]["result"] == "DENY_ATTESTATION"
    row = gw.conn.execute(
        "SELECT status, end_reason FROM agents WHERE agent_id = 'MedHistoryAgent1'"
    ).fetchone()
    assert row["status"] == "revoked" and "attestation" in row["end_reason"]
    assert gw.conn.execute("SELECT COUNT(*) FROM badges").fetchone()[0] == 0


def test_a_stolen_badge_is_useless_without_the_key(master) -> None:  # noqa: ANN001
    gw, me = master
    captured = me("capabilities")
    gw.capabilities(captured)  # the real call
    results = gw.steal_badge_test(me.token, captured)
    assert [r["result"] for r in results] == [
        "DENY_POP_REPLAY",
        "DENY_POP_MISMATCH",
        "DENY_POP_MISSING",
    ]
    with pytest.raises(Denied, match="DENY_REVOKED"):
        gw.check_badge(me.token)  # treated as compromised


def test_a_proof_is_only_good_for_its_operation(master) -> None:  # noqa: ANN001
    gw, me = master
    with pytest.raises(Denied, match="DENY_POP_MISMATCH"):
        gw.start_run(me("capabilities"), "t")


def test_only_the_master_can_delegate_and_trying_revokes(gw: Gateway) -> None:
    labs = Caller(gw, "labs")
    with pytest.raises(Denied, match="DENY_NOT_MASTER"):
        gw.declare_plan(labs("declare_plan"), "RUN-X", rx_plan("P001", "acetaminophen", 1000))
    assert (
        gw.conn.execute(
            "SELECT status FROM agents WHERE agent_id = ?", (labs.agent_id,)
        ).fetchone()[0]
        == "revoked"
    )


def test_specialist_refuses_a_delegation_not_signed_by_the_gateway(gw: Gateway) -> None:
    results = gw.rogue_test()
    assert [r["result"] for r in results] == ["DENY_NOT_MASTER", "DENY_BAD_DELEGATION"]


def test_delegation_for_another_instance_is_refused(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(
        token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000)[:1]
    )
    lease = gw.conn.execute(
        "SELECT * FROM leases WHERE lease_id = ?", (plan["leases"][0]["lease_id"],)
    ).fetchone()
    a = gw._instance_for(run_id, "med_history")  # noqa: SLF001
    other_id, other_secret = gw.provision("med_history", run_id)
    from ward.specialist import SpecialistInstance

    other = SpecialistInstance(
        other_id, "med_history", other_secret, CFG, gw.keys.delegation_public_pem, CFG.master_role
    )
    other.login(gw)
    master_badge = gw.check_badge(token.token)
    offer, challenge = gw._offer(master_badge, lease, a, {"patient_id": "P001"}, {})  # noqa: SLF001
    with pytest.raises(OfferRefused, match="DENY_BAD_DELEGATION"):
        other.handle_offer(offer, challenge)  # token's audience is `a`, not `other`


def test_sealed_consult_only_opens_with_the_target_key() -> None:
    keys = crypto.KeyRing()
    seal_a, _ = keys.instance_keys("A", "jti-a")
    seal_b, _ = keys.instance_keys("B", "jti-b")
    box = crypto.seal(seal_a, {"x": 1}, "L-1")
    assert crypto.open_sealed(seal_a, box, "L-1") == {"x": 1}
    with pytest.raises(Exception):  # noqa: B017
        crypto.open_sealed(seal_b, box, "L-1")
    with pytest.raises(Exception):  # noqa: B017
        crypto.open_sealed(seal_a, box, "L-2")


# ---- plans --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("steps", "reason"),
    [
        (
            [{"agent": "PharmacyAgent", "tool": "get_allergies", "args": {"patient_id": "P001"}}],
            "DENY_WRONG_AGENT",
        ),
        (
            [
                {
                    "agent": "PrescriberAgent",
                    "tool": "draft_order",
                    "args": {"patient_id": "P001", "drug": "ibuprofen", "daily_dose_mg": 400},
                }
            ],
            "DENY_PRECONDITION",
        ),
        (
            [{"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": "*"}}],
            "DENY_SCHEMA",
        ),
        (
            [{"agent": "PharmacyAgent", "tool": "lookup_drug", "args": {"drug": "fentanyl"}}],
            "DENY_SCHEMA",
        ),
        (
            [{"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": "P001"}}]
            * 2,
            "DENY_LOOP",
        ),
        ([{"agent": "RootAgent", "tool": "x", "args": {}}], "DENY_UNKNOWN_AGENT"),
        ([], "DENY_PLAN_INVALID"),
    ],
)
def test_bad_plans_are_rejected(master, steps, reason) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    with pytest.raises(Denied) as caught:
        gw.declare_plan(token("declare_plan"), run_id, steps)
    assert caught.value.reason == reason


def test_piped_inputs_must_match_shared_args(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    steps = rx_plan("P001", "ibuprofen", 400)
    steps[3]["args"]["patient_id"] = "P002"  # interactions for a different patient's meds
    with pytest.raises(Denied, match="DENY_PRECONDITION"):
        gw.declare_plan(token("declare_plan"), run_id, steps)


def test_three_denials_revoke_the_master(master) -> None:  # noqa: ANN001
    gw, token = master
    gw.start_run(token("start_run"), "t")
    for _ in range(3):
        with pytest.raises(Denied):
            gw.consult(token("consult"), "L-NOPE")  # misuse at run time counts
    with pytest.raises(Denied, match="DENY_REVOKED"):
        gw.check_badge(token.token)


def test_allergy_blocks_the_order(master) -> None:  # noqa: ANN001
    gw, token = master
    _, results = run_plan(gw, token, rx_plan("P003", "amoxicillin", 1500))
    assert results[-1]["result"]["status"] == "blocked"
    assert results[-1]["result"]["block_reasons"] == ["allergy"]


def test_safe_order_is_drafted_by_a_fresh_prescriber_instance(master) -> None:  # noqa: ANN001
    gw, token = master
    _, results = run_plan(gw, token, rx_plan("P003", "doxycycline", 200))
    assert results[-1]["result"]["status"] == "drafted"
    assert results[-1]["agent"] == "PrescriberAgent1"


def test_major_interaction_and_renal_block(master) -> None:  # noqa: ANN001
    gw, token = master
    _, results = run_plan(gw, token, rx_plan("P008", "ibuprofen", 1200))
    assert set(results[-1]["result"]["block_reasons"]) == {"major_interaction", "renal"}


def test_injected_record_never_leaves_the_specialist(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(token("declare_plan"), run_id, rx_plan("P007", "acetaminophen", 1000))
    gw.consult(token("consult"), plan["leases"][0]["lease_id"])
    with pytest.raises(Denied, match="DENY_OUTPUT_SCHEMA"):
        gw.consult(token("consult"), plan["leases"][1]["lease_id"])
    stored = gw.conn.execute(
        "SELECT result_json FROM leases WHERE lease_id = ?", (plan["leases"][1]["lease_id"],)
    ).fetchone()[0]
    assert stored is None


def test_steps_must_run_in_order(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000))
    with pytest.raises(Denied, match="DENY_OFF_PLAN"):
        gw.consult(token("consult"), plan["leases"][2]["lease_id"])


def test_a_lease_is_single_use(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(
        token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000)[:1]
    )
    gw.consult(token("consult"), plan["leases"][0]["lease_id"])
    with pytest.raises(Denied, match="DENY_LEASE_USED"):
        gw.consult(token("consult"), plan["leases"][0]["lease_id"])


# ---- revocation mid-call ---------------------------------------------------------------------


def revoke_during_sleep(gw: Gateway, pick) -> None:  # noqa: ANN001
    """Make the gateway's pacing sleep revoke an agent the first time it's called."""
    fired = []

    def sleep(_: float) -> None:
        if not fired:
            fired.append(True)
            gw.revoke(pick(), "operator:test", "mid-call")

    gw._sleep = sleep  # noqa: SLF001


def test_revoked_specialist_is_replaced_by_a_fresh_instance(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(
        token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000)[:1]
    )
    revoke_during_sleep(gw, lambda: "MedHistoryAgent1")
    out = gw.consult(token("consult"), plan["leases"][0]["lease_id"])
    assert out["agent"] == "MedHistoryAgent2"


def test_revoked_specialist_fails_the_step_without_replacement(master) -> None:  # noqa: ANN001
    gw, token = master
    gw.settings["replace_revoked_specialists"] = False
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(
        token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000)[:1]
    )
    revoke_during_sleep(gw, lambda: "MedHistoryAgent1")
    with pytest.raises(Denied, match="DENY_REVOKED"):
        gw.consult(token("consult"), plan["leases"][0]["lease_id"])


def test_revoking_the_master_aborts_the_run_and_retires_specialists(master) -> None:  # noqa: ANN001
    gw, token = master
    run_id = gw.start_run(token("start_run"), "t")
    plan = gw.declare_plan(token("declare_plan"), run_id, rx_plan("P001", "acetaminophen", 1000))
    master_id = gw.check_badge(token.token).agent_id
    revoke_during_sleep(gw, lambda: master_id)
    with pytest.raises(Denied):
        gw.consult(token("consult"), plan["leases"][0]["lease_id"])
    run = gw.conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert run["status"] == "aborted"
    statuses = {
        r[0] for r in gw.conn.execute("SELECT status FROM leases WHERE run_id = ?", (run_id,))
    }
    assert "active" not in statuses and "used" not in statuses
    assert (
        gw.conn.execute(
            "SELECT COUNT(*) FROM agents WHERE run_id = ? AND status = 'active'", (run_id,)
        ).fetchone()[0]
        == 0
    )


def test_watchdog_revokes_a_master_with_no_progress(master) -> None:  # noqa: ANN001
    gw, token = master
    gw.settings["watchdog_seconds"] = 0.05
    run_id = gw.start_run(token("start_run"), "t")
    time.sleep(0.1)
    gw.heartbeat(token("heartbeat"), run_id)  # pinging isn't progress
    gw.watchdog_tick()
    with pytest.raises(Denied, match="DENY_REVOKED"):
        gw.heartbeat(token("heartbeat"), run_id)


def test_audit_chain_detects_tampering(master) -> None:  # noqa: ANN001
    gw, token = master
    run_plan(gw, token, rx_plan("P003", "doxycycline", 200))
    assert gw.verify_chain()[0]
    with pytest.raises(Exception, match="append-only"):
        gw.conn.execute("UPDATE audit SET summary = 'nothing happened' WHERE seq = 3")


# ---- the master agent -------------------------------------------------------------------------


def test_master_end_to_end_with_a_fake_model(gw: Gateway) -> None:
    llm = FakeLLM(
        [
            plan_turn(rx_plan("P003", "amoxicillin", 1500)),
            done_turn(),
            text_turn("Blocked: penicillin allergy."),
        ]
    )
    agent = MasterAgent(gw, llm, "fake", sleep=lambda s: None)
    run_id = agent.handle("antibiotic for P003")
    run = gw.conn.execute("SELECT status, answer FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert (run["status"], run["answer"]) == ("done", "Blocked: penicillin allergy.")
    # The answer call saw only typed results, never a raw record.
    answer_prompt = llm.requests[-1]["messages"][-1]["content"]
    assert '"block_reasons": [\n   "allergy"' in answer_prompt or "allergy" in answer_prompt


def test_master_gets_one_retry_after_a_rejected_plan(gw: Gateway) -> None:
    bad = [{"agent": "PharmacyAgent", "tool": "get_allergies", "args": {"patient_id": "P002"}}]
    good = [{"agent": "MedHistoryAgent", "tool": "get_allergies", "args": {"patient_id": "P002"}}]
    llm = FakeLLM([plan_turn(bad), plan_turn(good), done_turn(), text_turn("Sulfa allergy.")])
    agent = MasterAgent(gw, llm, "fake", sleep=lambda s: None)
    run_id = agent.handle("allergies for P002")
    assert (
        gw.conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]
        == "done"
    )
    feedback = llm.requests[1]["messages"][-1]["content"]
    assert "DENY_WRONG_AGENT" in feedback


def test_a_revoked_master_is_replaced_by_a_new_identity(gw: Gateway) -> None:
    agent = MasterAgent(gw, FakeLLM([]), "fake")
    agent.ensure_identity()
    first = agent.agent_id
    gw.revoke(first, "test", "test")
    agent.ensure_identity()
    assert (first, agent.agent_id) == ("OrchestratorAgent1", "OrchestratorAgent2")


def test_planner_prompt_comes_from_policy(master) -> None:  # noqa: ANN001
    gw, token = master
    caps = gw.capabilities(token("capabilities"))
    assert {c["tool"] for c in caps} == set(CFG.tools)
    example = _example_plan(caps)
    assert "steps" in example


def test_config_rejects_a_master_that_owns_tools(tmp_path) -> None:  # noqa: ANN001
    text = (load_config.__globals__["DEFAULT_PATH"]).read_text()
    broken = text.replace("    master: true\n", "    master: true\n    tools: [get_allergies]\n", 1)
    path = tmp_path / "bad.yaml"
    path.write_text(broken)
    with pytest.raises(ConfigError):
        load_config(path)


# ---- web app ----------------------------------------------------------------------------------


def test_console_login_chat_and_revoke() -> None:
    llm = FakeLLM(
        [plan_turn(rx_plan("P003", "doxycycline", 200)), done_turn(), text_turn("Drafted.")]
    )
    app = create_app(
        llm=llm, model="fake", operators={"alice": "pw"}, watchdog=False, sleep=lambda s: None
    )
    client = TestClient(app)
    h = {"X-Ward": "1"}
    assert client.get("/api/state").status_code == 401
    assert (
        client.post(
            "/api/login", json={"username": "alice", "password": "bad"}, headers=h
        ).status_code
        == 401
    )
    assert client.post(
        "/api/login", json={"username": "alice", "password": "pw"}, headers=h
    ).json()["ok"]
    assert (
        client.post("/api/chat", json={"prompt": "doxy for P003"}).status_code == 400
    )  # no CSRF header
    assert client.post("/api/chat", json={"prompt": "doxy for P003"}, headers=h).json()["ok"]
    app.state.console.thread.join(timeout=10)
    state = client.get("/api/state").json()
    assert state["runs"][0]["status"] == "done" and state["chain"]["ok"]
    master = state["master"]
    assert client.post("/api/revoke", json={"agent_id": master}, headers=h).json()["ok"]
    assert client.post("/api/rogue", headers=h).json()["ok"]
    assert client.post("/api/reset", headers=h).json()["ok"]


def test_delegation_tokens_use_ed25519(gw: Gateway) -> None:
    token = gw.keys.sign_delegation({"sub": "a", "aud": "b", "exp": 9999999999})
    assert jwt.get_unverified_header(token)["alg"] == "EdDSA"


def test_follow_up_plans_use_earlier_results(gw: Gateway) -> None:
    """Name -> id, then id -> meds, then meds -> coverage: three plans, each built from
    the typed results of the one before."""
    find = [{"agent": "RegistrationAgent", "tool": "find_patient", "args": {"name": "Jordan"}}]
    meds = [
        {
            "agent": "MedHistoryAgent",
            "tool": "get_active_medications",
            "args": {"patient_id": "P002"},
        }
    ]
    cover = [
        {
            "agent": "InsuranceAgent",
            "tool": "check_coverage",
            "args": {"patient_id": "P002", "drug": d},
        }
        for d in ("warfarin", "lisinopril")
    ]
    llm = FakeLLM([plan_turn(find), plan_turn(meds), plan_turn(cover), text_turn("$20/month.")])
    agent = MasterAgent(gw, llm, "fake", sleep=lambda s: None)
    run_id = agent.handle("What does Jordan pay per month?")
    run = gw.conn.execute("SELECT status, plans FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    assert (run["status"], run["plans"]) == ("done", 3)
    copays = [
        json.loads(r[0])["monthly_copay_usd"]
        for r in gw.conn.execute(
            "SELECT result_json FROM leases WHERE run_id = ? AND tool = 'check_coverage'", (run_id,)
        )
    ]
    assert copays == [10, 10]
    second_call = llm.requests[1]["messages"][-1]["content"]
    assert '"patient_id": "P002"' in second_call  # the follow-up saw the typed lookup result


def test_master_explains_when_it_cannot_plan(gw: Gateway) -> None:
    explain = SimpleNamespace(
        content=None,
        tool_calls=[
            SimpleNamespace(
                id="c",
                function=SimpleNamespace(
                    name="answer_directly",
                    arguments='{"answer": "No specialist reports drug prices."}',
                ),
            )
        ],
    )
    agent = MasterAgent(gw, FakeLLM([explain]), "fake", sleep=lambda s: None)
    run_id = agent.handle("What's the cash price of apixaban?")
    answer = gw.conn.execute("SELECT answer FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]
    assert answer == "No specialist reports drug prices."


def test_after_a_rejected_plan_the_master_must_replan(gw: Gateway) -> None:
    bad = [
        {
            "agent": "PharmacyAgent",
            "tool": "check_coverage",
            "args": {"patient_id": "P002", "drug": "warfarin"},
        }
    ]
    good = [
        {
            "agent": "InsuranceAgent",
            "tool": "check_coverage",
            "args": {"patient_id": "P002", "drug": "warfarin"},
        }
    ]
    llm = FakeLLM([plan_turn(bad), plan_turn(good), done_turn(), text_turn("$10/month.")])
    agent = MasterAgent(gw, llm, "fake", sleep=lambda s: None)
    run_id = agent.handle("coverage for warfarin, P002")
    retry_tools = [t["function"]["name"] for t in llm.requests[1]["tools"]]
    assert retry_tools == ["declare_plan"]  # giving up isn't an option after a rejection
    assert (
        gw.conn.execute("SELECT status FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]
        == "done"
    )


# ---- model-output robustness -------------------------------------------------------------


def msg(content: str = "", calls: list[tuple[str, str]] | None = None) -> SimpleNamespace:
    tool_calls = [
        SimpleNamespace(id=f"c{i}", function=SimpleNamespace(name=n, arguments=a))
        for i, (n, a) in enumerate(calls or [])
    ]
    return SimpleNamespace(content=content, tool_calls=tool_calls or None)


STEP = {"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": "P001"}}


@pytest.mark.parametrize(
    "message",
    [
        msg(calls=[("declare_plan", json.dumps({"steps": [STEP]}))]),
        msg(calls=[("declare_plan", json.dumps([STEP]))]),
        msg(
            "<tool_call>"
            + json.dumps({"name": "declare_plan", "arguments": {"steps": [STEP]}})
            + "</tool_call>"
        ),
        msg(f"Here's my plan:\n```json\n{json.dumps({'steps': [STEP]})}\n```"),
        msg(json.dumps({"name": "declare_plan", "parameters": json.dumps({"steps": [STEP]})})),
    ],
)
def test_plans_are_recognized_in_the_shapes_small_models_use(message) -> None:  # noqa: ANN001
    from ward.master import _extract_steps

    kind, steps = _extract_steps(message)
    assert kind == "plan" and steps[0]["tool"] == "get_renal_function"


def test_answer_and_garbage_are_told_apart() -> None:
    from ward.master import _extract_steps

    assert _extract_steps(msg(calls=[("answer_directly", '{"answer": "No prices."}')])) == (
        "answer",
        "No prices.",
    )
    assert _extract_steps(msg("hmm, let me think")) == ("none", "hmm, let me think")


def test_missing_prerequisites_are_filled_from_policy(master) -> None:  # noqa: ANN001
    from ward.master import _complete_plan, _normalize_steps

    gw, me = master
    caps = gw.capabilities(me("capabilities"))
    lonely = [
        {
            "tool": "draft_order",
            "args": {"patient_id": "P003", "drug": "doxycycline", "daily_dose_mg": 200},
        }
    ]
    steps, added = _complete_plan(_normalize_steps(lonely, caps), caps, [])
    tools = [s["tool"] for s in steps]
    assert tools[-1] == "draft_order" and added == 5
    assert tools.index("get_active_medications") < tools.index("check_interactions")
    run_id = gw.start_run(me("start_run"), "t")
    plan = gw.declare_plan(me("declare_plan"), run_id, steps)  # the gateway accepts it
    assert len(plan["leases"]) == 6


def test_a_wrong_agent_is_not_silently_fixed(master) -> None:  # noqa: ANN001
    from ward.master import _normalize_steps

    gw, me = master
    caps = gw.capabilities(me("capabilities"))
    wrong = [{"agent": "PharmacyAgent", "tool": "get_allergies", "args": {"patient_id": "P002"}}]
    assert _normalize_steps(wrong, caps)[0]["agent"] == "PharmacyAgent"


def test_few_shot_examples_are_valid_under_the_policy(gw: Gateway) -> None:
    """Every worked example in the policy file must pass the gateway as written."""
    examples = CFG.master["few_shot"]
    assert examples
    for ex in examples:
        turns = [plan_turn(p) for p in ex.get("plans", [])]
        if "answer" in ex:
            turns = [msg(calls=[("answer_directly", json.dumps({"answer": ex["answer"]}))])]
        agent = MasterAgent(
            gw, FakeLLM(turns + [done_turn(), text_turn("ok")]), "fake", sleep=lambda s: None
        )
        run_id = agent.handle(ex["request"])
        row = gw.conn.execute(
            "SELECT status, plans FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        assert row["status"] == "done", ex["request"]
        assert row["plans"] == len(ex.get("plans", [])), ex["request"]


def test_a_nudge_rescues_a_prose_reply(gw: Gateway) -> None:
    llm = FakeLLM(
        [
            text_turn("Sure! I'd check the kidneys."),
            plan_turn(
                [
                    {
                        "agent": "LabsAgent",
                        "tool": "get_renal_function",
                        "args": {"patient_id": "P004"},
                    }
                ]
            ),
            done_turn(),
            text_turn("Severe."),
        ]
    )
    run_id = MasterAgent(gw, llm, "fake", sleep=lambda s: None).handle("P004 kidneys?")
    assert (
        gw.conn.execute("SELECT answer FROM runs WHERE run_id = ?", (run_id,)).fetchone()[0]
        == "Severe."
    )
    raw = [e for e in gw.snapshot()["audit"] if e["kind"] == "PROGRESS" and e["detail"]]
    assert "check the kidneys" in raw[0]["detail"]["raw_model_reply"]


def test_rejected_plans_do_not_burn_the_masters_badge(master) -> None:  # noqa: ANN001
    gw, me = master
    run_id = gw.start_run(me("start_run"), "t")
    bad = [{"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": "nope"}}]
    for _ in range(3):
        with pytest.raises(Denied):
            gw.declare_plan(me("declare_plan"), run_id, bad)
    gw.check_badge(me.token)  # still valid


def test_ollama_native_client_sets_the_context_window() -> None:
    import httpx

    from ward.llm import OllamaNative

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "declare_plan", "arguments": {"steps": [STEP]}}}
                    ],
                }
            },
        )

    client = OllamaNative("http://ollama:11434/v1", num_ctx=8192)
    client._http = httpx.Client(
        base_url="http://ollama:11434", transport=httpx.MockTransport(handler)
    )  # noqa: SLF001
    reply = client.chat.completions.create(
        model="m",
        messages=[
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "x",
                        "type": "function",
                        "function": {"name": "f", "arguments": '{"a": 1}'},
                    }
                ],
            }
        ],
    )
    assert seen["options"]["num_ctx"] == 8192 and seen["stream"] is False
    assert seen["messages"][0]["tool_calls"][0]["function"]["arguments"] == {"a": 1}
    call = reply.choices[0].message.tool_calls[0]
    assert call.function.name == "declare_plan" and json.loads(call.function.arguments)["steps"]


@pytest.mark.parametrize("follow_up", ["empty", "repeat"])
def test_empty_or_repeated_follow_up_means_done(gw: Gateway, follow_up: str) -> None:
    first = [{"agent": "LabsAgent", "tool": "get_renal_function", "args": {"patient_id": "P004"}}]
    second = plan_turn([] if follow_up == "empty" else first)
    llm = FakeLLM([plan_turn(first), second, text_turn("Severe.")])
    run_id = MasterAgent(gw, llm, "fake", sleep=lambda s: None).handle("P004 kidneys?")
    run = gw.conn.execute(
        "SELECT status, plans, answer FROM runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    assert (run["status"], run["plans"], run["answer"]) == ("done", 1, "Severe.")
    assert not [p for p in gw.snapshot()["runs"][0]["plans"] if p["status"] == "denied"]


def test_groq_model_is_picked_from_what_the_key_can_use() -> None:
    from ward.llm import ReasoningAware, pick_groq_model

    models = SimpleNamespace(
        list=lambda: SimpleNamespace(
            data=[
                SimpleNamespace(id="whisper-large-v3"),
                SimpleNamespace(id="openai/gpt-oss-20b"),
                SimpleNamespace(id="llama-3.1-8b-instant"),
            ]
        )
    )
    client = SimpleNamespace(models=models)
    assert pick_groq_model(client, None) == "openai/gpt-oss-20b"
    assert pick_groq_model(client, "my-model") == "my-model"

    seen = {}
    inner = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: seen.update(kw)))
    )
    ReasoningAware(inner).chat.completions.create(model="openai/gpt-oss-20b", max_tokens=900)
    assert seen["reasoning_effort"] == "low" and seen["max_tokens"] == 4096


def test_rate_limited_model_falls_back_to_the_next_one() -> None:
    from ward.llm import ReasoningAware

    calls = []

    class Limited(Exception):
        status_code = 429

    def create(**kw: Any) -> str:
        calls.append(kw["model"])
        if kw["model"] == "openai/gpt-oss-120b":
            raise Limited("TPM")
        return "ok"

    inner = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    client = ReasoningAware(inner, ["openai/gpt-oss-120b", "openai/gpt-oss-20b"])
    assert client.chat.completions.create(model="openai/gpt-oss-120b", max_tokens=900) == "ok"
    assert calls == ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]
    assert client.last_model == "openai/gpt-oss-20b"


# ---- the extra agents ----------------------------------------------------------------------


def step(agent: str, tool: str, **args: Any) -> dict[str, Any]:
    return {"agent": agent, "tool": tool, "args": args}


def test_discharge_readiness_uses_piped_vitals_and_labs(master) -> None:  # noqa: ANN001
    gw, me = master
    _, results = run_plan(
        gw,
        me,
        [
            step("VitalsAgent", "get_vitals", patient_id="P004"),
            step("LabsAgent", "get_latest_labs", patient_id="P004"),
            step("DischargeAgent", "check_discharge_readiness", patient_id="P004"),
            step("CareTeamAgent", "get_care_team", patient_id="P004"),
        ],
    )
    discharge = results[2]["result"]
    assert discharge["ready"] is False
    assert set(discharge["blockers"]) == {"low_oxygen", "abnormal_potassium", "tachycardia"}
    assert results[3]["result"]["nurse"] == "RN-304"


def test_discharge_needs_vitals_and_labs_first(master) -> None:  # noqa: ANN001
    gw, me = master
    run_id = gw.start_run(me("start_run"), "t")
    with pytest.raises(Denied, match="DENY_PRECONDITION"):
        gw.declare_plan(
            me("declare_plan"),
            run_id,
            [step("DischargeAgent", "check_discharge_readiness", patient_id="P006")],
        )


def test_find_then_book_an_appointment_across_two_plans(master) -> None:  # noqa: ANN001
    gw, me = master
    run_id = gw.start_run(me("start_run"), "t")
    plan = gw.declare_plan(
        me("declare_plan"),
        run_id,
        [step("SchedulingAgent", "find_appointment_slots", specialty="cardiology", within_days=7)],
    )
    slots = gw.consult(me("consult"), plan["leases"][0]["lease_id"])["result"]["slots"]
    assert slots == ["SLOT-CAR-021", "SLOT-CAR-052"]
    plan = gw.declare_plan(
        me("declare_plan"),
        run_id,
        [step("SchedulingAgent", "book_appointment", patient_id="P005", slot_id=slots[0])],
    )
    booked = gw.consult(me("consult"), plan["leases"][0]["lease_id"])["result"]
    assert booked["booked"] and booked["appointment_id"].startswith("APT-")


def test_other_new_tools(master) -> None:  # noqa: ANN001
    gw, me = master
    _, r = run_plan(
        gw,
        me,
        [
            step("RegistrationAgent", "get_patient_profile", patient_id="P008"),
            step("MedHistoryAgent", "get_problem_list", patient_id="P008"),
            step("ImagingAgent", "get_imaging_results", patient_id="P008"),
            step("PharmacyAgent", "check_stock", drug="azithromycin"),
            step("InsuranceAgent", "request_prior_auth", patient_id="P004", drug="apixaban"),
            step("LabsAgent", "order_lab", patient_id="P008", test="cbc", urgency="stat"),
            step(
                "CareTeamAgent",
                "page_clinician",
                patient_id="P008",
                clinician="DR-204",
                urgency="urgent",
            ),
        ],
    )
    assert r[0]["result"] == {"age": 83, "insurance_plan": "standard", "primary_care": "DR-104"}
    assert "copd" in r[1]["result"]["conditions"]
    assert "pneumonia" in r[2]["result"]["findings"]
    assert r[3]["result"] == {"in_stock": False, "units": 0}
    assert r[4]["result"]["status"] == "pending_review"
    assert r[5]["result"]["eta_hours"] == 1
    assert r[6]["result"]["paged"] is True


def test_every_role_has_an_attested_build(gw: Gateway) -> None:
    assert set(gw.expected_measurements) == set(CFG.roles)


# ---- badge encryption and rotation ---------------------------------------------------------


def test_badges_are_encrypted_and_tamper_evident(gw: Gateway) -> None:
    import base64

    caller = Caller(gw, "labs")
    token = caller.token
    assert token.startswith("wb1.")
    raw = base64.urlsafe_b64decode(token[4:] + "=" * (-len(token[4:]) % 4))
    assert b"LabsAgent" not in raw and b"labs" not in raw  # nothing readable inside
    flipped = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    with pytest.raises(Denied, match="DENY_BAD_BADGE"):
        gw.check_badge(flipped)


def rotate(gw: Gateway, caller: Caller) -> crypto.AgentKey:
    new_key = crypto.AgentKey()
    session = gw.rotate(
        caller("rotate"), new_key.public_pem, new_key.proof(caller.token, "rotate-new-key")
    )
    caller.token, caller.key = session["token"], new_key
    return new_key


def test_rotation_issues_a_new_badge_on_a_new_key_and_kills_the_old(master) -> None:  # noqa: ANN001
    gw, me = master
    old_token, old_key = me.token, me.key
    rotate(gw, me)
    assert me.token != old_token
    claims_old, claims_new = gw.keys.read_badge(old_token), gw.keys.read_badge(me.token)
    assert claims_old["cnf"]["jkt"] != claims_new["cnf"]["jkt"]
    assert claims_new["gen"] == 2
    gw.capabilities(me("capabilities"))  # the new pair works
    stolen = Credential(old_token, old_key.proof(old_token, "capabilities"))
    with pytest.raises(Denied, match="DENY_BADGE_SUPERSEDED"):
        gw.capabilities(stolen)  # badge + key stolen before rotation: dead
    assert any(e["kind"] == "STALE_BADGE" for e in gw.snapshot()["audit"])


def test_rotation_requires_both_keys(master) -> None:  # noqa: ANN001
    gw, me = master
    new_key, impostor = crypto.AgentKey(), crypto.AgentKey()
    with pytest.raises(Denied, match="DENY_POP_MISMATCH"):  # can't prove the new key
        gw.rotate(me("rotate"), new_key.public_pem, impostor.proof(me.token, "rotate-new-key"))
    thief = Credential(me.token, impostor.proof(me.token, "rotate"))
    with pytest.raises(Denied):  # can't prove the old key: a thief can't rotate a stolen badge
        gw.rotate(thief, new_key.public_pem, new_key.proof(me.token, "rotate-new-key"))


def test_master_rotates_on_schedule_and_keeps_working(gw: Gateway) -> None:
    agent = MasterAgent(gw, FakeLLM([]), "fake")
    agent.ensure_identity()
    first = agent._token  # noqa: SLF001
    assert agent.rotate_if_due() is False  # not due yet
    assert agent.rotate_if_due(force=True) is True
    assert agent._token != first  # noqa: SLF001
    gw.capabilities(agent._cred("capabilities"))  # noqa: SLF001


def test_specialists_rotate_before_an_offer_when_due(master) -> None:  # noqa: ANN001
    gw, me = master
    gw.config = __import__("dataclasses").replace(gw.config, rotate_after_seconds=0)
    run_id = gw.start_run(me("start_run"), "t")
    plan = gw.declare_plan(
        me("declare_plan"),
        run_id,
        [
            step("LabsAgent", "get_renal_function", patient_id="P001"),
            step("LabsAgent", "get_latest_labs", patient_id="P001"),
        ],
    )
    gw.consult(me("consult"), plan["leases"][0]["lease_id"])
    out = gw.consult(me("consult"), plan["leases"][1]["lease_id"])  # same instance, rotated
    assert out["agent"] == "LabsAgent1"
    assert any(
        e["kind"] == "BADGE_ROTATED" and e["actor"] == "LabsAgent1" for e in gw.snapshot()["audit"]
    )


def test_steal_demo_covers_the_pre_rotation_pair(gw: Gateway) -> None:
    from server.ward_app import steal_demo

    agent = MasterAgent(gw, FakeLLM([]), "fake")
    results = [r["result"] for r in steal_demo(gw, agent)]
    assert results == [
        "DENY_BADGE_SUPERSEDED",
        "DENY_POP_REPLAY",
        "DENY_POP_MISMATCH",
        "DENY_POP_MISSING",
    ]


def test_rotation_mid_call_lets_that_call_finish_but_not_the_next(master) -> None:  # noqa: ANN001
    """Rotation is routine: the in-flight call completes; the old badge then stops working.
    (Contrast: revocation mid-call discards the result. See the revoke tests above.)"""
    gw, me = master
    run_id = gw.start_run(me("start_run"), "t")
    plan = gw.declare_plan(
        me("declare_plan"),
        run_id,
        [
            step("LabsAgent", "get_renal_function", patient_id="P001"),
            step("LabsAgent", "get_latest_labs", patient_id="P001"),
        ],
    )
    old_token, old_key = me.token, me.key
    in_flight = me("consult")  # the call starts with the old badge
    fired = []

    def rotate_mid_call(_: float) -> None:
        if not fired:
            fired.append(True)
            rotate(gw, me)  # the master's scheduled rotation lands mid-call

    gw._sleep = rotate_mid_call  # noqa: SLF001
    out = gw.consult(in_flight, plan["leases"][0]["lease_id"])
    assert out["result"]["band"] == "mild"  # delivered: rotation didn't cut it off
    gw._sleep = lambda s: None  # noqa: SLF001
    with pytest.raises(Denied, match="DENY_BADGE_SUPERSEDED"):
        gw.consult(
            Credential(old_token, old_key.proof(old_token, "consult")),
            plan["leases"][1]["lease_id"],
        )
    assert gw.consult(me("consult"), plan["leases"][1]["lease_id"])["result"]["glucose"] == 148
