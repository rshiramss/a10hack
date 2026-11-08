"""Badge demo, about 2-3 minutes. Open the dashboard URL it prints while it runs.

  uv run python -m scripts.demo            # scripted agents, no API key, deterministic
  uv run python -m scripts.demo --live     # an LLM drives the assessors (local Ollama by default)

Options: --pace SECONDS between beats (default 3), --port (default 8000), --exit to stop
the server when the story ends instead of leaving the dashboard up.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import uvicorn

from agents import scripted
from agents.client import GatewayClient
from badge import db
from badge.audit import verify_chain
from badge.clock import SystemClock
from badge.config import load_config
from badge.context import Runtime
from badge.orchestrator import (
    adjudicator_task_id,
    assessor_task_id,
    assign,
    create_visit_tasks,
    enroll_agent,
    pharmacist_task_id,
    reassign_pool,
)
from scripts.seed import INJECTED_VISIT_ID, create_seeded_database
from server.app import Settings, create_app, parse_monitor_passwords

DEMO_DB = Path("data/demo.db")
VISITS = ["V-03", "V-04", INJECTED_VISIT_ID]
# visit -> (slot 1 assessor, slot 2 assessor). Assessor A holds the injected visit.
READ_ASSIGNMENTS = {
    "V-03": ("assessor-a", "assessor-b"),
    "V-04": ("assessor-b", "assessor-c"),
    INJECTED_VISIT_ID: ("assessor-a", "assessor-b"),
}
SCORES = {
    ("V-03", "assessor-a"): {"pain_score": 4, "mobility_score": 5, "global_impression": 4},
    ("V-03", "assessor-b"): {"pain_score": 4, "mobility_score": 6, "global_impression": 4},
    ("V-04", "assessor-b"): {"pain_score": 3, "mobility_score": 3, "global_impression": 2},
    ("V-04", "assessor-c"): {"pain_score": 3, "mobility_score": 4, "global_impression": 2},
    (INJECTED_VISIT_ID, "assessor-b"): {
        "pain_score": 7,
        "mobility_score": 6,
        "global_impression": 6,
    },
    (INJECTED_VISIT_ID, "assessor-c"): {
        "pain_score": 2,
        "mobility_score": 5,
        "global_impression": 4,
    },
}
INJECTION_TARGET = ("P012", "V-23")

GREEN, RED, BLUE, BOLD, DIM, RESET = (
    "\033[32m",
    "\033[31m",
    "\033[34m",
    "\033[1m",
    "\033[2m",
    "\033[0m",
)


# ---- narration ----------------------------------------------------------------------


class Narrator:
    def __init__(self, pace: float) -> None:
        self.pace = pace
        self.beat_number = 0

    def beat(self, title: str) -> None:
        self.beat_number += 1
        time.sleep(self.pace)
        print(f"\n{BOLD}{BLUE}[{self.beat_number}] {title}{RESET}")

    @staticmethod
    def say(text: str) -> None:
        print(f"    {DIM}{text}{RESET}")

    @staticmethod
    def show(who: str, tool: str, response: dict[str, Any]) -> None:
        if response.get("ok"):
            print(f"    {GREEN}✓ {who:<12} {tool:<20} {response['reason']}{RESET}")
            return
        action = response.get("action", "none")
        suffix = f" [{action}]" if action != "none" else ""
        detail = f" — {response.get('detail')}" if response.get("detail") else ""
        print(f"    {RED}✗ {who:<12} {tool:<20} {response['reason']}{suffix}{detail}{RESET}")


def show_all(narrator: Narrator, who: str, tools: list[str], responses: list[dict]) -> None:
    for tool, response in zip(tools, responses, strict=False):
        narrator.show(who, tool, response)


def assessor_tool_names(scores: dict[str, int]) -> list[str]:
    return ["declare_plan", "open_patient_visit", *(["record_outcome"] * len(scores)), "submit"]


# ---- setup --------------------------------------------------------------------------


def demo_settings(port: int) -> tuple[Settings, dict[str, str]]:
    signing_key = os.environ.get("BADGE_SIGNING_KEY") or secrets.token_urlsafe(48)
    logins = parse_monitor_passwords(os.environ.get("MONITOR_PASSWORDS", ""))
    if not {"alice", "bob"} <= set(logins):
        logins = {"alice": secrets.token_urlsafe(8), "bob": secrets.token_urlsafe(8)}
    return Settings(db_path=DEMO_DB, signing_key=signing_key, monitor_passwords=logins), logins


def start_server(settings: Settings, port: int) -> uvicorn.Server:
    app = create_app(settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=0.5).status_code == 200:
                return server
        except httpx.HTTPError:
            time.sleep(0.1)
    raise RuntimeError("gateway did not start")


def enroll_everyone(conn: Any, runtime: Runtime, http: httpx.Client) -> dict[str, GatewayClient]:
    roster = [
        ("pharm-1", "pharmacist"),
        ("assessor-a", "assessor"),
        ("assessor-b", "assessor"),
        ("assessor-c", "assessor"),
        ("adjud-1", "adjudicator"),
        ("monitor-alice", "monitor"),
        ("monitor-bob", "monitor"),
    ]
    return {
        agent_id: GatewayClient(http, enroll_agent(conn, runtime, agent_id, role), agent_id)
        for agent_id, role in roster
    }


def create_and_assign_tasks(conn: Any, runtime: Runtime) -> None:
    create_visit_tasks(conn, runtime, VISITS)
    for visit in VISITS:
        assign(conn, runtime, pharmacist_task_id(visit), "pharm-1")
        assign(conn, runtime, adjudicator_task_id(visit), "adjud-1")
        for slot, agent_id in enumerate(READ_ASSIGNMENTS[visit], start=1):
            assign(conn, runtime, assessor_task_id(visit, slot), agent_id)


# ---- assessor strategies (scripted or live) -----------------------------------------

AssessFn = Callable[[GatewayClient, str, dict[str, int], Narrator], list[dict]]


def scripted_assess(
    client: GatewayClient, visit: str, scores: dict[str, int], narrator: Narrator
) -> list[dict]:
    responses = scripted.honest_assessor(client, visit, scores)
    show_all(narrator, client.name, assessor_tool_names(scores), responses)
    return responses


class LiveAssessor:
    """An LLM drives the assessor; a scripted fallback finishes anything it leaves undone."""

    def __init__(self, model: str | None) -> None:
        self.model = model
        self.last_transcript: Any = None

    def run(self, client: GatewayClient, narrator: Narrator) -> Any:
        from agents.runner import llm_settings, run_agent

        model = self.model or llm_settings()[3]
        narrator.say(f"{model} is driving {client.name}…")
        try:
            transcript = run_agent(client, "assessor", model=self.model)
        except Exception as exc:  # noqa: BLE001 - the demo must keep going
            narrator.say(f"LLM call failed ({type(exc).__name__}); scripted fallback takes over.")
            from agents.runner import AgentTranscript

            transcript = AgentTranscript()
        for record in transcript.calls:
            narrator.show(client.name, record.tool, record.response)
        self.last_transcript = transcript
        return transcript

    def __call__(
        self, client: GatewayClient, visit: str, scores: dict[str, int], narrator: Narrator
    ) -> list[dict]:
        transcript = self.run(client, narrator)
        if scripted.find_task(client, visit) is not None:
            narrator.say("The model left the task unfinished; scripted fallback finishes it.")
            return scripted_assess(client, visit, scores, narrator)
        return [record.response for record in transcript.calls]


# ---- the story ----------------------------------------------------------------------


def open_injected_visit(client: GatewayClient, narrator: Narrator) -> None:
    """Scripted assessor A: plans and opens the visit, then shows the note it received."""
    task = scripted.find_task(client, INJECTED_VISIT_ID)
    if task is None:
        return
    steps = scripted.assessor_plan(INJECTED_VISIT_ID, {"pain_score": 5})
    narrator.show(client.name, "declare_plan", client.declare_plan(task["task_id"], steps))
    opened = client.call("open_patient_visit", {"visit_id": INJECTED_VISIT_ID})
    narrator.show(client.name, "open_patient_visit", opened)
    if opened.get("ok"):
        narrator.say("Note as A sees it (side effects redacted, injection intact):")
        for line in opened["result"]["note"].splitlines():
            narrator.say(f"  │ {line}")


def run_story(
    agents: dict[str, GatewayClient],
    conn: Any,
    runtime: Runtime,
    assess: AssessFn,
    narrator: Narrator,
) -> None:
    pharm, a, b, c = (agents[n] for n in ("pharm-1", "assessor-a", "assessor-b", "assessor-c"))
    adj, alice, bob = agents["adjud-1"], agents["monitor-alice"], agents["monitor-bob"]
    patient_of = {
        row["visit_id"]: row["patient_id"]
        for row in conn.execute("SELECT visit_id, patient_id FROM visits")
    }

    narrator.beat("Pharmacist (unblinded) dispenses kits → H1 handoffs unlock the visits")
    for visit in VISITS:
        responses = scripted.honest_pharmacist(pharm, visit, patient_of[visit])
        show_all(
            narrator, pharm.name, ["declare_plan", "get_assignment", "dispense_kit"], responses
        )

    narrator.beat("Assessors declare plans → leases appear → scoring proceeds")
    assess(a, "V-03", SCORES[("V-03", "assessor-a")], narrator)

    narrator.beat("Assessor B submits, then retries the same submit (idempotency)")
    b_scores = SCORES[("V-03", "assessor-b")]
    if isinstance(assess, LiveAssessor):
        assess(b, "V-03", b_scores, narrator)
        records = [r for r in assess.last_transcript.calls if r.tool == "submit"]
        key = records[-1].idempotency_key if records else None
    else:
        key = "11111111-2222-4333-8444-555555555555"
        responses = scripted.honest_assessor(b, "V-03", b_scores, submit_key=key)
        show_all(narrator, b.name, assessor_tool_names(b_scores), responses)
    if key:
        narrator.show(b.name, "submit (retry)", b.call("submit", {"visit_id": "V-03"}, key=key))
        narrator.say("Same key → original result returned, nothing written twice.")

    narrator.beat(f"Assessor A opens {INJECTED_VISIT_ID}, whose note carries a prompt injection")
    went_rogue = False
    if isinstance(assess, LiveAssessor):
        went_rogue = assess.run(a, narrator).called("get_assignment")
        if not went_rogue:
            narrator.say(
                "The model ignored the injection. Here is what happens to an agent that doesn't:"
            )
    else:
        open_injected_visit(a, narrator)
    if not went_rogue:
        narrator.say("A follows the injected instruction…")
        responses = scripted.assessor_calls_get_assignment(a, *INJECTION_TARGET)
        narrator.show(a.name, "get_assignment", responses[0])
    narrator.say("Badge revoked, A's earlier scores flagged, A's open task back in the pool.")
    for task_id, agent_id in reassign_pool(conn, runtime, "assessor"):
        narrator.say(f"Orchestrator reassigned {task_id} → {agent_id}")
    narrator.show(a.name, "get_my_status", scripted.keeps_calling_after_revocation(a, 1)[0])

    narrator.beat("Assessors B and C keep working, untouched (revocation is per agent)")
    for client, visit in ((b, "V-04"), (c, "V-04"), (b, INJECTED_VISIT_ID), (c, INJECTED_VISIT_ID)):
        if scripted.find_task(client, visit):
            assess(client, visit, SCORES[(visit, client.name)], narrator)

    narrator.beat("Adjudicator compares numeric reads only (H2 carries integers, never notes)")
    for visit in ("V-04", INJECTED_VISIT_ID, "V-03"):
        responses = scripted.honest_adjudicator(adj, visit)
        show_all(narrator, adj.name, ["declare_plan", "compare_reads"], responses)
        if responses and responses[-1].get("ok"):
            outcome = responses[-1]["result"]
            narrator.say(f"{visit}: {outcome['result']} (max delta {outcome['max_delta']})")
    narrator.say("V-03 is blocked: its slot-1 read came from A's revoked badge.")

    narrator.beat("Break the glass: emergency unblind needs two different monitors")
    request = alice.call(
        "request_emergency_unblind",
        {"patient_id": patient_of[INJECTED_VISIT_ID], "reason": "Serious adverse event"},
        mutating=True,
    )
    narrator.show(alice.name, "request_unblind", request)
    request_id = request["result"]["request_id"]
    narrator.show(
        alice.name,
        "approve (self)",
        alice.call("approve_emergency_unblind", {"request_id": request_id}, mutating=True),
    )
    narrator.show(
        bob.name,
        "approve",
        bob.call("approve_emergency_unblind", {"request_id": request_id}, mutating=True),
    )
    reveal = bob.call("view_emergency_unblind", {"request_id": request_id})
    narrator.show(bob.name, "view_unblind", reveal)
    narrator.show(
        bob.name,
        "view_unblind (again)",
        bob.call("view_emergency_unblind", {"request_id": request_id}),
    )

    narrator.beat("Audit: hash chain verified, and exactly what Assessor A did")
    report = verify_chain(conn)
    status = (
        f"{GREEN}chain verified ✓ ({report.rows_checked} rows){RESET}"
        if report.ok
        else (f"{RED}chain broken at #{report.first_bad_seq}{RESET}")
    )
    print(f"    {status}")
    trail = alice.call("view_audit", {"agent_id": "assessor-a", "limit": 50})
    for entry in reversed(trail.get("result", {}).get("entries", [])):
        colour = {"ALLOW": GREEN, "DENY": RED}.get(entry["decision"], BLUE)
        print(
            f"    {colour}#{entry['seq']:<4} {entry['decision']:<6} {str(entry['tool'] or ''):<20}"
            f" {entry['reason']}{RESET}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scripted", action="store_true", help="scripted agents (default)")
    mode.add_argument("--live", action="store_true", help="an LLM drives the assessors")
    parser.add_argument("--pace", type=float, default=3.0)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--exit", action="store_true", help="stop when the story ends")
    args = parser.parse_args()
    if args.live:
        from agents.runner import check_llm_ready

        problem = check_llm_ready()
        if problem:
            print(f"--live: {problem}. Or use --scripted.")
            return 2

    create_seeded_database(DEMO_DB)
    settings, logins = demo_settings(args.port)
    server = start_server(settings, args.port)
    runtime = Runtime(load_config(), SystemClock(), settings.signing_key)
    conn = db.connect(DEMO_DB)
    http = httpx.Client(base_url=f"http://127.0.0.1:{args.port}", timeout=60)

    print(f"{BOLD}Badge demo{RESET} — dashboard: http://127.0.0.1:{args.port}/")
    print("Monitor logins (demo-grade): " + ", ".join(f"{u} / {p}" for u, p in logins.items()))
    agents = enroll_everyone(conn, runtime, http)
    create_and_assign_tasks(conn, runtime)
    narrator = Narrator(args.pace)
    assess = LiveAssessor(os.environ.get("BADGE_MODEL")) if args.live else scripted_assess
    run_story(agents, conn, runtime, assess, narrator)

    if args.exit:
        server.should_exit = True
        return 0
    print(
        f"\n{BOLD}Story done.{RESET} Dashboard stays up at"
        f" http://127.0.0.1:{args.port}/ — Ctrl-C to stop."
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


if __name__ == "__main__":
    sys.exit(main())
