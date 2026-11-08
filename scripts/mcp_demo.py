"""The A10 Agentic Identity demo, over MCP, in about a minute.

  Authenticate an agent -> allow selected MCP tools -> revoke mid-task -> block what follows.

  uv run python -m scripts.mcp_demo                 # scripted agent, monitor auto-revokes
  uv run python -m scripts.mcp_demo --manual        # you click Revoke on the dashboard
  uv run python -m scripts.mcp_demo --live          # a local LLM (Ollama) drives the agent

Options: --pace SECONDS between beats (default 2), --port (default 8000), --exit to stop
when the story ends instead of leaving the dashboard up.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import sys
import time
import uuid
from typing import Any

import httpx

from agents import scripted
from agents.mcp_client import McpError, McpGatewayClient
from badge import db
from badge.audit import verify_chain
from badge.clock import SystemClock
from badge.config import load_config
from badge.context import Runtime
from badge.orchestrator import (
    assessor_task_id,
    assign,
    create_visit_tasks,
    pharmacist_task_id,
    provision_workload,
)
from scripts.demo import (
    BLUE,
    BOLD,
    DEMO_DB,
    DIM,
    GREEN,
    RED,
    RESET,
    Narrator,
    demo_settings,
    start_server,
)
from scripts.seed import create_seeded_database

VISIT = "V-04"
AGENT = "assessor-a"
SPARE_AGENT = "assessor-byo"  # credentials printed so you can plug in your own MCP client
SCORES = {"pain_score": 3, "mobility_score": 4, "global_impression": 2}
CSRF = {"x-badge-dashboard": "1"}


class StopAgent(Exception):
    """Raised to end an LLM agent's loop once the point has been made."""


class WatchedAgent(McpGatewayClient):
    """An MCP agent whose calls the demo narrates. After the first recorded outcome it
    hands control to `on_mid_task` (the revocation), exactly once."""

    def __init__(self, *args: Any, narrator: Narrator, on_mid_task: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.narrator = narrator
        self.on_mid_task = on_mid_task
        self.revoked = False
        self.blocked_calls = 0

    def call_tool(
        self, name: str, args: dict[str, Any] | None = None, key: str | None = None
    ) -> dict[str, Any]:
        if self.revoked and self.blocked_calls >= 3:
            raise StopAgent
        response = super().call_tool(name, args, key)
        if name != "list_my_tools":
            self.narrator.show(self.name, f"mcp:{name}", response)
        if self.revoked:
            self.blocked_calls += 1
        elif name == "record_outcome" and response.get("ok"):
            self.on_mid_task()
            self.revoked = True
        return response


def token_claims(token: str) -> dict[str, Any]:
    """Decode the JWT payload for display only. (The gateway verifies; we just show.)"""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


def authenticate(http: httpx.Client, client_id: str, secret: str) -> httpx.Response:
    return http.post(
        "/auth/agent/token",
        data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret},
    )


def monitor_session(port: int, username: str, password: str) -> httpx.Client:
    session = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=30)
    login = session.post(
        "/auth/login", json={"username": username, "password": password}, headers=CSRF
    )
    login.raise_for_status()
    return session


def agent_status(conn: Any, agent_id: str) -> str:
    row = conn.execute("SELECT status FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
    return row["status"] if row else "missing"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="a local LLM drives the agent")
    parser.add_argument("--manual", action="store_true", help="wait for a dashboard Revoke")
    parser.add_argument("--pace", type=float, default=2.0)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--exit", action="store_true", help="stop when the story ends")
    args = parser.parse_args()
    if args.live:
        from agents.runner import check_llm_ready

        problem = check_llm_ready()
        if problem:
            print(f"--live: {problem}. Or run without --live.")
            return 2

    create_seeded_database(DEMO_DB)
    settings, logins = demo_settings(args.port)
    server = start_server(settings, args.port)
    runtime = Runtime(load_config(), SystemClock(), settings.signing_key)
    conn = db.connect(DEMO_DB)
    base = f"http://127.0.0.1:{args.port}"
    http = httpx.Client(base_url=base, timeout=120)
    narrator = Narrator(args.pace)

    print(f"{BOLD}Badge × MCP demo{RESET} — dashboard: {base}/  (MCP endpoint: {base}/mcp)")
    print("Monitor logins (demo-grade): " + ", ".join(f"{u} / {p}" for u, p in logins.items()))

    # ---- setup: the orchestrator provisions workloads and assigns work ------------------
    secrets_by_agent = {
        agent_id: provision_workload(conn, runtime, agent_id, role)
        for agent_id, role in [
            ("pharm-1", "pharmacist"),
            (AGENT, "assessor"),
            (SPARE_AGENT, "assessor"),
        ]
    }
    create_visit_tasks(conn, runtime, [VISIT])
    assign(conn, runtime, pharmacist_task_id(VISIT), "pharm-1")
    assign(conn, runtime, assessor_task_id(VISIT, 1), AGENT)
    assign(conn, runtime, assessor_task_id(VISIT, 2), SPARE_AGENT)
    patient = conn.execute("SELECT patient_id FROM visits WHERE visit_id = ?", (VISIT,)).fetchone()[
        0
    ]

    # ---- 1. authenticate ----------------------------------------------------------------
    narrator.beat("Authenticate: the agent trades its workload credentials for a badge")
    bad = authenticate(http, AGENT, "stolen-or-guessed-secret")
    print(f"    {RED}✗ {AGENT:<12} POST /auth/agent/token  {bad.status_code} {bad.json()}{RESET}")
    narrator.say("Wrong secret: refused, and logged as a high-severity AUTH_FAILED event.")
    good = authenticate(http, AGENT, secrets_by_agent[AGENT])
    token = good.json()["access_token"]
    claims = token_claims(token)
    print(
        f"    {GREEN}✓ {AGENT:<12} POST /auth/agent/token  200 badge issued, "
        f"expires in {good.json()['expires_in']}s{RESET}"
    )
    narrator.say(
        "Badge claims: "
        + json.dumps({k: claims[k] for k in ("sub", "role", "trial_id", "jti", "exp")})
    )

    # ---- 2. selected MCP tools ----------------------------------------------------------
    narrator.beat("Connect over MCP: tools/list returns only what this identity may use")
    pharm_token = authenticate(http, "pharm-1", secrets_by_agent["pharm-1"]).json()["access_token"]
    pharmacist = McpGatewayClient(http, pharm_token, "pharm-1")
    pharmacist.initialize()
    agent = WatchedAgent(
        http, token, AGENT, narrator=narrator, on_mid_task=lambda: revoke_mid_task()
    )
    info = agent.initialize()
    narrator.say(f"initialize → {info['serverInfo']['name']}, protocol {info['protocolVersion']}")
    pharm_tools = [t["name"] for t in pharmacist.list_tools()]
    agent_tools = [t["name"] for t in agent.list_tools()]
    print(f"    {BLUE}pharm-1   (pharmacist) sees: {', '.join(pharm_tools)}{RESET}")
    print(f"    {BLUE}{AGENT} (assessor)   sees: {', '.join(agent_tools)}{RESET}")
    narrator.say(
        "Same server, different badge, different tools. get_assignment (the unblinded arm) "
        "doesn't exist for the assessor."
    )
    narrator.say("Pharmacist dispenses the kit so the assessor's visit can open (typed handoff):")
    for name, response in zip(
        ["declare_plan", "get_assignment", "dispense_kit"],
        scripted.honest_pharmacist(pharmacist, VISIT, patient),
        strict=False,
    ):
        narrator.show("pharm-1", f"mcp:{name}", response)

    # ---- 3. work, then revoke mid-task --------------------------------------------------
    def revoke_mid_task() -> None:
        narrator.beat("Revoke mid-task: the agent has opened the visit and recorded one score")
        if args.manual:
            print(f"    {BOLD}Open {base}/, log in, and click Revoke on {AGENT}. Waiting…{RESET}")
            while agent_status(conn, AGENT) != "revoked":
                time.sleep(0.5)
            narrator.say("Revoked from the dashboard.")
        else:
            user, password = next(iter(logins.items()))
            monitor = monitor_session(args.port, user, password)
            response = monitor.post(
                "/api/monitor/revoke_badge",
                json={
                    "args": {"agent_id": AGENT, "reason": "Revoked mid-task for the demo"},
                    "idempotency_key": str(uuid.uuid4()),
                },
                headers=CSRF,
            ).json()
            narrator.show(f"monitor-{user}", "revoke_badge", response)
        narrator.say("One transaction: badge on the revocation list, leases killed, the agent's")
        narrator.say("scores flagged, its open task back in the pool.")
        narrator.beat("Every request after that is blocked")

    narrator.beat(
        f"The agent starts its task over MCP ({'local LLM' if args.live else 'scripted'})"
    )
    if args.live:
        from agents.runner import llm_settings, run_agent

        narrator.say(f"{llm_settings()[3]} is driving {AGENT} through MCP…")
        with contextlib.suppress(StopAgent):
            run_agent(agent, "assessor")
        if not agent.revoked:
            narrator.say("The model stopped before recording a score; revoking now anyway.")
            revoke_mid_task()
            agent.revoked = True
    else:
        with contextlib.suppress(StopAgent):
            scripted.honest_assessor(agent, VISIT, SCORES)

    # ---- 4. blocked ---------------------------------------------------------------------
    if agent.blocked_calls < 3:
        agent.blocked_calls = 0
        narrator.show(AGENT, "mcp:submit", McpGatewayClient.call_tool(agent, "submit", {}))
    try:
        agent.list_tools()
        print(f"    {RED}tools/list unexpectedly succeeded{RESET}")
    except McpError as exc:
        print(f"    {RED}✗ {AGENT:<12} mcp:tools/list        {exc.reason}{RESET}")
    try:
        agent.initialize()
    except McpError as exc:
        print(f"    {RED}✗ {AGENT:<12} mcp:initialize        {exc.reason}{RESET}")
    again = authenticate(http, AGENT, secrets_by_agent[AGENT])
    print(
        f"    {RED}✗ {AGENT:<12} POST /auth/agent/token  {again.status_code} {again.json()}{RESET}"
    )
    narrator.say("Even valid credentials can't mint a new badge: revocation sticks.")

    # ---- 5. audit -----------------------------------------------------------------------
    narrator.beat("Audit: hash chain verified, and exactly what the agent did")
    report = verify_chain(conn)
    mark = (
        f"{GREEN}chain verified ✓" if report.ok else f"{RED}chain BROKEN at #{report.first_bad_seq}"
    )
    print(f"    {mark} ({report.rows_checked} rows){RESET}")
    rows = conn.execute(
        "SELECT seq, decision, tool, reason FROM audit_log WHERE agent_id = ? ORDER BY seq",
        (AGENT,),
    ).fetchall()
    for row in rows:
        colour = {"ALLOW": GREEN, "DENY": RED}.get(row["decision"], BLUE)
        print(
            f"    {colour}#{row['seq']:<4} {row['decision']:<6} {str(row['tool'] or ''):<20}"
            f" {row['reason']}{RESET}"
        )

    spare = authenticate(http, SPARE_AGENT, secrets_by_agent[SPARE_AGENT]).json()["access_token"]
    print(f"\n{BOLD}Bring your own MCP client{RESET} {DIM}(a fresh assessor badge, 15 min):{RESET}")
    print(
        f"  claude mcp add --transport http badge {base}/mcp "
        f'--header "Authorization: Bearer {spare}"'
    )

    if args.exit:
        server.should_exit = True
        return 0
    print(f"\n{BOLD}Story done.{RESET} Dashboard stays up at {base}/ — Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.should_exit = True
    return 0


if __name__ == "__main__":
    sys.exit(main())
