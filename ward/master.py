"""OrchestratorAgent: the master LLM behind the chat.

It can do exactly three things, all through the gateway: declare a plan of consults,
run the leased consults in order, and write an answer from the typed results. It never
touches patient data or a specialist directly, and what it may delegate comes from the
policy file at run time (`gateway.capabilities`), not from this code.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from ward.gateway import Denied, Gateway

PLAN_TOOL = {
    "type": "function",
    "function": {
        "name": "declare_plan",
        "description": "Declare, in order, every specialist consult needed for this request.",
        "parameters": {
            "type": "object",
            "properties": {
                "steps": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "agent": {"type": "string"},
                            "tool": {"type": "string"},
                            "args": {"type": "object"},
                        },
                        "required": ["agent", "tool", "args"],
                    },
                }
            },
            "required": ["steps"],
        },
    },
}
NO_CONSULT_TOOL = {
    "type": "function",
    "function": {
        "name": "answer_directly",
        "description": "Use only when the request needs no patient or drug information.",
        "parameters": {
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
        },
    },
}

PLANNER_PROMPT = """You are OrchestratorAgent, the coordinator in a hospital medication system.
You cannot see patient records. Specialist agents can, and you reach them only by declaring
a plan: an ordered list of consults. A gateway checks every plan against policy before any
consult runs, then runs the steps in order and gives you typed results.

Rules for plans:
- Use only the agents, tools, and argument values listed below. Arguments must match exactly.
- If a tool lists needs_earlier_steps, include those steps EARLIER in the same plan, with the
  same patient_id / drug values. Include uses_if_present steps when they are relevant.
- Never repeat an identical step. Keep plans short: only what the request needs.
- Patient ids look like P001. Doses are total mg per day.

Available consults (from policy):
{capabilities}

Example of the plan format (values are illustrative):
{example}

Call declare_plan with your steps. If the request needs no patient or drug facts, call
answer_directly instead."""

ANSWER_PROMPT = """You are OrchestratorAgent. Answer the clinician's request using ONLY the typed
results below from specialist agents. Be brief and concrete (3-6 sentences). Say which
facts came from which agent. If a step was denied, rejected, or skipped, say what couldn't be
checked and don't guess. If an order was drafted, give its order id; if blocked, give the
block reasons. Synthetic demo data, not medical advice."""


def _example_plan(caps: list[dict[str, Any]]) -> str:
    """A format example built from the live policy, not a canned scenario."""
    by_tool = {c["tool"]: c for c in caps}

    def sample(desc: str) -> Any:
        if desc.startswith("one of: "):
            return desc.removeprefix("one of: ").split(", ")[0]
        if desc.startswith("integer "):
            low, high = desc.removeprefix("integer ").split("..")
            return max(int(low), min(int(high), 100))
        if desc.startswith("id matching"):
            return "P001"
        return "value"

    chosen = next((c for c in caps if c["needs_earlier_steps"]), caps[0])
    chain = [by_tool[t] for t in chosen["needs_earlier_steps"] if t in by_tool] + [chosen]
    steps = [
        {
            "agent": c["agent"],
            "tool": c["tool"],
            "args": {a: sample(d) for a, d in c["args"].items()},
        }
        for c in chain
    ]
    shared: dict[str, Any] = {}
    for step in steps:  # keep shared args consistent across the example
        for name in step["args"]:
            step["args"][name] = shared.setdefault(name, step["args"][name])
    return json.dumps({"steps": steps})


def _extract_steps(message: Any) -> tuple[str, Any]:
    """('plan', steps) | ('answer', text) | ('none', text). Tolerates models that put JSON
    in the content instead of making a tool call."""
    calls = list(getattr(message, "tool_calls", None) or [])
    for call in calls:
        try:
            args = json.loads(call.function.arguments or "{}")
        except json.JSONDecodeError:
            args = {}
        if call.function.name == "declare_plan":
            return "plan", args.get("steps", args if isinstance(args, list) else [])
        if call.function.name == "answer_directly":
            return "answer", str(args.get("answer", ""))
    content = getattr(message, "content", "") or ""
    match = re.search(r"\{.*\"steps\".*\}", content, re.DOTALL)
    if match:
        try:
            return "plan", json.loads(match.group(0))["steps"]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass
    return "none", content


class MasterAgent:
    def __init__(
        self,
        gateway: Gateway,
        llm: Any,
        model: str,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.gw = gateway
        self.llm = llm
        self.model = model
        self._sleep = sleep
        self.agent_id: str | None = None
        self._secret: str | None = None
        self._token: str | None = None
        self.lock = threading.Lock()

    # ---- identity ---------------------------------------------------------------------

    def ensure_identity(self) -> str:
        """Authenticate, re-authenticating on expiry. A revoked master is never revived:
        a new instance (OrchestratorAgent2, ...) gets its own credentials."""
        if self._token:
            try:
                self.gw.check_badge(self._token)
                return self._token
            except Denied as exc:
                if exc.reason == "DENY_BADGE_EXPIRED":
                    self._token = self.gw.authenticate(self.agent_id, self._secret)["token"]
                    return self._token
        self.agent_id, self._secret = self.gw.provision(self.gw.config.master_role)
        self._token = self.gw.authenticate(self.agent_id, self._secret)["token"]
        return self._token

    # ---- one chat request ---------------------------------------------------------------

    def handle(self, prompt: str, fault: str | None = None) -> str:
        """Run one request end to end. Returns the run id. Blocks until done."""
        token = self.ensure_identity()
        run_id = self.gw.start_run(token, prompt)
        try:
            self._handle(token, run_id, prompt, fault)
        except Denied as exc:
            self.gw.fail_run(run_id, f"{exc.reason}: {exc.detail}")
        except Exception as exc:  # noqa: BLE001 - surface any model/network failure in the UI
            self.gw.fail_run(run_id, f"{type(exc).__name__}: {str(exc)[:200]}")
        return run_id

    def _chat(self, messages: list[dict[str, Any]], tools: list[dict] | None) -> Any:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": 900,
        }
        if tools:
            kwargs["tools"] = tools
        return self.llm.chat.completions.create(**kwargs).choices[0].message

    def _handle(self, token: str, run_id: str, prompt: str, fault: str | None) -> None:
        caps = self.gw.capabilities(token)
        system = PLANNER_PROMPT.format(
            capabilities=json.dumps(caps, indent=1), example=_example_plan(caps)
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        results: list[dict[str, Any]] = []
        max_plans = int(self.gw.config.run["max_plans_per_run"])
        for attempt in range(max_plans):
            message = self._chat(messages, [PLAN_TOOL, NO_CONSULT_TOOL])
            kind, payload = _extract_steps(message)
            self.gw.report_progress(token, run_id, "planned" if kind == "plan" else "replied")
            if kind != "plan":
                answer = payload or "I couldn't form a plan for that request."
                self.gw.finish_run(token, run_id, answer)
                return
            try:
                plan = self.gw.declare_plan(token, run_id, payload)
            except Denied as exc:
                if exc.reason in ("DENY_REVOKED", "DENY_RUN_ENDED") or attempt == max_plans - 1:
                    raise
                messages.append({"role": "assistant", "content": json.dumps({"steps": payload})})
                messages.append(
                    {
                        "role": "user",
                        "content": f"The gateway rejected that plan: {exc.reason} — {exc.detail}. "
                        "Fix it and call declare_plan again.",
                    }
                )
                continue
            results = self._execute(token, run_id, plan, fault)
            break
        answer_messages = [
            {"role": "system", "content": ANSWER_PROMPT},
            {
                "role": "user",
                "content": f"Request: {prompt}\n\nTyped results:\n{json.dumps(results, indent=1)}",
            },
        ]
        answer = self._chat(answer_messages, None).content or "(no answer)"
        self.gw.report_progress(token, run_id, "answered")
        self.gw.finish_run(token, run_id, answer.strip())

    def _execute(self, token: str, run_id: str, plan: dict[str, Any], fault: str | None) -> list:
        results: list[dict[str, Any]] = []
        failed = False
        for index, lease in enumerate(plan["leases"]):
            step = {"agent": lease["agent"], "tool": lease["tool"], "args": lease["args"]}
            if failed:
                results.append({**step, "status": "skipped (an earlier step failed)"})
                continue
            try:
                out = self.gw.consult(token, lease["lease_id"])
                results.append(
                    {**step, "status": "ok", "by": out["agent"], "result": out["result"]}
                )
            except Denied as exc:
                if exc.reason in ("DENY_RUN_ENDED",) or self._revoked(token):
                    raise
                results.append({**step, "status": "denied", "reason": exc.reason})
                failed = True
            if fault == "stuck" and index == 0:
                self._spin(token, run_id)  # never returns normally: the watchdog revokes us
        return results

    def _spin(self, token: str, run_id: str) -> None:
        """Simulated stuck agent: keeps polling, never makes progress."""
        while True:
            self.gw.heartbeat(token, run_id)  # raises Denied once the watchdog revokes us
            self._sleep(0.5)

    def _revoked(self, token: str) -> bool:
        try:
            self.gw.check_badge(token)
            return False
        except Denied:
            return True
