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
- Every argument must be known when you declare the plan. If a step needs a value you
  don't have yet (a patient's id from their name, the drugs a patient takes), declare a
  plan for what you can do now. You'll get the typed results and can declare a follow-up
  plan that uses them (up to {max_plans} plans per request).

Available consults (from policy):
{capabilities}

Example of the plan format (values are illustrative):
{example}

Call declare_plan with your steps. Call answer_directly instead if the request needs no
patient or drug facts, or if no listed tool can provide what's asked: then say plainly which
information isn't available through the specialists."""

FOLLOW_UP = """Typed results so far:
{results}

If answering the original request needs more consults that use these results, call
declare_plan again ({left} plan(s) left). Otherwise call answer_directly with "DONE"."""

ANSWER_PROMPT = """You are OrchestratorAgent. Answer the clinician's request using ONLY the typed
results below from specialist agents. Be brief and concrete (3-6 sentences). Say which
facts came from which agent. If (and only if) the request asks for a total, add up the numbers.
If a step was denied, rejected, or skipped, say what couldn't be checked; don't guess.
If an order was drafted, give its order id; if blocked, give the block reasons.
Synthetic demo data, not medical advice."""


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


def _capabilities_text(caps: list[dict[str, Any]]) -> str:
    """Policy capabilities grouped by agent, so a small model pairs tools with owners."""
    lines: list[str] = []
    for agent in dict.fromkeys(c["agent"] for c in caps):
        lines.append(f"{agent} (only this agent can run these tools):")
        for c in (c for c in caps if c["agent"] == agent):
            args = ", ".join(f"{a}: {d}" for a, d in c["args"].items())
            line = f"  - {c['tool']}({args}) — {c['description']}"
            if c["needs_earlier_steps"]:
                line += f" Needs earlier steps: {', '.join(c['needs_earlier_steps'])}."
            if c["uses_if_present"]:
                line += f" Uses if present: {', '.join(c['uses_if_present'])}."
            lines.append(line + f" Returns {json.dumps(c['returns'])}")
    return "\n".join(lines)


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
        max_plans = int(self.gw.config.run["max_plans_per_run"])
        system = PLANNER_PROMPT.format(
            capabilities=_capabilities_text(caps),
            example=_example_plan(caps),
            max_plans=max_plans,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        results: list[dict[str, Any]] = []
        plans_used = 0
        must_replan = False
        while plans_used < max_plans:
            # After a rejected plan the model must fix it: answer_directly isn't offered.
            tools = [PLAN_TOOL] if must_replan else [PLAN_TOOL, NO_CONSULT_TOOL]
            message = self._chat(messages, tools)
            must_replan = False
            kind, payload = _extract_steps(message)
            self.gw.report_progress(token, run_id, "planned" if kind == "plan" else "replied")
            if kind != "plan":
                if results:
                    break  # enough evidence; write the answer below
                answer = payload.strip() or (
                    "The model returned neither a plan nor an explanation. Try naming the "
                    "patient (by name or id like P003) and what you want checked."
                )
                self.gw.finish_run(token, run_id, answer)
                return
            plans_used += 1
            messages.append({"role": "assistant", "content": json.dumps({"steps": payload})})
            try:
                plan = self.gw.declare_plan(token, run_id, payload)
            except Denied as exc:
                if exc.reason in ("DENY_REVOKED", "DENY_RUN_ENDED") or self._revoked(token):
                    raise
                if plans_used >= max_plans:
                    if results:
                        break  # answer from what earlier plans already established
                    raise
                messages.append(
                    {
                        "role": "user",
                        "content": f"The gateway rejected that plan: {exc.reason} — {exc.detail}. "
                        "The request can be served; fix exactly that problem and call "
                        "declare_plan again.",
                    }
                )
                must_replan = True
                continue
            new = self._execute(token, run_id, plan, fault)
            results.extend(new)
            if plans_used >= max_plans or any(r["status"] != "ok" for r in new):
                break
            messages.append(
                {
                    "role": "user",
                    "content": FOLLOW_UP.format(
                        results=json.dumps(new, indent=1), left=max_plans - plans_used
                    ),
                }
            )
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
