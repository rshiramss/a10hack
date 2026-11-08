"""OrchestratorAgent: the master LLM behind the chat.

It can do exactly three things, all through the gateway: declare a plan of consults,
run the leased consults in order, and write an answer from the typed results. It never
touches patient data or a specialist directly, and what it may delegate comes from the
policy file at run time (`gateway.capabilities`), not from this code.
"""

from __future__ import annotations

import contextlib
import json
import re
import threading
import time
from collections.abc import Callable
from typing import Any

from ward import crypto
from ward.attestation import master_functions, measure
from ward.gateway import Credential, Denied, Gateway

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

Worked examples (other patients and drugs; copy the format, not the content):
{example}

Call declare_plan with your steps. Call answer_directly instead if the request needs no
patient or drug facts, or if no listed tool can provide what's asked: then say plainly which
information isn't available through the specialists."""

NUDGE = (
    "Reply by calling a tool: declare_plan with your steps, or answer_directly with one "
    "sentence saying what information the specialists can't provide."
)

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


def _capabilities_text(caps: list[dict[str, Any]], vocab: dict[str, tuple[str, ...]]) -> str:
    """Policy capabilities grouped by agent, so a small model pairs tools with owners.
    Each list of allowed values is printed once and referenced by name, which keeps the
    prompt short."""
    names = {"one of: " + ", ".join(values): name for name, values in vocab.items()}
    used: set[str] = set()

    def short(desc: str) -> str:
        for full, name in names.items():
            if full in desc:
                used.add(name)
                desc = desc.replace(full, f"a <{name}>")
        return desc

    lines: list[str] = []
    for agent in dict.fromkeys(c["agent"] for c in caps):
        lines.append(f"{agent} (only this agent can run these tools):")
        for c in (c for c in caps if c["agent"] == agent):
            args = ", ".join(f"{a}: {short(d)}" for a, d in c["args"].items())
            line = f"  - {c['tool']}({args}): {c['description']}"
            if c["needs_earlier_steps"]:
                line += f" Needs earlier steps: {', '.join(c['needs_earlier_steps'])}."
            if c["uses_if_present"]:
                line += f" Uses if present: {', '.join(c['uses_if_present'])}."
            returns = ", ".join(f"{f}: {short(d)}" for f, d in c["returns"].items())
            lines.append(line + f" Returns {{{returns}}}.")
    lines.append("Allowed values:")
    for name in sorted(used):
        lines.append(f"  <{name}>: {', '.join(vocab[name])}")
    return "\n".join(lines)


def _few_shot_text(examples: list[dict[str, Any]]) -> str:
    """Worked examples from the policy file, rendered as text."""
    out = []
    for i, ex in enumerate(examples, start=1):
        out.append(f'Example {i}. Request: "{ex["request"]}"')
        for j, plan in enumerate(ex.get("plans", [])):
            if j and ex.get("between"):
                out.append(f"  ({ex['between']})")
            prefix = "  then declare_plan" if j else "  declare_plan"
            out.append(f"{prefix} {json.dumps({'steps': plan})}")
        if "answer" in ex:
            out.append(f"  answer_directly {json.dumps({'answer': ex['answer']})}")
    return "\n".join(out)


def _raw_reply(message: Any) -> str:
    calls = [
        f"{c.function.name}({c.function.arguments})"
        for c in (getattr(message, "tool_calls", None) or [])
    ]
    return ((getattr(message, "content", "") or "") + " " + " ".join(calls)).strip()[:600]


def _json_candidates(text: str) -> list[Any]:
    """Every JSON value we can find in a model's text: the whole thing, fenced blocks,
    <tool_call> blocks, and balanced {...} / [...] spans."""
    found: list[Any] = []
    chunks = [text]
    chunks += re.findall(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    chunks += re.findall(r"<tool_call>\s*(.*?)\s*(?:</tool_call>|$)", text, re.DOTALL)
    for chunk in chunks:
        try:
            found.append(json.loads(chunk))
            continue
        except (json.JSONDecodeError, TypeError):
            pass
        for opener, closer in (("{", "}"), ("[", "]")):
            depth, begin = 0, None
            for i, ch in enumerate(chunk):
                if ch == opener:
                    if depth == 0:
                        begin = i
                    depth += 1
                elif ch == closer and depth:
                    depth -= 1
                    if depth == 0 and begin is not None:
                        with contextlib.suppress(json.JSONDecodeError):
                            found.append(json.loads(chunk[begin : i + 1]))
    return found


def _interpret(value: Any, name: str | None = None) -> tuple[str, Any] | None:
    """Recognize a plan or a direct answer in the shapes small models produce."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return ("answer", value) if name == "answer_directly" else None
    is_steps = isinstance(value, list) and value and all(isinstance(v, dict) for v in value)
    if is_steps and any("tool" in v or "function" in v for v in value):
        return "plan", value
    if not isinstance(value, dict):
        return None
    if name == "answer_directly" or ("answer" in value and len(value) == 1):
        return "answer", str(value.get("answer", ""))
    if "steps" in value:
        return "plan", value["steps"]
    call_name = value.get("name") or value.get("function")
    inner = value.get("arguments", value.get("parameters"))
    if isinstance(call_name, str) and inner is not None:
        return _interpret(inner, call_name)
    if "tool" in value:
        return "plan", [value]
    return None


def _extract_steps(message: Any) -> tuple[str, Any]:
    """('plan', steps) | ('answer', text) | ('none', raw text)."""
    for call in list(getattr(message, "tool_calls", None) or []):
        result = _interpret(call.function.arguments or "{}", call.function.name)
        if result:
            return result
    content = getattr(message, "content", "") or ""
    for value in _json_candidates(content):
        result = _interpret(value)
        if result:
            return result
    return "none", content


def _normalize_steps(steps: Any, caps: list[dict[str, Any]]) -> Any:
    """Common key spellings -> {agent, tool, args}; fill a missing agent with the tool's
    owner from policy. A wrong agent is left as is, for the gateway to reject."""
    if not isinstance(steps, list):
        return steps
    owners = {c["tool"]: c["agent"] for c in caps}
    out = []
    for step in steps:
        if not isinstance(step, dict):
            out.append(step)
            continue
        tool = step.get("tool") or step.get("name") or step.get("function")
        agent = step.get("agent") or step.get("agent_name") or step.get("role") or owners.get(tool)
        args = step.get("args", step.get("arguments", step.get("parameters", {})))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {}
        out.append({"agent": agent, "tool": tool, "args": args if isinstance(args, dict) else {}})
    return out


def _complete_plan(
    steps: Any, caps: list[dict[str, Any]], done: list[tuple[str, dict[str, Any]]]
) -> tuple[Any, int]:
    """Insert missing prerequisite steps, derived from policy, with args taken from the
    step that needs them. Returns (steps, number added). The master's own planning aid;
    the gateway still validates the whole plan."""
    if not isinstance(steps, list) or not all(isinstance(s, dict) for s in steps):
        return steps, 0
    by_tool = {c["tool"]: c for c in caps}
    produced = list(done)
    out: list[dict[str, Any]] = []
    added = 0

    def have(tool: str, args: dict[str, Any]) -> bool:
        return any(
            t == tool and all(a[k] == args[k] for k in set(a) & set(args)) for t, a in produced
        )

    def ensure(step: dict[str, Any], depth: int = 0, inserted: bool = False) -> None:
        nonlocal added
        cap = by_tool.get(step.get("tool"))
        if cap and depth < 4 and isinstance(step.get("args"), dict):
            for source in cap["needs_earlier_steps"] + cap["uses_if_present"]:
                if source not in by_tool or have(source, step["args"]):
                    continue
                needed = list(by_tool[source]["args"])
                if not all(a in step["args"] for a in needed):
                    continue  # can't derive its args; the gateway will explain
                pre = {
                    "agent": by_tool[source]["agent"],
                    "tool": source,
                    "args": {a: step["args"][a] for a in needed},
                }
                ensure(pre, depth + 1, inserted=True)
        if step not in out:
            out.append(step)
            if isinstance(step.get("args"), dict):
                produced.append((step.get("tool"), step["args"]))
            if inserted:
                added += 1

    for step in steps:
        ensure(step)
    return out, added


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
        self._key: crypto.AgentKey | None = None
        self.lock = threading.Lock()

    # ---- identity ---------------------------------------------------------------------

    def _cred(self, op: str) -> Credential:
        """Badge + a fresh proof, signed with this agent's own key, for one operation."""
        assert self._token is not None and self._key is not None
        return Credential(self._token, self._key.proof(self._token, op))

    def _login(self) -> None:
        cfg = self.gw.config
        session = self.gw.authenticate(
            self.agent_id,
            self._secret,
            self._key.public_pem,
            self._key.proof(self._secret, "authenticate"),
            measure(cfg.master_role, cfg, master_functions()),
        )
        self._token = session["token"]

    def ensure_identity(self) -> str:
        """Authenticate, re-authenticating on expiry. A revoked master is never revived:
        a new instance (OrchestratorAgent2, ...) gets its own credentials and key."""
        if self._token:
            try:
                self.gw.check_badge(self._token)
                return self._token
            except Denied as exc:
                if exc.reason == "DENY_BADGE_EXPIRED":
                    self._login()
                    return self._token
        self.agent_id, self._secret = self.gw.provision(self.gw.config.master_role)
        self._key = crypto.AgentKey()
        self._login()
        return self._token

    # ---- one chat request ---------------------------------------------------------------

    def handle(self, prompt: str, fault: str | None = None) -> str:
        """Run one request end to end. Returns the run id. Blocks until done."""
        token = self.ensure_identity()
        run_id = self.gw.start_run(self._cred("start_run"), prompt)
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
            "max_tokens": int(self.gw.config.master.get("max_tokens", 900)),
        }
        if tools:
            kwargs["tools"] = tools
        return self.llm.chat.completions.create(**kwargs).choices[0].message

    def _handle(self, token: str, run_id: str, prompt: str, fault: str | None) -> None:
        caps = self.gw.capabilities(self._cred("capabilities"))
        max_plans = int(self.gw.config.run["max_plans_per_run"])
        system = PLANNER_PROMPT.format(
            capabilities=_capabilities_text(caps, self.gw.config.vocab),
            example=_few_shot_text(self.gw.config.master.get("few_shot", []))
            or _example_plan(caps),
            max_plans=max_plans,
        )
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        results: list[dict[str, Any]] = []
        plans_used = 0
        nudges = 0
        done: list[tuple[str, dict[str, Any]]] = []
        must_replan = False
        while plans_used < max_plans:
            # After a rejected plan the model must fix it: answer_directly isn't offered.
            tools = [PLAN_TOOL] if must_replan else [PLAN_TOOL, NO_CONSULT_TOOL]
            message = self._chat(messages, tools)
            kind, payload = _extract_steps(message)
            if kind == "none" and nudges < 1 and not results:
                # One nudge before giving up: small models sometimes reply in prose.
                nudges += 1
                self.gw.report_progress(
                    self._cred("report_progress"),
                    run_id,
                    "unusable reply, nudged once",
                    raw=_raw_reply(message),
                )
                messages.append({"role": "assistant", "content": message.content or ""})
                messages.append({"role": "user", "content": NUDGE})
                continue
            must_replan = False
            added = 0
            if kind == "plan":
                payload, added = _complete_plan(_normalize_steps(payload, caps), caps, done)
            label = "planned" if kind == "plan" else "replied"
            if added:
                label += f" (+{added} prerequisite step{'s' * (added > 1)} filled in from policy)"
            self.gw.report_progress(
                self._cred("report_progress"),
                run_id,
                label,
                raw=None if kind == "plan" else _raw_reply(message),
            )
            if kind != "plan":
                if results:
                    break  # enough evidence; write the answer below
                answer = payload.strip() or (
                    "The model returned neither a plan nor an explanation. Try naming the "
                    "patient (by name or id like P003) and what you want checked."
                )
                self.gw.finish_run(self._cred("finish_run"), run_id, answer)
                return
            plans_used += 1
            messages.append({"role": "assistant", "content": json.dumps({"steps": payload})})
            try:
                plan = self.gw.declare_plan(self._cred("declare_plan"), run_id, payload)
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
            done.extend((r["tool"], r["args"]) for r in new if r["status"] == "ok")
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
        self.gw.report_progress(self._cred("report_progress"), run_id, "answered")
        self.gw.finish_run(self._cred("finish_run"), run_id, answer.strip())

    def _execute(self, token: str, run_id: str, plan: dict[str, Any], fault: str | None) -> list:
        results: list[dict[str, Any]] = []
        failed = False
        for index, lease in enumerate(plan["leases"]):
            step = {"agent": lease["agent"], "tool": lease["tool"], "args": lease["args"]}
            if failed:
                results.append({**step, "status": "skipped (an earlier step failed)"})
                continue
            try:
                out = self.gw.consult(self._cred("consult"), lease["lease_id"])
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
            self.gw.heartbeat(
                self._cred("heartbeat"), run_id
            )  # raises Denied once the watchdog revokes us
            self._sleep(0.5)

    def _revoked(self, token: str) -> bool:
        try:
            self.gw.check_badge(self._token)
            return False
        except Denied:
            return True
