"""Ward console: chat with the master agent, watch every identity check, revoke anything.

  uv run python -m scripts.ward          # then open http://127.0.0.1:8000/

Operator endpoints (session cookie + X-Ward header):
  POST /api/login, /api/logout
  GET  /api/state?after=<seq>      agents, runs, audit since seq, settings, chain status
  POST /api/chat {prompt, stuck}   hand a request to the master agent (runs in background)
  POST /api/revoke {agent_id}      revoke any agent, any time
  POST /api/settings {...}         watchdog seconds, step pace, replace-revoked toggle
  POST /api/rogue                  a specialist tries to call another one
  POST /api/reset                  fresh gateway, fresh agents, fresh audit log (wipes MCP creds)
  POST /api/clear-history          clear past runs/specialists/audit; keep MCP + master
  POST /api/mcp/issue {role}       provision an external MCP agent; secret shown once

Agent / MCP:
  POST /api/agent/token            workload credentials -> badge
  POST /api/agent/rotate           rotate badge + key
  POST /mcp                        MCP Streamable HTTP (JSON)
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from ward.config import DEFAULT_PATH, WardConfig, load_config
from ward.gateway import Credential, Denied, Gateway
from ward.master import MasterAgent
from ward.mcp import handle_message, proof_op

UI_DIR = Path(__file__).resolve().parent / "ward_ui"
COOKIE = "ward_operator"
CSRF = "x-ward"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com;"
        " font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self';"
        " frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def parse_operators(raw: str) -> dict[str, str]:
    out = {}
    for pair in raw.split(","):
        user, _, password = pair.strip().partition(":")
        if user and password:
            out[user] = password
    return out


def default_llm(config: WardConfig) -> tuple[Any, str, str]:
    """(client, model, problem-or-empty) for the configured backend."""
    from agents.runner import check_llm_ready
    from ward.llm import make_llm

    client, model = make_llm(num_ctx=int(config.master.get("num_ctx", 8192)))
    return client, model, check_llm_ready() or ""


WARD_DB = Path(__file__).resolve().parent.parent / "data" / "ward.db"
WARD_KEY = Path(__file__).resolve().parent.parent / "data" / "ward.key"


def _load_or_create_master_key(path: Path) -> bytes:
    if path.is_file():
        raw = path.read_bytes()
        if len(raw) == 32:
            return raw
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = secrets.token_bytes(32)
    path.write_bytes(raw)
    path.chmod(0o600)
    return raw


class Console:
    """Holds the live gateway + master. Reset swaps both for fresh ones.

    With persist=True (live `scripts.ward`), gateway state + HMAC master key live under
    data/ so a process restart does not orphan MCP credentials. Explicit Reset still wipes.
    """

    def __init__(
        self,
        config: WardConfig,
        llm: Any,
        model: str,
        sleep=time.sleep,  # noqa: ANN001
        persist: bool = False,
    ) -> None:
        self.config = config
        self.llm = llm
        self.model = model
        self._sleep = sleep
        self.persist = persist
        self.reset(wipe=False)

    def reset(self, wipe: bool = True) -> None:
        if self.persist and wipe:
            for path in (WARD_DB, WARD_KEY):
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            for side in (f"{WARD_DB}-wal", f"{WARD_DB}-shm"):
                with contextlib.suppress(FileNotFoundError):
                    Path(side).unlink()
        if self.persist:
            master_key = _load_or_create_master_key(WARD_KEY)
            self.gateway = Gateway(
                self.config,
                db_path=str(WARD_DB),
                sleep=self._sleep,
                master_key=master_key,
            )
        else:
            self.gateway = Gateway(self.config, sleep=self._sleep)
        self.master = MasterAgent(self.gateway, self.llm, self.model, sleep=self._sleep)
        self.master.ensure_identity()
        self.thread: threading.Thread | None = None

    @property
    def busy(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def submit(self, prompt: str, stuck: bool) -> None:
        master = self.master
        self.thread = threading.Thread(
            target=master.handle, args=(prompt, "stuck" if stuck else None), daemon=True
        )
        self.thread.start()


def steal_demo(gateway: Gateway, master: MasterAgent) -> list[dict[str, str]]:
    """Simulated exfiltration of the master's credentials, in two stages.

    1. The attacker steals the badge AND the private key, then the master rotates on
       schedule. The stolen pair is now dead.
    2. The attacker steals the new badge plus one signed request (but not the new key) and
       tries replay, its own key, and the bare badge. All refused; the badge is revoked.
    """
    from ward.gateway import Credential

    master.ensure_identity()
    old_token, old_key = master._token, master._key  # noqa: SLF001 - full compromise
    master.rotate_if_due(force=True)
    label = "Attacker uses badge + private key stolen before the last rotation"
    try:
        gateway.verify(
            Credential(old_token, old_key.proof(old_token, "capabilities")),
            "capabilities",
            revoke_on_fail=False,
        )
        results = [{"attempt": label, "result": "ACCEPTED?!"}]
    except Denied as exc:
        results = [{"attempt": label, "result": exc.reason}]
    captured = master._cred("capabilities")  # noqa: SLF001
    gateway.capabilities(captured)  # the real master's request, sent once
    return results + gateway.steal_badge_test(master._token, captured)  # noqa: SLF001


def create_app(
    config: WardConfig | None = None,
    llm: Any = None,
    model: str | None = None,
    operators: dict[str, str] | None = None,
    watchdog: bool = True,
    sleep=time.sleep,  # noqa: ANN001
    persist: bool = False,
) -> FastAPI:
    config = config or load_config()
    raw_demo = yaml.safe_load(DEFAULT_PATH.read_text()).get("demo", {})
    examples = list(raw_demo.get("examples", []))
    operators = operators or parse_operators(
        os.environ.get("WARD_OPERATORS") or raw_demo.get("operators", "")
    )
    llm_problem = ""
    if llm is None:
        llm, model, llm_problem = default_llm(config)
    console = Console(config, llm, model or "fake", sleep=sleep, persist=persist)
    sessions: dict[str, str] = {}

    app = FastAPI(title="Ward console", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.console = console

    def _mcp_ask(prompt: str) -> dict[str, Any]:
        """MCP ask_ward → same OrchestratorAgent path as the console chat.

        Runs the master on a worker thread (and /mcp itself is off the event loop) so
        /api/state keeps polling — the dashboard can show live leases and Revoke mid-run.
        """
        c = app.state.console
        if c.busy:
            raise Denied("DENY_BUSY", "orchestrator is busy with another request")
        c.gateway.close_mcp_sessions("superseded by ask_ward")
        box: dict[str, Any] = {}
        err: list[BaseException] = []

        def work() -> None:
            try:
                box["run_id"] = c.master.handle(prompt)
            except BaseException as exc:  # noqa: BLE001 - surface to MCP caller
                err.append(exc)

        c.thread = threading.Thread(target=work, daemon=True)
        c.thread.start()
        c.thread.join()
        if err:
            raise err[0]
        run_id = str(box.get("run_id", ""))
        row = c.gateway.conn.execute(
            "SELECT status, answer, error FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return {
            "run_id": run_id,
            "status": row["status"] if row else "unknown",
            "answer": (row["answer"] if row else None) or "",
            "error": (row["error"] if row else None) or "",
        }

    app.state.console.gateway.set_mcp_ask_handler(_mcp_ask)
    # Drop pre-fixover MCP session runs that held specialists open forever.
    app.state.console.gateway.close_mcp_sessions("mcp front door is ask_ward only")

    if watchdog:

        def tick() -> None:
            while True:
                with contextlib.suppress(Exception):  # the watchdog must never die
                    app.state.console.gateway.watchdog_tick()
                with contextlib.suppress(Exception):  # idle masters rotate on schedule too
                    app.state.console.master.rotate_if_due()
                time.sleep(0.25)

        threading.Thread(target=tick, daemon=True).start()

    @app.middleware("http")
    async def headers(request: Request, call_next):  # noqa: ANN001, ANN202
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    def operator(request: Request) -> str | None:
        return sessions.get(request.cookies.get(COOKIE, ""))

    def guarded(request: Request) -> JSONResponse | None:
        if request.headers.get(CSRF) != "1":
            return JSONResponse({"ok": False, "reason": "BAD_REQUEST"}, status_code=400)
        if operator(request) is None:
            return JSONResponse({"ok": False, "reason": "LOGIN_REQUIRED"}, status_code=401)
        return None

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(UI_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=UI_DIR), name="static")

    @app.post("/api/login")
    async def login(request: Request) -> JSONResponse:
        if request.headers.get(CSRF) != "1":
            return JSONResponse({"ok": False, "reason": "BAD_REQUEST"}, status_code=400)
        body = await request.json()
        user = str(body.get("username", ""))[:32]
        expected = operators.get(user)
        given = str(body.get("password", ""))[:128]
        if expected is None or not hmac.compare_digest(expected.encode(), given.encode()):
            app.state.console.gateway._audit(  # noqa: SLF001
                "OPERATOR_LOGIN_FAILED",
                f"Operator sign-in failed for {user!r}",
                decision="DENY",
                reason="BAD_LOGIN",
            )
            return JSONResponse({"ok": False, "reason": "BAD_LOGIN"}, status_code=401)
        session = secrets.token_urlsafe(24)
        sessions[session] = user
        app.state.console.gateway._audit(  # noqa: SLF001
            "OPERATOR_LOGIN", f"Operator {user} signed in", actor=f"operator:{user}"
        )
        response = JSONResponse({"ok": True, "operator": user})
        response.set_cookie(COOKIE, session, httponly=True, samesite="strict", max_age=8 * 3600)
        return response

    @app.post("/api/logout")
    def logout(request: Request) -> JSONResponse:
        sessions.pop(request.cookies.get(COOKIE, ""), None)
        response = JSONResponse({"ok": True})
        response.delete_cookie(COOKIE)
        return response

    @app.get("/api/state")
    def state(request: Request, after: int = 0) -> JSONResponse:
        user = operator(request)
        if user is None:
            return JSONResponse(
                {
                    "ok": False,
                    "reason": "LOGIN_REQUIRED",
                    "hint": " / ".join(f"{u}" for u in operators),
                },
                status_code=401,
            )
        c = app.state.console
        snap = c.gateway.snapshot(after_seq=max(0, after))
        return JSONResponse(
            {
                "ok": True,
                "operator": user,
                "busy": c.busy,
                "master": c.master.agent_id,
                "examples": examples,
                "llm": {"model": c.model, "problem": llm_problem},
                **snap,
            }
        )

    @app.post("/api/chat")
    async def chat(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        body = await request.json()
        prompt = str(body.get("prompt", "")).strip()[:2000]
        c = app.state.console
        if not prompt:
            return JSONResponse({"ok": False, "reason": "EMPTY"}, status_code=400)
        if c.busy:
            return JSONResponse({"ok": False, "reason": "BUSY"}, status_code=409)
        c.submit(prompt, bool(body.get("stuck")))
        return JSONResponse({"ok": True})

    @app.post("/api/revoke")
    async def revoke(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        body = await request.json()
        agent_id = str(body.get("agent_id", ""))[:64]
        done = app.state.console.gateway.revoke(
            agent_id, f"operator:{operator(request)}", "revoked from the console"
        )
        return JSONResponse({"ok": done, "reason": "OK" if done else "NOT_ACTIVE"})

    @app.post("/api/settings")
    async def settings(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        body = await request.json()
        s = app.state.console.gateway.settings
        if "watchdog_seconds" in body:
            # Floor: the master's model needs a few seconds per reply; below this the
            # watchdog would revoke a healthy agent.
            s["watchdog_seconds"] = float(min(300, max(10, float(body["watchdog_seconds"]))))
        if "step_delay_ms" in body:
            s["step_delay_ms"] = int(min(5000, max(0, int(body["step_delay_ms"]))))
        if "replace_revoked_specialists" in body:
            s["replace_revoked_specialists"] = bool(body["replace_revoked_specialists"])
        return JSONResponse({"ok": True, "settings": s})

    @app.post("/api/rogue")
    def rogue(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        return JSONResponse({"ok": True, "results": app.state.console.gateway.rogue_test()})

    @app.post("/api/attack/steal")
    def steal(request: Request) -> JSONResponse:
        """Exfiltrate the master's badge plus one signed request it already sent, and try
        to use them."""
        if (bad := guarded(request)) is not None:
            return bad
        c = app.state.console
        return JSONResponse({"ok": True, "results": steal_demo(c.gateway, c.master)})

    @app.post("/api/attack/tampered")
    def tampered(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        return JSONResponse(
            {"ok": True, "results": app.state.console.gateway.tampered_agent_test()}
        )

    @app.post("/api/clear-history")
    def clear_history(request: Request) -> JSONResponse:
        """Clear runs, specialists, and the audit feed.

        Keeps the current master, active MCP identities, and data/mcp-credentials.env.
        Aborts an in-flight run if needed (no longer returns BUSY).
        """
        if (bad := guarded(request)) is not None:
            return bad
        c = app.state.console
        keep = {c.master.agent_id} if c.master.agent_id else set()
        for row in c.gateway.conn.execute(
            "SELECT agent_id, role, status FROM agents WHERE status = 'active'"
        ):
            if c.gateway.config.roles[row["role"]].external:
                keep.add(row["agent_id"])
        stats = c.gateway.clear_history(keep_agent_ids=keep)
        # Let a just-aborted ask_ward/chat worker exit so busy clears.
        if c.thread is not None and c.thread.is_alive():
            c.thread.join(timeout=3)
        return JSONResponse({"ok": True, **stats})

    @app.post("/api/reset")
    def reset(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        c = app.state.console
        if c.busy:
            c.gateway.revoke(c.master.agent_id or "", "operator", "console reset")
            c.thread.join(timeout=5)
        c.reset()
        return JSONResponse({"ok": True})

    @app.post("/api/approvals/{approval_id}/approve")
    async def approve(request: Request, approval_id: str) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        ok = app.state.console.gateway.decide_approval(
            approval_id, True, operator(request) or "unknown"
        )
        return JSONResponse({"ok": ok, "reason": "OK" if ok else "NOT_PENDING"})

    @app.post("/api/approvals/{approval_id}/deny")
    async def deny_approval(request: Request, approval_id: str) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        body = await request.json()
        ok = app.state.console.gateway.decide_approval(
            approval_id,
            False,
            operator(request) or "unknown",
            str(body.get("reason", ""))[:200],
        )
        return JSONResponse({"ok": ok, "reason": "OK" if ok else "NOT_PENDING"})

    @app.post("/api/escalations/{escalation_id}/ack")
    async def ack_escalation(request: Request, escalation_id: str) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        ok = app.state.console.gateway.acknowledge_escalation(
            escalation_id, operator(request) or "unknown"
        )
        return JSONResponse({"ok": ok, "reason": "OK" if ok else "NOT_OPEN"})

    @app.post("/api/mcp/issue")
    async def mcp_issue(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        body = await request.json()
        role = str(body.get("role", ""))
        if role not in {r.name for r in app.state.console.gateway.config.external_roles()}:
            return JSONResponse({"ok": False, "reason": "UNKNOWN_ROLE"}, status_code=400)
        agent_id, secret = app.state.console.gateway.provision(role)
        # Operator-issued secret file for badge_agent (gitignored). Cursor never mints this.
        cred_dir = Path(__file__).resolve().parent.parent / "data"
        cred_dir.mkdir(parents=True, exist_ok=True)
        cred_path = cred_dir / "mcp-credentials.env"
        cred_path.write_text(
            f"WARD_CLIENT_ID={agent_id}\nWARD_CLIENT_SECRET={secret}\nWARD_ROLE={role}\n",
            encoding="utf-8",
        )
        cred_path.chmod(0o600)
        app.state.console.gateway._audit(  # noqa: SLF001
            "MCP_CREDENTIAL_ISSUED",
            f"Operator {operator(request)} issued MCP credentials for {agent_id} ({role})",
            actor=f"operator:{operator(request)}",
            target=agent_id,
            detail={"role": role, "secret": "written once to data/mcp-credentials.env"},
        )
        return JSONResponse(
            {
                "ok": True,
                "client_id": agent_id,
                "secret": secret,
                "role": role,
                "credentials_file": str(cred_path),
                "warning": (
                    "Operator-issued secret written to data/mcp-credentials.env (gitignored). "
                    "Point Cursor mcp.json at that file — do not let an agent invent credentials."
                ),
            }
        )

    def _bearer(request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            return header[7:].strip() or None
        return None

    @app.post("/api/agent/token")
    async def agent_token(request: Request) -> JSONResponse:
        body = await request.json()
        try:
            session = app.state.console.gateway.authenticate(
                str(body.get("client_id", "")),
                str(body.get("secret", "")),
                str(body.get("public_pem", "")),
                str(body.get("key_proof", "")),
                str(body.get("measurement", "")),
            )
        except Denied as exc:
            return JSONResponse(
                {"ok": False, "reason": exc.reason, "detail": exc.detail}, status_code=403
            )
        # External agents only need the badge token + timing. Seal/proof keys stay server-side
        # for specialist consults; never return them over this endpoint.
        return JSONResponse(
            {
                "ok": True,
                "token": session["token"],
                "jti": session["jti"],
                "issued_ms": session["issued_ms"],
                "expires_ms": session["expires_ms"],
                "rotate_after_ms": app.state.console.gateway.config.rotate_after_seconds * 1000,
            }
        )

    @app.post("/api/agent/rotate")
    async def agent_rotate(request: Request) -> JSONResponse:
        token = _bearer(request)
        proof = request.headers.get("x-badge-proof")
        body = await request.json()
        try:
            session = app.state.console.gateway.rotate(
                Credential(token or "", proof),
                str(body.get("public_pem", "")),
                str(body.get("key_proof", "")),
            )
        except Denied as exc:
            return JSONResponse(
                {"ok": False, "reason": exc.reason, "detail": exc.detail}, status_code=403
            )
        return JSONResponse(
            {
                "ok": True,
                "token": session["token"],
                "jti": session["jti"],
                "issued_ms": session["issued_ms"],
                "expires_ms": session["expires_ms"],
                "rotate_after_ms": app.state.console.gateway.config.rotate_after_seconds * 1000,
            }
        )

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        try:
            message = json.loads(await request.body())
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            )
        token = _bearer(request)
        proof = request.headers.get("x-badge-proof")
        method = message.get("method") if isinstance(message, dict) else None
        params = message.get("params") if isinstance(message, dict) else {}
        if not isinstance(params, dict):
            params = {}
        badge = None
        denied: Denied | None = None
        if isinstance(method, str) and "id" in (message or {}):
            op = proof_op(method, params)
            try:
                badge = app.state.console.gateway.verify(Credential(token, proof), op)
            except Denied as exc:
                denied = exc
        elif isinstance(method, str):
            # Notification: still require a valid badge when one is presented.
            try:
                badge = app.state.console.gateway.verify(
                    Credential(token, proof), proof_op(method, params), revoke_on_fail=False
                )
            except Denied as exc:
                denied = exc
        # Off the event loop: ask_ward can take many seconds; UI must keep polling.
        reply = await asyncio.to_thread(
            handle_message, message, app.state.console.gateway, badge, denied
        )
        if reply.body is None:
            return Response(status_code=202)
        return JSONResponse(reply.body, status_code=reply.status)

    @app.api_route("/mcp", methods=["GET", "DELETE"])
    def mcp_no_stream() -> Response:
        return Response(status_code=405, headers={"Allow": "POST"})

    @app.exception_handler(Denied)
    async def denied(_: Request, exc: Denied) -> JSONResponse:
        return JSONResponse(
            {"ok": False, "reason": exc.reason, "detail": exc.detail}, status_code=403
        )

    return app
