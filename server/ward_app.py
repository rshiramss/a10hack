"""Ward console: chat with the master agent, watch every identity check, revoke anything.

  uv run python -m scripts.ward          # then open http://127.0.0.1:8000/

Operator endpoints (session cookie + X-Ward header):
  POST /api/login, /api/logout
  GET  /api/state?after=<seq>      agents, runs, audit since seq, settings, chain status
  POST /api/chat {prompt, stuck}   hand a request to the master agent (runs in background)
  POST /api/revoke {agent_id}      revoke any agent, any time
  POST /api/settings {...}         watchdog seconds, step pace, replace-revoked toggle
  POST /api/rogue                  a specialist tries to call another one
  POST /api/reset                  fresh gateway, fresh agents, fresh audit log
"""

from __future__ import annotations

import contextlib
import hmac
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from ward.config import DEFAULT_PATH, WardConfig, load_config
from ward.gateway import Denied, Gateway
from ward.master import MasterAgent

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


class Console:
    """Holds the live gateway + master. Reset swaps both for fresh ones."""

    def __init__(self, config: WardConfig, llm: Any, model: str, sleep=time.sleep) -> None:  # noqa: ANN001
        self.config = config
        self.llm = llm
        self.model = model
        self._sleep = sleep
        self.reset()

    def reset(self) -> None:
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


def create_app(
    config: WardConfig | None = None,
    llm: Any = None,
    model: str | None = None,
    operators: dict[str, str] | None = None,
    watchdog: bool = True,
    sleep=time.sleep,  # noqa: ANN001
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
    console = Console(config, llm, model or "fake", sleep=sleep)
    sessions: dict[str, str] = {}

    app = FastAPI(title="Ward console", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.console = console

    if watchdog:

        def tick() -> None:
            while True:
                with contextlib.suppress(Exception):  # the watchdog must never die
                    app.state.console.gateway.watchdog_tick()
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
        c.master.ensure_identity()
        captured = c.master._cred("capabilities")  # noqa: SLF001 - simulated exfiltration
        c.gateway.capabilities(captured)  # the real master's request, sent once
        stolen = c.master._token  # noqa: SLF001
        return JSONResponse({"ok": True, "results": c.gateway.steal_badge_test(stolen, captured)})

    @app.post("/api/attack/tampered")
    def tampered(request: Request) -> JSONResponse:
        if (bad := guarded(request)) is not None:
            return bad
        return JSONResponse(
            {"ok": True, "results": app.state.console.gateway.tampered_agent_test()}
        )

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

    @app.exception_handler(Denied)
    async def denied(_: Request, exc: Denied) -> JSONResponse:
        return JSONResponse(
            {"ok": False, "reason": exc.reason, "detail": exc.detail}, status_code=403
        )

    return app
