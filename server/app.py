"""FastAPI gateway + monitor dashboard.

Agent authentication (workload identity, OAuth2 client_credentials):
  POST /auth/agent/token  form or JSON {grant_type, client_id, client_secret} -> badge

Agent endpoints (Authorization: Bearer <badge>):
  POST /mcp              MCP (Streamable HTTP, JSON responses): tools/list, tools/call
  POST /tools/{name}     body {"args": {...}, "idempotency_key": "<uuid>"}
  POST /declare_plan     body {"task_id": ..., "steps": [...]}
  GET  /list_my_tools
Every one of them goes through `badge.pipeline.handle_call`. There is no other path.

Dashboard: GET /, POST /auth/login, POST /auth/logout, GET /api/snapshot,
POST /api/monitor/{tool} (monitor badge in an HttpOnly cookie).
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import sqlite3
import time
from collections import defaultdict, deque
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from badge import db, identity, mcp, workload
from badge.clock import Clock, SystemClock
from badge.config import DEFAULT_CONFIG_PATH, load_config
from badge.context import CallContext, CallRequest, Runtime
from badge.db import write_tx
from badge.decisions import Allow, Deny
from badge.pipeline import CallResult, handle_call
from badge.tools.registry import check_registry
from badge.views import dashboard_snapshot

logger = logging.getLogger(__name__)

DASHBOARD_DIR = Path(__file__).resolve().parent / "dashboard"
MAX_BODY_BYTES = 64 * 1024
MONITOR_COOKIE = "badge_monitor"
CSRF_HEADER = "x-badge-dashboard"
LOGIN_ATTEMPTS_PER_MINUTE = 5
MONITOR_PREFIX = "monitor-"
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


@dataclass(frozen=True)
class Settings:
    db_path: Path
    signing_key: str
    monitor_passwords: dict[str, str]
    config_path: Path = DEFAULT_CONFIG_PATH

    @classmethod
    def from_env(cls) -> Settings:
        signing_key = os.environ.get("BADGE_SIGNING_KEY", "")
        if not signing_key:
            raise RuntimeError("BADGE_SIGNING_KEY is required (see .env.example)")
        return cls(
            db_path=Path(os.environ.get("BADGE_DB", "data/badge.db")),
            signing_key=signing_key,
            monitor_passwords=parse_monitor_passwords(os.environ.get("MONITOR_PASSWORDS", "")),
        )


def parse_monitor_passwords(raw: str) -> dict[str, str]:
    """'alice:pw1,bob:pw2' -> {'alice': 'pw1', 'bob': 'pw2'}. Demo-grade only."""
    logins = {}
    for pair in filter(None, (item.strip() for item in raw.split(","))):
        user, _, password = pair.partition(":")
        if user.isalnum() and user.islower() and password:
            logins[user] = password
    return logins


class LoginThrottle:
    """In-memory sliding-window limit on login attempts per username."""

    def __init__(self, limit: int, window_seconds: float = 60) -> None:
        self._limit, self._window = limit, window_seconds
        self._attempts: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, username: str) -> bool:
        now = time.monotonic()
        attempts = self._attempts[username]
        while attempts and now - attempts[0] > self._window:
            attempts.popleft()
        if len(attempts) >= self._limit:
            return False
        attempts.append(now)
        return True


def bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token else None


async def read_json(request: Request) -> Any:
    """The parsed body, or a sentinel string the schema check will reject (and audit)."""
    body = await request.body()
    if not body:
        return {}
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "<malformed json>"


def result_response(result: CallResult) -> JSONResponse:
    return JSONResponse(result.to_json(), status_code=200 if result.allowed else 403)


def create_app(settings: Settings | None = None, clock: Clock | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    config = load_config(settings.config_path)
    check_registry(config)
    runtime = Runtime(config=config, clock=clock or SystemClock(), signing_key=settings.signing_key)
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    setup_conn = db.connect(settings.db_path)
    db.migrate(setup_conn)
    setup_conn.close()
    throttle = LoginThrottle(LOGIN_ATTEMPTS_PER_MINUTE)

    app = FastAPI(title="Badge gateway", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.runtime = runtime
    app.state.settings = settings

    @contextmanager
    def connection() -> Iterator[sqlite3.Connection]:
        conn = db.connect(settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def run_call(token: str | None, tool: str, args: Any, key: Any) -> CallResult:
        with connection() as conn:
            request = CallRequest(
                token=token,
                tool=tool,
                args=args,
                idempotency_key=key if isinstance(key, str) else None,
            )
            return handle_call(runtime, conn, request)

    @app.middleware("http")
    async def limits_and_headers(request: Request, call_next):  # noqa: ANN001, ANN202
        declared = request.headers.get("content-length")
        if declared and (not declared.isdigit() or int(declared) > MAX_BODY_BYTES):
            return JSONResponse({"ok": False, "reason": "BODY_TOO_LARGE"}, status_code=413)
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        return response

    # ---- agent API -------------------------------------------------------------------

    @app.post("/tools/{tool_name}")
    async def call_tool(tool_name: str, request: Request) -> JSONResponse:
        body = await read_json(request)
        args = body.get("args", {}) if isinstance(body, dict) else body
        key = body.get("idempotency_key") if isinstance(body, dict) else None
        if isinstance(body, dict) and set(body) - {"args", "idempotency_key"}:
            args = "<unexpected body fields>"
        result = await run_in_threadpool(run_call, bearer_token(request), tool_name, args, key)
        return result_response(result)

    @app.post("/declare_plan")
    async def declare_plan(request: Request) -> JSONResponse:
        body = await read_json(request)
        result = await run_in_threadpool(
            run_call, bearer_token(request), "declare_plan", body, None
        )
        return result_response(result)

    @app.get("/list_my_tools")
    async def list_my_tools(request: Request) -> JSONResponse:
        result = await run_in_threadpool(run_call, bearer_token(request), "list_my_tools", {}, None)
        return result_response(result)

    # ---- agent authentication (workload identity) ------------------------------------

    def exchange(client_id: str, client_secret: str) -> str | Deny:
        with connection() as conn, write_tx(conn):
            return workload.exchange_credentials(conn, runtime, client_id, client_secret)

    @app.post("/auth/agent/token")
    async def agent_token(request: Request) -> JSONResponse:
        """OAuth2 client_credentials grant. The access token is the badge (a signed JWT)."""
        if request.headers.get("content-type", "").startswith("application/json"):
            body = await read_json(request)
        else:
            raw = (await request.body()).decode("utf-8", "replace")[:4096]
            body = {k: v[0] for k, v in parse_qs(raw).items()}
        if not isinstance(body, dict) or body.get("grant_type") != "client_credentials":
            return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
        client_id = str(body.get("client_id", ""))
        if not throttle.allow(f"agent:{client_id[:64]}"):
            return JSONResponse({"error": "slow_down"}, status_code=429)
        result = await run_in_threadpool(exchange, client_id, str(body.get("client_secret", "")))
        if isinstance(result, Deny):
            return JSONResponse(
                {"error": "invalid_client", "reason": result.reason}, status_code=401
            )
        info = identity.decode_badge(runtime, result, runtime.clock.now())
        expires_in = int(info.expires_at - runtime.clock.now()) if not isinstance(info, Deny) else 0
        return JSONResponse(
            {"access_token": result, "token_type": "Bearer", "expires_in": expires_in},
            headers={"Cache-Control": "no-store"},
        )

    # ---- MCP -------------------------------------------------------------------------

    mutating_tools = {name for name, spec in config.tools.items() if spec.mutating}

    def mcp_check_badge(token: str | None) -> str | None:
        with connection() as conn:
            ctx = CallContext(runtime, conn, CallRequest(token, "mcp", {}), runtime.clock.now())
            decision = identity.check_badge(ctx)
        return None if isinstance(decision, Allow) else decision.reason

    def mcp_handle(token: str | None, message: Any) -> mcp.McpReply:
        def run(tool: str, args: Any, key: str | None) -> dict[str, Any]:
            return run_call(token, tool, args, key).to_json()

        return mcp.handle_message(message, lambda: mcp_check_badge(token), run, mutating_tools)

    @app.post("/mcp")
    async def mcp_endpoint(request: Request) -> Response:
        try:
            message = json.loads(await request.body())
        except (ValueError, UnicodeDecodeError):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            )
        reply = await run_in_threadpool(mcp_handle, bearer_token(request), message)
        if reply.body is None:
            return Response(status_code=202)
        return JSONResponse(reply.body, status_code=reply.status)

    @app.api_route("/mcp", methods=["GET", "DELETE"])
    def mcp_no_stream() -> Response:
        # No server-initiated stream and no sessions to end.
        return Response(status_code=405, headers={"Allow": "POST"})

    @app.get("/favicon.ico")
    def favicon() -> Response:
        return Response(status_code=204)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ---- dashboard -------------------------------------------------------------------

    def monitor_identity(request: Request) -> str | None:
        """The verified monitor agent_id behind the session cookie, or None."""
        token = request.cookies.get(MONITOR_COOKIE)
        with connection() as conn:
            ctx = CallContext(
                runtime, conn, CallRequest(token, "view_audit", {}), runtime.clock.now()
            )
            decision = identity.check_badge(ctx)
        if not isinstance(decision, Allow) or decision.updates["badge"].role != "monitor":
            return None
        return decision.updates["badge"].agent_id

    def login_monitor(username: str) -> str | None:
        """Register the monitor on first login and mint a fresh badge. None if revoked."""
        agent_id = f"{MONITOR_PREFIX}{username}"
        with connection() as conn, write_tx(conn):
            row = conn.execute(
                "SELECT status FROM agents WHERE agent_id = ?", (agent_id,)
            ).fetchone()
            if row is None:
                identity.register_agent(conn, runtime, agent_id, "monitor")
            elif row["status"] != "active":
                return None
            return identity.issue_badge(conn, runtime, agent_id)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(DASHBOARD_DIR / "index.html")

    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR / "static"), name="static")

    @app.post("/auth/login")
    async def login(request: Request) -> Response:
        body = await read_json(request)
        if not isinstance(body, dict) or request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"ok": False, "reason": "BAD_REQUEST"}, status_code=400)
        username = str(body.get("username", ""))[:32]
        password = str(body.get("password", ""))[:128]
        if not throttle.allow(username):
            return JSONResponse({"ok": False, "reason": "TOO_MANY_ATTEMPTS"}, status_code=429)
        expected = settings.monitor_passwords.get(username)
        if expected is None or not hmac.compare_digest(expected.encode(), password.encode()):
            return JSONResponse({"ok": False, "reason": "BAD_LOGIN"}, status_code=401)
        token = await run_in_threadpool(login_monitor, username)
        if token is None:
            return JSONResponse({"ok": False, "reason": "DENY_REVOKED"}, status_code=403)
        response = JSONResponse({"ok": True, "agent_id": f"{MONITOR_PREFIX}{username}"})
        response.set_cookie(
            MONITOR_COOKIE,
            token,
            httponly=True,
            samesite="strict",
            max_age=config.badge_ttl_for("monitor") * 60,
        )
        return response

    @app.post("/auth/logout")
    def logout() -> Response:
        response = JSONResponse({"ok": True})
        response.delete_cookie(MONITOR_COOKIE)
        return response

    @app.get("/api/snapshot")
    def snapshot(request: Request, agent: str | None = None) -> JSONResponse:
        monitor = monitor_identity(request)
        if monitor is None:
            return JSONResponse({"ok": False, "reason": "LOGIN_REQUIRED"}, status_code=401)
        audit_agent = agent[:64] if agent else None
        with connection() as conn:
            data = dashboard_snapshot(conn, runtime, audit_agent=audit_agent)
        return JSONResponse({"ok": True, "monitor": monitor, **data})

    @app.post("/api/monitor/{tool_name}")
    async def monitor_action(tool_name: str, request: Request) -> JSONResponse:
        if request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"ok": False, "reason": "BAD_REQUEST"}, status_code=400)
        body = await read_json(request)
        args = body.get("args", {}) if isinstance(body, dict) else body
        key = body.get("idempotency_key") if isinstance(body, dict) else None
        token = request.cookies.get(MONITOR_COOKIE)
        result = await run_in_threadpool(run_call, token, tool_name, args, key)
        return result_response(result)

    return app


def app_from_env() -> FastAPI:
    """Entry point for `uvicorn server.app:app_from_env --factory`."""
    logging.basicConfig(level=logging.INFO)
    return create_app()
